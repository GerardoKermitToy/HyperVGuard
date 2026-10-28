// Offline fixtures: every device API is faked; only private unnamed events are real.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "DriverProtocol.h"
#include "RecordOutput.h"
#include "../../driver/shim/adapter_info.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <cstdlib>
#include <cwchar>
#include <new>
#include <stdexcept>
#include <vector>

// Compile the implementation with private device entry points. The static
// pmkext archive still supplies the independent codec, not a second Driver.
namespace adapter_test_io {
HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL CloseHandle(HANDLE);
BOOL DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL CancelIoEx(HANDLE, LPOVERLAPPED);
}
#define CreateFileW adapter_test_io::CreateFileW
#define CloseHandle adapter_test_io::CloseHandle
#define DeviceIoControl adapter_test_io::DeviceIoControl
#define GetOverlappedResult adapter_test_io::GetOverlappedResult
#define ReadFile adapter_test_io::ReadFile
#define WriteFile adapter_test_io::WriteFile
#define CancelIoEx adapter_test_io::CancelIoEx
#include "../src/PortmasterKext.cpp"
#undef CreateFileW
#undef CloseHandle
#undef DeviceIoControl
#undef GetOverlappedResult
#undef ReadFile
#undef WriteFile
#undef CancelIoEx

namespace allocation {
thread_local size_t fail_size = 0;
thread_local bool failed = false;
struct FailSize {
    size_t previous = fail_size;
    bool previous_failed = failed;
    explicit FailSize(size_t size) { fail_size = size; failed = false; }
    ~FailSize() { fail_size = previous; failed = previous_failed; }
};
}
void* operator new(size_t size) {
    if (allocation::fail_size && size == allocation::fail_size) {
        allocation::fail_size = 0; allocation::failed = true;
        throw std::bad_alloc();
    }
    if (void* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void* operator new[](size_t size) { return ::operator new(size); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete(void* p, size_t) noexcept { ::operator delete(p); }
void operator delete[](void* p, size_t) noexcept { ::operator delete(p); }
void* operator new(size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void* operator new[](size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new[](size); } catch (...) { return nullptr; }
}
void operator delete(void* p, const std::nothrow_t&) noexcept { ::operator delete(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { ::operator delete(p); }

namespace adapter_test_io {
struct Reply {
    std::vector<uint8_t> bytes;
    DWORD error = ERROR_SUCCESS, reported = UINT32_MAX;
    bool pending = false;
};
struct State {
    std::vector<uint8_t> snapshot;
    std::vector<Reply> replies;
    std::vector<DWORD> capacities;
    size_t next = 0;
    OVERLAPPED* active = nullptr;
    DWORD bytes = 0, error = ERROR_SUCCESS;
    bool legacy = false;
} state;
HANDLE Device() { return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x5678)); }
void Reset(std::vector<uint8_t> snapshot = {}) {
    if (state.active) throw std::runtime_error("unreaped fake adapter query");
    state = {};
    state.snapshot = std::move(snapshot);
}
HANDLE CreateFileW(LPCWSTR path, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES,
                   DWORD mode, DWORD flags, HANDLE) {
    if (std::wcscmp(path, L"\\\\.\\HyperVXNdisFilter") || access != (GENERIC_READ | GENERIC_WRITE) ||
        sharing || mode != OPEN_EXISTING || !(flags & FILE_FLAG_OVERLAPPED)) {
        ::SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
    }
    return Device();
}
BOOL CloseHandle(HANDLE handle) { return handle == Device() ? TRUE : ::CloseHandle(handle); }
BOOL DeviceIoControl(HANDLE handle, DWORD code, LPVOID input, DWORD input_size, LPVOID output,
                     DWORD capacity, LPDWORD actual, LPOVERLAPPED ov) {
    if (handle != Device() || input || input_size || !ov || state.active) {
        ::SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    if (code == pmkext::wire::kIoctlShutdown) {
        state.active = ov; state.bytes = 0; state.error = ERROR_SUCCESS; *actual = 0; return TRUE;
    }
    if (code != pmkext::wire::kIoctlAdapterInfo || !output || capacity < HV_ADAPTER_INFO_HEADER_SIZE) {
        ::SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    state.capacities.push_back(capacity);
    const Reply* reply = state.next < state.replies.size() ? &state.replies[state.next++] : nullptr;
    const auto& bytes = reply ? reply->bytes : state.snapshot;
    DWORD error = reply ? reply->error : ERROR_SUCCESS;
    DWORD returned = reply && reply->reported != UINT32_MAX ? reply->reported : static_cast<DWORD>(bytes.size());
    if (!reply && capacity < bytes.size()) {
        if (state.legacy) { ::SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        returned = HV_ADAPTER_INFO_HEADER_SIZE; error = ERROR_MORE_DATA;
    }
    if (error && error != ERROR_MORE_DATA && !(reply && reply->pending)) {
        ::SetLastError(error); return FALSE;
    }
    const size_t copied = (std::min)({bytes.size(), static_cast<size_t>(returned), static_cast<size_t>(capacity)});
    if (copied) std::memcpy(output, bytes.data(), copied);
    state.active = ov; state.bytes = returned; state.error = error;
    // Immediate MORE_DATA deliberately reports zero here: the client must reap
    // the completed OVERLAPPED to obtain the authoritative 16-byte header size.
    *actual = error == ERROR_MORE_DATA ? 0 : returned;
    if (reply && reply->pending) { ::SetLastError(ERROR_IO_PENDING); return FALSE; }
    if (error) { ::SetLastError(error); return FALSE; }
    return TRUE;
}
BOOL GetOverlappedResult(HANDLE handle, LPOVERLAPPED ov, LPDWORD actual, BOOL) {
    if (handle != Device() || ov != state.active) { ::SetLastError(ERROR_NOT_FOUND); return FALSE; }
    state.active = nullptr; *actual = state.bytes;
    if (state.error) { ::SetLastError(state.error); return FALSE; }
    return TRUE;
}
BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) { ::SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) { ::SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL CancelIoEx(HANDLE, LPOVERLAPPED) { ::SetLastError(ERROR_NOT_FOUND); return FALSE; }
}

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return false; } } while (0)

static_assert(pmkext::wire::kAdapterInfoVersion == HV_ADAPTER_INFO_VERSION);
static_assert(pmkext::wire::kAdapterInfoEntrySize == HV_ADAPTER_INFO_ENTRY_SIZE);
static_assert(pmkext::wire::kAdapterInfoHeaderSize == HV_ADAPTER_INFO_HEADER_SIZE);
static_assert(pmkext::wire::kMaxAdapters == HV_ADAPTER_INFO_MAX_ADAPTERS);
static_assert(pmkext::wire::kAdapterNameCapacity == HV_ADAPTER_INFO_NAME_CAPACITY);
static_assert(pmkext::wire::kMaxAdapterInfoSize == HV_ADAPTER_INFO_MAX_SIZE);
static_assert(pmkext::wire::kIoctlAdapterInfo == 0x9c40e00c);
static_assert(pmkext::AdapterInfo::Running == HV_ADAPTER_RUNNING);
static_assert(pmkext::AdapterInfo::GeneralAttributesValid == HV_ADAPTER_GENERAL_VALID);
static_assert(pmkext::AdapterInfo::ConnectorPresentValid == HV_ADAPTER_CONNECTOR_VALID);
static_assert(pmkext::AdapterInfo::InstanceNameTruncated == HV_ADAPTER_INSTANCE_NAME_TRUNCATED);
static_assert(pmkext::AdapterInfo::BaseNameTruncated == HV_ADAPTER_BASE_NAME_TRUNCATED);
static_assert(pmkext::AdapterInfo::FilterModuleNameTruncated == HV_ADAPTER_FILTER_NAME_TRUNCATED);
static_assert(pmkext::AdapterInfo::LinkStateValid == HV_ADAPTER_LINK_STATE_VALID);
static_assert(pmkext::AdapterInfo::PauseValid == HV_ADAPTER_PAUSE_VALID);

HV_ADAPTER_INFO Fixture() {
    HV_ADAPTER_INFO a{};
    a.ModuleId = 0x0102030405060708ULL;
    a.InterfaceIndex = 0x89abcdef;
    a.FilterInterfaceIndex = 17; a.LowerInterfaceIndex = 18;
    a.Flags = HV_ADAPTER_RUNNING | HV_ADAPTER_GENERAL_VALID | HV_ADAPTER_CONNECTOR_VALID |
              HV_ADAPTER_LINK_STATE_VALID | HV_ADAPTER_PAUSE_VALID;
    a.InterfaceLuid = 0x1122334455667788ULL;
    a.FilterInterfaceLuid = 0x8877665544332211ULL;
    a.LowerInterfaceLuid = 0x123456789abcdef0ULL;
    const uint8_t guid[]{0x78,0x56,0x34,0x12,0xbc,0x9a,0xf0,0xde,1,2,3,4,5,6,7,8};
    std::copy(std::begin(guid), std::end(guid), a.InterfaceGuid);
    a.MediaType = 0; a.PhysicalMedium = 14; a.MediaConnectState = 1; a.MediaDuplexState = 2;
    a.XmitLinkSpeed = 10000000000ULL; a.RcvLinkSpeed = 20000000000ULL;
    a.Mtu = 1500; a.MacOptions = 0x101; a.SupportedPacketFilters = 0x202; a.MaxMulticastListSize = 33;
    a.MaxXmitLinkSpeed = 30000000000ULL; a.MaxRcvLinkSpeed = 40000000000ULL;
    a.LookaheadSize = 128; a.AccessType = 2; a.ConnectionType = 3; a.SupportedStatistics = 0x404;
    a.DataBackFillSize = 4; a.ContextBackFillSize = 5; a.RestartFlags = 0x606; a.AttachFlags = 0x707;
    a.ConnectorPresent = 1; a.MacAddressLength = 6;
    for (unsigned i = 0; i < 6; ++i) a.MacAddress[i] = static_cast<uint8_t>(0xa0 + i);
    a.AutoNegotiationFlags = 0x808; a.PauseReason = 0x909; a.PauseFlags = 0xa0a;
    const uint16_t name[]{0x0410, 0x0434, 0x0430, 0x043f, 0x0442, 0x0435, 0x0440};
    a.InstanceNameLength = HvCopyAdapterName(a.InstanceName, name, 7, &a.Flags, HV_ADAPTER_INSTANCE_NAME_TRUNCATED);
    const uint16_t base[]{'\\','D','e','v','i','c','e','\\','t','e','s','t'};
    a.BaseNameLength = HvCopyAdapterName(a.BaseName, base, 12, &a.Flags, HV_ADAPTER_BASE_NAME_TRUNCATED);
    const uint16_t filter[]{'{','1','2','3','4','}'};
    a.FilterModuleNameLength = HvCopyAdapterName(a.FilterModuleName, filter, 6, &a.Flags, HV_ADAPTER_FILTER_NAME_TRUNCATED);
    return a;
}

std::vector<uint8_t> Encode(unsigned count) {
    std::vector<uint8_t> bytes(HvAdapterInfoSize(count), 0xcc);
    HvEncodeAdapterInfoHeader(bytes.data(), count, count == 0 ? 0 : 1);
    auto a = Fixture();
    for (unsigned i = 0; i < count; ++i) {
        a.ModuleId += i;
        if (i != 0) a.Flags &= ~HV_ADAPTER_RUNNING;
        HvEncodeAdapterInfo(bytes.data() + HV_ADAPTER_INFO_HEADER_SIZE + i * HV_ADAPTER_INFO_ENTRY_SIZE, &a);
    }
    return bytes;
}

bool CheckRoundTrip() {
    CHECK(HvAdapterInfoSize(0) == 16 && HvAdapterInfoSize(32) == 56336 && HvAdapterInfoSize(33) == 58096);
    CHECK(HV_ADAPTER_INFO_MAX_ADAPTERS == 2440322u && HV_ADAPTER_INFO_MAX_SIZE == 4294966736u);
    CHECK(HvAdapterInfoSize(HV_ADAPTER_INFO_MAX_ADAPTERS) == HV_ADAPTER_INFO_MAX_SIZE);
    CHECK(HvAdapterInfoSize(HV_ADAPTER_INFO_MAX_ADAPTERS + 1u) == 0);
    CHECK(HvAdapterInfoSize(UINT32_MAX) == 0);
    static_assert(pmkext::wire::kInitialAdapterInfoSize == 56336);
    static_assert(static_cast<uint64_t>(HV_ADAPTER_INFO_MAX_SIZE) + HV_ADAPTER_INFO_ENTRY_SIZE > UINT32_MAX);
    auto bytes = Encode(2);
    CHECK(bytes[0] == 1 && bytes[4] == 0xe0 && bytes[5] == 6 && bytes[8] == 2 && bytes[12] == 1);
    const size_t p = 16;
    CHECK(bytes[p] == 8 && bytes[p + 7] == 1 && bytes[p + 8] == 0xef && bytes[p + 11] == 0x89);
    CHECK(bytes[p + 48] == 0x78 && bytes[p + 96] == 0xdc && bytes[p + 97] == 5);
    CHECK(bytes[p + 200] == 7 && bytes[p + 224] == 0x10 && bytes[p + 225] == 4);
    std::string error;
    pmkext::AdapterSnapshot s;
    // An intentionally unaligned buffer must decode without native-layout casts.
    std::vector<uint8_t> unaligned(1, 0xff);
    unaligned.insert(unaligned.end(), bytes.begin(), bytes.end());
    CHECK(pmkext::wire::DecodeAdapterInfo(unaligned.data() + 1, bytes.size(), s, error) && error.empty());
    CHECK(s.running_count == 1 && s.adapters.size() == 2);
    const auto& a = s.adapters[0];
    const auto expected = Fixture();
    CHECK(a.module_id == expected.ModuleId && a.interface_index == expected.InterfaceIndex);
    CHECK(a.filter_interface_index == 17 && a.lower_interface_index == 18 && a.flags == expected.Flags);
    CHECK(a.interface_luid == expected.InterfaceLuid && a.filter_interface_luid == expected.FilterInterfaceLuid);
    CHECK(a.lower_interface_luid == expected.LowerInterfaceLuid);
    CHECK(std::equal(a.interface_guid.begin(), a.interface_guid.end(), expected.InterfaceGuid));
    CHECK(a.media_type == 0 && a.physical_medium == 14 && a.media_connect_state == 1 && a.media_duplex_state == 2);
    CHECK(a.xmit_link_speed == expected.XmitLinkSpeed && a.rcv_link_speed == expected.RcvLinkSpeed);
    CHECK(a.mtu == 1500 && a.mac_options == 0x101 && a.supported_packet_filters == 0x202 && a.max_multicast_list_size == 33);
    CHECK(a.max_xmit_link_speed == expected.MaxXmitLinkSpeed && a.max_rcv_link_speed == expected.MaxRcvLinkSpeed);
    CHECK(a.lookahead_size == 128 && a.access_type == 2 && a.connection_type == 3 && a.supported_statistics == 0x404);
    CHECK(a.data_backfill_size == 4 && a.context_backfill_size == 5 && a.restart_flags == 0x606 && a.attach_flags == 0x707);
    CHECK(a.connector_present == 1 && a.mac_address_length == 6 && a.mac_address[0] == 0xa0 && a.mac_address[5] == 0xa5);
    CHECK(a.auto_negotiation_flags == 0x808 && a.pause_reason == 0x909 && a.pause_flags == 0xa0a);
    CHECK(a.instance_name == L"Адаптер" && a.base_name == L"\\Device\\test" && a.filter_module_name == L"{1234}");
    CHECK(!(s.adapters[1].flags & pmkext::AdapterInfo::Running));
    bytes = Encode(97);
    CHECK(pmkext::wire::DecodeAdapterInfo(bytes.data(), bytes.size(), s, error) && s.adapters.size() == 97);
    bytes = Encode(0);
    CHECK(pmkext::wire::DecodeAdapterInfo(bytes.data(), bytes.size(), s, error) && s.adapters.empty() && s.running_count == 0);
    return true;
}

bool CheckMalformed() {
    std::string error;
    pmkext::AdapterSnapshot out;
    out.running_count = 77;
    out.adapters.resize(1); out.adapters[0].instance_name = L"unchanged";
    auto reject = [&](const uint8_t* data, size_t size) {
        return !pmkext::wire::DecodeAdapterInfo(data, size, out, error) && !error.empty() &&
            out.running_count == 77 && out.adapters.size() == 1 && out.adapters[0].instance_name == L"unchanged";
    };
    const auto valid = Encode(2);
    CHECK(reject(nullptr, valid.size()));
    for (size_t size : {size_t{0}, size_t{15}, size_t{16}, valid.size() - 1, valid.size() + 1,
                        size_t{HV_ADAPTER_INFO_MAX_SIZE + 1}}) CHECK(reject(valid.data(), size));
    for (const auto [offset, value] : std::vector<std::pair<size_t, uint32_t>>{
            {0,2}, {4,1759}, {8,33}, {8,0xffffffff}, {12,3}, {12,0},
            {16+20,0x100}, {16+164,33}, {16+160,2},
            {16+200,256}, {16+204,0xffffffff}, {16+208,256},
            {16+1760+20,HV_ADAPTER_RUNNING}}) {
        auto bad = valid;
        HvInfoWrite32(bad.data() + offset, value);
        CHECK(reject(bad.data(), bad.size()));
    }
    for (size_t offset : {size_t{16+224}, size_t{16+736}, size_t{16+1248}}) {
        auto bad = valid; bad[offset] = bad[offset + 1] = 0; // Embedded NUL.
        CHECK(reject(bad.data(), bad.size()));
    }
    for (size_t offset : {size_t{16+224+14}, size_t{16+736+24}, size_t{16+1248+12}}) {
        auto bad = valid; bad[offset] = 1; // Missing counted-string terminator.
        CHECK(reject(bad.data(), bad.size()));
    }
    pmkext::Driver driver;
    CHECK(!driver.GetAdapterInfo(out, error) && error == "device not open");
    CHECK(out.running_count == 77 && out.adapters[0].instance_name == L"unchanged");
    return true;
}

std::vector<uint8_t> Header(uint32_t count, uint32_t running = 0) {
    std::vector<uint8_t> bytes(HV_ADAPTER_INFO_HEADER_SIZE);
    HvEncodeAdapterInfoHeader(bytes.data(), count, running);
    return bytes;
}

bool CheckHeaderBounds() {
    std::string error;
    uint32_t required = 123;
    const auto maximum = Header(HV_ADAPTER_INFO_MAX_ADAPTERS);
    CHECK(pmkext::wire::DecodeAdapterInfoHeader(maximum.data(), maximum.size(), required, error));
    CHECK(required == HV_ADAPTER_INFO_MAX_SIZE);
    for (uint32_t count : {HV_ADAPTER_INFO_MAX_ADAPTERS + 1u, UINT32_MAX}) {
        auto bad = Header(count);
        CHECK(!pmkext::wire::DecodeAdapterInfoHeader(bad.data(), bad.size(), required, error));
        CHECK(required == HV_ADAPTER_INFO_MAX_SIZE && !error.empty());
    }
    CHECK(!pmkext::wire::DecodeAdapterInfoHeader(maximum.data(), 15, required, error));
    CHECK(!pmkext::wire::DecodeAdapterInfoHeader(nullptr, 16, required, error));
    const auto bad_running = Header(33, 34);
    CHECK(!pmkext::wire::DecodeAdapterInfoHeader(bad_running.data(), 16, required, error));
    CHECK(required == HV_ADAPTER_INFO_MAX_SIZE);

    CHECK(HvPlanAdapterInfo(0, 15, 0, &required) == HvAdapterInfoTooSmall);
    CHECK(required == HV_ADAPTER_INFO_MAX_SIZE);
    CHECK(HvPlanAdapterInfo(static_cast<uint64_t>(HV_ADAPTER_INFO_MAX_ADAPTERS) + 1, UINT32_MAX,
                            0, &required) == HvAdapterInfoCountOverflow);
    CHECK(required == HV_ADAPTER_INFO_MAX_SIZE);
    CHECK(HvPlanAdapterInfo(0, 16, 0, &required) == HvAdapterInfoEncode && required == 16);
    CHECK(HvPlanAdapterInfo(1, 16, 0, &required) == HvAdapterInfoHeaderOnly && required == 1776);
    const uint32_t capacity = HvAdapterInfoSize(100);
    CHECK(HvPlanAdapterInfo(40, capacity, 0, &required) == HvAdapterInfoGrowStaging);
    // Deterministic attach race: user capacity already fits, staging does not.
    CHECK(HvPlanAdapterInfo(97, capacity, 40, &required) == HvAdapterInfoGrowStaging);
    CHECK(required == HvAdapterInfoSize(97) && required < capacity);
    CHECK(HvPlanAdapterInfo(97, capacity, 97, &required) == HvAdapterInfoEncode);
    CHECK(HvPlanAdapterInfo(30, capacity, 97, &required) == HvAdapterInfoEncode); // Detach/shrink.
    CHECK(HvPlanAdapterInfo(101, capacity, 97, &required) == HvAdapterInfoHeaderOnly && required > capacity);
    uint64_t staged = 0;
    for (uint32_t attempt = 0; attempt < HV_ADAPTER_INFO_MAX_STAGING_ATTEMPTS; ++attempt) {
        CHECK(HvPlanAdapterInfo(40 + attempt, capacity, staged, &required) == HvAdapterInfoGrowStaging);
        CHECK(required < capacity); // Kernel exhaustion returns RETRY, never a false MORE_DATA.
        staged = 40 + attempt;
    }
    return true;
}

bool CheckQueries() {
    using namespace adapter_test_io;
    const auto kept = Encode(1), many = Encode(97);
    Reset(Encode(0));
    pmkext::Driver driver;
    pmkext::AdapterSnapshot out;
    std::string error;
    CHECK(pmkext::wire::DecodeAdapterInfo(kept.data(), kept.size(), out, error));
    CHECK(driver.Open(error)); // Private fake handle, never the production device.
    CHECK(driver.GetAdapterInfo(out, error) && out.adapters.empty());
    state.snapshot = Encode(2); state.legacy = true;
    CHECK(driver.GetAdapterInfo(out, error) && out.adapters.size() == 2); // Old SYS needs no header probe.
    CHECK(state.capacities.back() == pmkext::wire::kInitialAdapterInfoSize);
    state.snapshot = many; state.legacy = false; state.capacities.clear();
    CHECK(driver.GetAdapterInfo(out, error) && out.adapters.size() == 97 && error.empty());
    CHECK(state.capacities == std::vector<DWORD>({56336u, static_cast<DWORD>(many.size())}));
    CHECK(!state.active);

    // A new attachment between header and retry asks for another checked growth.
    state.replies = {{Header(40), ERROR_MORE_DATA}, {Header(97), ERROR_MORE_DATA, 16, true}, {many}};
    state.next = 0; state.capacities.clear();
    CHECK(driver.GetAdapterInfo(out, error) && out.adapters.size() == 97);
    CHECK(state.capacities == std::vector<DWORD>({56336u, HvAdapterInfoSize(40), HvAdapterInfoSize(97)}));
    // Detach/shrink between probe and full query is also valid, with an exact shorter snapshot.
    state.replies = {{Header(97), ERROR_MORE_DATA}, {kept}}; state.next = 0;
    CHECK(driver.GetAdapterInfo(out, error) && out.adapters.size() == 1);
    const auto* original = out.adapters.data();
    const auto unchanged = [&] { return out.adapters.data() == original && out.adapters.size() == 1 &&
        out.adapters[0].instance_name == L"Адаптер" && out.running_count == 1 && !state.active; };
    const auto reject = [&](std::vector<Reply> replies) {
        state.replies = std::move(replies); state.next = 0;
        return !driver.GetAdapterInfo(out, error) && !error.empty() && unchanged();
    };
    for (DWORD code : {DWORD{ERROR_NOT_SUPPORTED}, DWORD{ERROR_ACCESS_DENIED}, DWORD{ERROR_INSUFFICIENT_BUFFER}}) {
        CHECK(reject({{{}, code}}));
        CHECK(reject({{Header(40), ERROR_MORE_DATA}, {{}, code, 0, true}}));
    }
    for (auto header : {Header(0), Header(32), Header(HV_ADAPTER_INFO_MAX_ADAPTERS + 1u), Header(40, 41)})
        CHECK(reject({{std::move(header), ERROR_MORE_DATA}}));
    auto bad = Header(40); HvInfoWrite32(bad.data(), 2);
    CHECK(reject({{bad, ERROR_MORE_DATA}}));
    bad = Header(40); HvInfoWrite32(bad.data() + 4, 1759);
    CHECK(reject({{bad, ERROR_MORE_DATA}}));
    for (DWORD size : {0u, 15u, 17u, 56337u}) CHECK(reject({{Header(40), ERROR_MORE_DATA, size}}));
    CHECK(reject({{Header(40), ERROR_MORE_DATA}, {Header(40), ERROR_MORE_DATA}})); // No growth.
    CHECK(reject({{kept, ERROR_SUCCESS, 56337}})); // Never decode beyond the actual buffer.
    CHECK(reject({{Header(40)}})); // A successful response must be complete, not a probe.
    bad = many; bad.pop_back();
    CHECK(reject({{Header(97), ERROR_MORE_DATA}, {bad}}));
    std::vector<Reply> churn;
    for (unsigned i = 0; i < 8; ++i) churn.push_back({Header(40 + i), ERROR_MORE_DATA});
    state.capacities.clear();
    CHECK(reject(std::move(churn)) && state.capacities.size() == 8);

    state.replies.clear(); state.next = 0; state.snapshot = many; state.capacities.clear();
    {
        allocation::FailSize fail(pmkext::wire::kInitialAdapterInfoSize);
        CHECK(!driver.GetAdapterInfo(out, error) && allocation::failed && unchanged());
    }
    CHECK(state.capacities.empty());
    {
        allocation::FailSize fail(many.size()); // Header was reaped, then fallible growth fails.
        CHECK(!driver.GetAdapterInfo(out, error) && allocation::failed && unchanged());
    }
    CHECK(state.capacities.size() == 1);
    state.snapshot = Encode(2);
    {
        // Keep the vector allocation below MSVC's large-allocation alignment
        // threshold so the injected size is the allocator's exact request.
        static_assert(2 * sizeof(pmkext::AdapterInfo) < 4096);
        allocation::FailSize fail(2 * sizeof(pmkext::AdapterInfo));
        CHECK(!driver.GetAdapterInfo(out, error) && allocation::failed && unchanged());
    }
    driver.Cleanup();
    CHECK(!state.active && unchanged());
    return true;
}

bool CheckNames() {
    uint16_t out[HV_ADAPTER_INFO_NAME_CAPACITY];
    uint32_t flags = 0;
    std::vector<uint16_t> input(300, 'X');
    CHECK(HvCopyAdapterName(out, nullptr, 300, &flags, HV_ADAPTER_BASE_NAME_TRUNCATED) == 0 && out[0] == 0);
    CHECK(HvCopyAdapterName(out, input.data(), 255, &flags, HV_ADAPTER_BASE_NAME_TRUNCATED) == 255);
    CHECK(flags == 0 && out[255] == 0);
    CHECK(HvCopyAdapterName(out, input.data(), 256, &flags, HV_ADAPTER_BASE_NAME_TRUNCATED) == 255);
    CHECK(flags == HV_ADAPTER_BASE_NAME_TRUNCATED && out[255] == 0);
    input[254] = 0xd83d; input[255] = 0xde80; flags = 0;
    CHECK(HvCopyAdapterName(out, input.data(), 300, &flags, HV_ADAPTER_INSTANCE_NAME_TRUNCATED) == 254);
    CHECK(flags == HV_ADAPTER_INSTANCE_NAME_TRUNCATED && out[254] == 0 && out[255] == 0);
    input[2] = 0; flags = 0;
    CHECK(HvCopyAdapterName(out, input.data(), 300, &flags, HV_ADAPTER_FILTER_NAME_TRUNCATED) == 2 && flags == 0);
    return true;
}

bool CheckRestartGeneralReset() {
    HV_ADAPTER_INFO info = Fixture();
    const uint32_t preservedFlags = info.Flags & ~HV_ADAPTER_GENERAL_VALID;
    // A later restart without general attributes must not publish the prior
    // restart's values as current.
    HvClearGeneralAttributes(&info);
    CHECK(info.Flags == preservedFlags);
    CHECK(info.Mtu == 0 && info.MaxXmitLinkSpeed == 0 && info.MaxRcvLinkSpeed == 0);
    CHECK(info.LookaheadSize == 0 && info.MacOptions == 0 && info.SupportedPacketFilters == 0);
    CHECK(info.MaxMulticastListSize == 0 && info.AccessType == 0 && info.RestartFlags == 0);
    CHECK(info.ConnectionType == 0 && info.SupportedStatistics == 0);
    CHECK(info.DataBackFillSize == 0 && info.ContextBackFillSize == 0);
    return true;
}

bool CheckOutput() {
    using File = std::unique_ptr<FILE, decltype(&std::fclose)>;
    File file(std::fopen("adapter_info_tests.tmp", "w+b"), std::fclose);
    CHECK(file);
    std::mutex mutex;
    auto bytes = Encode(2);
    std::string error;
    pmkext::AdapterSnapshot s;
    CHECK(pmkext::wire::DecodeAdapterInfo(bytes.data(), bytes.size(), s, error));
    s.adapters[1].flags = pmkext::AdapterInfo::BaseNameTruncated;
    s.adapters[1].base_name = L"line\r\nbreak";
    s.adapters[1].xmit_link_speed = ~uint64_t{0};
    {
        pmkext::RecordOutput output(file.get(), mutex);
        output.WriteAdapters(s, "12:34:56.789 ");
    }
    std::rewind(file.get());
    std::string text;
    char buffer[1024];
    while (const size_t n = std::fread(buffer, 1, sizeof(buffer), file.get())) text.append(buffer, n);
    for (const char* expected : {"12:34:56.789 Attached network adapters: 2 (running=1", "interface_index=2309737967 state=running",
            "instance_name=Адаптер", "interface_guid={12345678-9ABC-DEF0-0102-030405060708}",
            "interface_luid=0x1122334455667788", "mac=A0:A1:A2:A3:A4:A5", "mtu=1500", "tx_bps=10000000000",
            "last_pause_reason=0x00000909", "base_name=line\\x0D\\x0Abreak [truncated]", "state=not-running",
            "connector=unknown", "mtu/general_attributes=unknown", "auto_negotiation_flags=unknown", "tx_bps=unknown"}) {
        CHECK(text.find(expected) != std::string::npos);
    }
    return true;
}

int main() {
    if (!CheckRoundTrip() || !CheckMalformed() || !CheckHeaderBounds() || !CheckQueries() ||
        !CheckNames() || !CheckRestartGeneralReset() || !CheckOutput()) return 1;
    std::puts("Adapter information codec/name/output tests passed (no driver).");
    return 0;
}
