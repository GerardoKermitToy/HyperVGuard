// All device entry points are faked; only private unnamed Win32 events are real.
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <future>
#include <mutex>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include "../../driver/shim/adapter_info.h" // Fixture encoder only; the client remains independent.

// Thread-local, one-shot allocation failures exercise both the nothrow IOCTL
// buffer and each owning-decoder allocation without affecting the Run thread.
namespace allocation {
thread_local ptrdiff_t remaining = -1;
thread_local bool failed = false;
bool ShouldFail() noexcept {
    if (remaining < 0) return false;
    if (remaining > 0) { --remaining; return false; }
    remaining = -1; failed = true;
    return true;
}
struct FailAfter {
    ptrdiff_t previous = remaining;
    bool previous_failed = failed;
    explicit FailAfter(ptrdiff_t count) { remaining = count; failed = false; }
    ~FailAfter() { remaining = previous; failed = previous_failed; }
    bool Triggered() const noexcept { return failed; }
};
}
void* operator new(size_t size) {
    if (!allocation::ShouldFail()) if (void* p = std::malloc(size ? size : 1)) return p;
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

namespace testio {
HANDLE CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL CloseHandle(HANDLE);
BOOL DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
BOOL CancelIoEx(HANDLE, LPOVERLAPPED);
}
#define CreateEventW testio::CreateEventW
#define CreateFileW testio::CreateFileW
#define CloseHandle testio::CloseHandle
#define DeviceIoControl testio::DeviceIoControl
#define ReadFile testio::ReadFile
#define WriteFile testio::WriteFile
#define GetOverlappedResult testio::GetOverlappedResult
#define CancelIoEx testio::CancelIoEx
#include "HyperVXNdisFilter.hpp"
#undef CreateEventW
#undef CreateFileW
#undef CloseHandle
#undef DeviceIoControl
#undef ReadFile
#undef WriteFile
#undef GetOverlappedResult
#undef CancelIoEx

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return false; } } while (false)
using Client = hypervxndisfilter::Client;
using Bytes = std::vector<uint8_t>;

namespace testio {
struct Operation {
    bool complete = false;
    DWORD bytes = 0, error = ERROR_SUCCESS;
    uint8_t* buffer = nullptr;
    DWORD capacity = 0;
};
struct State {
    std::mutex mutex;
    std::unordered_map<OVERLAPPED*, Operation> operations;
    OVERLAPPED* pending = nullptr;
    HANDLE submitted = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE startup_seen = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE driver_ready = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Bytes queued, written, adapter_info;
    DWORD adapter_info_error = ERROR_SUCCESS;
    std::vector<DWORD> open_errors;
    size_t offset = 0;
    unsigned reads = 0, cancels = 0, opens = 0, closes = 0, adapter_queries = 0;
    bool empty_read = false, short_control = false, wrong_version = false, fail_open = false, secure_ready = false;
    const uint8_t* first_buffer = nullptr;
    Client* stop_on_read = nullptr;
    ~State() { ::CloseHandle(submitted); ::CloseHandle(startup_seen); ::CloseHandle(driver_ready); }
} state;
HANDLE Device() { return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234)); }
void Reset() {
    std::lock_guard lock(state.mutex);
    if (!state.operations.empty()) throw std::runtime_error("unreaped fake I/O");
    state.pending = nullptr;
    state.queued.clear(); state.written.clear(); state.open_errors.clear(); state.offset = 0;
    state.adapter_info.assign(HV_ADAPTER_INFO_HEADER_SIZE, 0);
    HvEncodeAdapterInfoHeader(state.adapter_info.data(), 0, 0);
    state.adapter_info_error = ERROR_SUCCESS;
    state.reads = state.cancels = state.opens = state.closes = state.adapter_queries = 0;
    state.empty_read = state.short_control = state.wrong_version = state.fail_open = state.secure_ready = false;
    state.first_buffer = nullptr; state.stop_on_read = nullptr;
    ::ResetEvent(state.submitted); ::ResetEvent(state.startup_seen); ::ResetEvent(state.driver_ready);
}
void Complete(OVERLAPPED* ov, DWORD bytes, DWORD error = ERROR_SUCCESS) {
    auto& op = state.operations.at(ov);
    op.complete = true; op.bytes = bytes; op.error = error;
    if (state.pending == ov) state.pending = nullptr;
    ::SetEvent(ov->hEvent);
}
void Fill(OVERLAPPED* ov) {
    const auto& op = state.operations.at(ov);
    const size_t n = (std::min)(static_cast<size_t>(op.capacity), state.queued.size() - state.offset);
    std::memcpy(op.buffer, state.queued.data() + state.offset, n);
    state.offset += n;
    Complete(ov, static_cast<DWORD>(n));
}
void Inject(Bytes bytes) {
    std::lock_guard lock(state.mutex);
    state.queued = std::move(bytes); state.offset = 0;
    if (state.pending) Fill(state.pending);
}
HANDLE CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCWSTR name) {
    if (!name) return ::CreateEventW(sa, manual, initial, nullptr);
    std::lock_guard lock(state.mutex);
    if (std::wcscmp(name, L"Global\\HyperVXNdisFilter.DriverReady")) {
        ::SetLastError(ERROR_INVALID_NAME); return nullptr;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    state.secure_ready = sa && !sa->bInheritHandle && sa->lpSecurityDescriptor &&
        ::GetSecurityDescriptorControl(sa->lpSecurityDescriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) && manual && !initial;
    HANDLE duplicate = nullptr;
    if (!::DuplicateHandle(::GetCurrentProcess(), state.driver_ready, ::GetCurrentProcess(),
                           &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) return nullptr;
    ::SetEvent(state.startup_seen);
    return duplicate;
}
HANDLE CreateFileW(LPCWSTR path, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES, DWORD mode, DWORD flags, HANDLE) {
    std::lock_guard lock(state.mutex);
    if (std::wcscmp(path, L"\\\\.\\HyperVXNdisFilter") || access != (GENERIC_READ | GENERIC_WRITE) ||
        sharing || mode != OPEN_EXISTING || !(flags & FILE_FLAG_OVERLAPPED)) {
        ::SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
    }
    ++state.opens;
    if (state.opens <= state.open_errors.size()) {
        const DWORD error = state.open_errors[state.opens - 1];
        if (state.opens == 2) ::SetEvent(state.submitted);
        if (error) { ::SetLastError(error); return INVALID_HANDLE_VALUE; }
    }
    if (state.fail_open) { ::SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    return Device();
}
BOOL CloseHandle(HANDLE handle) {
    if (handle != Device()) return ::CloseHandle(handle);
    std::lock_guard lock(state.mutex);
    ++state.closes;
    return TRUE;
}
BOOL DeviceIoControl(HANDLE, DWORD code, LPVOID input, DWORD input_size, LPVOID output,
                     DWORD capacity, LPDWORD actual, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    if (input || input_size) { ::SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (code == 0x9c40e00cu) {
        ++state.adapter_queries;
        if (!output || capacity != HV_ADAPTER_INFO_MAX_SIZE || !ov) {
            ::SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
        }
        if (state.adapter_info_error) { ::SetLastError(state.adapter_info_error); return FALSE; }
        const DWORD size = static_cast<DWORD>(state.adapter_info.size());
        const size_t copied = (std::min)(state.adapter_info.size(), static_cast<size_t>(capacity));
        if (copied) std::memcpy(output, state.adapter_info.data(), copied);
        state.operations[ov] = {};
        // A malformed fake may claim more bytes than fit, but never overwrite.
        Complete(ov, size);
        *actual = size;
        return TRUE;
    }
    uint8_t bytes[4]{};
    DWORD size = 4;
    if (code == 0x9c40e000u) {
        const auto version = Client::RequiredVersion;
        std::memcpy(bytes, version.data(), 4);
        if (state.wrong_version) bytes[2] = 1;
    } else if (code == 0x9c40e008u) bytes[0] = 1;
    else if (code == 0x9c40e004u) {
        size = 0;
        if (state.pending) Complete(state.pending, 0, ERROR_OPERATION_ABORTED);
    } else { ::SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (size && state.short_control) size = 3;
    if (capacity < size) { ::SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (size) std::memcpy(output, bytes, size);
    state.operations[ov] = {};
    Complete(ov, size);
    *actual = size;
    return TRUE;
}
BOOL ReadFile(HANDLE, LPVOID buffer, DWORD capacity, LPDWORD actual, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    ++state.reads;
    if (state.stop_on_read) {
        state.stop_on_read->Stop();
        ::SetLastError(ERROR_DEVICE_NOT_CONNECTED); return FALSE;
    }
    if (!state.first_buffer) state.first_buffer = static_cast<uint8_t*>(buffer);
    state.operations[ov] = {false, 0, 0, static_cast<uint8_t*>(buffer), capacity};
    if (state.empty_read) { Complete(ov, 0); *actual = 0; return TRUE; }
    if (state.offset < state.queued.size()) { Fill(ov); *actual = state.operations.at(ov).bytes; return TRUE; }
    state.pending = ov;
    ::SetEvent(state.submitted);
    ::SetLastError(ERROR_IO_PENDING);
    return FALSE;
}
BOOL WriteFile(HANDLE, LPCVOID buffer, DWORD size, LPDWORD actual, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    const auto* p = static_cast<const uint8_t*>(buffer);
    state.written.insert(state.written.end(), p, p + size);
    state.operations[ov] = {};
    Complete(ov, size);
    *actual = size;
    return TRUE;
}
BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED ov, LPDWORD actual, BOOL wait) {
    for (;;) {
        {
            std::lock_guard lock(state.mutex);
            const auto it = state.operations.find(ov);
            if (it == state.operations.end()) { ::SetLastError(ERROR_NOT_FOUND); return FALSE; }
            if (it->second.complete) {
                const auto op = it->second;
                state.operations.erase(it);
                *actual = op.bytes;
                if (op.error) { ::SetLastError(op.error); return FALSE; }
                return TRUE;
            }
        }
        if (!wait) { ::SetLastError(ERROR_IO_INCOMPLETE); return FALSE; }
        ::WaitForSingleObject(ov->hEvent, INFINITE);
    }
}
BOOL CancelIoEx(HANDLE, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    ++state.cancels;
    const auto it = state.operations.find(ov);
    if (it == state.operations.end() || it->second.complete) { ::SetLastError(ERROR_NOT_FOUND); return FALSE; }
    Complete(ov, 0, ERROR_OPERATION_ABORTED);
    return TRUE;
}
} // namespace testio

namespace {
void Put(Bytes& bytes, size_t offset, uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i) bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}
void SetAdapterName(uint16_t (&out)[HV_ADAPTER_INFO_NAME_CAPACITY], uint32_t& length, std::wstring_view name) {
    if (name.size() >= HV_ADAPTER_INFO_NAME_CAPACITY) throw std::runtime_error("oversized fixture name");
    std::fill(std::begin(out), std::end(out), uint16_t{0});
    length = static_cast<uint32_t>(name.size());
    for (size_t i = 0; i < name.size(); ++i) out[i] = static_cast<uint16_t>(name[i]);
}
HV_ADAPTER_INFO AdapterFixture(uint32_t seed, uint32_t flags) {
    HV_ADAPTER_INFO a{};
    a.ModuleId = 0xfedcba9876543200ull + seed;
    a.InterfaceIndex = 0x80000010u + seed;
    a.FilterInterfaceIndex = 0x90000020u + seed;
    a.LowerInterfaceIndex = 0xa0000030u + seed;
    a.Flags = flags;
    a.InterfaceLuid = 0x8123456789abcd00ull + seed;
    a.FilterInterfaceLuid = 0x923456789abcde00ull + seed;
    a.LowerInterfaceLuid = 0xa3456789abcdef00ull + seed;
    for (size_t i = 0; i < sizeof(a.InterfaceGuid); ++i) a.InterfaceGuid[i] = static_cast<uint8_t>(i * 13 + seed);
    a.InterfaceGuid[3] = 0; // Binary identity is not a GUID string or an integer.
    a.MediaType = 0xf1000001u + seed; // Unknown NDIS enum values must remain usable.
    a.PhysicalMedium = 0xf2000002u + seed;
    a.MediaConnectState = 0xf3000003u + seed;
    a.MediaDuplexState = 0xf4000004u + seed;
    a.XmitLinkSpeed = 0xb456789abcdef000ull + seed;
    a.RcvLinkSpeed = 0xc56789abcdef0100ull + seed;
    a.Mtu = 0xe0000100u + seed;
    a.MacOptions = 0xe0000200u + seed;
    a.SupportedPacketFilters = 0xe0000300u + seed;
    a.MaxMulticastListSize = 0xe0000400u + seed;
    a.MaxXmitLinkSpeed = 0xd6789abcdef01200ull + seed;
    a.MaxRcvLinkSpeed = 0xe789abcdef012300ull + seed;
    a.LookaheadSize = 0xe0000500u + seed;
    a.AccessType = 0xf5000005u + seed;
    a.ConnectionType = 0xf6000006u + seed;
    a.SupportedStatistics = 0xe0000600u + seed;
    a.DataBackFillSize = 0xe0000700u + seed;
    a.ContextBackFillSize = 0xe0000800u + seed;
    a.RestartFlags = 0xe0000900u + seed;
    a.AttachFlags = 0xe0000a00u + seed;
    a.ConnectorPresent = seed % 2;
    a.MacAddressLength = seed % 2 ? HV_ADAPTER_INFO_MAC_CAPACITY : 6;
    for (size_t i = 0; i < sizeof(a.MacAddress); ++i) a.MacAddress[i] = static_cast<uint8_t>(i * 7 + seed);
    a.MacAddress[5] = 0;
    a.AutoNegotiationFlags = 0xe0000b00u + seed;
    a.PauseReason = 0xf7000007u + seed;
    a.PauseFlags = 0xe0000c00u + seed;
    SetAdapterName(a.InstanceName, a.InstanceNameLength, L"instance-网卡-Ω-\U0001f680-" + std::to_wstring(seed));
    SetAdapterName(a.BaseName, a.BaseNameLength, L"base-é-中-name-" + std::to_wstring(seed));
    SetAdapterName(a.FilterModuleName, a.FilterModuleNameLength, L"filter-Ж-日-name-" + std::to_wstring(seed));
    return a;
}
Bytes AdapterResponse(std::span<const HV_ADAPTER_INFO> adapters = {}) {
    if (adapters.size() > HV_ADAPTER_INFO_MAX_ADAPTERS) throw std::runtime_error("oversized fixture snapshot");
    const auto count = static_cast<uint32_t>(adapters.size());
    uint32_t running = 0;
    for (const auto& adapter : adapters) if (adapter.Flags & HV_ADAPTER_RUNNING) ++running;
    Bytes bytes(HvAdapterInfoSize(count));
    HvEncodeAdapterInfoHeader(bytes.data(), count, running);
    for (size_t i = 0; i < adapters.size(); ++i)
        HvEncodeAdapterInfo(bytes.data() + HV_ADAPTER_INFO_HEADER_SIZE + i * HV_ADAPTER_INFO_ENTRY_SIZE, &adapters[i]);
    return bytes;
}
bool NameMatches(std::wstring_view actual, const uint16_t* expected, uint32_t length) {
    CHECK(actual.size() == length);
    for (size_t i = 0; i < actual.size(); ++i) CHECK(actual[i] == static_cast<wchar_t>(expected[i]));
    return true;
}
bool MatchesAdapter(const Client::AdapterInfo& a, const HV_ADAPTER_INFO& b) {
#define FIELD(name, source) CHECK(a.name == b.source)
    FIELD(module_id, ModuleId);
    FIELD(interface_index, InterfaceIndex);
    FIELD(filter_interface_index, FilterInterfaceIndex);
    FIELD(lower_interface_index, LowerInterfaceIndex);
    FIELD(flags, Flags);
    FIELD(interface_luid, InterfaceLuid);
    FIELD(filter_interface_luid, FilterInterfaceLuid);
    FIELD(lower_interface_luid, LowerInterfaceLuid);
    FIELD(media_type, MediaType);
    FIELD(physical_medium, PhysicalMedium);
    FIELD(media_connect_state, MediaConnectState);
    FIELD(media_duplex_state, MediaDuplexState);
    FIELD(xmit_link_speed, XmitLinkSpeed);
    FIELD(rcv_link_speed, RcvLinkSpeed);
    FIELD(mtu, Mtu);
    FIELD(mac_options, MacOptions);
    FIELD(supported_packet_filters, SupportedPacketFilters);
    FIELD(max_multicast_list_size, MaxMulticastListSize);
    FIELD(max_xmit_link_speed, MaxXmitLinkSpeed);
    FIELD(max_rcv_link_speed, MaxRcvLinkSpeed);
    FIELD(lookahead_size, LookaheadSize);
    FIELD(access_type, AccessType);
    FIELD(connection_type, ConnectionType);
    FIELD(supported_statistics, SupportedStatistics);
    FIELD(data_backfill_size, DataBackFillSize);
    FIELD(context_backfill_size, ContextBackFillSize);
    FIELD(restart_flags, RestartFlags);
    FIELD(attach_flags, AttachFlags);
    FIELD(connector_present, ConnectorPresent);
    FIELD(mac_address_length, MacAddressLength);
    FIELD(instance_name_length, InstanceNameLength);
    FIELD(base_name_length, BaseNameLength);
    FIELD(filter_module_name_length, FilterModuleNameLength);
    FIELD(auto_negotiation_flags, AutoNegotiationFlags);
    FIELD(pause_reason, PauseReason);
    FIELD(pause_flags, PauseFlags);
#undef FIELD
    CHECK(std::equal(a.interface_guid.begin(), a.interface_guid.end(), std::begin(b.InterfaceGuid)));
    CHECK(std::equal(a.mac_address.begin(), a.mac_address.end(), std::begin(b.MacAddress)));
    CHECK(NameMatches(a.instance_name, b.InstanceName, b.InstanceNameLength));
    CHECK(NameMatches(a.base_name, b.BaseName, b.BaseNameLength));
    CHECK(NameMatches(a.filter_module_name, b.FilterModuleName, b.FilterModuleNameLength));
    return true;
}
bool MatchesSnapshot(const Client::AdapterSnapshot& snapshot, std::span<const HV_ADAPTER_INFO> expected) {
    CHECK(snapshot.adapters.size() == expected.size());
    uint32_t running = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        CHECK(MatchesAdapter(snapshot.adapters[i], expected[i]));
        if (expected[i].Flags & HV_ADAPTER_RUNNING) ++running;
    }
    CHECK(snapshot.running_count == running);
    return true;
}
bool TestAdapterInfoCodec() {
    static_assert(Client::AdapterInfoVersion == HV_ADAPTER_INFO_VERSION);
    static_assert(Client::AdapterInfoHeaderSize == HV_ADAPTER_INFO_HEADER_SIZE);
    static_assert(Client::AdapterInfoEntrySize == HV_ADAPTER_INFO_ENTRY_SIZE);
    static_assert(Client::MaxAdapters == HV_ADAPTER_INFO_MAX_ADAPTERS);
    static_assert(Client::AdapterNameCapacity == HV_ADAPTER_INFO_NAME_CAPACITY);
    static_assert(Client::AdapterMacCapacity == HV_ADAPTER_INFO_MAC_CAPACITY);
    static_assert(Client::MaxAdapterInfoSize == HV_ADAPTER_INFO_MAX_SIZE && Client::MaxAdapterInfoSize == 56336);
    static_assert(Client::AdapterRunning == HV_ADAPTER_RUNNING && Client::AdapterGeneralValid == HV_ADAPTER_GENERAL_VALID);
    static_assert(Client::AdapterConnectorValid == HV_ADAPTER_CONNECTOR_VALID);
    static_assert(Client::AdapterInstanceNameTruncated == HV_ADAPTER_INSTANCE_NAME_TRUNCATED);
    static_assert(Client::AdapterBaseNameTruncated == HV_ADAPTER_BASE_NAME_TRUNCATED);
    static_assert(Client::AdapterFilterNameTruncated == HV_ADAPTER_FILTER_NAME_TRUNCATED);
    static_assert(Client::AdapterLinkStateValid == HV_ADAPTER_LINK_STATE_VALID && Client::AdapterPauseValid == HV_ADAPTER_PAUSE_VALID);
    static_assert(Client::AdapterKnownFlags == HV_ADAPTER_INFO_KNOWN_FLAGS);
    static_assert(Client::RequiredVersion == std::array<uint8_t, 4>{0, 3, 2, 0}); // Additive, not an event-wire change.
    std::vector<HV_ADAPTER_INFO> fixtures{
        AdapterFixture(1, HV_ADAPTER_INFO_KNOWN_FLAGS),
        AdapterFixture(2, HV_ADAPTER_INFO_KNOWN_FLAGS & ~HV_ADAPTER_RUNNING),
        {}};
    fixtures[2].ModuleId = 3; // Initially attached, no optional attributes yet.
    fixtures[2].InterfaceIndex = 19;
    const std::wstring longest(HV_ADAPTER_INFO_NAME_CAPACITY - 1, L'中');
    SetAdapterName(fixtures[1].InstanceName, fixtures[1].InstanceNameLength, longest);
    SetAdapterName(fixtures[1].BaseName, fixtures[1].BaseNameLength, longest);
    SetAdapterName(fixtures[1].FilterModuleName, fixtures[1].FilterModuleNameLength, longest);
    const auto response = AdapterResponse(fixtures);
    CHECK(response.size() == HV_ADAPTER_INFO_HEADER_SIZE + fixtures.size() * HV_ADAPTER_INFO_ENTRY_SIZE);
    Client::AdapterSnapshot snapshot;
    for (size_t shift = 0; shift < 8; ++shift) {
        Bytes storage(shift + response.size());
        std::memcpy(storage.data() + shift, response.data(), response.size());
        CHECK(Client::DecodeAdapterInfo(Client::Bytes(storage).subspan(shift), snapshot) == ERROR_SUCCESS);
        std::fill(storage.begin(), storage.end(), uint8_t{0}); // No decoded identity or name borrows response memory.
        CHECK(MatchesSnapshot(snapshot, fixtures));
        CHECK(snapshot.running_count == 1 && snapshot.adapters.size() == 3);
    }
    CHECK(Client::DecodeAdapterInfo(AdapterResponse(), snapshot) == ERROR_SUCCESS);
    CHECK(snapshot.running_count == 0 && snapshot.adapters.empty());
    std::vector<HV_ADAPTER_INFO> maximum;
    for (uint32_t i = 0; i < HV_ADAPTER_INFO_MAX_ADAPTERS; ++i)
        maximum.push_back(AdapterFixture(i, i % 2 ? 0 : HV_ADAPTER_RUNNING));
    maximum.back() = fixtures[1];
    const auto full = AdapterResponse(maximum);
    CHECK(full.size() == Client::MaxAdapterInfoSize);
    CHECK(Client::DecodeAdapterInfo(full, snapshot) == ERROR_SUCCESS);
    CHECK(MatchesSnapshot(snapshot, maximum) && snapshot.running_count == 16);
    return true;
}
bool TestAdapterInfoMalformed() {
    const std::vector<HV_ADAPTER_INFO> fixtures{
        AdapterFixture(1, HV_ADAPTER_INFO_KNOWN_FLAGS), AdapterFixture(2, HV_ADAPTER_PAUSE_VALID)};
    const auto good = AdapterResponse(fixtures);
    const std::vector<HV_ADAPTER_INFO> kept{AdapterFixture(99, HV_ADAPTER_RUNNING)};
    Client::AdapterSnapshot snapshot;
    CHECK(Client::DecodeAdapterInfo(AdapterResponse(kept), snapshot) == ERROR_SUCCESS);
    const auto* original = snapshot.adapters.data();
    const auto reject = [&](Client::Bytes bytes) {
        CHECK(Client::DecodeAdapterInfo(bytes, snapshot) == ERROR_INVALID_DATA);
        CHECK(snapshot.adapters.data() == original && MatchesSnapshot(snapshot, kept));
        return true;
    };
    const auto reject32 = [&](size_t offset, uint32_t value) {
        auto bad = good; Put(bad, offset, value, 4);
        return reject(bad);
    };
    CHECK(reject({})); // Null/empty input, before any header load.
    for (size_t length = 0; length < good.size(); ++length) CHECK(reject(Client::Bytes(good).first(length)));
    auto bad = good; bad.push_back(0); CHECK(reject(bad));
    CHECK(reject(Bytes(Client::MaxAdapterInfoSize + 1)));
    for (uint32_t value : {0u, 2u, 0xffffffffu}) CHECK(reject32(0, value));
    for (uint32_t value : {0u, 1759u, 1761u, 0xffffffffu}) CHECK(reject32(4, value));
    for (uint32_t value : {0u, 1u, 33u, 0xffffffffu}) CHECK(reject32(8, value));
    for (uint32_t value : {0u, 2u, 3u, 0xffffffffu}) CHECK(reject32(12, value));
    for (size_t i = 0; i < fixtures.size(); ++i) { // Also reject after an earlier entry has already decoded.
        const size_t entry = HV_ADAPTER_INFO_HEADER_SIZE + i * HV_ADAPTER_INFO_ENTRY_SIZE;
        CHECK(reject32(entry + 20, fixtures[i].Flags | 0x100u));
        CHECK(reject32(entry + 20, fixtures[i].Flags | 0x80000000u));
        for (uint32_t value : {2u, 0xffffffffu}) CHECK(reject32(entry + 160, value));
        for (uint32_t value : {33u, 0xffffffffu}) CHECK(reject32(entry + 164, value));
        const size_t length_offsets[]{200, 204, 208}, name_offsets[]{224, 736, 1248};
        const uint32_t lengths[]{fixtures[i].InstanceNameLength, fixtures[i].BaseNameLength, fixtures[i].FilterModuleNameLength};
        for (size_t name = 0; name < 3; ++name) {
            for (uint32_t value : {0u, 256u, 0xffffffffu}) CHECK(reject32(entry + length_offsets[name], value));
            bad = good; Put(bad, entry + name_offsets[name] + 2 * lengths[name], 0x1234, 2);
            CHECK(reject(bad)); // Counted terminator must be zero.
            bad = good; Put(bad, entry + name_offsets[name] + 2, 0, 2);
            CHECK(reject(bad)); // Counted contents cannot contain an embedded NUL.
        }
    }
    return true;
}
bool TestAdapterInfoQuery() {
    testio::Reset();
    const std::vector<HV_ADAPTER_INFO> fixtures{
        AdapterFixture(7, HV_ADAPTER_INFO_KNOWN_FLAGS), AdapterFixture(8, HV_ADAPTER_PAUSE_VALID)};
    const auto good = AdapterResponse(fixtures);
    Client::AdapterSnapshot snapshot;
    CHECK(Client::DecodeAdapterInfo(good, snapshot) == ERROR_SUCCESS);
    const auto* original = snapshot.adapters.data();
    Client client;
    CHECK(client.GetAdapterInfo(snapshot) == ERROR_INVALID_HANDLE);
    CHECK(snapshot.adapters.data() == original && MatchesSnapshot(snapshot, fixtures));
    CHECK(client.Open() == ERROR_SUCCESS);
    CHECK(client.GetAdapterInfo(snapshot) == ERROR_SUCCESS); // Successful zero-adapter response replaces old output.
    CHECK(snapshot.adapters.empty() && snapshot.running_count == 0);
    testio::state.adapter_info = good;
    CHECK(client.GetAdapterInfo(snapshot) == ERROR_SUCCESS && MatchesSnapshot(snapshot, fixtures));
    original = snapshot.adapters.data();
    const auto unchanged = [&] {
        CHECK(snapshot.adapters.data() == original && MatchesSnapshot(snapshot, fixtures));
        CHECK(testio::state.operations.empty());
        return true;
    };
    for (DWORD error : {DWORD{ERROR_NOT_SUPPORTED}, DWORD{ERROR_ACCESS_DENIED}, DWORD{ERROR_INSUFFICIENT_BUFFER}}) {
        testio::state.adapter_info_error = error;
        CHECK(client.GetAdapterInfo(snapshot) == error && unchanged());
    }
    testio::state.adapter_info_error = ERROR_SUCCESS;
    std::vector<Bytes> malformed{{}, Bytes(good.begin(), good.begin() + 15), good, good, Bytes(Client::MaxAdapterInfoSize + 1)};
    malformed[2].pop_back(); malformed[3].push_back(0);
    const auto add_bad32 = [&](size_t offset, uint32_t value) {
        malformed.push_back(good); Put(malformed.back(), offset, value, 4);
    };
    add_bad32(0, 2); add_bad32(4, 1761); add_bad32(8, 33); add_bad32(12, 0);
    add_bad32(HV_ADAPTER_INFO_HEADER_SIZE + 20, 0x100);
    add_bad32(HV_ADAPTER_INFO_HEADER_SIZE + 160, 2);
    add_bad32(HV_ADAPTER_INFO_HEADER_SIZE + 164, 33);
    add_bad32(HV_ADAPTER_INFO_HEADER_SIZE + 200, 256);
    malformed.push_back(good);
    Put(malformed.back(), HV_ADAPTER_INFO_HEADER_SIZE + 224 + 2 * fixtures[0].InstanceNameLength, 1, 2);
    for (auto& response : malformed) {
        testio::state.adapter_info = std::move(response);
        CHECK(client.GetAdapterInfo(snapshot) == ERROR_INVALID_DATA && unchanged());
    }
    CHECK(testio::state.adapter_queries == 5 + malformed.size());
    CHECK(client.Close() == ERROR_SUCCESS);
    CHECK(client.GetAdapterInfo(snapshot) == ERROR_INVALID_HANDLE && unchanged());
    return true;
}
bool TestAdapterInfoAllocationFailures() {
    const std::vector<HV_ADAPTER_INFO> kept{AdapterFixture(99, HV_ADAPTER_RUNNING)};
    const std::vector<HV_ADAPTER_INFO> fixtures{
        AdapterFixture(1, HV_ADAPTER_INFO_KNOWN_FLAGS), AdapterFixture(2, HV_ADAPTER_PAUSE_VALID)};
    const auto good = AdapterResponse(fixtures);
    Client::AdapterSnapshot snapshot;
    CHECK(Client::DecodeAdapterInfo(AdapterResponse(kept), snapshot) == ERROR_SUCCESS);
    const auto* original = snapshot.adapters.data();
    unsigned failures = 0;
    for (ptrdiff_t after = 0; after < 32; ++after) {
        DWORD result = ERROR_SUCCESS;
        bool triggered = false;
        {
            allocation::FailAfter fail(after);
            result = Client::DecodeAdapterInfo(good, snapshot);
            triggered = fail.Triggered();
        }
        if (!triggered) {
            CHECK(result == ERROR_SUCCESS && MatchesSnapshot(snapshot, fixtures));
            break;
        }
        ++failures;
        CHECK(result == ERROR_NOT_ENOUGH_MEMORY);
        CHECK(snapshot.adapters.data() == original && MatchesSnapshot(snapshot, kept));
    }
    CHECK(failures >= 7 && failures < 32); // Vector plus all three owning names for both entries.
    testio::Reset();
    Client client;
    CHECK(client.Open() == ERROR_SUCCESS);
    original = snapshot.adapters.data();
    DWORD result = ERROR_SUCCESS;
    {
        allocation::FailAfter fail(0);
        result = client.GetAdapterInfo(snapshot); // The bounded nothrow raw buffer fails before any IOCTL.
        CHECK(fail.Triggered());
    }
    CHECK(result == ERROR_NOT_ENOUGH_MEMORY && testio::state.adapter_queries == 0);
    CHECK(snapshot.adapters.data() == original && MatchesSnapshot(snapshot, fixtures));
    CHECK(client.Close() == ERROR_SUCCESS && testio::state.operations.empty());
    return true;
}
Bytes Connection(bool ipv6, size_t payload, uint32_t interface_index = 0x12345678) {
    const size_t prefix = ipv6 ? 60 : 36, addr = ipv6 ? 16 : 4;
    Bytes bytes(prefix + payload);
    bytes[0] = ipv6 ? 2 : 1;
    Put(bytes, 1, bytes.size() - 5, 4);
    Put(bytes, 5, 0x0102030405060708ull, 8);
    Put(bytes, 13, interface_index, 4);
    bytes[17] = ipv6 ? 1 : 0; bytes[18] = 17;
    bytes[19] = 0x20; bytes[19 + addr] = 0x30;
    Put(bytes, 19 + addr * 2, 12345, 2); Put(bytes, 21 + addr * 2, 443, 2);
    bytes[prefix - 5] = 3;
    Put(bytes, prefix - 4, payload, 4);
    for (size_t i = 0; i < payload; ++i) bytes[prefix + i] = static_cast<uint8_t>(i % 251);
    return bytes;
}
struct Observed {
    bool good = true, ipv6 = false;
    unsigned calls = 0;
    size_t payload = 0;
    const uint8_t* pointer = nullptr;
    const void* header = nullptr;
    Client* client = nullptr;
    bool throw_callback = false;
};
template <class T> void Observe(void* context, const T* packet, const uint8_t* payload, uint32_t size) {
    auto& s = *static_cast<Observed*>(context);
    ++s.calls;
    s.good &= packet->id == 0x0102030405060708ull && packet->interface_index == 0x12345678 && (sizeof(packet->local_ip) == 16) == s.ipv6 &&
        packet->direction == (s.ipv6 ? 1 : 0) && packet->protocol == 17 && packet->payload_layer == 3 &&
        packet->local_ip[0] == 0x20 && packet->remote_ip[0] == 0x30 &&
        packet->local_port == 12345 && packet->remote_port == 443 && size == s.payload &&
        (!s.pointer || payload == s.pointer) && (!s.header || packet == s.header);
    for (size_t i = 0; i < size; ++i) s.good &= payload[i] == static_cast<uint8_t>(i % 251);
    if (s.throw_callback) throw std::runtime_error("callback");
    if (s.client) {
        s.good &= s.client->SendVerdict(packet->id, Client::Verdict::PermanentAccept) == ERROR_SUCCESS;
        s.client->Stop();
    }
}
Client::Callbacks ConnectionCallbacks(Observed& observed) {
    Client::Callbacks cb;
    cb.context = &observed;
    cb.on_connection_v4 = Observe<Client::ConnectionV4>;
    cb.on_connection_v6 = Observe<Client::ConnectionV6>;
    return cb;
}
bool Feed(Client::Stream& stream, const Bytes& bytes, size_t chunk, const Client::Callbacks& cb) {
    for (size_t offset = 0; offset < bytes.size();) {
        auto buffer = stream.Buffer();
        const size_t n = (std::min)({chunk, buffer.size(), bytes.size() - offset});
        CHECK(n != 0);
        std::memcpy(buffer.data(), bytes.data() + offset, n);
        CHECK(stream.Commit(n, cb) == ERROR_SUCCESS);
        offset += n;
    }
    return true;
}
template <class T> void ObserveInterface(void* context, const T* connection, const uint8_t*, uint32_t) {
    static_cast<std::vector<uint32_t>*>(context)->push_back(connection->interface_index);
}
bool TestAdapterIndices() {
    const std::vector<uint32_t> expected{101, 0x12345678, 101, 0x87654321};
    for (bool ipv6 : {false, true}) {
        Bytes records;
        for (uint32_t index : expected) {
            const auto record = Connection(ipv6, 28, index);
            records.insert(records.end(), record.begin(), record.end());
        }
        for (size_t chunk : {size_t{1}, size_t{16}, size_t{65536}}) {
            std::vector<uint32_t> observed;
            Client::Callbacks cb;
            cb.context = &observed;
            cb.on_connection_v4 = ObserveInterface<Client::ConnectionV4>;
            cb.on_connection_v6 = ObserveInterface<Client::ConnectionV6>;
            Client::Stream stream;
            CHECK(Feed(stream, records, chunk, cb));
            CHECK(stream.PendingBytes() == 0 && observed == expected);
        }
    }
    return true;
}
bool TestCodecAndStream() {
    static_assert(sizeof(Client) < 1024 && sizeof(Client::Stream) < 1024);
    static_assert(Client::RequiredVersion == std::array<uint8_t, 4>{0, 3, 2, 0});
    for (bool v6 : {false, true}) for (size_t size : {size_t{0}, size_t{28}, size_t{65537}, size_t{1048576}}) {
        auto record = Connection(v6, size);
        Observed observed;
        observed.ipv6 = v6; observed.payload = size;
        observed.header = record.data() + 5; observed.pointer = record.data() + (v6 ? 60 : 36);
        auto cb = ConnectionCallbacks(observed);
        CHECK(Client::DispatchRecord(record, cb) == ERROR_SUCCESS);
        CHECK(observed.calls == 1 && observed.good);
        for (size_t chunk : {size_t{1}, size_t{31}, size_t{65536}}) {
            Client::Stream stream;
            observed.calls = 0; observed.header = stream.Buffer().data() + 5;
            observed.pointer = stream.Buffer().data() + (v6 ? 60 : 36);
            CHECK(Feed(stream, record, chunk, cb));
            CHECK(stream.PendingBytes() == 0 && observed.calls == 1 && observed.good);
        }
    }
    auto record = Connection(false, 32);
    Bytes pair = record; pair.insert(pair.end(), record.begin(), record.end());
    Observed observed; observed.payload = 32;
    auto cb = ConnectionCallbacks(observed);
    Client::Stream stream;
    CHECK(Feed(stream, pair, 79, cb));
    CHECK(observed.good && observed.calls == 2 && stream.PendingBytes() == 0);
    for (size_t n = 0; n < record.size(); ++n)
        CHECK(Client::DispatchRecord(Client::Bytes(record).first(n), cb) != ERROR_SUCCESS);
    for (size_t offset : {size_t{17}, size_t{31}, size_t{32}}) {
        auto invalid = record; invalid[offset] = 9;
        CHECK(Client::DispatchRecord(invalid, cb) != ERROR_SUCCESS);
    }
    const unsigned calls = observed.calls;
    auto invalid = record; Put(invalid, 1, 0xffffffff, 4);
    std::memcpy(stream.Buffer().data(), invalid.data(), 5);
    CHECK(stream.Commit(5, cb) == ERROR_INVALID_DATA);
    CHECK(observed.calls == calls && stream.Buffer().empty());
    CHECK(stream.Commit(0, cb) == ERROR_INVALID_DATA);
    stream.Reset();
    CHECK(Feed(stream, record, 31, cb));
    CHECK(observed.calls == calls + 1);
    return true;
}
bool TestUnalignedViewsAndDeferredCompaction() {
    struct Natural { uint8_t byte; uint64_t value; };
    static_assert(alignof(Natural) == alignof(uint64_t) && offsetof(Natural, value) == 8); // pack was restored.
    for (bool v6 : {false, true}) {
        auto record = Connection(v6, 28);
        Observed observed; observed.ipv6 = v6; observed.payload = 28;
        auto cb = ConnectionCallbacks(observed);
        for (size_t shift = 0; shift < 8; ++shift) {
            Bytes storage(shift + record.size());
            std::memcpy(storage.data() + shift, record.data(), record.size());
            observed.header = storage.data() + shift + 5;
            observed.pointer = storage.data() + shift + (v6 ? 60 : 36);
            CHECK(Client::DispatchRecord(Client::Bytes(storage).subspan(shift), cb) == ERROR_SUCCESS);
            CHECK(observed.good && observed.calls == shift + 1);
        }
        const unsigned calls = observed.calls;
        for (size_t offset : {size_t{17}, record.size() - 28 - 5, record.size() - 28 - 4}) {
            auto invalid = record; invalid[offset] = 9;
            CHECK(Client::DispatchRecord(invalid, cb) == ERROR_INVALID_DATA);
            CHECK(Client::DispatchRecord(invalid, {}) == ERROR_INVALID_DATA);
        }
        CHECK(observed.calls == calls);
    }
    Client::Stream stream;
    uint8_t* base = stream.Buffer().data();
    auto first = Connection(false, 0);
    auto second = Connection(true, Client::MaxPayloadSize);
    const size_t partial = 17, written = first.size() + partial;
    std::memcpy(base, first.data(), first.size());
    std::memcpy(base + first.size(), second.data(), partial);
    Observed observed; observed.header = base + 5; observed.pointer = base + 36;
    auto cb = ConnectionCallbacks(observed);
    CHECK(stream.Commit(written, cb) == ERROR_SUCCESS);
    CHECK(observed.good && observed.calls == 1 && stream.PendingBytes() == partial);
    CHECK(stream.Buffer().data() == base + written); // The partial frame was not moved after dispatch.
    observed.ipv6 = true; observed.payload = Client::MaxPayloadSize;
    observed.header = base + 5; observed.pointer = base + 60; // Compaction is eventually necessary at capacity.
    Bytes remainder(second.begin() + partial, second.end());
    CHECK(Feed(stream, remainder, Client::ReadSize, cb));
    CHECK(observed.good && observed.calls == 2 && stream.PendingBytes() == 0);
    CHECK(stream.Buffer().data() == base);
    CHECK(stream.Commit(Client::ReadSize + 1, cb) == ERROR_INVALID_DATA);
    CHECK(stream.Buffer().empty());
    stream.Reset();
    CHECK(!stream.Buffer().empty());
    return true;
}
bool TestLogAndBandwidth() {
    struct State {
        unsigned logs = 0, batches = 0, entries = 0;
        bool good = true, ipv6 = false;
        const void* pointer = nullptr;
    } state;
    Client::Callbacks cb;
    cb.context = &state;
    cb.on_log = [](void* context, uint8_t level, std::string_view text) {
        auto& s = *static_cast<State*>(context); ++s.logs;
        s.good &= level == 3 && text == "abc" && text.data() == s.pointer;
    };
    const auto bandwidth = []<class T>(void* context, uint8_t protocol, const T* entries, uint32_t count) {
        auto& s = *static_cast<State*>(context); ++s.batches; s.entries += count;
        s.good &= protocol == 6 && (sizeof(entries->local_ip) == 16) == s.ipv6 &&
            entries == s.pointer && count == 2;
        for (uint32_t i = 0; i < count; ++i) {
            const auto& b = entries[i];
            s.good &= b.local_ip[0] == 1 && b.remote_ip[0] == 2 &&
                b.local_port == 12345 && b.remote_port == 443 &&
                b.transmitted_bytes == 0x0123456789abcdefull + i && b.received_bytes == 0xfedcba9876543210ull - i;
        }
    };
    cb.on_bandwidth_v4 = bandwidth;
    cb.on_bandwidth_v6 = bandwidth;
    Bytes log{0, 4, 0, 0, 0, 3, 'a', 'b', 'c'};
    state.pointer = log.data() + 6;
    CHECK(Client::DispatchRecord(log, cb) == ERROR_SUCCESS);
    for (uint8_t severity : {uint8_t{0}, uint8_t{8}}) {
        log[5] = severity; CHECK(Client::DispatchRecord(log, cb) == ERROR_INVALID_DATA);
    }
    for (bool v6 : {false, true}) {
        const size_t addr = v6 ? 16 : 4, entry = addr * 2 + 20;
        Bytes stats(10 + 2 * entry);
        stats[0] = v6 ? 6 : 5; Put(stats, 1, stats.size() - 5, 4); stats[5] = 6; Put(stats, 6, 2, 4);
        for (size_t i = 0; i < 2; ++i) {
            const size_t offset = 10 + i * entry;
            stats[offset] = 1; Put(stats, offset + addr, 12345, 2);
            stats[offset + addr + 2] = 2; Put(stats, offset + addr * 2 + 2, 443, 2);
            Put(stats, offset + addr * 2 + 4, 0x0123456789abcdefull + i, 8);
            Put(stats, offset + addr * 2 + 12, 0xfedcba9876543210ull - i, 8);
        }
        state.ipv6 = v6;
        for (size_t shift = 0; shift < 8; ++shift) {
            Bytes storage(shift + stats.size());
            std::memcpy(storage.data() + shift, stats.data(), stats.size());
            state.pointer = storage.data() + shift + 10;
            const unsigned batches = state.batches;
            CHECK(Client::DispatchRecord(Client::Bytes(storage).subspan(shift), cb) == ERROR_SUCCESS);
            CHECK(state.good && state.batches == batches + 1); // One borrowed array, not two temporary entries.
        }
        const unsigned batches = state.batches;
        auto invalid = stats;
        Put(invalid, 6, 0xffffffff, 4);
        CHECK(Client::DispatchRecord(invalid, cb) == ERROR_INVALID_DATA);
        CHECK(Client::DispatchRecord(invalid, {}) == ERROR_INVALID_DATA);
        invalid = stats; invalid.pop_back(); Put(invalid, 1, invalid.size() - 5, 4);
        CHECK(Client::DispatchRecord(invalid, cb) == ERROR_INVALID_DATA);
        for (size_t n = 0; n < stats.size(); ++n)
            CHECK(Client::DispatchRecord(Client::Bytes(stats).first(n), cb) != ERROR_SUCCESS);
        Bytes empty{static_cast<uint8_t>(v6 ? 6 : 5), 5, 0, 0, 0, 6, 0, 0, 0, 0};
        CHECK(Client::DispatchRecord(empty, cb) == ERROR_SUCCESS);
        CHECK(state.batches == batches);
    }
    CHECK(state.good && state.logs == 1 && state.batches == 16 && state.entries == 32);
    return true;
}
bool TestIdleAndStop() {
    testio::Reset();
    const std::vector<HV_ADAPTER_INFO> adapters{
        AdapterFixture(1, HV_ADAPTER_INFO_KNOWN_FLAGS), AdapterFixture(2, HV_ADAPTER_PAUSE_VALID)};
    testio::state.adapter_info = AdapterResponse(adapters);
    Client client;
    CHECK(client.Open() == ERROR_SUCCESS);
    auto run = std::async(std::launch::async, [&] { return client.Run({}, 1000); });
    CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
    CHECK(client.Close() == ERROR_BUSY);
    uint32_t count = 0;
    CHECK(client.GetFilteredDeviceCount(count) == ERROR_SUCCESS && count == 1); // While read is pending.
    Client::AdapterSnapshot snapshot;
    CHECK(client.GetAdapterInfo(snapshot) == ERROR_SUCCESS && MatchesSnapshot(snapshot, adapters));
    CHECK(testio::state.adapter_queries == 1);
    HANDLE quiet = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const DWORD waited = ::WaitForSingleObject(quiet, 80);
    ::CloseHandle(quiet);
    CHECK(waited == WAIT_TIMEOUT);
    { std::lock_guard lock(testio::state.mutex); CHECK(testio::state.reads == 1 && testio::state.pending); }
    client.Stop();
    CHECK(run.get() == ERROR_SUCCESS);
    CHECK(client.Close() == ERROR_SUCCESS);
    CHECK(testio::state.operations.empty() && testio::state.cancels == 1 && testio::state.closes == 1);
    testio::Reset();
    CHECK(client.Open() == ERROR_SUCCESS);
    auto shutdown = std::async(std::launch::async, [&] { return client.Run({}, 1000); });
    CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
    CHECK(client.Shutdown() == ERROR_SUCCESS);
    CHECK(shutdown.get() == ERROR_SUCCESS && testio::state.operations.empty());
    CHECK(client.Close() == ERROR_SUCCESS);
    return true;
}
bool TestStartupWait() {
    for (bool cancel : {false, true}) {
        testio::Reset();
        testio::state.fail_open = true;
        ::SetEvent(testio::state.driver_ready); // Stale signal must not cause retry spinning.
        Client client;
        auto open = std::async(std::launch::async, [&] { return client.Open(); });
        struct Guard {
            Client& client; std::future<DWORD>& open;
            ~Guard() { client.Stop(); if (open.valid()) open.wait(); }
        } guard{client, open};
        CHECK(::WaitForSingleObject(testio::state.startup_seen, 2000) == WAIT_OBJECT_0);
        HANDLE quiet = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const DWORD waited = ::WaitForSingleObject(quiet, 80);
        ::CloseHandle(quiet);
        CHECK(waited == WAIT_TIMEOUT);
        { std::lock_guard lock(testio::state.mutex);
          CHECK(testio::state.opens == 2 && testio::state.secure_ready); }
        if (cancel) client.Stop();
        else {
            std::lock_guard lock(testio::state.mutex);
            testio::state.fail_open = false;
            ::SetEvent(testio::state.driver_ready);
        }
        CHECK(open.get() == static_cast<DWORD>(cancel ? ERROR_OPERATION_ABORTED : ERROR_SUCCESS));
        CHECK(testio::state.operations.empty());
        client.Close();
    }
    return true;
}
bool TestBusyStartup() {
    for (const auto& errors : std::vector<std::vector<DWORD>>{
            {ERROR_SHARING_VIOLATION},
            {ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION},
            {ERROR_FILE_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION}}) {
        testio::Reset();
        testio::state.open_errors = errors;
        Client client;
        auto open = std::async(std::launch::async, [&] { return client.Open(); });
        struct Guard {
            Client& client; std::future<DWORD>& open;
            ~Guard() { client.Stop(); if (open.valid()) open.wait(); }
        } guard{client, open};
        if (errors.size() == 3) {
            CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
            ::SetEvent(testio::state.driver_ready);
        }
        const bool completed = open.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        if (!completed) client.Stop();
        CHECK(open.get() == ERROR_SHARING_VIOLATION && completed);
        CHECK(testio::state.opens == errors.size() && testio::state.operations.empty());
        if (errors.size() == 1) CHECK(::WaitForSingleObject(testio::state.startup_seen, 0) == WAIT_TIMEOUT);
        testio::state.open_errors.clear();
        CHECK(client.Open() == ERROR_SUCCESS);
        CHECK(client.Close() == ERROR_SUCCESS && testio::state.operations.empty());
    }
    return true;
}

bool TestTimeoutAndLegacy() {
    testio::Reset();
    Client client;
    CHECK(client.Open() == ERROR_SUCCESS);
    const auto started = GetTickCount64();
    CHECK(client.Run({}, 30) == ERROR_SUCCESS);
    CHECK(GetTickCount64() - started >= 20);
    CHECK(testio::state.reads == 1 && testio::state.cancels == 1 && testio::state.operations.empty());
    client.Close();
    testio::Reset();
    CHECK(client.Open() == ERROR_SUCCESS);
    testio::state.empty_read = true;
    CHECK(client.Run({}, 1000) == ERROR_INVALID_DATA);
    CHECK(testio::state.reads == 1 && testio::state.operations.empty());
    client.Close();
    testio::Reset();
    CHECK(client.Open() == ERROR_SUCCESS);
    testio::state.stop_on_read = &client;
    CHECK(client.Run({}, 1000) == ERROR_SUCCESS);
    CHECK(testio::state.reads == 1 && testio::state.operations.empty());
    return true;
}
bool TestCallbacksAndLargeRead() {
    for (size_t size : {size_t{32}, size_t{1048576}}) {
        testio::Reset();
        Client client;
        CHECK(client.Open() == ERROR_SUCCESS);
        Observed observed; observed.ipv6 = true; observed.payload = size; observed.client = &client;
        auto cb = ConnectionCallbacks(observed);
        auto run = std::async(std::launch::async, [&] { return client.Run(cb, 2000); });
        CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
        { std::lock_guard lock(testio::state.mutex);
          observed.pointer = testio::state.first_buffer + 60; observed.header = testio::state.first_buffer + 5; }
        testio::Inject(Connection(true, size));
        CHECK(run.get() == ERROR_SUCCESS);
        CHECK(observed.good && observed.calls == 1 && testio::state.operations.empty());
        const Bytes expected{1, 8, 7, 6, 5, 4, 3, 2, 1, 3};
        CHECK(testio::state.written == expected);
        CHECK(client.Send(Client::Command::GetBandwidthStats) == ERROR_SUCCESS);
        CHECK(testio::state.written.back() == 6);
        client.Close();
    }
    return true;
}
bool TestErrorsAndException() {
    testio::Reset();
    Client client;
    uint32_t count = 99;
    std::array<uint8_t, 4> version{9, 9, 9, 9};
    CHECK(client.GetVersion(version) == ERROR_INVALID_HANDLE && version[0] == 9);
    CHECK(client.GetFilteredDeviceCount(count) == ERROR_INVALID_HANDLE && count == 99);
    CHECK(client.Run({}, 10) == ERROR_INVALID_HANDLE);
    CHECK(client.SendVerdict(1, static_cast<Client::Verdict>(9)) == ERROR_INVALID_PARAMETER);
    CHECK(client.Send(static_cast<Client::Command>(0)) == ERROR_INVALID_PARAMETER);
    testio::state.wrong_version = true;
    CHECK(client.Open() == ERROR_REVISION_MISMATCH && testio::state.closes == 1);
    testio::state.wrong_version = false;
    CHECK(client.Open() == ERROR_SUCCESS);
    testio::state.short_control = true;
    CHECK(client.GetFilteredDeviceCount(count) == ERROR_BAD_LENGTH && count == 99);
    testio::state.short_control = false;
    Observed observed; observed.payload = 32; observed.throw_callback = true;
    auto cb = ConnectionCallbacks(observed);
    auto run = std::async(std::launch::async, [&] { return client.Run(cb, 1000); });
    CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
    testio::Inject(Connection(false, 32));
    bool threw = false;
    try { (void)run.get(); } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw && testio::state.operations.empty());
    CHECK(client.Close() == ERROR_SUCCESS);
    CHECK(client.Close() == ERROR_SUCCESS);
    return true;
}
} // namespace

int main() {
    const struct { const char* name; bool (*run)(); } tests[]{
        {"owning adapter snapshots, binary identity, UTF-16 names, wide scalars and maximum bounds", TestAdapterInfoCodec},
        {"adapter snapshot validation rejects malformed lengths, versions, flags, counts, MAC and names without changing output", TestAdapterInfoMalformed},
        {"adapter-information IOCTL empty/multiadapter replies, unsupported/errors and malformed responses preserve output", TestAdapterInfoQuery},
        {"adapter-information raw-buffer and owning-decoder allocation failures preserve output", TestAdapterInfoAllocationFailures},
        {"interleaved adapter indices survive fragmented/coalesced IPv4/IPv6 streams", TestAdapterIndices},
        {"borrowed packed connection headers/payloads, 1 MiB packets, chunked/coalesced reads and poisoned-stream reset", TestCodecAndStream},
        {"unaligned zero-copy views, restored packing and deferred stream compaction", TestUnalignedViewsAndDeferredCompaction},
        {"borrowed logs and batched bandwidth arrays, exact layouts and malformed records", TestLogAndBandwidth},
        {"idle read without polling, concurrent IOCTL, Stop/Shutdown cancellation and reaping", TestIdleAndStop},
        {"unlimited DriverReady startup wait, protected ACL, stale signal and Stop without device polling", TestStartupWait},
        {"exclusive-device sharing errors never wait for DriverReady and allow a later reopen", TestBusyStartup},
        {"deadline reaping, no legacy-read spin, and Stop during read admission", TestTimeoutAndLegacy},
        {"callback verdict bytes and full maximum packet read without payload allocation/copy", TestCallbacksAndLargeRead},
        {"unopened/short/version errors and callback exception cleanup", TestErrorsAndException},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
