// Offline fixtures: no device, global readiness event, registry or NDIS access.
#include "DriverProtocol.h"
#include "RecordOutput.h"
#include "../../driver/shim/adapter_info.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

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
    CHECK(HvAdapterInfoSize(0) == 16 && HvAdapterInfoSize(32) == 56336 && HvAdapterInfoSize(33) == 0);
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
    bytes = Encode(32);
    CHECK(pmkext::wire::DecodeAdapterInfo(bytes.data(), bytes.size(), s, error) && s.adapters.size() == 32);
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
    if (!CheckRoundTrip() || !CheckMalformed() || !CheckNames() || !CheckOutput()) return 1;
    std::puts("Adapter information codec/name/output tests passed (no driver).");
    return 0;
}
