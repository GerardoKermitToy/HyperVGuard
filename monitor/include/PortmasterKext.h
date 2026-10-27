// Portmaster-compatible client API for the HyperVXNdisFilter host-adapter NDIS LWF.
// Adapted from kext_client on 2026-10-25; see README.md and LICENSE for provenance.
// Wire integers are little-endian; record headers are [u8 type][u32 size].
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pmkext {
namespace wire {
class RecordStream;
}

enum class InfoType : uint8_t {
    LogLine              = 0,
    ConnectionIpv4       = 1,
    ConnectionIpv6       = 2,
    ConnectionEndEventV4 = 3,
    ConnectionEndEventV6 = 4,
    BandwidthStatsV4     = 5,
    BandwidthStatsV6     = 6,
};

enum class CommandType : uint8_t {
    Shutdown              = 0,
    Verdict               = 1,
    UpdateV4              = 2,
    UpdateV6              = 3,
    ClearCache            = 4,
    GetLogs               = 5,
    GetBandwidthStats     = 6,
    PrintMemoryStats      = 7,
    CleanEndedConnections = 8,
};

// Values outside 2..7 are retained for source compatibility only. HyperVXNdisFilter
// rejects them (including all redirect verdicts) before any device write.
enum class Verdict : uint8_t {
    Undecided           = 0,
    Undeterminable      = 1,
    Accept              = 2,
    PermanentAccept     = 3,
    Block               = 4,
    PermanentBlock      = 5,
    Drop                = 6,
    PermanentDrop       = 7,
    RedirectNameServer  = 8,
    RedirectTunnel      = 9,
    Failed              = 10,
    RedirectSplitTunnel = 11,
};

enum class Severity : uint8_t {
    Trace    = 1,
    Debug    = 2,
    Info     = 3,
    Warning  = 4,
    Error    = 5,
    Critical = 6,
    Disabled = 7,
};

const char* ToString(Verdict v);
const char* ToString(Severity s);
const char* ToString(InfoType t);
// HyperVXNdisFilter captures an IP packet, so its payload_layer is always 3.
const char* PayloadLayerToString(uint8_t layer);
const char* ProtocolToString(uint8_t proto);
// 0 means guest outbound (host receive), 1 means guest inbound (host send).
const char* DirectionToString(uint8_t dir);

std::string FormatIpv4(const uint8_t ip[4]);
std::string FormatIpv6(const uint8_t ip[16]);
bool NormalizeIpAddress(const std::wstring& literal, std::string& normalized);

// One event identifies one owned NBL pending one verdict. For a homogeneous
// multi-NB NBL, payload is the complete first NB IP packet, not concatenated NB
// data. Unsupported/mixed batches are dropped. interface_index identifies the host
// adapter at the interception point, not a guest NIC. No process/thread is inferred.
struct Connection {
    bool     ipv6 = false;
    uint64_t id = 0;
    uint32_t interface_index = 0;
    uint8_t  direction = 0;  // Guest outbound=0/inbound=1; local=guest, opposite host NDIS path.
    uint8_t  protocol = 0;
    uint8_t  local_ip[16] = {};
    uint8_t  remote_ip[16] = {};
    uint16_t local_port = 0;
    uint16_t remote_port = 0;
    uint8_t  payload_layer = 3;
    uint32_t payload_size = 0; // Complete logical IP packet length, at most 1 MiB.
    std::vector<uint8_t> payload; // All IP bytes, without Ethernet/VLAN headers or truncation.

    std::string LocalIpString() const;
    std::string RemoteIpString() const;
    std::string PayloadHexString() const;
};

// Retained API/wire types. This LWF does not manufacture connection-end
// events. Bandwidth counts admitted guest outbound/inbound IP bytes in tx/rx, with no PID.
// CleanEndedConnections only sweeps expired cache entries, never fabricates END.
struct ConnectionEnd {
    bool     ipv6 = false;
    uint64_t process_id = 0;
    uint8_t  direction = 0;
    uint8_t  protocol = 0;
    uint8_t  local_ip[16] = {};
    uint8_t  remote_ip[16] = {};
    uint16_t local_port = 0;
    uint16_t remote_port = 0;

    std::string LocalIpString() const;
    std::string RemoteIpString() const;
};

struct LogLine {
    Severity    severity = Severity::Trace;
    std::string message;
};

struct BandwidthEntry {
    bool     ipv6 = false;
    uint8_t  local_ip[16] = {};
    uint16_t local_port = 0;
    uint8_t  remote_ip[16] = {};
    uint16_t remote_port = 0;
    uint64_t transmitted_bytes = 0;
    uint64_t received_bytes = 0;

    std::string LocalIpString() const;
    std::string RemoteIpString() const;
};

struct BandwidthStats {
    uint8_t                     protocol = 0;
    std::vector<BandwidthEntry> entries;
};

// A diagnostic snapshot of an attached NDIS module. Indices/LUIDs describe the
// host stack, never guest NICs. Strings/MAC are copied at attach; link/general
// attributes are the last values supplied by NDIS, not fresh OID queries.
struct AdapterInfo {
    static constexpr uint32_t Running = 0x01;
    static constexpr uint32_t GeneralAttributesValid = 0x02;
    static constexpr uint32_t ConnectorPresentValid = 0x04;
    static constexpr uint32_t InstanceNameTruncated = 0x08;
    static constexpr uint32_t BaseNameTruncated = 0x10;
    static constexpr uint32_t FilterModuleNameTruncated = 0x20;
    static constexpr uint32_t LinkStateValid = 0x40;
    static constexpr uint32_t PauseValid = 0x80;

    uint64_t module_id = 0;
    uint32_t interface_index = 0, filter_interface_index = 0, lower_interface_index = 0, flags = 0;
    uint64_t interface_luid = 0, filter_interface_luid = 0, lower_interface_luid = 0;
    std::array<uint8_t, 16> interface_guid{};
    uint32_t media_type = 0, physical_medium = 0, media_connect_state = 0, media_duplex_state = 0;
    uint64_t xmit_link_speed = 0, rcv_link_speed = 0;
    uint32_t mtu = 0, mac_options = 0, supported_packet_filters = 0, max_multicast_list_size = 0;
    uint64_t max_xmit_link_speed = 0, max_rcv_link_speed = 0;
    uint32_t lookahead_size = 0, access_type = 0, connection_type = 0, supported_statistics = 0;
    uint32_t data_backfill_size = 0, context_backfill_size = 0, restart_flags = 0, attach_flags = 0;
    uint32_t connector_present = 0, mac_address_length = 0;
    std::array<uint8_t, 32> mac_address{};
    uint32_t instance_name_length = 0, base_name_length = 0, filter_module_name_length = 0;
    uint32_t auto_negotiation_flags = 0, pause_reason = 0, pause_flags = 0;
    std::wstring instance_name, base_name, filter_module_name;
};

struct AdapterSnapshot {
    uint32_t running_count = 0;
    std::vector<AdapterInfo> adapters; // Includes attached but not running modules.
};

// Callbacks are optional. on_poll runs on Run()'s thread; other handlers run
// on its reader thread. All driver records are dispatched locally.
struct Handlers {
    std::function<void(const Connection&)>     on_connection;
    std::function<void(const ConnectionEnd&)>  on_connection_end;
    std::function<void(const LogLine&)>        on_log;
    std::function<void(const BandwidthStats&)> on_bandwidth;
    std::function<void(const std::string&)>    on_warning;
    std::function<void()>                      on_poll;
};

// Manages a device session only, never an SCM service or LWF installation.
// Opening the device requires an elevated Administrator or SYSTEM token.
class Driver {
public:
    explicit Driver(std::wstring service_name = L"HyperVXNdisFilter");
    ~Driver();

    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;

    // Compatibility stub: returns a descriptive unsupported error. Install the
    // NDIS LWF explicitly with dist/Install.exe, which targets only the
    // Default Switch host vNIC. Neither this call nor Cleanup ever modifies SCM state.
    bool Install(const std::wstring& sys_path, std::string& error,
                 bool inbound_udp_pid_fallback = true);

    // Opens the installed device using FILE_FLAG_OVERLAPPED. No IPC server or
    // external verdict client is started; records go to the local handlers.
    bool Open(std::string& error);

    // Nonzero reads wait for data and support cancellation; no idle polling.
    // Only complete bounded wire records are dispatched.
    // Stop() is thread-safe during Run(). Join Run() before Cleanup/destruction.
    void Run(const Handlers& handlers, unsigned poll_interval_ms = 1000);

    // Signals Run() and issues IOCTL_SHUTDOWN once to release pending packets;
    // it does not unload or disable the installed NDIS LWF.
    void Stop();

    bool GetVersion(uint8_t out[4], std::string& error);
    // Snapshot of running NDIS modules, not configured/enabled bindings or traffic.
    // Paused modules are excluded; the count does not depend on policy-session state.
    bool GetFilteredDeviceCount(uint32_t& out, std::string& error);
    // Bounded, versioned snapshot; leaves out unchanged on every failure.
    bool GetAdapterInfo(AdapterSnapshot& out, std::string& error);
    bool RequestShutdown(std::string& error);

    // Original unframed commands, with unchanged IDs and fixed field sizes.
    // UpdateV4/UpdateV6 remain named for compatibility but are unsupported.
    // Only verdicts 2..7 are supported. Only TCP/UDP can use permanent cache:
    // four growing tables per interface: TCP/UDP, each IPv4/IPv6; key=IP+port only.
    // TCP/UDP stay separate; both directions share tuples within one table. OOM skips insertion.
    // Default TTL is 60 seconds: PermanentAccept hits refresh it; Block/Drop do not.
    // Pending verdict timeout is 8 seconds by default, with fail-open behavior.
    bool SendVerdict(uint64_t id, Verdict verdict, std::string& error);
    bool RequestLogs(std::string& error);
    bool RequestBandwidthStats(std::string& error);
    bool RequestMemoryStats(std::string& error);
    // Requests a full asynchronous expiry sweep; it does not migrate tables.
    bool RequestCleanEndedConnections(std::string& error);
    bool RequestClearCache(std::string& error);

    void Cleanup();

private:
    bool SendCommand(const uint8_t* data, size_t len, std::string& error);
    bool DeviceControl(uint32_t code, uint8_t* out, uint32_t out_len,
                       std::string& error, uint32_t* returned = nullptr);
    void Dispatch(const uint8_t* record, size_t length, const Handlers& handlers);
    void ReaderLoop(const Handlers& handlers);

    std::wstring         service_name_;
    std::unique_ptr<wire::RecordStream> records_;
    std::atomic<bool>     shutdown_requested_{false};
    void*                device_ = nullptr; // HANDLE
    void*                stop_event_ = nullptr; // HANDLE
    std::mutex           write_mutex_;
};

} // namespace pmkext
