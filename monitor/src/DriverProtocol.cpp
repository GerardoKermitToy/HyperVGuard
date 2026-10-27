#include "DriverProtocol.h"

#include <algorithm>
#include <cstring>
#include <new>
#include <utility>

namespace pmkext::wire {
namespace {

uint16_t ReadU16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                (static_cast<uint16_t>(p[1]) << 8));
}
uint32_t ReadU32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t ReadU64(const uint8_t* p) noexcept {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    return value;
}

bool ValidBodySize(uint8_t type, size_t size) noexcept {
    switch (static_cast<InfoType>(type)) {
        case InfoType::LogLine: return size >= 1 && size <= kMaxLogRecordSize - kRecordHeaderSize;
        case InfoType::ConnectionIpv4:
            return size >= kConnectionIpv4PrefixSize - kRecordHeaderSize &&
                   size <= kConnectionIpv4PrefixSize - kRecordHeaderSize + kMaxPayloadSize;
        case InfoType::ConnectionIpv6:
            return size >= kConnectionIpv6PrefixSize - kRecordHeaderSize &&
                   size <= kConnectionIpv6PrefixSize - kRecordHeaderSize + kMaxPayloadSize;
        case InfoType::BandwidthStatsV4: return size >= 9 && (size - 9) % 28 == 0;
        case InfoType::BandwidthStatsV6: return size >= 9 && (size - 9) % 52 == 0;
        default: return size <= kMaxRecordSize - kRecordHeaderSize;
    }
}

} // namespace

bool IsCompatibleVersion(const uint8_t version[4]) noexcept {
    return version != nullptr &&
           std::equal(kRequiredDeviceVersion.begin(), kRequiredDeviceVersion.end(), version);
}

bool DecodeFilteredDeviceCount(const uint8_t* bytes, size_t length,
                               uint32_t& out, std::string& error) {
    if (bytes == nullptr || length != sizeof(uint32_t)) {
        error = "IOCTL_FILTERED_DEVICE_COUNT did not return exactly four bytes";
        return false;
    }
    out = ReadU32(bytes);
    error.clear();
    return true;
}

bool DecodeAdapterInfoHeader(const uint8_t* bytes, size_t length,
                             uint32_t& required_size, std::string& error) {
    if (bytes == nullptr || length < kAdapterInfoHeaderSize ||
        ReadU32(bytes) != kAdapterInfoVersion || ReadU32(bytes + 4) != kAdapterInfoEntrySize ||
        ReadU32(bytes + 8) > kMaxAdapters || ReadU32(bytes + 12) > ReadU32(bytes + 8)) {
        error = "IOCTL_ADAPTER_INFO returned an invalid header";
        return false;
    }
    // Compare before multiplying, so this also remains safe on 32-bit hosts.
    required_size = static_cast<uint32_t>(kAdapterInfoHeaderSize +
        static_cast<size_t>(ReadU32(bytes + 8)) * kAdapterInfoEntrySize);
    error.clear();
    return true;
}

bool DecodeAdapterInfo(const uint8_t* bytes, size_t length,
                       AdapterSnapshot& out, std::string& error) {
    auto invalid = [&]() {
        error = "IOCTL_ADAPTER_INFO returned an invalid snapshot";
        return false;
    };
    uint32_t required = 0;
    if (!DecodeAdapterInfoHeader(bytes, length, required, error) || length != required) return invalid();
    const uint32_t count = ReadU32(bytes + 8), running = ReadU32(bytes + 12);
    try {
        AdapterSnapshot snapshot;
        snapshot.running_count = running;
        snapshot.adapters.reserve(count);
        uint32_t observed_running = 0;
        for (uint32_t i = 0; i < count; ++i) {
            const uint8_t* p = bytes + kAdapterInfoHeaderSize + i * kAdapterInfoEntrySize;
            AdapterInfo a;
            a.module_id = ReadU64(p);
            a.interface_index = ReadU32(p + 8);
            a.filter_interface_index = ReadU32(p + 12);
            a.lower_interface_index = ReadU32(p + 16);
            a.flags = ReadU32(p + 20);
            a.interface_luid = ReadU64(p + 24);
            a.filter_interface_luid = ReadU64(p + 32);
            a.lower_interface_luid = ReadU64(p + 40);
            std::copy_n(p + 48, a.interface_guid.size(), a.interface_guid.begin());
            a.media_type = ReadU32(p + 64);
            a.physical_medium = ReadU32(p + 68);
            a.media_connect_state = ReadU32(p + 72);
            a.media_duplex_state = ReadU32(p + 76);
            a.xmit_link_speed = ReadU64(p + 80);
            a.rcv_link_speed = ReadU64(p + 88);
            a.mtu = ReadU32(p + 96);
            a.mac_options = ReadU32(p + 100);
            a.supported_packet_filters = ReadU32(p + 104);
            a.max_multicast_list_size = ReadU32(p + 108);
            a.max_xmit_link_speed = ReadU64(p + 112);
            a.max_rcv_link_speed = ReadU64(p + 120);
            a.lookahead_size = ReadU32(p + 128);
            a.access_type = ReadU32(p + 132);
            a.connection_type = ReadU32(p + 136);
            a.supported_statistics = ReadU32(p + 140);
            a.data_backfill_size = ReadU32(p + 144);
            a.context_backfill_size = ReadU32(p + 148);
            a.restart_flags = ReadU32(p + 152);
            a.attach_flags = ReadU32(p + 156);
            a.connector_present = ReadU32(p + 160);
            a.mac_address_length = ReadU32(p + 164);
            std::copy_n(p + 168, a.mac_address.size(), a.mac_address.begin());
            a.instance_name_length = ReadU32(p + 200);
            a.base_name_length = ReadU32(p + 204);
            a.filter_module_name_length = ReadU32(p + 208);
            a.auto_negotiation_flags = ReadU32(p + 212);
            a.pause_reason = ReadU32(p + 216);
            a.pause_flags = ReadU32(p + 220);
            if ((a.flags & ~0xffu) != 0 || a.mac_address_length > a.mac_address.size() ||
                a.connector_present > 1) return invalid();
            auto name = [&](size_t offset, uint32_t units, std::wstring& text) {
                if (units >= kAdapterNameCapacity || ReadU16(p + offset + 2 * units) != 0) return false;
                text.reserve(units);
                for (uint32_t j = 0; j < units; ++j) {
                    const uint16_t unit = ReadU16(p + offset + 2 * j);
                    if (unit == 0) return false;
                    text.push_back(static_cast<wchar_t>(unit));
                }
                return true;
            };
            if (!name(224, a.instance_name_length, a.instance_name) ||
                !name(736, a.base_name_length, a.base_name) ||
                !name(1248, a.filter_module_name_length, a.filter_module_name)) return invalid();
            if (a.flags & AdapterInfo::Running) ++observed_running;
            snapshot.adapters.push_back(std::move(a));
        }
        if (observed_running != running) return invalid();
        out = std::move(snapshot);
    } catch (const std::bad_alloc&) {
        error = "cannot allocate adapter information snapshot";
        return false;
    }
    error.clear();
    return true;
}

bool IsSupportedVerdict(uint8_t verdict) noexcept {
    return verdict >= static_cast<uint8_t>(Verdict::Accept) &&
           verdict <= static_cast<uint8_t>(Verdict::PermanentDrop);
}

bool ValidateCommands(const uint8_t* bytes, size_t length, std::string& error) {
    if (bytes == nullptr || length == 0 || length > kMaxCommandBatchSize) {
        error = "command batch must contain 1.." +
                std::to_string(kMaxCommandBatchSize) + " bytes";
        return false;
    }
    size_t offset = 0;
    while (offset < length) {
        size_t command_size = 0;
        switch (static_cast<CommandType>(bytes[offset])) {
            case CommandType::Shutdown:
            case CommandType::ClearCache:
            case CommandType::GetLogs:
            case CommandType::GetBandwidthStats:
            case CommandType::PrintMemoryStats:
            case CommandType::CleanEndedConnections:
                command_size = 1;
                break;
            case CommandType::Verdict: command_size = kVerdictCommandSize; break;
            case CommandType::UpdateV4:
            case CommandType::UpdateV6:
                error = "UpdateV4/UpdateV6 commands are not supported by HyperVXNdisFilter";
                return false;
            default:
                error = "unknown command byte " + std::to_string(bytes[offset]);
                return false;
        }
        if (command_size > length - offset) {
            error = "truncated fixed-size command";
            return false;
        }
        if (command_size > 1 && !IsSupportedVerdict(bytes[offset + command_size - 1])) {
            error = "unsupported verdict: HyperVXNdisFilter accepts only bytes 2..7 (no redirects)";
            return false;
        }
        offset += command_size;
    }
    error.clear();
    return true;
}

bool EncodeVerdict(uint64_t id, Verdict verdict,
                   std::array<uint8_t, kVerdictCommandSize>& out, std::string& error) {
    if (!IsSupportedVerdict(static_cast<uint8_t>(verdict))) {
        error = "unsupported verdict: HyperVXNdisFilter accepts only bytes 2..7 (no redirects)";
        return false;
    }
    out[0] = static_cast<uint8_t>(CommandType::Verdict);
    for (unsigned i = 0; i < 8; ++i) {
        out[1 + i] = static_cast<uint8_t>(id >> (i * 8));
    }
    out[9] = static_cast<uint8_t>(verdict);
    error.clear();
    return true;
}

bool DispatchRecord(const uint8_t* bytes, size_t length, const Handlers& handlers,
                    std::string& error) {
    if (bytes == nullptr || length < kRecordHeaderSize) {
        error = "record is shorter than its five-byte header";
        return false;
    }
    const size_t size = ReadU32(bytes + 1);
    if (size != length - kRecordHeaderSize) {
        error = "record header length disagrees with frame size";
        return false;
    }
    const auto type = static_cast<InfoType>(bytes[0]);
    const uint8_t* p = bytes + kRecordHeaderSize;
    switch (type) {
        case InfoType::LogLine: {
            if (length > kMaxLogRecordSize || size < 1 || p[0] < 1 || p[0] > 7) {
                error = "invalid LogLine severity, empty payload or record over 512 bytes";
                return false;
            }
            LogLine line;
            line.severity = static_cast<Severity>(p[0]);
            line.message.assign(reinterpret_cast<const char*>(p + 1), size - 1);
            if (handlers.on_log) handlers.on_log(line);
            break;
        }
        case InfoType::ConnectionIpv4:
        case InfoType::ConnectionIpv6: {
            const bool v6 = type == InfoType::ConnectionIpv6;
            const size_t addr_size = v6 ? 16 : 4;
            const size_t fixed = (v6 ? kConnectionIpv6PrefixSize : kConnectionIpv4PrefixSize) -
                                 kRecordHeaderSize;
            if (size < fixed) {
                error = "Connection record too short";
                return false;
            }
            Connection c;
            c.ipv6 = v6;
            size_t offset = 0;
            c.id = ReadU64(p + offset); offset += 8;
            c.interface_index = ReadU32(p + offset); offset += 4;
            c.direction = p[offset++];
            c.protocol = p[offset++];
            std::memcpy(c.local_ip, p + offset, addr_size); offset += addr_size;
            std::memcpy(c.remote_ip, p + offset, addr_size); offset += addr_size;
            c.local_port = ReadU16(p + offset); offset += 2;
            c.remote_port = ReadU16(p + offset); offset += 2;
            c.payload_layer = p[offset++];
            c.payload_size = ReadU32(p + offset); offset += 4;
            if (c.direction > 1 || c.payload_layer != 3) {
                error = "invalid HyperVXNdisFilter Connection metadata (expected outbound/inbound, IP payload)";
                return false;
            }
            if (c.payload_size > kMaxPayloadSize) {
                error = "Connection IP packet exceeds the 1 MiB payload limit";
                return false;
            }
            if (c.payload_size != size - offset) {
                error = "Connection captured payload length disagrees with record";
                return false;
            }
            c.payload.assign(p + offset, p + size);
            if (handlers.on_connection) handlers.on_connection(c);
            break;
        }
        // Decode only real compatibility records. The LWF never
        // generates END events or invents a teardown from a timeout/cache expiry.
        case InfoType::ConnectionEndEventV4:
        case InfoType::ConnectionEndEventV6: {
            const bool v6 = type == InfoType::ConnectionEndEventV6;
            const size_t addr_size = v6 ? 16 : 4;
            const size_t fixed = 8 + 1 + 1 + addr_size * 2 + 2 + 2;
            if (size != fixed) {
                error = "ConnectionEnd record has invalid length";
                return false;
            }
            ConnectionEnd e;
            e.ipv6 = v6;
            size_t offset = 0;
            e.process_id = ReadU64(p + offset); offset += 8;
            e.direction = p[offset++];
            e.protocol = p[offset++];
            std::memcpy(e.local_ip, p + offset, addr_size); offset += addr_size;
            std::memcpy(e.remote_ip, p + offset, addr_size); offset += addr_size;
            e.local_port = ReadU16(p + offset); offset += 2;
            e.remote_port = ReadU16(p + offset);
            if (e.process_id != 0 || e.direction > 1) {
                error = "invalid HyperVXNdisFilter ConnectionEnd metadata";
                return false;
            }
            if (handlers.on_connection_end) handlers.on_connection_end(e);
            break;
        }
        case InfoType::BandwidthStatsV4:
        case InfoType::BandwidthStatsV6: {
            const bool v6 = type == InfoType::BandwidthStatsV6;
            const size_t addr_size = v6 ? 16 : 4;
            const size_t entry_size = addr_size * 2 + 2 + 2 + 8 + 8;
            if (size < 9) {
                error = "Bandwidth record too short";
                return false;
            }
            const uint32_t interface_index = ReadU32(p + 1);
            const uint32_t count = ReadU32(p + 5);
            // Divide before multiplying: a hostile count must not overflow size_t.
            if (count != (size - 9) / entry_size || (size - 9) % entry_size != 0) {
                error = "Bandwidth entry count disagrees with payload";
                return false;
            }
            BandwidthStats stats;
            stats.protocol = p[0];
            stats.interface_index = interface_index;
            try {
                stats.entries.reserve(count);
            } catch (const std::bad_alloc&) {
                error = "not enough memory for bandwidth entries";
                return false;
            }
            size_t offset = 9;
            for (uint32_t i = 0; i < count; ++i) {
                BandwidthEntry e;
                e.ipv6 = v6;
                std::memcpy(e.local_ip, p + offset, addr_size); offset += addr_size;
                e.local_port = ReadU16(p + offset); offset += 2;
                std::memcpy(e.remote_ip, p + offset, addr_size); offset += addr_size;
                e.remote_port = ReadU16(p + offset); offset += 2;
                e.transmitted_bytes = ReadU64(p + offset); offset += 8;
                e.received_bytes = ReadU64(p + offset); offset += 8;
                stats.entries.push_back(e);
            }
            if (handlers.on_bandwidth) handlers.on_bandwidth(stats);
            break;
        }
        default:
            error = "unknown InfoType " + std::to_string(bytes[0]);
            return false;
    }
    error.clear();
    return true;
}

bool RecordStream::Feed(const uint8_t* bytes, size_t length, const Callback& callback,
                        std::string& error) {
    if (failed_) {
        error = "record stream is invalid after a malformed or oversized header";
        return false;
    }
    if (bytes == nullptr && length != 0) {
        error = "null record input";
        return false;
    }
    if (!record_) {
        error = "not enough memory for record stream";
        return false;
    }
    while (length != 0) {
        const size_t take = std::min(length, wanted_ - used_);
        std::memcpy(record_.get() + used_, bytes, take);
        used_ += take;
        bytes += take;
        length -= take;
        if (used_ < wanted_) continue;
        if (wanted_ == kRecordHeaderSize) {
            const uint32_t payload_size = ReadU32(record_.get() + 1);
            if (!ValidBodySize(record_[0], payload_size)) {
                failed_ = true;
                error = "driver record has an invalid type-specific length";
                return false;
            }
            wanted_ = kRecordHeaderSize + static_cast<size_t>(payload_size);
            if (wanted_ > capacity_) {
                std::unique_ptr<uint8_t[]> grown{new (std::nothrow) uint8_t[wanted_]};
                if (!grown) {
                    failed_ = true;
                    error = "not enough memory for bandwidth record";
                    return false;
                }
                std::memcpy(grown.get(), record_.get(), used_);
                record_ = std::move(grown);
                capacity_ = wanted_;
            }
            if (used_ < wanted_) continue;
        }
        const size_t complete = wanted_;
        used_ = 0;
        wanted_ = kRecordHeaderSize;
        if (callback) callback(record_.get(), complete);
    }
    error.clear();
    return true;
}

void RecordStream::Reset() noexcept {
    used_ = 0;
    wanted_ = kRecordHeaderSize;
    failed_ = false;
}

} // namespace pmkext::wire
