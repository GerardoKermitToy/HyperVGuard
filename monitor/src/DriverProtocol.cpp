#include "DriverProtocol.h"

#include <algorithm>
#include <cstring>

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

bool IsSupportedVerdict(uint8_t verdict) noexcept {
    return verdict >= static_cast<uint8_t>(Verdict::Accept) &&
           verdict <= static_cast<uint8_t>(Verdict::PermanentDrop);
}

bool ValidateCommands(const uint8_t* bytes, size_t length, std::string& error) {
    if (bytes == nullptr || length == 0 || length > kMaxCommandBatchSize) {
        error = "command batch must contain 1..65536 bytes";
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
    if (bytes == nullptr || length < kRecordHeaderSize || length > kMaxRecordSize) {
        error = "record length is outside the 5..1048632 byte limit";
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
            if (size < 5) {
                error = "Bandwidth record too short";
                return false;
            }
            const uint32_t count = ReadU32(p + 1);
            // Divide before multiplying: a hostile count must not overflow size_t.
            if (count != (size - 5) / entry_size || (size - 5) % entry_size != 0) {
                error = "Bandwidth entry count disagrees with payload";
                return false;
            }
            BandwidthStats stats;
            stats.protocol = p[0];
            stats.entries.reserve(count);
            size_t offset = 5;
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
        error = "record stream is invalid after an oversized header";
        return false;
    }
    if (bytes == nullptr && length != 0) {
        error = "null record input";
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
            if (payload_size > kMaxRecordSize - kRecordHeaderSize) {
                failed_ = true;
                error = "driver record exceeds the 1048632-byte protocol limit";
                return false;
            }
            wanted_ = kRecordHeaderSize + payload_size;
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
