// Bounded, device-independent Portmaster wire codec used by the monitor/tests.
#pragma once

#include "PortmasterKext.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace pmkext::wire {

constexpr size_t kRecordHeaderSize = 5;
// Matches protocol/src/lib.rs. Connection prefixes include the record header;
// their payload is the complete logical IP packet, never a shortened capture.
constexpr size_t kConnectionIpv4PrefixSize = 32;
constexpr size_t kConnectionIpv6PrefixSize = 56;
constexpr size_t kMaxPayloadSize = 1024 * 1024;
constexpr size_t kMaxRecordSize = kConnectionIpv6PrefixSize + kMaxPayloadSize;
constexpr size_t kMaxLogRecordSize = 512;
constexpr size_t kMaxCommandBatchSize = 64 * 1024;
constexpr size_t kVerdictCommandSize = 10;
constexpr std::array<uint8_t, 4> kRequiredDeviceVersion = {0, 3, 1, 0};

bool IsCompatibleVersion(const uint8_t version[4]) noexcept;

constexpr uint32_t MakeCtlCode(uint32_t function) {
    return (40000u << 16) | (3u << 14) | (function << 2);
}
constexpr uint32_t kIoctlVersion = MakeCtlCode(0x800);
constexpr uint32_t kIoctlShutdown = MakeCtlCode(0x801);
constexpr uint32_t kIoctlFilteredDeviceCount = MakeCtlCode(0x802);

bool DecodeFilteredDeviceCount(const uint8_t* bytes, size_t length,
                               uint32_t& out, std::string& error);

bool IsSupportedVerdict(uint8_t verdict) noexcept;
bool ValidateCommands(const uint8_t* bytes, size_t length, std::string& error);
bool EncodeVerdict(uint64_t id, Verdict verdict,
                   std::array<uint8_t, kVerdictCommandSize>& out, std::string& error);

// Exactly one [type][u32 LE length][payload] record. Invalid records are rejected
// before invoking event handlers. No END or bandwidth event is synthesized.
bool DispatchRecord(const uint8_t* bytes, size_t length, const Handlers& handlers,
                    std::string& error);

// Accept arbitrary read boundaries while keeping at most one bounded record
// on the heap, including packets spanning many <=65536-byte device reads.
// Oversized headers permanently invalidate the stream: guessing a new boundary
// would turn arbitrary payload bytes into fabricated events.
class RecordStream {
public:
    using Callback = std::function<void(const uint8_t*, size_t)>;
    bool Feed(const uint8_t* bytes, size_t length, const Callback& callback,
              std::string& error);
    void Reset() noexcept;
    size_t PendingBytes() const noexcept { return used_; }

private:
    // A fixed bound, not a peer-selected allocation or a megabyte stack object.
    std::unique_ptr<uint8_t[]> record_ = std::make_unique<uint8_t[]>(kMaxRecordSize);
    size_t used_ = 0;
    size_t wanted_ = kRecordHeaderSize;
    bool failed_ = false;
};

} // namespace pmkext::wire
