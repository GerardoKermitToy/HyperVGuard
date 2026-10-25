// Bounded, device-independent Portmaster wire codec used by the monitor/tests.
#pragma once

#include "PortmasterKext.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace pmkext::wire {

constexpr size_t kRecordHeaderSize = 5;
// Matches protocol/src/lib.rs. No length from a peer controls an unbounded allocation.
constexpr size_t kMaxRecordSize = 512;
constexpr size_t kMaxCommandBatchSize = 64 * 1024;
constexpr size_t kVerdictCommandSize = 10;

constexpr uint32_t MakeCtlCode(uint32_t function) {
    return (40000u << 16) | (3u << 14) | (function << 2);
}
constexpr uint32_t kIoctlVersion = MakeCtlCode(0x800);
constexpr uint32_t kIoctlShutdown = MakeCtlCode(0x801);

bool IsSupportedVerdict(uint8_t verdict) noexcept;
bool ValidateCommands(const uint8_t* bytes, size_t length, std::string& error);
bool EncodeVerdict(uint64_t id, Verdict verdict,
                   std::array<uint8_t, kVerdictCommandSize>& out, std::string& error);

// Exactly one [type][u32 LE length][payload] record. Invalid records are rejected
// before invoking event handlers. No END or bandwidth event is synthesized.
bool DispatchRecord(const uint8_t* bytes, size_t length, const Handlers& handlers,
                    std::string& error);

// Accept arbitrary read boundaries while keeping at most one 512-byte record.
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
    std::array<uint8_t, kMaxRecordSize> record_{};
    size_t used_ = 0;
    size_t wanted_ = kRecordHeaderSize;
    bool failed_ = false;
};

} // namespace pmkext::wire
