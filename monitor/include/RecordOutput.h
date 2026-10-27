#pragma once

#include "PortmasterKext.h"

#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace pmkext {

// Keep every part of a record under one lock, including the final flush.
class RecordOutput {
public:
    RecordOutput(FILE* output, std::mutex& mutex)
        : guard_(mutex), output_(output) {}

    ~RecordOutput() {
        if (output_ != nullptr) {
            std::fflush(output_);
        }
    }

    RecordOutput(const RecordOutput&) = delete;
    RecordOutput& operator=(const RecordOutput&) = delete;

    void Write(const char* format, ...) {
        va_list args;
        va_start(args, format);
        WriteV(format, args);
        va_end(args);
    }

    void WriteV(const char* format, va_list args) {
        if (output_ != nullptr) {
            std::vfprintf(output_, format, args);
        }
    }

    void WriteConnection(const Connection& c, const char* prefix) {
        Write("%s[CONN %s] id=%llu interface_index=%u %s proto=%u(%s) layer=%u(%s)\n"
              "          local(guest)=%s:%u  remote(peer)=%s:%u  payload=%u bytes\n",
              prefix, c.ipv6 ? "v6" : "v4", static_cast<unsigned long long>(c.id),
              static_cast<unsigned>(c.interface_index), DirectionToString(c.direction),
              static_cast<unsigned>(c.protocol), ProtocolToString(c.protocol),
              static_cast<unsigned>(c.payload_layer), PayloadLayerToString(c.payload_layer),
              c.LocalIpString().c_str(), static_cast<unsigned>(c.local_port),
              c.RemoteIpString().c_str(), static_cast<unsigned>(c.remote_port),
              static_cast<unsigned>(c.payload_size));
    }

private:
    std::lock_guard<std::mutex> guard_;
    FILE* output_;
};

} // namespace pmkext
