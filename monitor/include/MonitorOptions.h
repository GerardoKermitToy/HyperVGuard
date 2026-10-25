#pragma once

#include "PortmasterKext.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace pmkext::monitor {

struct Endpoint {
    bool present = false;
    bool has_port = false;
    std::string ip;
    uint16_t port = 0;
};

struct Options {
    std::wstring out_path;
    unsigned duration_s = 0; // Omitted: wait for startup and run until Ctrl+C.
    unsigned poll_ms = 1000;
    unsigned verdict_delay_ms = 0;
    bool show_connections = true;
    bool show_ends = true;
    bool show_logs = true;
    bool show_bandwidth = true;
    bool timestamps = false;
    bool send_verdicts = true;
    bool show_payload = false;
    bool memory_stats = false;
    bool help = false;
    Verdict alt_verdict = Verdict::PermanentAccept;
    bool has_alt = false;
    Endpoint match;
    Endpoint filter;
    bool has_filter_protocol = false;
    uint8_t filter_protocol = 0;
};

// Pure argument validation: no device, SCM, singleton or output-file access.
bool ParseOptions(int argc, const wchar_t* const* argv, Options& options, std::string& error);
void PrintUsage(FILE* output = stdout);
bool MatchesEndpoint(const Endpoint& endpoint, const std::string& ip, uint16_t port);
bool ShowConnection(const Options& options, const Connection& connection);
bool AlternateMatches(const Options& options, const Connection& connection);

} // namespace pmkext::monitor
