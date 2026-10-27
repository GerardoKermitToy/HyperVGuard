#include "MonitorOptions.h"

#include <limits>
#include <string_view>
#include <utility>

namespace pmkext::monitor {
namespace {

bool ParseUnsigned(std::wstring_view text, uint64_t maximum, uint64_t& value) {
    if (text.empty()) return false;
    uint64_t result = 0;
    for (const wchar_t c : text) {
        if (c < L'0' || c > L'9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - L'0');
        if (digit > maximum || result > (maximum - digit) / 10) return false;
        result = result * 10 + digit;
    }
    value = result;
    return true;
}

bool ParseEndpoint(std::wstring_view text, Endpoint& endpoint, std::string& error) {
    std::wstring_view ip = text;
    std::wstring_view port;
    bool has_port = false;
    if (!text.empty() && text.front() == L'[') {
        const size_t close = text.find(L']');
        if (close == std::wstring_view::npos) {
            error = "unterminated IPv6 bracket";
            return false;
        }
        ip = text.substr(1, close - 1);
        if (close + 1 != text.size()) {
            if (text[close + 1] != L':') {
                error = "[IPv6] must be followed by :PORT or nothing";
                return false;
            }
            has_port = true;
            port = text.substr(close + 2);
        }
    } else if (text.find(L':') != std::wstring_view::npos &&
               text.find(L':') == text.find_last_of(L':')) {
        const size_t colon = text.find(L':');
        ip = text.substr(0, colon);
        has_port = true;
        port = text.substr(colon + 1);
    }
    // Multi-colon unbracketed IPv6 is always an address, never IP:PORT.
    if (ip.empty() || !NormalizeIpAddress(std::wstring(ip), endpoint.ip)) {
        error = "IP must be a valid IPv4 or IPv6 literal";
        return false;
    }
    uint64_t number = 0;
    if (has_port && (!ParseUnsigned(port, 65535, number) || number == 0)) {
        error = "port must be a decimal number from 1 to 65535";
        return false;
    }
    endpoint.present = true;
    endpoint.has_port = has_port;
    endpoint.port = static_cast<uint16_t>(number);
    return true;
}

} // namespace

bool ParseOptions(int argc, const wchar_t* const* argv, Options& opt, std::string& error) {
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg(argv[i]);
        auto next = [&](std::wstring_view& value) {
            if (i + 1 >= argc) {
                error = "option needs a value";
                return false;
            }
            value = argv[++i];
            return true;
        };
        auto number = [&](uint64_t maximum, uint64_t& value) {
            std::wstring_view text;
            return next(text) && ParseUnsigned(text, maximum, value);
        };
        if (arg == L"--help" || arg == L"-h") {
            opt.help = true;
        } else if (arg == L"--duration") {
            uint64_t value = 0;
            if (!number(std::numeric_limits<unsigned>::max(), value) || value == 0) {
                error = "--duration must be a positive decimal number of seconds (1..4294967295)";
                return false;
            }
            opt.duration_s = static_cast<unsigned>(value);
        } else if (arg == L"--poll") {
            uint64_t value = 0;
            if (!number(std::numeric_limits<unsigned>::max(), value) || value == 0) {
                error = "--poll must be a positive decimal number of milliseconds";
                return false;
            }
            opt.poll_ms = static_cast<unsigned>(value);
        } else if (arg == L"--verdict-delay-ms") {
            uint64_t value = 0;
            if (!number(std::numeric_limits<unsigned>::max(), value)) {
                error = "--verdict-delay-ms must be a number from 0 to 4294967295";
                return false;
            }
            opt.verdict_delay_ms = static_cast<unsigned>(value);
        } else if (arg == L"--out") {
            std::wstring_view path;
            if (!next(path) || path.empty()) {
                error = "--out needs a nonempty path";
                return false;
            }
            opt.out_path = path;
        } else if (arg == L"--timestamps") {
            opt.timestamps = true;
        } else if (arg == L"--payload") {
            opt.show_payload = true;
        } else if (arg == L"--memory-stats") {
            opt.memory_stats = true;
        } else if (arg == L"--only-logs") {
            opt.show_connections = opt.show_ends = opt.show_bandwidth = false;
        } else if (arg == L"--no-bandwidth") {
            opt.show_bandwidth = false;
        } else if (arg == L"--no-conn") {
            opt.show_connections = opt.show_ends = false;
        } else if (arg == L"--no-verdicts") {
            opt.send_verdicts = false;
        } else if (arg == L"--sys") {
            error = "--sys/automatic SCM installation is not supported; use dist/Install.exe and bind the LWF explicitly";
            return false;
        } else if (arg == L"--suspend-pid-on-verdict-delay") {
            error = "PID suspension is not supported: NDIS LWF events have no process owner";
            return false;
        } else if (arg == L"--no-inbound-udp-pid-fallback") {
            error = "PID fallback is not supported at the NDIS LWF layer (connection events have no process ID)";
            return false;
        } else if (arg == L"--verdict") {
            std::wstring_view verdict;
            if (!next(verdict)) {
                error = "--verdict needs a value";
                return false;
            }
            if (verdict == L"accept") opt.alt_verdict = Verdict::Accept;
            else if (verdict == L"permanent-accept") opt.alt_verdict = Verdict::PermanentAccept;
            else if (verdict == L"block") opt.alt_verdict = Verdict::Block;
            else if (verdict == L"permanent-block") opt.alt_verdict = Verdict::PermanentBlock;
            else if (verdict == L"drop") opt.alt_verdict = Verdict::Drop;
            else if (verdict == L"permanent-drop") opt.alt_verdict = Verdict::PermanentDrop;
            else if (verdict.starts_with(L"redirect")) {
                error = "redirect verdicts are not supported by HyperVXNdisFilter";
                return false;
            } else {
                error = "unknown verdict; use accept, permanent-accept, block, permanent-block, drop or permanent-drop";
                return false;
            }
            opt.has_alt = true;
        } else if (arg == L"--match" || arg == L"--filter-ip") {
            std::wstring_view value;
            if (!next(value)) {
                error = arg == L"--match" ? "--match needs IP or IP:PORT" : "--filter-ip needs IP or IP:PORT";
                return false;
            }
            Endpoint endpoint;
            if (!ParseEndpoint(value, endpoint, error)) {
                error = std::string(arg == L"--match" ? "--match: " : "--filter-ip: ") + error;
                return false;
            }
            (arg == L"--match" ? opt.match : opt.filter) = std::move(endpoint);
        } else if (arg == L"--filter-protocol") {
            uint64_t protocol = 0;
            if (!number(255, protocol)) {
                error = "--filter-protocol must be a number from 0 to 255";
                return false;
            }
            opt.has_filter_protocol = true;
            opt.filter_protocol = static_cast<uint8_t>(protocol);
        } else {
            error = "unknown option or positional driver path; use --help (automatic driver loading is not supported)";
            return false;
        }
    }
    if (opt.match.present && !opt.has_alt) {
        error = "--match given without --verdict";
        return false;
    }
    error.clear();
    return true;
}

bool MatchesEndpoint(const Endpoint& endpoint, const std::string& ip, uint16_t port) {
    return !endpoint.present ||
           (endpoint.ip == ip && (!endpoint.has_port || endpoint.port == port));
}

bool ShowConnection(const Options& opt, const Connection& c) {
    if (!opt.show_connections ||
        (opt.has_filter_protocol && opt.filter_protocol != c.protocol)) return false;
    // IP and optional port must belong to the SAME endpoint.
    return !opt.filter.present || MatchesEndpoint(opt.filter, c.LocalIpString(), c.local_port) ||
           MatchesEndpoint(opt.filter, c.RemoteIpString(), c.remote_port);
}

bool AlternateMatches(const Options& opt, const Connection& c) {
    return opt.has_alt && MatchesEndpoint(opt.match, c.RemoteIpString(), c.remote_port);
}

void PrintUsage(FILE* out) {
    std::fprintf(out,
        "Usage: hyperv_monitor.exe [--duration SECONDS] [options]\n"
        "       hyperv_monitor.exe --help\n\n"
        "Opens the existing \\\\.\\HyperVXNdisFilter device; never installs/starts/stops an SCM service.\n"
        "Install explicitly with dist/Install.exe for the host adapter\n"
        "vEthernet (Default Switch). Device access requires elevated admin/SYSTEM.\n"
        "Without --duration, wait for driver startup if open fails; Ctrl+C exits\n"
        "both the startup wait and monitoring. The monitor never loads the LWF.\n\n"
        "Collection:\n"
        "  --duration N     optional positive seconds; never wait for driver startup.\n"
        "                   Open failure exits immediately; otherwise stop after N s.\n"
        "                   This does not uninstall or unbind the LWF.\n"
        "  --out FILE       write records to FILE, flushed per record.\n"
        "  --poll N         query device count/logs/bandwidth every N ms (default 1000).\n"
        "  --timestamps     prefix records with local HH:MM:SS.mmm.\n"
        "  --payload        dump the complete IP packet as one hex string.\n"
        "  --memory-stats   request compatible memory-stat LogLine records each poll.\n\n"
        "Display filters (do not change verdicts):\n"
        "  --filter-ip IP[:PORT]  match local or remote; [IPv6]:PORT for IPv6.\n"
        "  --filter-protocol N    protocol number 0..255 (e.g. 1, 6, 17, 58).\n"
        "  --only-logs            suppress connection/end/bandwidth records.\n"
        "  --no-conn              suppress connection/end records.\n"
        "  --no-bandwidth         suppress bandwidth records.\n\n"
        "Verdicts:\n"
        "  --verdict V [--match IP[:PORT]]\n"
        "                   V: accept | permanent-accept | block | permanent-block\n"
        "                      | drop | permanent-drop. Redirects are NOT supported.\n"
        "                   --match tests the remote endpoint in BOTH directions.\n"
        "                   Unmatched events get PermanentAccept. Without --match,\n"
        "                   V applies to EVERY event. Default: PermanentAccept.\n"
        "                   TCP/UDP cache only: IPv4/IPv6 tables per interface; key=IP+port.\n"
        "                   TCP/UDP and both directions share matching normalized tuples.\n"
        "                   Default cache TTL: 60 s; TCP/UDP PermanentAccept refreshes\n"
        "                   on matching cache hits; PermanentBlock/Drop keep a fixed TTL.\n"
        "  --no-verdicts    do not answer events (pending timeout defaults to 2 s;\n"
        "                   driver is fail-open by default, not indefinitely stalled).\n"
        "  --verdict-delay-ms N  delay automatic verdicts by N ms (0..4294967295);\n"
        "                   only matching events if --match is used. Unsent verdicts\n"
        "                   are discarded on stop. No PID suspension is performed.\n"
        "                   Delays >= 2000 ms can expire before a decision is sent.\n\n"
        "Semantics:\n"
        "  CONN is one event/verdict per NBL, not a process-owned socket.\n"
        "  direction=0 outbound, 1 inbound relative to the guest side;\n"
        "  local=guest endpoint, remote=peer. Host receive=outbound, send=inbound.\n"
        "  Connection events carry no process/thread identity.\n"
        "  payload_layer=3 is the complete logical IP packet (up to 1 MiB, no truncation).\n"
        "  Mixed/unsupported batches are dropped rather than misreported.\n"
        "  Bandwidth: admitted IP bytes, tx=outbound, rx=inbound; no PID.\n"
        "  CleanEndedConnections sweeps TTLs; no END is fabricated on expiry/timeout.\n"
        "  UpdateV4/UpdateV6 commands and redirect verdicts are unsupported.\n"
        "  Block/drop for all events can cut host-vNIC traffic and remote access.\n"
        "  --sys, positional .sys paths and PID-suspension options are rejected.\n\n"
        "Examples:\n"
        "  hyperv_monitor.exe\n"
        "  hyperv_monitor.exe --duration 10 --only-logs\n"
        "  hyperv_monitor.exe --duration 30 --out run.log --timestamps --payload\n"
        "  hyperv_monitor.exe --duration 30 --filter-protocol 17\n"
        "  hyperv_monitor.exe --duration 30 --verdict block --match 192.0.2.10:53\n");
}

} // namespace pmkext::monitor
