#include "MonitorOptions.h"

#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return false; } } while (false)

namespace {

bool Parse(std::initializer_list<const wchar_t*> args, pmkext::monitor::Options& options,
           std::string& error) {
    std::vector<const wchar_t*> argv{L"hyperv_monitor.exe"};
    argv.insert(argv.end(), args.begin(), args.end());
    return pmkext::monitor::ParseOptions(static_cast<int>(argv.size()), argv.data(), options, error);
}

bool TestValidOptions() {
    pmkext::monitor::Options opt;
    std::string error;
    CHECK(Parse({L"--duration", L"1", L"--out", L"never-opened-by-parser.log", L"--poll", L"4294967295",
        L"--timestamps", L"--payload", L"--memory-stats", L"--filter-pid", L"0", L"--filter-protocol", L"17",
        L"--filter-ip", L"[2001:DB8::1]:53", L"--verdict", L"drop", L"--match", L"192.0.2.1:53",
        L"--verdict-delay-ms", L"4294967295"}, opt, error));
    CHECK(opt.duration_s == 1 && opt.poll_ms == 4294967295u && opt.verdict_delay_ms == 4294967295u);
    CHECK(opt.timestamps && opt.show_payload && opt.memory_stats && opt.has_filter_pid && opt.filter_pid == 0);
    CHECK(opt.has_filter_protocol && opt.filter_protocol == 17);
    CHECK(opt.filter.ip == "2001:0db8:0000:0000:0000:0000:0000:0001" && opt.filter.port == 53);
    CHECK(opt.match.ip == "192.0.2.1" && opt.match.port == 53 && opt.alt_verdict == pmkext::Verdict::Drop);
    for (const wchar_t* verdict : {L"accept", L"permanent-accept", L"block", L"permanent-block", L"drop", L"permanent-drop"}) {
        pmkext::monitor::Options one;
        CHECK(Parse({L"--duration", L"1", L"--verdict", verdict}, one, error));
        CHECK(one.has_alt && static_cast<uint8_t>(one.alt_verdict) >= 2 && static_cast<uint8_t>(one.alt_verdict) <= 7);
    }
    pmkext::monitor::Options help;
    CHECK(Parse({L"--help"}, help, error) && help.help && help.duration_s == 0);
    pmkext::monitor::Options compressed;
    CHECK(Parse({L"--duration", L"01", L"--match", L"::1", L"--verdict", L"accept", L"--filter-protocol", L"255",
                 L"--verdict-delay-ms", L"0", L"--no-verdicts", L"--only-logs"}, compressed, error));
    CHECK(compressed.match.ip == "0000:0000:0000:0000:0000:0000:0000:0001");
    CHECK(!compressed.match.has_port && !compressed.send_verdicts && !compressed.show_connections);
    return true;
}

bool TestInvalidNumbersAndEndpoints() {
    std::string error;
    for (const wchar_t* bad : {L"0", L"-1", L"+1", L"1.5", L"junk", L"4294967296", L"", L" 1", L"1x"}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", bad}, opt, error));
        opt = {};
        CHECK(!Parse({L"--duration", L"1", L"--poll", bad}, opt, error));
    }
    for (const wchar_t* bad : {L"-1", L"256", L"1x", L"18446744073709551616", L""}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", L"--filter-protocol", bad}, opt, error));
    }
    for (const wchar_t* bad : {L"1", L"4", L"-1", L"not-a-pid", L"18446744073709551616"}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", L"--filter-pid", bad}, opt, error));
    }
    for (const wchar_t* bad : {L"-1", L"1x", L"4294967296", L""}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", L"--verdict-delay-ms", bad}, opt, error));
    }
    for (const wchar_t* bad : {L"", L"localhost", L"192.0.2.1:", L"192.0.2.1:0", L"192.0.2.1:65536",
                              L"192.0.2.1:65537", L"192.0.2.1:-1", L"192.0.2.1:53junk", L"[::1", L"[::1]:",
                              L"[::1]garbage", L"[::1]:65536", L"::1%1"}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", L"--filter-ip", bad}, opt, error));
        opt = {};
        CHECK(!Parse({L"--duration", L"1", L"--verdict", L"accept", L"--match", bad}, opt, error));
    }
    for (const wchar_t* option : {L"--duration", L"--poll", L"--out", L"--filter-ip", L"--filter-pid",
                                 L"--filter-protocol", L"--verdict", L"--verdict-delay-ms", L"--match"}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", option}, opt, error));
    }
    return true;
}

bool TestRejectedCapabilities() {
    std::string error;
    for (const wchar_t* redirect : {L"redirect-tunnel", L"redirect-split", L"redirect-dns", L"redirect-name-server",
                                   L"redirect-split-tunnel", L"redirect", L"redirect-whatever"}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", L"--verdict", redirect}, opt, error));
        CHECK(error.find("redirect") != std::string::npos);
    }
    for (const wchar_t* unsupported : {L"--sys", L"driver.sys", L"--suspend-pid-on-verdict-delay",
                                      L"--no-inbound-udp-pid-fallback", L"--update-v4", L"--update-v6", L"--unknown"}) {
        pmkext::monitor::Options opt;
        CHECK(!Parse({L"--duration", L"1", unsupported}, opt, error));
    }
    pmkext::monitor::Options missing_duration;
    CHECK(!Parse({}, missing_duration, error));
    CHECK(error.find("positive --duration") != std::string::npos);
    pmkext::monitor::Options bare_match;
    CHECK(!Parse({L"--duration", L"1", L"--match", L"192.0.2.1"}, bare_match, error));
    return true;
}

bool TestFilterAndVerdictSeparation() {
    pmkext::monitor::Options opt;
    std::string error;
    CHECK(Parse({L"--duration", L"1", L"--verdict", L"block", L"--match", L"10.0.0.2:53",
                 L"--filter-ip", L"10.0.0.1:53", L"--filter-pid", L"0", L"--filter-protocol", L"17"}, opt, error));
    pmkext::Connection c;
    const uint8_t local[] = {10, 0, 0, 1};
    const uint8_t remote[] = {10, 0, 0, 2};
    std::memcpy(c.local_ip, local, 4);
    std::memcpy(c.remote_ip, remote, 4);
    c.local_port = 1234; c.remote_port = 53; c.protocol = 17;
    CHECK(pmkext::monitor::AlternateMatches(opt, c));
    // A local IP paired with a remote port is not an endpoint match.
    CHECK(!pmkext::monitor::ShowConnection(opt, c));
    c.local_port = 53;
    CHECK(pmkext::monitor::ShowConnection(opt, c));
    c.protocol = 6;
    CHECK(!pmkext::monitor::ShowConnection(opt, c));
    CHECK(pmkext::monitor::AlternateMatches(opt, c)); // Filter cannot alter verdict selection.
    c.protocol = 17; c.process_id = 1;
    CHECK(!pmkext::monitor::ShowConnection(opt, c));
    c.process_id = 0; c.remote_port = 80;
    CHECK(!pmkext::monitor::AlternateMatches(opt, c));
    opt.match = {};
    CHECK(pmkext::monitor::AlternateMatches(opt, c));
    return true;
}

} // namespace

int main() {
    const struct { const char* name; bool (*run)(); } tests[] = {
        {"valid monitor arguments without device access", TestValidOptions},
        {"strict numeric/endpoint validation", TestInvalidNumbersAndEndpoints},
        {"duration required, redirects/SCM/suspension/updates rejected", TestRejectedCapabilities},
        {"source/destination filters do not alter verdicts", TestFilterAndVerdictSeparation},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
