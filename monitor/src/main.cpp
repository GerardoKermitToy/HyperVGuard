// HyperVGuard console monitor, adapted from kext_client on 2026-10-25 (see README.md/LICENSE).
// Interactive runs wait for driver startup; --duration runs never wait.
#include "PortmasterKext.h"
#include "DriverStartup.h"
#include "DelayedVerdicts.h"
#include "MonitorOptions.h"
#include "RecordOutput.h"

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <exception>
#include <memory>
#include <mutex>
#include <string>

namespace {

std::atomic<bool> g_shutdown_requested{false};
std::mutex g_print_mutex;
FILE* g_out = stdout;

void Emit(const char* format, ...) {
    pmkext::RecordOutput output(g_out, g_print_mutex);
    va_list args;
    va_start(args, format);
    output.WriteV(format, args);
    va_end(args);
}

std::string TimePrefix(bool enabled) {
    if (!enabled) return {};
    SYSTEMTIME time{};
    GetLocalTime(&time);
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u.%03u ",
                  time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
    return buffer;
}

// Independent name: the WFP monitor and this host-vNIC monitor may coexist. The
// protected object ACL prevents an unprivileged peer from joining the mutex.
class SingleInstanceGuard {
public:
    ~SingleInstanceGuard() {
        if (mutex_ != nullptr) {
            if (owned_) ReleaseMutex(mutex_);
            CloseHandle(mutex_);
        }
    }
    bool Acquire(std::string& error) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) {
            error = "cannot create singleton ACL: error " + std::to_string(GetLastError());
            return false;
        }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        mutex_ = CreateMutexW(&security, TRUE, L"Global\\HyperVGuardMonitor.Singleton");
        const DWORD status = GetLastError();
        LocalFree(descriptor);
        if (mutex_ == nullptr) {
            error = "CreateMutexW failed: error " + std::to_string(status);
            return false;
        }
        if (status != ERROR_ALREADY_EXISTS) {
            owned_ = true;
            return true;
        }
        const DWORD wait = WaitForSingleObject(mutex_, 0);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
            owned_ = true;
            return true;
        }
        error = wait == WAIT_TIMEOUT ? "another hyperv_monitor instance is already running"
                                     : "singleton wait failed: error " + std::to_string(GetLastError());
        return false;
    }
private:
    HANDLE mutex_ = nullptr;
    bool owned_ = false;
};

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        // Do not touch a possibly destructing Driver or lock output from this
        // asynchronous callback. The bounded control cadence performs shutdown.
        g_shutdown_requested.store(true, std::memory_order_release);
        return TRUE;
    }
    return FALSE;
}

class ConsoleRegistration {
public:
    ~ConsoleRegistration() {
        if (registered_) SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    }
    bool Register(std::string& error) {
        registered_ = SetConsoleCtrlHandler(ConsoleHandler, TRUE) != FALSE;
        if (!registered_) error = "cannot register console handler: error " + std::to_string(GetLastError());
        return registered_;
    }
private:
    bool registered_ = false;
};

class OutputFile {
public:
    ~OutputFile() {
        if (g_out != stdout) {
            std::fclose(g_out);
            g_out = stdout;
        }
    }
    bool Open(const std::wstring& path) {
        if (path.empty()) return true;
        g_out = _wfopen(path.c_str(), L"w");
        if (g_out == nullptr) {
            g_out = stdout;
            std::fprintf(stderr, "ERROR: cannot open output file for writing\n");
            return false;
        }
        std::wprintf(L"Writing records to %ls\n", path.c_str());
        return true;
    }
};

int MonitorMain(int argc, wchar_t** argv) {
    pmkext::monitor::Options opt;
    std::string error;
    if (!pmkext::monitor::ParseOptions(argc, argv, opt, error)) {
        std::fprintf(stderr, "ERROR: %s\n", error.c_str());
        return 2;
    }
    if (opt.help) {
        pmkext::monitor::PrintUsage();
        return 0;
    }
    // Everything above is device/service/output-file free.
    SingleInstanceGuard single_instance;
    if (!single_instance.Acquire(error)) {
        std::fprintf(stderr, "ERROR: %s. No device or service state was changed.\n", error.c_str());
        return 1;
    }
    ConsoleRegistration console_handler;
    if (!console_handler.Register(error)) {
        std::fprintf(stderr, "ERROR: %s\n", error.c_str());
        return 1;
    }
    OutputFile output;
    if (!output.Open(opt.out_path)) return 1;

    std::printf("Device name : HyperVGuard\n"
                "Opening explicitly installed host-adapter NDIS LWF (no SCM lifecycle).\n");
    pmkext::Driver driver;
    const auto startup = pmkext::monitor::OpenDriverWhenReady(
        [&](std::string& reason) { return driver.Open(reason); }, opt.duration_s == 0,
        g_shutdown_requested, [&](const std::string& reason) {
            std::printf("Device open failed: %s\n"
                        "Waiting for driver startup (Global\\HyperVGuard.DriverReady); Ctrl+C to exit.\n",
                        reason.c_str());
            std::fflush(stdout);
        }, error);
    if (startup == pmkext::monitor::StartupResult::Failed) {
        std::fprintf(stderr, "ERROR: open device failed: %s\n", error.c_str());
        return 1;
    }
    if (startup == pmkext::monitor::StartupResult::Cancelled || g_shutdown_requested.load()) {
        std::printf("Console stop requested during startup; exiting.\n");
        return 0;
    }

    uint8_t version[4]{};
    if (!driver.GetVersion(version, error)) {
        std::fprintf(stderr, "ERROR: could not read version: %s\n", error.c_str());
        return 1;
    }
    std::printf("Driver version: %u.%u.%u.%u\n", version[0], version[1], version[2], version[3]);
    if (version[0] != 0 || version[1] != 2 || version[2] != 1 || version[3] != 0) {
        std::fprintf(stderr, "ERROR: incompatible HyperVGuard driver version (expected 0.2.1.0)\n");
        return 1;
    }
    std::printf("CONN: one NBL decision, pid=0, direction=0 outbound/1 inbound from the guest side.\n"
                "Local=guest endpoint, remote=peer; host receive=outbound, host send=inbound; no process/thread identity. Payload is layer-3 IP.\n"
                "Permanent cache TTL: 60 s; pending timeout: 2 s by default, fail-open by default.\n"
                "Bandwidth: tx/rx=admitted guest outbound/inbound IP bytes, no PID; clean-ended only sweeps TTLs.\n"
                "No synthetic END events; UpdateV4/UpdateV6 and redirects are unsupported.\n");
    if (!opt.send_verdicts) {
        std::printf("NOT answering events (--no-verdicts); pending packets can wait until timeout.\n");
    } else if (opt.has_alt && opt.match.present) {
        std::printf("Answering remote endpoint %s%s with %s, everything else with PermanentAccept.\n",
                    opt.match.ip.c_str(),
                    opt.match.has_port ? (":" + std::to_string(opt.match.port)).c_str() : "",
                    pmkext::ToString(opt.alt_verdict));
    } else {
        std::printf("Answering EVERY event with %s.\n", pmkext::ToString(opt.alt_verdict));
        if (opt.has_alt && opt.alt_verdict != pmkext::Verdict::Accept &&
            opt.alt_verdict != pmkext::Verdict::PermanentAccept) {
            std::printf("WARNING: block/drop applies to all observed host-vNIC traffic and can cut remote access.\n");
        }
    }
    if (opt.send_verdicts && opt.verdict_delay_ms > 0) {
        std::printf("Delaying %s by %u ms (no PID suspension).\n",
                    opt.match.present ? "matching automatic verdicts" : "each automatic verdict",
                    opt.verdict_delay_ms);
        if (opt.verdict_delay_ms >= 2000) {
            std::printf("WARNING: delay reaches/exceeds the default pending timeout; verdicts may arrive too late.\n");
        }
    }
    if (opt.duration_s != 0) {
        std::printf("Running for %u second(s), then stopping the session (LWF remains installed).\n\n",
                    opt.duration_s);
    } else {
        std::printf("Running until Ctrl+C; stopping the session leaves the LWF installed.\n\n");
    }
    std::fflush(stdout);

    unsigned long long connections = 0;
    unsigned long long logs = 0;
    unsigned long long ends = 0;
    unsigned long long bandwidth_records = 0;
    std::atomic<unsigned long long> verdicts{0};
    std::atomic<bool> failed{false};
    auto guard_work = [&](auto&& work) {
        try {
            work();
        } catch (const std::exception& failure) {
            failed.store(true);
            g_shutdown_requested.store(true);
            Emit("[WARN] monitor processing failed; stopping: %s\n", failure.what());
            driver.Stop();
        } catch (...) {
            failed.store(true);
            g_shutdown_requested.store(true);
            Emit("[WARN] monitor processing failed; stopping (unknown exception)\n");
            driver.Stop();
        }
    };

    // Declare the queue after everything its queued callbacks capture, so its
    // destructor joins the sender first even when Run() unwinds with an error.
    std::unique_ptr<pmkext::DelayedVerdicts> delayed;
    if (opt.send_verdicts && opt.verdict_delay_ms > 0) {
        delayed = std::make_unique<pmkext::DelayedVerdicts>(opt.verdict_delay_ms);
    }
    pmkext::Handlers handlers;

    auto handle_connection = [&](const pmkext::Connection& c) {
        ++connections;
        const bool matched = pmkext::monitor::AlternateMatches(opt, c);
        const auto verdict = matched ? opt.alt_verdict : pmkext::Verdict::PermanentAccept;
        const bool show = pmkext::monitor::ShowConnection(opt, c);
        bool sent = false;
        bool queued = false;
        std::string verdict_error;
        if (opt.send_verdicts && c.id != 0 && !g_shutdown_requested.load()) {
            if (delayed && (!opt.match.present || matched)) {
                // Capture no payload/process state. Expired IDs are checked by
                // the driver; scheduling a verdict never extends its timeout.
                queued = delayed->Schedule([&, id = c.id, verdict, matched, show]() {
                    guard_work([&]() {
                        if (g_shutdown_requested.load()) return;
                        std::string send_error;
                        if (!driver.SendVerdict(id, verdict, send_error)) {
                            Emit("%s[WARN] id=%llu verdict %s FAILED: %s\n",
                                 TimePrefix(opt.timestamps).c_str(), static_cast<unsigned long long>(id),
                                 pmkext::ToString(verdict), send_error.c_str());
                            return;
                        }
                        ++verdicts;
                        if (show) Emit("%s[VERDICT] id=%llu -> verdict %s sent%s\n",
                            TimePrefix(opt.timestamps).c_str(), static_cast<unsigned long long>(id),
                            pmkext::ToString(verdict), (matched && opt.match.present) ? "  <== MATCHED" : "");
                    });
                });
                if (!queued) verdict_error = "delayed-verdict queue is stopping";
            } else {
                sent = driver.SendVerdict(c.id, verdict, verdict_error);
                if (sent) ++verdicts;
            }
        }
        // Output filtering must never withhold or change a verdict.
        if (!show) return;
        pmkext::RecordOutput record(g_out, g_print_mutex);
        record.Write("%s[CONN %s] id=%llu pid=0 %s proto=%u(%s) layer=%u(%s)\n"
                     "          local(guest)=%s:%u  remote(peer)=%s:%u  payload=%u bytes\n",
                     TimePrefix(opt.timestamps).c_str(), c.ipv6 ? "v6" : "v4",
                     static_cast<unsigned long long>(c.id), pmkext::DirectionToString(c.direction),
                     static_cast<unsigned>(c.protocol), pmkext::ProtocolToString(c.protocol),
                     static_cast<unsigned>(c.payload_layer), pmkext::PayloadLayerToString(c.payload_layer),
                     c.LocalIpString().c_str(), static_cast<unsigned>(c.local_port),
                     c.RemoteIpString().c_str(), static_cast<unsigned>(c.remote_port),
                     static_cast<unsigned>(c.payload_size));
        if (opt.show_payload) {
            record.Write("          payload: %s\n", c.payload.empty() ? "(none)" : c.PayloadHexString().c_str());
        }
        if (c.id == 0) record.Write("          (no pending packet, no verdict needed)\n");
        else if (!opt.send_verdicts) record.Write("          -> no verdict sent (--no-verdicts)\n");
        else if (queued) record.Write("          -> verdict %s scheduled after %u ms%s\n",
            pmkext::ToString(verdict), opt.verdict_delay_ms,
            (matched && opt.match.present) ? "  <== MATCHED" : "");
        else if (sent) record.Write("          -> verdict %s sent%s\n", pmkext::ToString(verdict),
            (matched && opt.match.present) ? "  <== MATCHED" : "");
        else if (g_shutdown_requested.load()) record.Write("          -> no verdict sent (stopping)\n");
        else record.Write("          -> verdict FAILED: %s\n", verdict_error.c_str());
    };
    handlers.on_connection = [&](const pmkext::Connection& c) {
        guard_work([&]() { handle_connection(c); });
    };
    handlers.on_log = [&](const pmkext::LogLine& line) {
        ++logs;
        if (opt.show_logs) Emit("%s[LOG %-5s] %s\n", TimePrefix(opt.timestamps).c_str(),
                               pmkext::ToString(line.severity), line.message.c_str());
    };
    // Compatibility handlers only consume records actually supplied by a driver.
    // This code never synthesizes END or bandwidth from NBL/verdict counters.
    handlers.on_connection_end = [&](const pmkext::ConnectionEnd& end) {
        ++ends;
        if (!opt.show_ends || (opt.has_filter_pid && opt.filter_pid != end.process_id) ||
            (opt.has_filter_protocol && opt.filter_protocol != end.protocol)) return;
        if (opt.filter.present &&
            !pmkext::monitor::MatchesEndpoint(opt.filter, end.LocalIpString(), end.local_port) &&
            !pmkext::monitor::MatchesEndpoint(opt.filter, end.RemoteIpString(), end.remote_port)) return;
        Emit("%s[END  %s] pid=0 %s proto=%u(%s) %s:%u -> %s:%u\n",
             TimePrefix(opt.timestamps).c_str(), end.ipv6 ? "v6" : "v4",
             pmkext::DirectionToString(end.direction), static_cast<unsigned>(end.protocol),
             pmkext::ProtocolToString(end.protocol), end.LocalIpString().c_str(), end.local_port,
             end.RemoteIpString().c_str(), end.remote_port);
    };
    handlers.on_bandwidth = [&](const pmkext::BandwidthStats& stats) {
        ++bandwidth_records;
        if (!opt.show_bandwidth || opt.has_filter_pid ||
            (opt.has_filter_protocol && opt.filter_protocol != stats.protocol)) return;
        auto keep = [&](const pmkext::BandwidthEntry& entry) {
            return !opt.filter.present ||
                pmkext::monitor::MatchesEndpoint(opt.filter, entry.LocalIpString(), entry.local_port) ||
                pmkext::monitor::MatchesEndpoint(opt.filter, entry.RemoteIpString(), entry.remote_port);
        };
        const size_t shown = static_cast<size_t>(std::count_if(stats.entries.begin(), stats.entries.end(), keep));
        if (opt.filter.present && shown == 0) return;
        pmkext::RecordOutput record(g_out, g_print_mutex);
        record.Write("%s[BANDWIDTH] proto=%u(%s) entries=%zu\n", TimePrefix(opt.timestamps).c_str(),
                     static_cast<unsigned>(stats.protocol), pmkext::ProtocolToString(stats.protocol), shown);
        for (const auto& entry : stats.entries) {
            if (!keep(entry)) continue;
            record.Write("            %s:%u <-> %s:%u  tx=%llu rx=%llu\n",
                         entry.LocalIpString().c_str(), entry.local_port, entry.RemoteIpString().c_str(),
                         entry.remote_port, static_cast<unsigned long long>(entry.transmitted_bytes),
                         static_cast<unsigned long long>(entry.received_bytes));
        }
    };
    handlers.on_warning = [&](const std::string& warning) {
        failed.store(true);
        Emit("%s[WARN] %s\n", TimePrefix(opt.timestamps).c_str(), warning.c_str());
    };

    const ULONGLONG started = GetTickCount64();
    const ULONGLONG deadline = started + static_cast<ULONGLONG>(opt.duration_s) * 1000;
    ULONGLONG next_poll = started;
    ULONGLONG next_cleanup = started + 30'000;
    auto poll = [&]() {
        const ULONGLONG now = GetTickCount64();
        const bool duration_elapsed = opt.duration_s != 0 && now >= deadline;
        if (g_shutdown_requested.load() || duration_elapsed) {
            Emit(duration_elapsed ? "\nDuration elapsed, stopping...\n" : "\nConsole stop requested, stopping...\n");
            g_shutdown_requested.store(true);
            driver.Stop();
            return;
        }
        if (now < next_poll) return;
        next_poll = now + opt.poll_ms;
        std::string command_error;
        if (now >= next_cleanup) {
            if (!driver.RequestCleanEndedConnections(command_error))
                Emit("[WARN] CleanEndedConnections failed: %s\n", command_error.c_str());
            next_cleanup = now + 30'000;
        }
        if (opt.memory_stats && !driver.RequestMemoryStats(command_error))
            Emit("[WARN] PrintMemoryStats failed: %s\n", command_error.c_str());
        if (!driver.RequestLogs(command_error))
            Emit("[WARN] GetLogs failed: %s\n", command_error.c_str());
        if (!driver.RequestBandwidthStats(command_error))
            Emit("[WARN] GetBandwidthStats failed: %s\n", command_error.c_str());
    };
    handlers.on_poll = [&]() { guard_work(poll); };
    // A long --poll must not turn a short --duration into an unbounded run.
    driver.Run(handlers, std::min(opt.poll_ms, 100u));
    g_shutdown_requested.store(true);
    if (delayed) delayed->Stop(); // Join sends before closing driver/output or reading counts.
    std::printf("\nShutting down.\nConnections (NBL events): %llu (verdicts sent: %llu), ends: %llu, "
                "log lines: %llu, bandwidth records: %llu\n",
                connections, verdicts.load(), ends, logs, bandwidth_records);
    driver.Cleanup();
    std::printf("Device closed; LWF remains installed/bound (no SCM changes).\n");
    return failed.load() ? 1 : 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        return MonitorMain(argc, argv);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "ERROR: %s\n", error.what());
    } catch (...) {
        std::fprintf(stderr, "ERROR: unexpected monitor failure\n");
    }
    return 1;
}
