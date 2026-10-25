#include "DriverStartup.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return false; } } while (false)

namespace {

using pmkext::monitor::OpenDriverWhenReady;
using pmkext::monitor::StartupResult;

std::wstring UniqueName() {
    static unsigned sequence = 0;
    return L"Local\\HyperVGuard.StartupTests." + std::to_wstring(GetCurrentProcessId()) +
           L"." + std::to_wstring(++sequence);
}

class TestEvent {
public:
    TestEvent() : name(UniqueName()) {
        // A private local object owned by the test user: no elevation, global
        // production event, driver device, installation or network state needed.
        handle = CreateEventW(nullptr, TRUE, FALSE, name.c_str());
    }
    ~TestEvent() { Close(); }
    void Close() {
        if (handle != nullptr) { CloseHandle(handle); handle = nullptr; }
    }
    bool Signal() const { return SetEvent(handle) != FALSE; }
    bool IsSet() const { return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0; }
    std::wstring name;
    HANDLE handle = nullptr;
};

bool IsAbsent(const std::wstring& name) {
    HANDLE event = OpenEventW(SYNCHRONIZE, FALSE, name.c_str());
    if (event != nullptr) { CloseHandle(event); return false; }
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

bool TestDurationNeverWaits() {
    const auto name = UniqueName();
    std::atomic<bool> stop{false};
    unsigned attempts = 0, reports = 0;
    std::string error;
    const auto result = OpenDriverWhenReady([&](std::string& reason) {
        ++attempts; reason = "fake device unavailable"; return false;
    }, false, stop, [&](const std::string&) { ++reports; }, error, name.c_str());
    CHECK(result == StartupResult::Failed && attempts == 1 && reports == 0);
    CHECK(error == "fake device unavailable" && IsAbsent(name));
    // Even an existing signal must not be consumed/reset by a duration run.
    TestEvent event;
    CHECK(event.handle != nullptr && event.Signal());
    CHECK(OpenDriverWhenReady([](std::string&) { return false; }, false, stop,
        {}, error, event.name.c_str()) == StartupResult::Failed);
    CHECK(event.IsSet());
    return true;
}

bool TestAlreadyAvailable() {
    const auto name = UniqueName();
    std::atomic<bool> stop{false};
    unsigned attempts = 0, reports = 0;
    std::string error;
    CHECK(OpenDriverWhenReady([&](std::string&) { ++attempts; return true; }, true,
        stop, [&](const std::string&) { ++reports; }, error, name.c_str()) == StartupResult::Opened);
    CHECK(attempts == 1 && reports == 0 && IsAbsent(name));
    return true;
}

bool TestStartupBeforeEventOpen() {
    TestEvent event;
    CHECK(event.handle != nullptr);
    std::atomic<bool> stop{false};
    unsigned attempts = 0, reports = 0;
    bool signaled = false;
    std::string error;
    const auto result = OpenDriverWhenReady([&](std::string&) {
        if (++attempts == 1) {
            // Startup occurs after the failed first open, before CreateEventEx.
            signaled = event.Signal();
            return false;
        }
        return true;
    }, true, stop, [&](const std::string&) { ++reports; }, error, event.name.c_str());
    CHECK(result == StartupResult::Opened && attempts == 2 && reports == 0 && signaled);
    CHECK(!event.IsSet());
    event.Close();
    CHECK(IsAbsent(event.name)); // The helper released its handle as well.
    return true;
}

bool TestSignalBeforeWait() {
    TestEvent event;
    CHECK(event.handle != nullptr);
    std::atomic<bool> stop{false};
    unsigned attempts = 0, reports = 0;
    bool available = false, signaled = false;
    std::string error;
    const auto result = OpenDriverWhenReady([&](std::string& reason) {
        ++attempts; reason = "not ready"; return available;
    }, true, stop, [&](const std::string& reason) {
        ++reports;
        available = reason == "not ready";
        signaled = event.Signal();
    }, error, event.name.c_str());
    CHECK(result == StartupResult::Opened && attempts == 3 && reports == 1 && signaled);
    CHECK(!event.IsSet());
    return true;
}

bool TestSignalDuringWait() {
    TestEvent event;
    CHECK(event.handle != nullptr);
    std::atomic<bool> stop{false}, available{false}, signaled{false};
    unsigned attempts = 0;
    std::string error;
    std::jthread notifier;
    const auto result = OpenDriverWhenReady([&](std::string&) {
        ++attempts; return available.load();
    }, true, stop, [&](const std::string&) {
        notifier = std::jthread([&]() {
            Sleep(25);
            available.store(true);
            signaled.store(event.Signal());
        });
    }, error, event.name.c_str());
    notifier.join();
    CHECK(result == StartupResult::Opened && attempts == 3 && signaled.load());
    return true;
}

bool TestStaleSignal() {
    TestEvent event;
    CHECK(event.handle != nullptr && event.Signal());
    std::atomic<bool> stop{false};
    unsigned attempts = 0;
    bool reset_before_retry = false;
    std::string error = "old error";
    const auto result = OpenDriverWhenReady([&](std::string&) {
        if (++attempts == 2) reset_before_retry = !event.IsSet();
        return false;
    }, true, stop, [&](const std::string&) { stop.store(true); }, error, event.name.c_str());
    CHECK(result == StartupResult::Cancelled && attempts == 2 && reset_before_retry);
    CHECK(error.empty());
    return true;
}

bool TestRepeatedUnusableSignals() {
    TestEvent event;
    CHECK(event.handle != nullptr);
    std::atomic<bool> stop{false};
    unsigned attempts = 0, reports = 0;
    bool signals_ok = true;
    std::string error;
    const auto result = OpenDriverWhenReady([&](std::string&) {
        ++attempts;
        // A notification is never treated as successful device access.
        if (attempts == 3) signals_ok = event.Signal() && signals_ok;
        if (attempts == 4) stop.store(true);
        return false;
    }, true, stop, [&](const std::string&) {
        ++reports; signals_ok = event.Signal() && signals_ok;
    }, error, event.name.c_str());
    CHECK(result == StartupResult::Cancelled && attempts == 4 && reports == 1 && signals_ok);
    return true;
}

bool TestCancellationWithoutPollingDevice() {
    TestEvent event;
    CHECK(event.handle != nullptr);
    std::atomic<bool> stop{false};
    unsigned attempts = 0;
    std::string error;
    std::jthread canceller;
    const ULONGLONG started = GetTickCount64();
    const auto result = OpenDriverWhenReady([&](std::string&) {
        ++attempts; return false;
    }, true, stop, [&](const std::string&) {
        canceller = std::jthread([&]() { Sleep(250); stop.store(true); });
    }, error, event.name.c_str());
    canceller.join();
    CHECK(result == StartupResult::Cancelled && attempts == 2 && error.empty());
    CHECK(GetTickCount64() - started < 5000);
    event.Close();
    CHECK(IsAbsent(event.name));
    return true;
}

bool TestCancellationWinsSignal() {
    TestEvent event;
    CHECK(event.handle != nullptr);
    std::atomic<bool> stop{false};
    unsigned attempts = 0;
    bool signaled = false;
    std::string error;
    const auto result = OpenDriverWhenReady([&](std::string&) {
        ++attempts; return false;
    }, true, stop, [&](const std::string&) {
        signaled = event.Signal(); stop.store(true);
    }, error, event.name.c_str());
    CHECK(result == StartupResult::Cancelled && attempts == 2 && signaled);
    return true;
}

bool TestPrecancelledStartup() {
    const auto name = UniqueName();
    std::atomic<bool> stop{true};
    unsigned attempts = 0;
    std::string error = "old error";
    CHECK(OpenDriverWhenReady([&](std::string&) { ++attempts; return true; }, true,
        stop, {}, error, name.c_str()) == StartupResult::Cancelled);
    CHECK(attempts == 0 && error.empty() && IsAbsent(name));
    return true;
}

bool TestWrongObjectType() {
    const auto name = UniqueName();
    HANDLE mutex = CreateMutexW(nullptr, FALSE, name.c_str());
    CHECK(mutex != nullptr);
    std::atomic<bool> stop{false};
    unsigned attempts = 0;
    std::string error;
    const auto result = OpenDriverWhenReady([&](std::string&) {
        ++attempts; return false;
    }, true, stop, {}, error, name.c_str());
    CloseHandle(mutex);
    CHECK(result == StartupResult::Failed && attempts == 1);
    CHECK(error.find("cannot create/open driver-ready event") != std::string::npos);
    return true;
}

} // namespace

int main() {
    const struct { const char* name; bool (*run)(); } tests[] = {
        {"duration run never creates, resets or waits on readiness", TestDurationNeverWaits},
        {"available driver needs no event", TestAlreadyAvailable},
        {"startup before event open cannot be lost", TestStartupBeforeEventOpen},
        {"signal before waiting cannot be lost", TestSignalBeforeWait},
        {"signal wakes an existing wait", TestSignalDuringWait},
        {"stale signal is cleared before device retry", TestStaleSignal},
        {"unusable signals cannot bypass open or spin", TestRepeatedUnusableSignals},
        {"console cancellation is bounded without device polling", TestCancellationWithoutPollingDevice},
        {"console cancellation wins a simultaneous signal", TestCancellationWinsSignal},
        {"pre-cancelled startup has no side effects", TestPrecancelledStartup},
        {"named-object type collision fails safely", TestWrongObjectType},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
