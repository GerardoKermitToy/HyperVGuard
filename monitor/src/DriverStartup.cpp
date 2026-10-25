#include "DriverStartup.h"

#include <windows.h>
#include <sddl.h>

namespace pmkext::monitor {
namespace {

class ReadyEvent {
public:
    ~ReadyEvent() {
        if (handle_ != nullptr) CloseHandle(handle_);
    }
    bool Create(const wchar_t* name, std::string& error) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) {
            error = "cannot create driver-ready event ACL: error " + std::to_string(GetLastError());
            return false;
        }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        handle_ = CreateEventExW(&security, name, CREATE_EVENT_MANUAL_RESET,
                                EVENT_MODIFY_STATE | SYNCHRONIZE);
        const DWORD status = GetLastError();
        LocalFree(descriptor);
        if (handle_ == nullptr) {
            error = "cannot create/open driver-ready event: error " + std::to_string(status);
            return false;
        }
        return true;
    }
    bool Reset(std::string& error) {
        if (ResetEvent(handle_)) return true;
        error = "cannot reset driver-ready event: error " + std::to_string(GetLastError());
        return false;
    }
    bool Wait(const std::atomic<bool>& stop_requested, std::string& error) {
        while (!stop_requested.load(std::memory_order_acquire)) {
            // Keep Ctrl+C responsive without handing a destructible handle to the
            // asynchronous console callback. Timeouts do not retry device opens.
            const DWORD status = WaitForSingleObject(handle_, 100);
            if (status == WAIT_OBJECT_0) return true;
            if (status == WAIT_TIMEOUT) continue;
            error = "driver-ready event wait failed: error " + std::to_string(GetLastError());
            return false;
        }
        return true;
    }
private:
    HANDLE handle_ = nullptr;
};

} // namespace

StartupResult OpenDriverWhenReady(
    const std::function<bool(std::string&)>& open_device,
    bool wait_for_driver,
    const std::atomic<bool>& stop_requested,
    const std::function<void(const std::string&)>& on_waiting,
    std::string& error,
    const wchar_t* event_name) {
    auto cancelled = [&]() {
        error.clear();
        return StartupResult::Cancelled;
    };
    if (stop_requested.load(std::memory_order_acquire)) return cancelled();
    if (open_device(error)) { error.clear(); return StartupResult::Opened; }
    if (!wait_for_driver) return StartupResult::Failed;

    ReadyEvent ready;
    if (!ready.Create(event_name, error)) return StartupResult::Failed;
    bool reported = false;
    for (;;) {
        if (stop_requested.load(std::memory_order_acquire)) return cancelled();
        // Clear BEFORE rechecking the device: a startup between the first open
        // and event creation/reset cannot be lost, nor can a stale signal spin.
        if (!ready.Reset(error)) return StartupResult::Failed;
        if (open_device(error)) { error.clear(); return StartupResult::Opened; }
        if (!reported && on_waiting) on_waiting(error);
        reported = true;
        if (!ready.Wait(stop_requested, error)) return StartupResult::Failed;
    }
}

} // namespace pmkext::monitor
