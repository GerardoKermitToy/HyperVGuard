#pragma once

#include "../../driver/shim/driver_ready.h"

#include <atomic>
#include <functional>
#include <string>

namespace pmkext::monitor {

enum class StartupResult { Opened, Cancelled, Failed };

// The injected opener and alternate event name allow no-driver lifecycle tests.
// Duration-limited runs never create, reset or wait on the named event.
StartupResult OpenDriverWhenReady(
    const std::function<bool(std::string&)>& open_device,
    bool wait_for_driver,
    const std::atomic<bool>& stop_requested,
    const std::function<void(const std::string&)>& on_waiting,
    std::string& error,
    const wchar_t* event_name = HV_READY_EVENT_USER_NAME);

} // namespace pmkext::monitor
