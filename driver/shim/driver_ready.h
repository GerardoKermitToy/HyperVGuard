#pragma once

// Startup notification only; device access/version checks remain authoritative.
// Win32 Global maps to the kernel's session-independent BaseNamedObjects directory.
#define HV_READY_EVENT_USER_NAME L"Global\\HyperVGuard.DriverReady"
#define HV_READY_EVENT_KERNEL_NAME L"\\BaseNamedObjects\\HyperVGuard.DriverReady"
