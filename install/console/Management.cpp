#include "Management.h"

#include <algorithm>
#include <cwchar>
#include <string_view>

namespace hyperv_xndis_filter::setup {
namespace {

void RequireFresh(System& system) {
    if (system.HasService() || system.HasComponent()) {
        throw Error{L"HyperVXNdisFilter is already installed or removal is pending. Stop the monitor and run Uninstall.exe first; a live driver is never replaced."};
    }
}

void RevalidateTarget(System& system, const Adapter& target) {
    if (!SameTarget(target, system.ResolveTarget())) {
        throw Error{L"The Default Switch host vNIC changed. No alternate adapter will be selected; uninstall and reinstall explicitly."};
    }
}

int NeedsReboot(System& system) {
    system.Print(L"A reboot is required. Target configuration remains disarmed. After reboot, run Install.exe --enable explicitly (or finish removal with Uninstall.exe).\n");
    return kRebootRequired;
}

int Enable(System& system, const Adapter& target) {
    ValidateBindings(system.ReadBindings(), target, false);
    RevalidateTarget(system, target);
    system.VerifyConfiguration(target);
    system.RequireMonitorStopped();
    system.DisarmIfPresent();
    if (system.DisableTarget(target) == Change::RebootRequired) return NeedsReboot(system);
    ValidateBindings(system.ReadBindings(), target, true);
    RevalidateTarget(system, target);
    system.VerifyConfiguration(target);
    system.AllowBindings();
    if (system.EnableTarget(target) == Change::RebootRequired) {
        system.DisarmIfPresent();
        return NeedsReboot(system);
    }
    ValidateBindings(system.ReadBindings(), target, false, true);
    RevalidateTarget(system, target);
    system.VerifyConfiguration(target);
    system.Print(L"HyperVXNdisFilter is enabled only on the exact Default Switch host vNIC.\n");
    return 0;
}

void Rollback(System& system, bool attempted_install) noexcept {
    try {
        system.DisarmIfPresent();
    } catch (const Error& error) {
        system.Print(L"WARNING: could not disarm configuration: " + error.message + L"\n");
    } catch (...) {
        system.Print(L"WARNING: could not disarm configuration.\n");
    }
    if (!attempted_install) return;
    system.Print(L"Installation failed; rolling back only this new HyperVXNdisFilter component.\n");
    try {
        if (system.RemoveComponent() == Change::RebootRequired) {
            system.Print(L"Rollback requires a reboot; configuration is retained disarmed.\n");
        } else if (system.HasComponent() || system.HasService()) {
            system.Print(L"WARNING: rollback is incomplete. Configuration is retained; use Uninstall.exe.\n");
        } else {
            system.DeleteConfiguration();
        }
    } catch (const Error& error) {
        system.Print(L"WARNING: rollback is incomplete: " + error.message + L". Use Uninstall.exe.\n");
    } catch (...) {
        system.Print(L"WARNING: rollback is incomplete. Use Uninstall.exe.\n");
    }
}

} // namespace

bool ParseOptions(Action executable, int argc, const wchar_t* const* argv,
                  Options& options, std::wstring& error) {
    options = {};
    options.action = executable;
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg(argv[i]);
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") options.help = true;
        else if (arg == L"--yes") options.yes = true;
        else if (arg == L"--what-if") options.what_if = true;
        else if (arg == L"--enable" && executable == Action::Install) options.action = Action::Enable;
        else if (arg == L"--package" && executable == Action::Install) {
            if (!options.package.empty() || i + 1 >= argc || argv[i + 1][0] == L'\0' ||
                std::wstring_view(argv[i + 1]).starts_with(L"--")) {
                error = L"--package requires one nonempty directory path";
                return false;
            }
            options.package = argv[++i];
        } else {
            error = L"unknown option or positional argument: " + std::wstring(arg) + L"; use --help";
            return false;
        }
    }
    if (options.action == Action::Enable && !options.package.empty()) {
        error = L"--enable uses the installed component, not --package";
        return false;
    }
    error.clear();
    return true;
}

std::wstring Usage(Action executable) {
    const bool uninstall = executable == Action::Uninstall;
    std::wstring result = uninstall
        ? L"Usage: Uninstall.exe [--yes] [--what-if]\n       Uninstall.exe --help\n\n"
        : L"Usage: Install.exe [--package DIRECTORY] [--yes] [--what-if]\n       Install.exe --enable [--yes] [--what-if]\n       Install.exe --help\n\n";
    result += uninstall
        ? L"Disarms and removes only the hyperv_xndis_filter NetCfg component.\nNo Default Switch, VM, HNS, NAT or unrelated binding is changed.\n"
        : L"Installs the optional NDIS LWF only on the Default Switch host vNIC.\nThe package directory defaults to the directory containing this EXE.\n--enable resumes an installed, disarmed component after a requested reboot;\nit never retargets stale GUID/NET_LUID configuration.\n";
    result += L"\nRun from an elevated Administrator/SYSTEM console; stop hyperv_monitor first.\nConfirmation is required unless --yes is supplied. --what-if performs read-only\npreflight without a write lock, registry writes, installation or binding changes.\n--help and invalid arguments do not access WMI, NetCfg, registry or the driver.\n\nExit codes: 0 success/dry run, 1 failure, 2 invalid arguments,\n1223 cancelled, 3010 reboot required (configuration retained disarmed).\nThe programs never open the driver device or create an SCM service manually.\n";
    return result;
}

bool ParseGuid(const std::wstring& text, GUID& guid) {
    if (text.size() != 36 && text.size() != 38) return false;
    if (text.size() == 38 && (text.front() != L'{' || text.back() != L'}')) return false;
    const std::wstring braced = text.size() == 36 ? L"{" + text + L"}" : text;
    return SUCCEEDED(CLSIDFromString(braced.c_str(), &guid)) && guid != GUID_NULL;
}

GUID InternalPortGuid(const std::wstring& device_id) {
    constexpr std::wstring_view prefix = L"Microsoft:";
    GUID guid{};
    if (!std::wstring_view(device_id).starts_with(prefix) ||
        !ParseGuid(device_id.substr(prefix.size()), guid)) {
        throw Error{L"The management-OS internal Ethernet port has no valid interface GUID."};
    }
    return guid;
}

Adapter SelectTarget(const std::vector<GUID>& switches, const std::vector<HostPort>& ports,
                     const std::vector<Adapter>& adapters) {
    if (std::count(switches.begin(), switches.end(), kDefaultSwitchId) != 1) {
        throw Error{L"The automatic Default Switch is missing or ambiguous. No name-based fallback is allowed."};
    }
    const HostPort* selected = nullptr;
    for (const auto& port : ports) {
        if (std::find(port.switches.begin(), port.switches.end(), kDefaultSwitchId) == port.switches.end()) continue;
        if (selected || port.switches.size() != 1) {
            throw Error{L"Expected one unambiguous management-OS vNIC connected to Default Switch."};
        }
        selected = &port;
    }
    if (!selected) throw Error{L"Expected one management-OS vNIC connected to Default Switch."};
    const GUID guid = InternalPortGuid(selected->device_id);
    const Adapter* target = nullptr;
    for (const auto& adapter : adapters) {
        if (adapter.guid != guid) continue;
        if (target) throw Error{L"The exact Default Switch host adapter is ambiguous."};
        target = &adapter;
    }
    if (!target) throw Error{L"The exact Default Switch host adapter was not found. No alternate adapter will be selected."};
    if (!target->is_virtual || target->hardware || target->interface_type != 6 || !target->luid) {
        throw Error{L"The target is not an Ethernet host vNIC with a valid NET_LUID."};
    }
    return *target;
}

bool SameTarget(const Adapter& first, const Adapter& second) {
    return first.guid == second.guid && first.luid == second.luid;
}

void ValidateBindings(const std::vector<Binding>& bindings, const Adapter& target,
                      bool all_disabled, bool require_enabled) {
    size_t targets = 0;
    for (const auto& binding : bindings) {
        if (binding.adapter == GUID_NULL) throw Error{L"An ambiguous HyperVXNdisFilter binding path was found."};
        if (binding.enabled && (all_disabled || binding.adapter != target.guid)) {
            throw Error{L"HyperVXNdisFilter has an unexpectedly enabled binding. No foreign adapter will be edited."};
        }
        if (binding.adapter == target.guid) {
            ++targets;
            if (require_enabled && !binding.enabled) throw Error{L"The exact target binding did not enable. No other binding will be tried."};
        }
    }
    // NetCfg can expose several paths to one adapter. Every path must terminate
    // at exactly one GUID; only paths to the same exact target may be enabled.
    if (!targets) throw Error{L"No HyperVXNdisFilter binding exists on the exact Default Switch host adapter."};
}

int Execute(const Options& options, System& system) {
    system.RequireAdministrator();
    if (options.action != Action::Uninstall) system.RequireSupportedOS();
    system.RequireMonitorStopped();
    Adapter target;
    if (options.action != Action::Uninstall) {
        target = system.ResolveTarget();
        if (options.action == Action::Install) {
            RequireFresh(system);
            system.ValidatePackage(options.package);
        } else {
            if (!system.HasComponent()) throw Error{L"HyperVXNdisFilter is not installed. Run Install.exe without --enable first."};
            system.VerifyConfiguration(target);
            ValidateBindings(system.ReadBindings(), target, false);
        }
        system.Print(L"Target only: " + target.name + L", NET_LUID=" + std::to_wstring(target.luid) + L"\n");
        system.Print(L"WARNING: this is the host-vNIC path, not all VM-to-VM traffic. Blocking verdicts can disconnect it.\n");
    }
    if (options.what_if) {
        system.Print(L"What-if: preflight completed. No system state was changed.\n");
        return 0;
    }
    const std::wstring operation = options.action == Action::Uninstall
        ? L"Disarm and uninstall ONLY HyperVXNdisFilter"
        : options.action == Action::Enable ? L"Enable ONLY the configured Default Switch host binding"
                                          : L"Install HyperVXNdisFilter and enable ONLY the Default Switch host binding";
    if (!options.yes && !system.Confirm(operation)) {
        system.Print(L"Cancelled. No system state was changed.\n");
        return ERROR_CANCELLED;
    }
    system.LockNetwork();
    system.RequireMonitorStopped();
    if (options.action == Action::Uninstall) {
        system.DisarmIfPresent();
        if (system.RemoveComponent() == Change::RebootRequired) return NeedsReboot(system);
        if (system.HasComponent() || system.HasService()) {
            throw Error{L"HyperVXNdisFilter removal is incomplete. Configuration remains disarmed; reboot if requested and run Uninstall.exe again."};
        }
        system.DeleteConfiguration();
        system.Print(L"HyperVXNdisFilter removed. No other component, switch, VM, HNS or NAT setting was changed.\n");
        return 0;
    }
    RevalidateTarget(system, target);
    if (options.action == Action::Enable) {
        if (!system.HasComponent()) throw Error{L"The installed HyperVXNdisFilter component disappeared."};
        try {
            return Enable(system, target);
        } catch (...) {
            Rollback(system, false);
            throw;
        }
    }
    RequireFresh(system);
    bool attempted_install = false;
    try {
        system.WriteDisarmedConfiguration(target);
        attempted_install = true;
        if (system.InstallComponent(options.package) == Change::RebootRequired) return NeedsReboot(system);
        ValidateBindings(system.ReadBindings(), target, false);
        return Enable(system, target);
    } catch (...) {
        Rollback(system, attempted_install);
        throw;
    }
}

} // namespace hyperv_xndis_filter::setup
