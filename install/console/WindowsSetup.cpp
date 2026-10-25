#include "WindowsSupport.h"
#include "../notify/BindingPolicy.h"
#include "../notify/AdapterInventory.h"

#include <netcfgx.h>
#include <netcfgn.h>
#include <devguid.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <iostream>

namespace hyperv_guard::setup {
namespace {

constexpr wchar_t kServiceKey[] = L"SYSTEM\\CurrentControlSet\\Services\\HyperVGuard";

class Network {
public:
    explicit Network(bool writable) : writable_(writable) {
        try {
            Check(CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&config)), L"Create NetCfg session");
            if (writable_) {
                Check(config.As(&lock_), L"Get NetCfg write lock");
                CoString holder;
                const HRESULT result = lock_->AcquireWriteLock(15000, L"HyperVGuard console setup", &holder.value);
                if (result != S_OK) {
                    throw Error{L"NetCfg write lock is unavailable" +
                                (holder.value ? L" (held by " + std::wstring(holder.value) + L")" : std::wstring{}) +
                                L": " + ErrorCode(static_cast<DWORD>(result))};
                }
                locked_ = true;
            }
            Initialize();
        } catch (...) {
            Close();
            throw;
        }
    }
    ~Network() { Close(); }

    void Refresh(bool cancel = false) {
        if (cancel) Check(config->Cancel(), L"Discard pending HyperVGuard NetCfg changes");
        Check(config->Uninitialize(), L"Refresh NetCfg session");
        initialized_ = false;
        Initialize();
    }

    ComPtr<INetCfgComponent> Component() {
        ComPtr<INetCfgComponent> component;
        const HRESULT result = config->FindComponent(kComponentId, &component);
        Check(result, L"Find HyperVGuard component");
        if (result != S_OK && result != S_FALSE) throw Error{L"Unexpected NetCfg component lookup result."};
        return component;
    }

    ComPtr<INetCfg> config;
private:
    void Initialize() {
        Check(config->Initialize(nullptr), L"Initialize NetCfg session");
        initialized_ = true;
    }
    void Close() noexcept {
        if (initialized_) {
            if (writable_) config->Cancel();
            config->Uninitialize();
            initialized_ = false;
        }
        if (locked_) {
            lock_->ReleaseWriteLock();
            locked_ = false;
        }
    }
    ComPtr<INetCfgLock> lock_;
    bool writable_ = false;
    bool locked_ = false;
    bool initialized_ = false;
};

struct Path {
    Binding binding;
    ComPtr<INetCfgBindingPath> path;
};

std::vector<Path> Paths(Network& network) {
    auto component = network.Component();
    if (!component) throw Error{L"The HyperVGuard component is not installed."};
    GUID filter_instance{}, component_class{};
    Check(component->GetInstanceGuid(&filter_instance), L"Read HyperVGuard instance GUID");
    Check(component->GetClassGuid(&component_class), L"Read HyperVGuard component class");
    if (filter_instance != kFilterInstanceId || component_class != GUID_DEVCLASS_NETSERVICE) {
        throw Error{L"The installed component is not the expected HyperVGuard LWF instance."};
    }
    ComPtr<INetCfgComponentBindings> bindings;
    Check(component.As(&bindings), L"Get HyperVGuard bindings");
    ComPtr<IEnumNetCfgBindingPath> enumerator;
    Check(bindings->EnumBindingPaths(EBP_BELOW, &enumerator), L"Enumerate HyperVGuard binding paths");
    if (!enumerator) throw Error{L"Missing HyperVGuard binding path enumerator."};
    std::vector<GUID> adapter_instances;
    Check(ReadBindingAdapterInventory(network.config.Get(), adapter_instances), L"Read NetCfg/NETIO adapter inventory");
    std::vector<Path> paths;
    for (;;) {
        Path entry;
        ULONG fetched = 0;
        HRESULT result = enumerator->Next(1, &entry.path, &fetched);
        if (result == S_FALSE && fetched == 0 && !entry.path) break;
        Check(result, L"Read HyperVGuard binding path");
        if (result != S_OK || fetched != 1 || !entry.path || paths.size() == 4096) throw Error{L"Invalid or excessive NetCfg binding paths."};
        result = entry.path->IsEnabled();
        if (result != S_OK && result != S_FALSE) {
            Check(result, L"Read HyperVGuard binding state");
            throw Error{L"Unexpected HyperVGuard binding state."};
        }
        entry.binding.enabled = result == S_OK;
        BindingPathIdentity identity;
        BindingPathDiagnostic diagnostic;
        const HRESULT inspected = InspectBindingPath(entry.path.Get(), filter_instance, adapter_instances, identity, &diagnostic);
        const std::wstring context = L"Inspect binding path " + std::to_wstring(paths.size()) + L", interface " +
                                     std::to_wstring(diagnostic.interface_index) + L", " + diagnostic.operation +
                                     (entry.binding.enabled ? L", enabled" : L", disabled");
        if (FAILED(inspected)) {
            CoString token;
            if (entry.path->GetPathToken(&token.value) == S_OK && token.value) {
                WriteText(L"Binding path token: " + std::wstring(token.value) + L"\n");
            }
        }
        Check(inspected, context.c_str());
        if (!identity.owns_path || identity.adapters != 1 || identity.adapter == GUID_NULL) {
            throw Error{L"HyperVGuard binding path does not resolve to exactly one adapter. No binding will be guessed."};
        }
        entry.binding.adapter = identity.adapter;
        paths.push_back(std::move(entry));
    }
    return paths;
}

Change Applied(Network& network, HRESULT operation) {
    const HRESULT result = network.config->Apply();
    Check(result, L"Apply HyperVGuard NetCfg changes");
    const bool reboot = result == NETCFG_S_REBOOT || operation == NETCFG_S_REBOOT;
    network.Refresh();
    return reboot ? Change::RebootRequired : Change::Complete;
}

bool KeyExists(const wchar_t* path) {
    RegistryKey key;
    const LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key.value);
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return false;
    CheckWin32(result, L"Check HyperVGuard registry state");
    return true;
}

template<typename T>
T RegistryValue(const wchar_t* name, DWORD flags) {
    T value{};
    DWORD size = sizeof(value);
    CheckWin32(RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, name, flags | RRF_SUBKEY_WOW6464KEY,
                           nullptr, &value, &size), name);
    if (size != sizeof(value)) throw Error{L"Invalid target configuration value size."};
    return value;
}

class WindowsSystem final : public System {
public:
    WindowsSystem() {
        Check(CoInitializeEx(nullptr, COINIT_MULTITHREADED), L"Initialize COM");
        const HRESULT result = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                                    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                                    RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
        if (FAILED(result) && result != RPC_E_TOO_LATE) {
            CoUninitialize();
            Check(result, L"Initialize local COM security");
        }
    }
    ~WindowsSystem() override {
        network_.reset();
        files_.clear();
        CoUninitialize();
    }

    void RequireAdministrator() override {
        SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
        PSID administrators = nullptr;
        if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                      0, 0, 0, 0, 0, 0, &administrators)) {
            throw Error{L"Check administrator token: " + ErrorCode(GetLastError())};
        }
        BOOL member = FALSE;
        const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
        const DWORD error = GetLastError();
        FreeSid(administrators);
        if (!checked) throw Error{L"Check administrator membership: " + ErrorCode(error)};
        if (!member) throw Error{L"An elevated Administrator/SYSTEM console is required. --help needs no elevation."};
    }

    void RequireSupportedOS() override {
        SYSTEM_INFO information{};
        GetNativeSystemInfo(&information);
        if (information.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 || sizeof(void*) != 8) {
            throw Error{L"The package requires Windows x64."};
        }
        wchar_t build[32]{};
        DWORD size = sizeof(build);
        CheckWin32(RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                               L"CurrentBuildNumber", RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                               nullptr, build, &size), L"Read Windows build number");
        wchar_t* end = nullptr;
        const unsigned long value = wcstoul(build, &end, 10);
        if (end == build || *end != L'\0' || value < 25341) {
            throw Error{L"Driver-store NetCfg notify objects require Windows x64 build 25341 or later."};
        }
    }

    void RequireMonitorStopped() override {
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snapshot.get() == INVALID_HANDLE_VALUE) throw Error{L"Enumerate running processes: " + ErrorCode(GetLastError())};
        PROCESSENTRY32W process{};
        process.dwSize = sizeof(process);
        if (!Process32FirstW(snapshot.get(), &process)) throw Error{L"Read process list: " + ErrorCode(GetLastError())};
        do {
            if (_wcsicmp(process.szExeFile, L"hyperv_monitor.exe") == 0) {
                throw Error{L"Stop hyperv_monitor cleanly before changing the network component. No process will be terminated."};
            }
        } while (Process32NextW(snapshot.get(), &process));
        if (GetLastError() != ERROR_NO_MORE_FILES) throw Error{L"Read process list: " + ErrorCode(GetLastError())};
    }

    Adapter ResolveTarget() override { return ResolveWindowsTarget(); }
    bool HasService() override { return KeyExists(kServiceKey); }
    bool HasComponent() override {
        if (network_) return static_cast<bool>(network_->Component());
        Network readonly(false);
        return static_cast<bool>(readonly.Component());
    }

    void ValidatePackage(const std::filesystem::path& package) override {
        package_ = std::filesystem::canonical(package);
        files_ = LockAndVerifyPackage(package_);
        Print(L"Package signatures, catalog membership and target-restricted INF verified.\n");
    }

    void VerifyConfiguration(const Adapter& target) override {
        const DWORD version = RegistryValue<DWORD>(L"ConfigVersion", RRF_RT_REG_DWORD);
        const uint64_t luid = RegistryValue<uint64_t>(L"TargetNetLuid", RRF_RT_REG_QWORD);
        const DWORD allowed = RegistryValue<DWORD>(L"AllowBindings", RRF_RT_REG_DWORD);
        wchar_t text[39]{};
        DWORD size = sizeof(text);
        CheckWin32(RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, L"TargetInterfaceGuid",
                               RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, text, &size), L"Read configured target GUID");
        GUID guid{};
        if (version != 2 || allowed > 1 || size != sizeof(text) || text[38] != L'\0' ||
            !ParseGuid(text, guid) || guid != target.guid || luid != target.luid) {
            throw Error{L"Configured GUID/NET_LUID does not match the current Default Switch host vNIC. Uninstall and reinstall explicitly; no automatic retargeting is allowed."};
        }
    }

    bool Confirm(const std::wstring& action) override {
        Print(action + L"? [y/N] ");
        std::wstring answer;
        if (!std::getline(std::wcin, answer)) return false;
        return _wcsicmp(answer.c_str(), L"y") == 0 || _wcsicmp(answer.c_str(), L"yes") == 0;
    }
    void Print(const std::wstring& text) override { WriteText(text); }

    void LockNetwork() override { network_ = std::make_unique<Network>(true); }

    void WriteDisarmedConfiguration(const Adapter& target) override {
        RegistryKey key;
        CheckWin32(RegCreateKeyExW(HKEY_LOCAL_MACHINE, kConfigKey, 0, nullptr, 0,
                                  kDurableConfigAccess, nullptr, &key.value, nullptr), L"Create target configuration");
        const DWORD disarmed = 0, version = 2;
        CheckWin32(RegSetValueExW(key.value, L"AllowBindings", 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&disarmed), sizeof(disarmed)), L"Disarm bindings before installation");
        const auto guid = GuidText(target.guid);
        CheckWin32(RegSetValueExW(key.value, L"TargetInterfaceGuid", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(guid.c_str()),
                                 static_cast<DWORD>((guid.size() + 1) * sizeof(wchar_t))), L"Write target GUID");
        CheckWin32(RegSetValueExW(key.value, L"TargetNetLuid", 0, REG_QWORD,
                                 reinterpret_cast<const BYTE*>(&target.luid), sizeof(target.luid)), L"Write target NET_LUID");
        CheckWin32(RegSetValueExW(key.value, L"ConfigVersion", 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&version), sizeof(version)), L"Write target configuration version");
        CheckWin32(RegFlushKey(key.value), L"Persist disarmed target configuration");
    }

    void DisarmIfPresent() override {
        RegistryKey key;
        const LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kConfigKey, 0,
                                            kDurableConfigAccess, &key.value);
        if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return;
        CheckWin32(result, L"Open target configuration for disarm");
        const DWORD disarmed = 0;
        CheckWin32(RegSetValueExW(key.value, L"AllowBindings", 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&disarmed), sizeof(disarmed)), L"Disarm HyperVGuard bindings");
        CheckWin32(RegFlushKey(key.value), L"Persist disarmed target configuration");
    }

    void AllowBindings() override {
        RegistryKey key;
        CheckWin32(RegOpenKeyExW(HKEY_LOCAL_MACHINE, kConfigKey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key.value), L"Open target configuration for arming");
        const DWORD allowed = 1;
        CheckWin32(RegSetValueExW(key.value, L"AllowBindings", 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&allowed), sizeof(allowed)), L"Arm the exact target binding");
    }

    Change InstallComponent(const std::filesystem::path&) override {
        if (!network_ || files_.size() != 4) throw Error{L"Installation was not preflighted or locked."};
        if (!SetupCopyOEMInfW((package_ / L"HyperVGuard.inf").c_str(), package_.c_str(), SPOST_PATH,
                              0, nullptr, 0, nullptr, nullptr)) {
            throw Error{L"Stage the validated driver-store package: " + ErrorCode(GetLastError())};
        }
        ComPtr<INetCfgClassSetup> setup;
        Check(network_->config->QueryNetCfgClass(&GUID_DEVCLASS_NETSERVICE, IID_PPV_ARGS(&setup)), L"Get NetService setup class");
        OBO_TOKEN token{};
        token.Type = OBO_USER;
        ComPtr<INetCfgComponent> installed;
        const HRESULT result = setup->Install(kComponentId, &token, NSF_POSTSYSINSTALL, 0, nullptr, nullptr, &installed);
        Check(result, L"Install only hyperv_guard");
        if (!installed) throw Error{L"NetCfg did not return the installed HyperVGuard component."};
        installed.Reset();
        setup.Reset();
        return Applied(*network_, result);
    }

    Change RemoveComponent() override {
        if (!network_) throw Error{L"NetCfg write lock is required for removal."};
        // Discard a failed in-memory enable/install transaction before selecting
        // the persisted component. Never commit pending changes during rollback.
        network_->Refresh(true);
        auto component = network_->Component();
        if (!component) {
            if (HasService()) throw Error{L"HyperVGuard service remains without a NetCfg component; no SCM service will be forcibly deleted. Reboot/repair the old installation explicitly."};
            return Change::Complete;
        }
        GUID component_class{};
        Check(component->GetClassGuid(&component_class), L"Get HyperVGuard component class");
        ComPtr<INetCfgClassSetup> setup;
        Check(network_->config->QueryNetCfgClass(&component_class, IID_PPV_ARGS(&setup)), L"Get HyperVGuard removal class");
        OBO_TOKEN token{};
        token.Type = OBO_USER;
        CoString references;
        const HRESULT result = setup->DeInstall(component.Get(), &token, &references.value);
        Check(result, L"Uninstall only hyperv_guard");
        component.Reset();
        setup.Reset();
        return Applied(*network_, result);
    }

    std::vector<Binding> ReadBindings() override {
        std::unique_ptr<Network> readonly;
        if (!network_) readonly = std::make_unique<Network>(false);
        const auto paths = Paths(network_ ? *network_ : *readonly);
        std::vector<Binding> result;
        for (const auto& entry : paths) result.push_back(entry.binding);
        return result;
    }

    Change DisableTarget(const Adapter& target) override { return SetTargetBinding(target, false); }
    Change EnableTarget(const Adapter& target) override { return SetTargetBinding(target, true); }

    void DeleteConfiguration() override {
        const LSTATUS result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, kConfigKey);
        if (result != ERROR_FILE_NOT_FOUND && result != ERROR_PATH_NOT_FOUND) CheckWin32(result, L"Remove only HyperVGuard target configuration");
    }
private:
    Change SetTargetBinding(const Adapter& target, bool enabled) {
        if (!network_) throw Error{L"NetCfg write lock is required for binding changes."};
        auto paths = Paths(*network_);
        std::vector<Binding> bindings;
        for (const auto& entry : paths) bindings.push_back(entry.binding);
        ValidateBindings(bindings, target, false);
        HRESULT operation = S_OK;
        bool changed = false;
        for (auto& entry : paths) {
            if (entry.binding.adapter != target.guid || entry.binding.enabled == enabled) continue;
            const HRESULT result = entry.path->Enable(enabled ? TRUE : FALSE);
            Check(result, enabled ? L"Enable exact target binding path" : L"Disable exact target binding path before arming");
            changed = true;
            if (result == NETCFG_S_REBOOT) operation = result;
        }
        paths.clear();
        return changed ? Applied(*network_, operation) : Change::Complete;
    }

    std::unique_ptr<Network> network_;
    std::filesystem::path package_;
    std::vector<Handle> files_;
};

} // namespace

std::unique_ptr<System> CreateWindowsSystem() { return std::make_unique<WindowsSystem>(); }

std::filesystem::path ExecutableDirectory() {
    std::vector<wchar_t> path(32768);
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) throw Error{L"Find executable directory: " + ErrorCode(GetLastError())};
    return std::filesystem::path(std::wstring(path.data(), length)).parent_path();
}

void WriteText(const std::wstring& text, bool error) {
    const HANDLE output = GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    DWORD mode = 0, written = 0;
    if (GetConsoleMode(output, &mode)) {
        WriteConsoleW(output, text.c_str(), static_cast<DWORD>(text.size()), &written, nullptr);
    } else {
        const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (size <= 0) return;
        std::string utf8(static_cast<size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), size, nullptr, nullptr);
        WriteFile(output, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    }
}

} // namespace hyperv_guard::setup
