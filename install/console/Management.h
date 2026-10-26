#pragma once
#include <windows.h>
#include <objbase.h>
#include <cguid.h>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace hyperv_xndis_filter::setup {

inline constexpr GUID kDefaultSwitchId = {0xc08cb7b8, 0x9b3c, 0x408e, {0x8e, 0x30, 0x5e, 0x16, 0xa3, 0xae, 0xb4, 0x44}};
inline constexpr int kRebootRequired = ERROR_SUCCESS_REBOOT_REQUIRED;
// Coherent driver-store package for the PID-free, full-packet, blocking-read 0.3.1.0 API.
inline constexpr wchar_t kPackageVersion[] = L"0.3.1.0";
inline constexpr wchar_t kDriverFileName[] = L"HyperVXNdisFilter.sys";
inline constexpr wchar_t kServiceName[] = L"HyperVXNdisFilter";

enum class Action { Install, Enable, Uninstall };
enum class Change { Complete, RebootRequired };

struct Error {
    std::wstring message;
};

struct Options {
    Action action = Action::Install;
    bool help = false;
    bool yes = false;
    bool what_if = false;
    std::filesystem::path package;
};

struct Adapter {
    GUID guid{};
    uint64_t luid = 0;
    std::wstring name;
    bool is_virtual = false;
    bool hardware = true;
    uint32_t interface_type = 0;
};

// Only Msvm_InternalEthernetPort instances may enter this list. Switch identity
// comes from connected LAN endpoints, never from a display name or port name.
struct HostPort {
    std::wstring device_id;
    std::vector<GUID> switches;
};

struct Binding {
    GUID adapter{};
    bool enabled = false;
};

bool ParseOptions(Action executable, int argc, const wchar_t* const* argv,
                  Options& options, std::wstring& error);
std::wstring Usage(Action executable);
bool ParseGuid(const std::wstring& text, GUID& guid);
GUID InternalPortGuid(const std::wstring& device_id);
Adapter SelectTarget(const std::vector<GUID>& switches, const std::vector<HostPort>& ports,
                     const std::vector<Adapter>& adapters);
bool SameTarget(const Adapter& first, const Adapter& second);
void ValidateBindings(const std::vector<Binding>& bindings, const Adapter& target,
                      bool all_disabled, bool require_enabled = false);

// The workflow is shared by the EXEs and a fake implementation in offline tests.
// Only the Windows implementation may touch WMI, NetCfg, files or registry state.
class System {
public:
    virtual ~System() = default;
    virtual void RequireAdministrator() = 0;
    virtual void RequireSupportedOS() = 0;
    virtual void RequireMonitorStopped() = 0;
    virtual Adapter ResolveTarget() = 0;
    virtual bool HasService() = 0;
    virtual bool HasComponent() = 0;
    virtual void ValidatePackage(const std::filesystem::path& package) = 0;
    virtual void VerifyConfiguration(const Adapter& target) = 0;
    virtual bool Confirm(const std::wstring& action) = 0;
    virtual void Print(const std::wstring& text) = 0;
    virtual void LockNetwork() = 0;
    virtual void WriteDisarmedConfiguration(const Adapter& target) = 0;
    virtual void DisarmIfPresent() = 0;
    virtual void AllowBindings() = 0;
    virtual void AllowRuntimeRecovery() = 0;
    virtual Change InstallComponent(const std::filesystem::path& package) = 0;
    virtual Change RemoveComponent() = 0;
    virtual std::vector<std::wstring> ReadDriverPackages() = 0;
    virtual Change RemoveDriverPackage(const std::wstring& published_inf) = 0;
    virtual std::vector<Binding> ReadBindings() = 0;
    virtual Change DisableTarget(const Adapter& target) = 0;
    virtual Change EnableTarget(const Adapter& target) = 0;
    virtual void DeleteConfiguration() = 0;
};

int Execute(const Options& options, System& system);
std::unique_ptr<System> CreateWindowsSystem();
std::filesystem::path ExecutableDirectory();
void WriteText(const std::wstring& text, bool error = false);

} // namespace hyperv_xndis_filter::setup
