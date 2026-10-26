#include "Management.h"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <utility>

using namespace hyperv_xndis_filter::setup;
namespace {

void Require(bool value, const char* message = "assertion failed") {
    if (!value) throw std::runtime_error(message);
}

template<typename F>
void Throws(F&& action, const wchar_t* text) {
    try { action(); }
    catch (const Error& error) {
        Require(error.message.find(text) != std::wstring::npos, "unexpected error message");
        return;
    }
    throw std::runtime_error("expected failure");
}

GUID Guid(const wchar_t* text) {
    GUID result{};
    Require(ParseGuid(text, result));
    return result;
}

const GUID target_guid = Guid(L"{9EB6CA05-3905-4420-A34F-4FA09DCC6A2D}");
const GUID foreign_guid = Guid(L"{00000001-0002-0003-0405-060708090A0B}");

Adapter Target() { return {target_guid, 1689399750295552ull, L"Renamed host vNIC", true, false, 6}; }

class FakeSystem final : public System {
public:
    Adapter target = Target();
    Adapter configured = target;
    std::vector<Binding> bindings;
    std::vector<std::string> calls;
    std::vector<std::wstring> messages;
    std::string fail;
    size_t fail_on_occurrence = 1;
    bool appear_after_confirm = false, remove_fails = false;
    bool service = false, component = false, config = false, allowed = false;
    bool consent = true, foreign_enabled = false, target_enabled_on_install = false;
    bool change_luid_after_install = false, change_target_after_confirm = false;
    bool enable_has_effect = true, disable_has_effect = true, leave_service = false;
    Change install_result = Change::Complete, remove_result = Change::Complete, enable_result = Change::Complete, disable_result = Change::Complete;

    void Step(const char* name) {
        calls.emplace_back(name);
        if (fail == name && static_cast<size_t>(std::count(calls.begin(), calls.end(), name)) == fail_on_occurrence) {
            throw Error{L"injected failure"};
        }
    }
    void RequireAdministrator() override { Step("admin"); }
    void RequireSupportedOS() override { Step("os"); }
    void RequireMonitorStopped() override { Step("monitor"); }
    Adapter ResolveTarget() override {
        Step("resolve");
        return target;
    }
    bool HasService() override { Step("service"); return service; }
    bool HasComponent() override { Step("component"); return component; }
    void ValidatePackage(const std::filesystem::path&) override { Step("package"); }
    void VerifyConfiguration(const Adapter& adapter) override {
        Step("verify-config");
        if (!config || !SameTarget(configured, adapter)) throw Error{L"stale configuration"};
    }
    bool Confirm(const std::wstring&) override {
        Step("confirm");
        if (change_target_after_confirm) target.guid = foreign_guid;
        if (appear_after_confirm) service = component = true;
        return consent;
    }
    void Print(const std::wstring& text) override { messages.push_back(text); }
    void LockNetwork() override { Step("lock"); }
    void WriteDisarmedConfiguration(const Adapter& adapter) override {
        config = true;
        allowed = false;
        configured = adapter;
        Step("write-disarmed");
    }
    void DisarmIfPresent() override { Step("disarm"); if (config) allowed = false; }
    void AllowBindings() override { allowed = true; Step("arm"); }
    Change InstallComponent(const std::filesystem::path&) override {
        Require(config && !allowed, "NetCfg must never install armed");
        component = service = true;
        bindings = {{target.guid, target_enabled_on_install}, {foreign_guid, foreign_enabled}};
        if (change_luid_after_install) ++target.luid;
        Step("install");
        return install_result;
    }
    Change RemoveComponent() override {
        Require(!allowed, "removal must follow disarm");
        Step("remove");
        if (remove_fails) throw Error{L"rollback removal failure"};
        if (remove_result == Change::Complete) {
            component = false;
            service = leave_service;
            bindings.clear();
        }
        return remove_result;
    }
    std::vector<Binding> ReadBindings() override { Step("bindings"); return bindings; }
    Change DisableTarget(const Adapter& adapter) override {
        Require(config && !allowed && SameTarget(configured, adapter), "disable must follow exact config validation and disarm");
        Step("disable");
        if (disable_has_effect) {
            for (auto& binding : bindings) if (binding.adapter == adapter.guid) binding.enabled = false;
        }
        return disable_result;
    }
    Change EnableTarget(const Adapter& adapter) override {
        Require(allowed && config && SameTarget(configured, adapter), "enable must follow exact config validation and arming");
        Step("enable");
        if (enable_has_effect) {
            for (auto& binding : bindings) if (binding.adapter == adapter.guid) binding.enabled = true;
        }
        return enable_result;
    }
    void DeleteConfiguration() override { Step("delete-config"); config = allowed = false; }

    bool Called(const char* name) const { return std::find(calls.begin(), calls.end(), name) != calls.end(); }
    size_t At(const char* name) const {
        const auto found = std::find(calls.begin(), calls.end(), name);
        Require(found != calls.end(), "missing expected operation");
        return static_cast<size_t>(found - calls.begin());
    }
    void RequireNoMutation() const {
        for (const auto name : {"lock", "write-disarmed", "disarm", "arm", "install", "disable", "enable", "remove", "delete-config"}) {
            Require(!Called(name), "unexpected mutation in read-only path");
        }
    }
    void Installed() {
        service = component = config = true;
        configured = target;
        bindings = {{target.guid, false}, {foreign_guid, false}};
    }
};

Options Install() { Options options; options.package = L"offline-package"; return options; }
Options Uninstall() { Options options; options.action = Action::Uninstall; return options; }
Options Enable() { Options options; options.action = Action::Enable; return options; }

struct Case { const char* name; std::function<void()> test; };

} // namespace

int main() {
    const std::vector<Case> cases = {
        {"CLI help/defaults and explicit modes", [] {
            Options options;
            std::wstring error;
            const wchar_t* help[] = {L"Install.exe", L"--help"};
            Require(ParseOptions(Action::Install, 2, help, options, error) && options.help);
            Require(Usage(Action::Install).find(L"--what-if") != std::wstring::npos);
            const wchar_t* args[] = {L"Install.exe", L"--enable", L"--yes", L"--what-if"};
            Require(ParseOptions(Action::Install, 4, args, options, error));
            Require(options.action == Action::Enable && options.yes && options.what_if);
            const wchar_t* package[] = {L"Install.exe", L"--package", L"C:\\package with spaces"};
            Require(ParseOptions(Action::Install, 3, package, options, error));
            Require(options.package == package[2]);
            Require(ParseOptions(Action::Uninstall, 1, package, options, error) && options.action == Action::Uninstall);
        }},
        {"CLI rejects unsupported, missing and conflicting arguments", [] {
            for (const auto arg : {L"--unknown", L"--sys", L"x.sys", L"--package"}) {
                const wchar_t* args[] = {L"Install.exe", arg}; Options opt; std::wstring error;
                Require(!ParseOptions(Action::Install, 2, args, opt, error));
            }
            for (const auto arg : {L"--enable", L"--package", L"x.sys"}) {
                const wchar_t* args[] = {L"Uninstall.exe", arg}; Options opt; std::wstring error;
                Require(!ParseOptions(Action::Uninstall, 2, args, opt, error));
            }
            const wchar_t* conflict[] = {L"Install.exe", L"--package", L"directory", L"--enable"};
            Options opt; std::wstring error;
            Require(!ParseOptions(Action::Install, 4, conflict, opt, error));
            const wchar_t* empty[] = {L"Install.exe", L"--package", L""};
            Require(!ParseOptions(Action::Install, 3, empty, opt, error));
            const wchar_t* dup[] = {L"Install.exe", L"--package", L"a", L"--package", L"b"};
            Require(!ParseOptions(Action::Install, 5, dup, opt, error));
        }},
        {"target resolution uses switch connections and GUID, never alias", [] {
            const HostPort port{L"Microsoft:{9EB6CA05-3905-4420-A34F-4FA09DCC6A2D}", {kDefaultSwitchId}};
            auto target = Target();
            const auto selected = SelectTarget({kDefaultSwitchId}, {port}, {target});
            Require(SameTarget(selected, target));
            target.name = L"a localized alias";
            Require(SelectTarget({kDefaultSwitchId}, {port}, {target}).name == target.name);
            Throws([&] { SelectTarget({}, {port}, {target}); }, L"missing or ambiguous");
            Throws([&] { SelectTarget({kDefaultSwitchId, kDefaultSwitchId}, {port}, {target}); }, L"missing or ambiguous");
            Throws([&] { SelectTarget({kDefaultSwitchId}, {port, port}, {target}); }, L"unambiguous");
            Throws([&] { SelectTarget({kDefaultSwitchId}, {}, {target}); }, L"management-OS");
            Throws([&] { SelectTarget({kDefaultSwitchId}, {{port.device_id, {foreign_guid}}}, {target}); }, L"management-OS");
            Throws([&] { SelectTarget({kDefaultSwitchId}, {{port.device_id, {kDefaultSwitchId, foreign_guid}}}, {target}); }, L"unambiguous");
            Throws([&] { SelectTarget({kDefaultSwitchId}, {port}, {}); }, L"not found");
            Throws([&] { SelectTarget({kDefaultSwitchId}, {port}, {target, target}); }, L"ambiguous");
            target.guid = foreign_guid;
            target.name = L"vEthernet (Default Switch)";
            Throws([&] { SelectTarget({kDefaultSwitchId}, {port}, {target}); }, L"not found");
        }},
        {"invalid port GUIDs and non-host Ethernet adapters are rejected", [] {
            for (const auto text : {L"not-a-guid", L"Microsoft:not-a-guid", L"Microsoft:{00000000-0000-0000-0000-000000000000}", L"{9EB6CA05-3905-4420-A34F-4FA09DCC6A2D}"}) {
                Throws([&] { InternalPortGuid(text); }, L"valid interface GUID");
            }
            const HostPort port{L"Microsoft:{9EB6CA05-3905-4420-A34F-4FA09DCC6A2D}", {kDefaultSwitchId}};
            for (int condition = 0; condition != 4; ++condition) {
                auto target = Target();
                if (condition == 0) target.is_virtual = false;
                if (condition == 1) target.hardware = true;
                if (condition == 2) target.interface_type = 71;
                if (condition == 3) target.luid = 0;
                Throws([&] { SelectTarget({kDefaultSwitchId}, {port}, {target}); }, L"Ethernet host vNIC");
            }
        }},
        {"all exact target paths are required; foreign enabled paths are rejected", [] {
            const auto target = Target();
            ValidateBindings({{target.guid, false}, {target.guid, false}, {foreign_guid, false}}, target, true);
            ValidateBindings({{target.guid, true}, {target.guid, true}, {foreign_guid, false}}, target, false, true);
            Throws([&] { ValidateBindings({{target.guid, true}}, target, true); }, L"unexpectedly enabled");
            Throws([&] { ValidateBindings({{target.guid, true}, {foreign_guid, true}}, target, false); }, L"unexpectedly enabled");
            Throws([&] { ValidateBindings({{target.guid, true}, {target.guid, false}}, target, false, true); }, L"did not enable");
            Throws([&] { ValidateBindings({{foreign_guid, false}}, target, false); }, L"No HyperVXNdisFilter binding");
            Throws([&] { ValidateBindings({{GUID_NULL, false}}, target, false); }, L"ambiguous");
        }},
        {"fresh install orders validation, disarm, NetCfg, arm and exact enable", [] {
            FakeSystem system;
            Require(Execute(Install(), system) == 0);
            Require(system.At("package") < system.At("confirm"));
            Require(system.At("confirm") < system.At("lock"));
            Require(system.At("write-disarmed") < system.At("install"));
            Require(system.At("install") < system.At("verify-config"));
            Require(system.At("verify-config") < system.At("arm"));
            Require(system.At("arm") < system.At("enable"));
            Require(system.component && system.service && system.config && system.allowed);
            Require(system.bindings[0].enabled && !system.bindings[1].enabled);
            Require(!system.Called("remove"));
        }},
        {"existing service or component cannot be replaced", [] {
            for (const bool service : {false, true}) {
                FakeSystem system; system.service = service; system.component = !service;
                Throws([&] { Execute(Install(), system); }, L"already installed");
                system.RequireNoMutation();
            }
        }},
        {"preflight failures never reach mutation or installation", [] {
            for (const auto stage : {"admin", "os", "monitor", "resolve", "package"}) {
                FakeSystem system; system.fail = stage;
                Throws([&] { Execute(Install(), system); }, L"injected");
                system.RequireNoMutation();
            }
        }},
        {"declined confirmation changes nothing", [] {
            FakeSystem system; system.consent = false;
            Require(Execute(Install(), system) == ERROR_CANCELLED);
            system.RequireNoMutation();
        }},
        {"what-if is read-only for install, resume and removal", [] {
            for (const auto action : {Action::Install, Action::Enable, Action::Uninstall}) {
                FakeSystem system;
                Options options = Install(); options.action = action; options.what_if = true;
                if (action == Action::Enable) system.Installed();
                Require(Execute(options, system) == 0);
                Require(!system.Called("confirm"));
                system.RequireNoMutation();
                if (action == Action::Uninstall) Require(!system.Called("resolve") && !system.Called("os"));
            }
        }},
        {"--yes skips only confirmation, not safety checks", [] {
            FakeSystem system; auto options = Install(); options.yes = true;
            Require(Execute(options, system) == 0);
            Require(!system.Called("confirm") && system.Called("admin") && system.Called("package") && system.Called("lock"));
        }},
        {"target recreation during confirmation is rejected before writes", [] {
            FakeSystem system; system.change_target_after_confirm = true;
            Throws([&] { Execute(Install(), system); }, L"changed");
            Require(!system.Called("write-disarmed") && !system.Called("install") && !system.Called("arm"));
        }},
        {"write failure is disarmed but never removes a preexisting component", [] {
            FakeSystem system; system.fail = "write-disarmed";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("disarm") && !system.allowed && !system.Called("remove"));
        }},
        {"partially failed installation rolls back only the new component", [] {
            FakeSystem system; system.fail = "install";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.At("disarm") < system.At("remove"));
            Require(system.At("remove") < system.At("delete-config"));
            Require(!system.component && !system.service && !system.config);
        }},
        {"automatic non-PnP target path is disabled while disarmed before enable", [] {
            FakeSystem system; system.target_enabled_on_install = true;
            Require(Execute(Install(), system) == 0);
            Require(system.At("disarm") < system.At("disable") && system.At("disable") < system.At("arm"));
            Require(system.allowed && system.bindings[0].enabled && !system.bindings[1].enabled);
            Require(!system.Called("remove"));
        }},
        {"unexpected foreign enabled path causes rollback without editing it", [] {
            FakeSystem system; system.foreign_enabled = true;
            Throws([&] { Execute(Install(), system); }, L"unexpectedly enabled");
            Require(system.Called("remove") && !system.Called("disable") && !system.Called("arm"));
        }},
        {"target disable failure cannot arm a fresh installation", [] {
            FakeSystem system; system.target_enabled_on_install = true; system.fail = "disable";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("remove") && !system.Called("arm") && !system.allowed);
        }},
        {"target disable without effect cannot arm the component", [] {
            FakeSystem system; system.target_enabled_on_install = true; system.disable_has_effect = false;
            Throws([&] { Execute(Install(), system); }, L"unexpectedly enabled");
            Require(system.Called("remove") && !system.Called("arm") && !system.allowed);
        }},
        {"target disable reboot preserves disarmed component", [] {
            FakeSystem system; system.target_enabled_on_install = true; system.disable_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.component && system.config && !system.allowed && !system.Called("arm") && !system.Called("remove"));
        }},
        {"resume reattaches an already enabled non-PnP target", [] {
            FakeSystem system; system.Installed(); system.bindings[0].enabled = true;
            Require(Execute(Enable(), system) == 0);
            Require(system.At("disable") < system.At("arm") && system.At("arm") < system.At("enable"));
            Require(system.allowed && system.bindings[0].enabled && !system.Called("install"));
        }},
        {"GUID/LUID changes after install cannot arm the component", [] {
            FakeSystem system; system.change_luid_after_install = true;
            Throws([&] { Execute(Install(), system); }, L"changed");
            Require(system.Called("remove") && !system.Called("arm"));
        }},
        {"arming and enable errors disarm and roll back fresh installs", [] {
            for (const auto stage : {"arm", "enable"}) {
                FakeSystem system; system.fail = stage;
                Throws([&] { Execute(Install(), system); }, L"injected");
                Require(system.Called("disarm") && system.Called("remove") && !system.allowed);
            }
        }},
        {"a binding that did not enable is never silently accepted", [] {
            FakeSystem system; system.enable_has_effect = false;
            Throws([&] { Execute(Install(), system); }, L"did not enable");
            Require(system.Called("remove") && !system.allowed);
        }},
        {"install reboot preserves disarmed config without enabling", [] {
            FakeSystem system; system.install_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.component && system.config && !system.allowed);
            Require(!system.Called("arm") && !system.Called("enable") && !system.Called("remove"));
        }},
        {"enable reboot disarms and preserves the installed component", [] {
            FakeSystem system; system.enable_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.component && system.config && !system.allowed && !system.Called("remove"));
        }},
        {"rollback reboot retains the exact target configuration disarmed", [] {
            FakeSystem system; system.fail = "enable"; system.remove_result = Change::RebootRequired;
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.config && !system.allowed && !system.Called("delete-config"));
        }},
        {"resume requires installed matching configuration", [] {
            FakeSystem missing;
            Throws([&] { Execute(Enable(), missing); }, L"not installed");
            missing.RequireNoMutation();
            FakeSystem stale; stale.Installed(); ++stale.configured.luid;
            Throws([&] { Execute(Enable(), stale); }, L"stale");
            stale.RequireNoMutation();
        }},
        {"resume enables only existing target without reinstalling", [] {
            FakeSystem system; system.Installed();
            Require(Execute(Enable(), system) == 0);
            Require(system.allowed && system.bindings[0].enabled && !system.bindings[1].enabled);
            Require(!system.Called("write-disarmed") && !system.Called("package") && !system.Called("install"));
        }},
        {"failed resume disarms but never removes an existing installation", [] {
            FakeSystem system; system.Installed(); system.fail = "enable";
            Throws([&] { Execute(Enable(), system); }, L"injected");
            Require(system.component && system.config && !system.allowed && !system.Called("remove"));
        }},
        {"uninstall disarms then removes own component and configuration", [] {
            FakeSystem system; system.Installed(); system.allowed = true;
            Require(Execute(Uninstall(), system) == 0);
            Require(system.At("disarm") < system.At("remove") && system.At("remove") < system.At("delete-config"));
            Require(!system.component && !system.service && !system.config);
            Require(!system.Called("resolve") && !system.Called("os") && !system.Called("enable") && !system.Called("package"));
        }},
        {"already absent component removal is safe", [] {
            FakeSystem system;
            Require(Execute(Uninstall(), system) == 0);
            Require(!system.config && !system.allowed);
        }},
        {"uninstall reboot and failure retain disarmed configuration", [] {
            FakeSystem reboot; reboot.Installed(); reboot.allowed = true; reboot.remove_result = Change::RebootRequired;
            Require(Execute(Uninstall(), reboot) == kRebootRequired);
            Require(reboot.config && !reboot.allowed && !reboot.Called("delete-config"));
            FakeSystem failure; failure.Installed(); failure.allowed = true; failure.fail = "remove";
            Throws([&] { Execute(Uninstall(), failure); }, L"injected");
            Require(failure.config && !failure.allowed && !failure.Called("delete-config"));
        }},
        {"monitor restart is checked after confirmation and before arming", [] {
            for (const size_t occurrence : {size_t{2}, size_t{3}}) {
                FakeSystem system; system.fail = "monitor"; system.fail_on_occurrence = occurrence;
                Throws([&] { Execute(Install(), system); }, L"injected");
                Require(!system.Called("arm") && !system.Called("enable"));
                if (occurrence == 2) Require(!system.Called("write-disarmed") && !system.Called("remove"));
                else Require(system.Called("remove") && !system.allowed);
            }
        }},
        {"component appearing during confirmation is never overwritten or removed", [] {
            FakeSystem system; system.appear_after_confirm = true;
            Throws([&] { Execute(Install(), system); }, L"already installed");
            Require(system.component && system.service && !system.Called("install") && !system.Called("remove") && !system.Called("write-disarmed"));
        }},
        {"rollback failure preserves original error and disarmed recovery state", [] {
            FakeSystem system; system.fail = "enable"; system.remove_fails = true;
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("remove") && system.component && system.config && !system.allowed && !system.Called("delete-config"));
        }},
        {"uninstall disarm failure cannot proceed to removal", [] {
            FakeSystem system; system.Installed(); system.allowed = true; system.fail = "disarm";
            Throws([&] { Execute(Uninstall(), system); }, L"injected");
            Require(!system.Called("remove") && !system.Called("delete-config") && system.component);
        }},
        {"uninstall cancellation leaves existing state untouched", [] {
            FakeSystem system; system.Installed(); system.allowed = true; system.consent = false;
            Require(Execute(Uninstall(), system) == ERROR_CANCELLED);
            system.RequireNoMutation();
            Require(system.component && system.config && system.allowed);
        }},
        {"residual service blocks configuration deletion", [] {
            FakeSystem system; system.Installed(); system.allowed = true; system.leave_service = true;
            Throws([&] { Execute(Uninstall(), system); }, L"incomplete");
            Require(system.config && !system.allowed && !system.Called("delete-config"));
        }}
    };
    for (const auto& test : cases) {
        try { test.test(); }
        catch (...) { std::fprintf(stderr, "FAIL: %s\n", test.name); return 1; }
        std::printf("PASS: %s\n", test.name);
    }
    std::printf("%zu console management tests passed; fake system only.\n", cases.size());
    return 0;
}
