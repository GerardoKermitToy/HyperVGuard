# Native HyperVXNdisFilter setup tools

Current driver-store package and SYS/device API version: **0.3.2.0**. Connection records add the per-module host adapter `interface_index:u32` immediately after `id:u64`; nonzero device reads still wait for data and support cancellation. Existing GUID/LUID target checks and disable-before-arm setup behavior are unchanged. Use the coherent new INF/DLL/CAT/setup EXE set and matching monitor; older device versions are rejected. Package generation does not replace the installed driver.

`Install.exe` and `Uninstall.exe` replace `scripts/Install.ps1` and `scripts/Uninstall.ps1`. They are native Windows x64 C++ console programs using system APIs directly, not compiled script launchers. No PowerShell module, PowerShell execution policy, `netcfg.exe` child process, SCM service creation, or driver-device access is involved.

The binaries are packaged beside **`HyperVXNdisFilter.sys`**, `HyperVXNdisFilter.inf`, `HyperVXNdisFilter.cat`, and the required `HyperVXNdisFilterNotify.dll` in `dist/`; matching debug symbols are `HyperVXNdisFilter.pdb`. The service is `HyperVXNdisFilter` and the NetCfg component is `hyperv_xndis_filter`; the device, startup event and clients use the same product name. A package with inconsistent filenames or service identities is rejected. Before using this renamed package, remove a previous-name installation with its matching old `Uninstall.exe`. The new tools reject a conflicting filter instance GUID and never migrate or remove a differently named component. Never rename an installed SYS. The default package directory is the **EXE directory**, not the current working directory. Actions require an already elevated Administrator/SYSTEM console; the EXEs deliberately use `asInvoker` so help and invalid-CLI tests need no elevation or UAC prompt.

## Commands

From Git Bash at the repository root, with the monitor stopped:

```bash
./dist/Install.exe
```

An alternate package directory:

```bash
./dist/Install.exe --package 'C:/path/to/package'
```

Read-only preflight, without taking the NetCfg write lock or writing configuration:

```bash
./dist/Install.exe --what-if
```

Resume an installed component **after** a requested reboot, using the existing GUID/LUID configuration rather than retargeting it:

```bash
./dist/Install.exe --enable
```

Remove only HyperVXNdisFilter and **all its identified Driver Store package versions**, even if Default Switch or its adapter no longer exists:

```bash
./dist/Uninstall.exe
```

Help performs no WMI, NetCfg, registry, or driver initialization:

```bash
./dist/Install.exe --help
```

```bash
./dist/Uninstall.exe --help
```

Both accept `--yes` to skip confirmation, without bypassing any safety check. `--what-if` still requires privileges and checks the real system; it is not an appropriate automated offline test. EOF or any answer other than `y`/`yes` cancels by default. No process is forcibly stopped.

| Exit code | Meaning |
|---:|---|
| 0 | Completed, or read-only preflight completed |
| 1 | Failure; diagnostic on stderr |
| 2 | Invalid CLI, rejected before system initialization |
| 1223 | Confirmation declined / input ended |
| 3010 | Component/package removal or enable requires reboot; configuration is retained disarmed |

When installation requests reboot, do not bypass the disarmed state. Reboot, then explicitly run `Install.exe --enable`. When removal requests reboot, reboot and run `Uninstall.exe` again to finish package cleanup before attempting a fresh installation. A partial removal or orphaned service is not treated as a clean installation; the tools never forcibly delete an SCM service.

## Native lifecycle and scope

- `Target.cpp` queries only local WMI. It verifies the built-in Default Switch identity `c08cb7b8-9b3c-408e-8e30-5e16a3aeb444`, follows **internal management-OS Ethernet port → LAN endpoint → active connection → switch endpoint** associations, and matches the port's `Microsoft:{GUID}` device ID to the exact `MSFT_NetAdapter`. Ethernet type, virtual/hardware flags, nonzero LUID, and native GUID/LUID round-trip conversion are checked. Names are diagnostic only. Missing/ambiguous/stale identity aborts; there is no friendly-name fallback.
- `Package.cpp` keeps non-write/non-delete-sharing handles open on all four package files. SetupAPI parses the supported 0.3.2.0 NetService/LWF INF, notify CLSID, driver-store destinations and binding policy. The INF service binary, driver copy list and source-disk entry must name `HyperVXNdisFilter.sys`; the driver and notify copy lists each contain exactly one expected file. WinVerifyTrust validates SYS/DLL/CAT trust and SHA-256 catalog membership of INF/SYS/DLL. Verification uses cached trust information without a timestamp request, certificate import, trust-store mutation or security-policy change.
- `Management.cpp` implements an injectable workflow shared by the real EXEs and offline fake-system tests. Before installation it refuses an existing service/component and a running monitor, requires confirmation, acquires a NetCfg write lock, and rechecks the target and installation state. `AutoRepairAllowed=0` is durably persisted before disarming. `AllowBindings=0` is written before target identity and before NetCfg can install the component; `ConfigVersion=2` is written last.
- `WindowsSetup.cpp` stages the validated INF through `SetupCopyOEMInfW` and uses `INetCfgClassSetup::Install` / `DeInstall` plus `INetCfg::Apply` directly. It inspects only `hyperv_xndis_filter` binding paths, requiring each path to terminate at exactly one adapter GUID. An automatically enabled non-PnP exact-target path is explicitly disabled while disarmed, applied/refreshed and verified disabled before arming; resume follows the same ordering. Only paths to the exact target may be enabled; an enabled foreign path causes abort/rollback, not edits to that adapter. Several NetCfg paths to the same exact target are handled together.
- A failed **new installation** first disarms, discards pending NetCfg changes, and attempts to remove only its own new component. A failed **resume** after mutation disarms but never removes a preexisting component; rejected preflight remains read-only. Configuration is deleted only after complete component/service removal. On failure or reboot it is retained for safe recovery. Fresh-install rollback does not purge preexisting staged packages. Explicit uninstall separately cleans up all verified package versions, but never forces deletion of an in-use package.
- Only successful exact-target enable publishes `AutoRepairAllowed=1` for compatible runtime controllers. Failed setup, removal and reboot-required states keep it `0`; runtime recovery must not override that installer-controlled state. `AllowBindings=0` alone is an attach gate, not a permanent ban on retrying a transient runtime repair. Older configurations without the recovery flag need explicit operator-controlled migration when already disarmed.
- `DriverStore.cpp` enumerates published OEM INFs through SetupAPI. Original filename is only a candidate filter: each candidate must be a NetService package whose every model and platform-specific DDInstall/Services variant uses `hyperv_xndis_filter`, the stable filter GUID, and only the `HyperVXNdisFilter` kernel service with `HyperVXNdisFilter.sys`. This ownership check is independent of `DriverVer`, model OS decoration, CopyFiles destination and current signature trust. A colliding/ambiguous identity is refused, never guessed. Original Driver Store paths come from SetupAPI, not a folder-name wildcard.
- After complete component/service removal, setup uninitializes NetCfg and releases unused notify DLLs while retaining the write lock. `DiUninstallDriverW` removes every verified package through Windows servicing APIs; no shell, forced file deletion, ownership/ACL change or certificate-store change is used. Each package is revalidated just before removal. One package failure does not skip the others, but any partial failure prevents success and retains disarmed configuration. A final inventory must be empty before configuration deletion and exit 0. Reboot instructions are emitted immediately when any package requests one, even if a later package or final inventory check fails. In-use/reboot-required packages return 3010; reboot and rerun uninstall. A later uninstall also cleans staged versions when the component is already absent. `--what-if` lists the matching OEM INFs without mutation.
- Uninstall does not resolve a target or require the Hyper-V WMI provider. It disarms first and removes only `hyperv_xndis_filter`. It does not change switches, VMs, HNS, ICS, NAT, routes, certificate stores or unrelated network components. NetCfg itself can still cause system-wide network reconfiguration; use local console/recovery, not an irreplaceable remote connection.

Disarming `AllowBindings` prevents new target attachments; it is **not** an unload/detach operation and does not undo binding changes that NetCfg has already committed. Setup now forces target disable-before-arm/enable even when a non-PnP path initially reports enabled. Real failed-resume/reboot recovery still needs NDIS runtime validation. An enabled NetCfg path alone is not proof of a working filter attachment.

The optional `scripts/Set-Binding.ps1` remains available for an explicit target-only disable/rebind. The monitor remains direct device-only transport and never performs installation or binding.

## Build and offline tests

The existing user-mode CMake project builds both tools with a static MSVC CRT. In an initialized VS x64 environment:

```bash
cmake -S monitor -B build/monitor -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
```

```bash
cmake --build build/monitor --target hyperv_Install hyperv_Uninstall management_console_tests management_package_tests
```

```bash
ctest --test-dir build/monitor -R '^management_' --output-on-failure
```

The normal `scripts/Build.ps1` also builds/copies both EXEs, including with `-SkipMonitor`; supplied signing arguments sign both EXEs as well as the existing driver package. Building never installs, binds, loads or removes the driver and never registers the notify COM object.

- `management_console_tests`: fake system only; identity selection, exact binding scope, confirmation, dry run, fresh/duplicate install, partial failure/rollback, reboot, resume, stale LUID, and target-independent uninstall.
- `management_driver_store_tests`: version-independent ownership fixtures, old/undecorated/multiple OS model sections, mixed-package rejection, and strict published OEM basename validation; no system inventory or package deletion.
- `management_package_tests`: SetupAPI parsing of the actual INF and rejected mutations, using only temporary INF files in the build directory. An optional additional package-directory argument validates an existing signed package read-only; this is not part of default CTest and depends on configured local certificate trust.
- `management_cli_tests`: only `--help` and deliberately invalid invocations of both EXEs, including invalid arguments combined with `--yes` / `--what-if`. No valid action is launched.

**Live installation/removal, real NetCfg callbacks and binding changes are intentionally not exercised by these tests.** Offline API/fixture tests and trusted signatures do not prove successful kernel admission or network lifecycle under a loaded driver.

The native setup sources are licensed under the GNU General Public License version 3 only (`GPL-3.0-only`); see [LICENSE](../../LICENSE). They remain independent of the monitor implementation.

## Historical validation

The explicitly authorized 2026-10-25 installation of **0.2.1.4** predates the product rename. It completed with exit 0 and no reboot request; the pre-rename service was running with only the exact Default Switch host adapter binding enabled, all 239 unrelated bindings unchanged, and installed package hashes matching that snapshot's dist. This does not describe an installed renamed package. No monitor/device/traffic test was run; packet interception and real resume remain unverified. See [the historical live report](../../docs/NETCFG-IDENTITY-FIX.md).

### Historical offline validation

The following is the **initial console conversion snapshot**. The preceding package 0.2.1.4 passed **15/15** suites, including adapter GetClassGuid/E_POINTER and non-PnP regressions, **38** fake-system lifecycle cases and **13** rejected INF mutations; that snapshot's signing and artifact details are in [NETCFG-IDENTITY-FIX](../../docs/NETCFG-IDENTITY-FIX.md).

The 2026-10-25 Release build in `build/native-management` passed **14/14 no-driver CTest suites**, including **33 fake-system console management cases**, **12 rejected INF mutations**, and **24 actual help/invalid-CLI invocations** of the two EXEs. Optional read-only validation also accepted the existing signed 0.2.1.0 package and checked SHA-256 catalog membership for INF/SYS/DLL. PE inspection found no child-process launch/manual-SCM lifecycle imports and no dynamic VC++ runtime dependency in the setup EXEs.

`dist/Install.exe`, `dist/Uninstall.exe` and the monitor with updated installation/help text are built and copied. The existing signed SYS/INF/CAT/notify DLL were verified byte-for-byte unchanged. The original Install/Uninstall PowerShell scripts were removed, not retained as a second lifecycle implementation. Build.ps1 and the optional binding/helper scripts remain.

A final native API review also caught and corrected both registry access masks used with `RegFlushKey`: the shared access mask includes its required `KEY_QUERY_VALUE` as well as `KEY_SET_VALUE` and the 64-bit view. This contract is compile-time checked; no real target configuration was opened/written to test it.

No actual install/uninstall/resume/dry-run action of the native tools was executed; the driver was not loaded, bound, removed or opened, and notify COM was not registered. Real NetCfg/driver lifecycle remains user-run validation. No commit was created.
