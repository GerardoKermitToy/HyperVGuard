# HyperVXNdisFilter monitor

Standalone C++20 monitor/client library for the Rust host-adapter NDIS LWF for the Default Switch host vNIC. The kernel image is **`HyperVXNdisFilter.sys`**; service/device names are `HyperVXNdisFilter`, and startup notification is `Global\HyperVXNdisFilter.DriverReady`. These names and the header-only namespace were renamed together; older-name aliases are not provided. It keeps the familiar `pmkext::Driver`, `Handlers`, verdict values and direct device access, without depending on a Portmaster source tree at build/run time. The 0.3.2.0 Connection API carries the host adapter `interface_index` immediately after `id`, without a process ID, and preserves complete IP packets.

## Header-only callback client

[HyperVXNdisFilter.hpp](include/HyperVXNdisFilter.hpp) is an independent C++20 Windows x64 client in namespace **`hypervxndisfilter`**, not `pmkext`. It needs no monitor sources or client library. MSVC automatically links its system Advapi32 dependency; other toolchains must link Advapi32 explicitly. Full method/type contracts are in the root [API reference](../README.md#lightweight-header-only-client).

`Client::Open()` waits **without a startup timeout** for `Global\HyperVXNdisFilter.DriverReady` after an open failure, except `ERROR_SHARING_VIOLATION`, which returns immediately even after a startup notification. Releasing another controller is not a startup signal; retrying a busy device is the caller's responsibility. The protected manual-reset event is reset before retrying to avoid stale signals and lost wakeups. Stop cancels the wait; there is no device polling. Once opened, `Run(callbacks, duration_ms)` uses the calling thread, blocking on data/stop/deadline; it creates no worker/poll thread of its own. There are no automatic statistics requests or verdicts. `on_connection_v4/v6` receive packed fixed-header and complete-IP payload pointers directly into the input buffer; `on_bandwidth_v4/v6` receive the entire packed tuple array in one call. No normalized event structures are rebuilt, and no per-event allocation or payload copy is performed. All callback pointers/views expire on callback return. A head/tail cursor defers partial-frame compaction until writable space is short. Stop then join all callers before Close/destruction. An optional Run duration does not limit Open's startup wait.

The pointer callbacks replace the former unified `Connection` / `Bandwidth` callbacks in this header only. Fixed layouts have one-byte alignment and compile-time size/offset checks; read numeric fields by value, without taking naturally aligned integer pointers/references to them. Both this header and the separate `pmkext` API expose `interface_index:u32` immediately after `id:u64` and require driver wire version **0.3.2.0**. It is the host adapter index (`BaseMiniportIfIndex`), retained per attached module, not a guest interface or compartment ID. Packed ConnectionV4/V6 headers are 27/51 bytes; do not mix older SYS/client generations.

[examples/callback_client.cpp](examples/callback_client.cpp) compiles as `callback_client.exe` without pmkext. It waits for startup, answers with PermanentAccept and limits the actual monitoring phase to ten seconds. It is a live example, not an offline test; do not run it incidentally. `header_client_tests` substitutes every device API and the production named event with fakes/private unnamed events, checking startup wait, idle pending read, cancellation/reaping, callback views, framing and large packets without opening the real device.

## Build and no-driver tests

On Windows x64 with CMake and the Visual Studio C++ toolchain installed:

```powershell
cmake -S C:\hyperv\monitor -B C:\hyperv\monitor\build -G "Visual Studio 18 2026" -A x64 -DBUILD_TESTING=ON
cmake --build C:\hyperv\monitor\build --config Release --parallel
ctest --test-dir C:\hyperv\monitor\build -C Release --output-on-failure -L no-driver
```

For Visual Studio 2022 use `-G "Visual Studio 17 2022"`. Alternatively configure with Ninja from an x64 VS developer shell and add `-DCMAKE_BUILD_TYPE=Release`; the executable then appears directly in the build directory. A parent build can configure this CMake project without building a driver. Targets include `hyperv_monitor`, `pmkext`, and `hyperv_xndis_filter_notify` (the separate NetCfg binding-policy DLL, built but never registered by CMake).

With the VS generator the executable is `build\Release\hyperv_monitor.exe`. It deliberately uses an **as-invoker** manifest so `--help` and invalid-CLI tests need neither elevation nor a device. Actual device access still requires elevated Administrator/SYSTEM because of the driver's device ACL.

CTest registers **only no-driver tests**: exact IPv4/IPv6/event/command codecs and device-only lifecycle checks, fragmented streams and length limits, strict CLI/filter validation, startup-event races/cancellation with fake device opens and private local test events, delayed-verdict scheduling, output serialization, `--help`, and deliberately invalid CLI invocations. Additional offline tests cover LWF target/copy/ownership helpers, binding-policy decisions, mock management preflight and user-mode COM factory/lifetime. The notify DLL is loaded only as a normal DLL for that test; it is never registered. No test installs/loads/binds a driver, opens its device, or runs a monitoring session. The record-output test writes only in its CTest build working directory. Do not substitute a valid monitoring run when validating a build without explicit authorization.

## Explicit installation and session startup

An NDIS LWF is a NetCfg network component, not a legacy demand-start service. Install explicitly using the native `dist/Install.exe`, which restricts the new component to the exact Default Switch host vNIC through a notify object and a separate kernel GUID/LUID gate. Use `Install.exe --enable` to resume after a requested reboot, `Uninstall.exe` for removal, and the optional `Set-Binding.ps1` for explicit rebind/unbind. Setup EXEs do not launch PowerShell/netcfg.exe. The monitor performs neither installation nor binding.

`Driver::Open()` opens the existing `\\.\HyperVXNdisFilter` device only; it does not start an IPC server. `Driver::Install(...)` keeps its old signature but returns a descriptive **not supported** error without touching SCM or registry state. `Stop()` sends the existing shutdown IOCTL to end the device session and release pending packets; `Cleanup()` closes handles. Neither disables, uninstalls or unloads the LWF.

`Driver::GetFilteredDeviceCount(uint32_t& out, std::string& error)` queries the number of running NDIS filter modules, not installed/enabled bindings. The monitor prints `Filtered network devices: N (running NDIS modules)` at startup and on changes, querying at `--poll` intervals (default 1000 ms). Status lines use `--out`/`--timestamps`. Paused or detached modules do not count; a loaded driver can report zero. This is an instantaneous interception-state snapshot, not a traffic or connectivity test. Unsupported/failed queries produce a warning, not a fabricated zero, and subsequent polls retry without stopping monitoring.

`Driver::GetAdapterInfo(AdapterSnapshot&, error)` and header-only `Client::GetAdapterInfo(AdapterSnapshot&)` query all attached modules, including not-running ones. The monitor prints this snapshot once at startup, after version validation, honoring `--out`/`--timestamps`: instance/base/filter names, host interface indices/GUID/LUIDs, running state, MAC, media/duplex/link speeds, MTU and available general restart attributes. Values are the last NDIS-supplied data, not fresh OID queries; unknown fields and truncated names are labelled. A failed/unsupported query warns and monitoring continues; snapshots are unchanged on failure. See the root [adapter snapshot reference](../README.md#adapter-information-snapshot) for every field, validity flag and wire offset.

Connection headers print `id=... interface_index=...` for both IPv4 and IPv6, including with `--out` and `--timestamps`. The unsigned index comes from each event and identifies the host adapter at the interception point, not an interface inside the guest.

`--duration` is optional. With no duration (including no arguments), the monitor runs until **Ctrl+C**. If the initial device open fails, it creates/opens the Administrator/SYSTEM-only manual-reset event `Global\HyperVXNdisFilter.DriverReady` and waits for the driver to signal startup. Ctrl+C cancels that wait as well. The driver signals only after its control device and timer are initialized, retains the event handle while loaded, and clears/closes it on unload. The updated SYS is required for notification; this does not install or load it. Notification is best-effort during early boot before the global object directory exists.

The monitor resets the event before rechecking the device to avoid lost startup races and stale-signal spinning. A signal only requests another device-open attempt; it does not bypass exclusive access, elevation or version checks. An access failure can therefore keep waiting for the next startup; closing another controller is not a startup signal. No reconnect after an established session is implemented.

With a **positive `--duration N`**, device-open failure exits immediately without creating, resetting or waiting on the event, and a successful session stops after N seconds. Automated/live tests must still use positive durations. Explicit zero/negative/junk durations, `.sys` positional arguments, `--sys`, process-suspension options, redirect verdict names and unsupported options fail before taking a singleton, opening an output file or accessing a device. `--help` also stays entirely on this no-device path.

```powershell
# Help only: no device access.
.\build\Release\hyperv_monitor.exe --help

# Runtime examples only; require an explicitly installed/bound LWF,
# elevation, and separate permission to run against live host-vNIC traffic.
.\build\Release\hyperv_monitor.exe  # Interactive: wait for startup, then Ctrl+C exits.
.\build\Release\hyperv_monitor.exe --duration 10 --only-logs
.\build\Release\hyperv_monitor.exe --duration 30 --out run.log --timestamps --payload
.\build\Release\hyperv_monitor.exe --duration 30 --filter-protocol 17
.\build\Release\hyperv_monitor.exe --duration 30 --verdict block --match 192.0.2.10:53
```

Supported options include `--out`, `--filter-ip IP[:PORT]` (`[IPv6]:PORT` for IPv6), `--filter-protocol`, `--match`, `--verdict`, `--no-verdicts`, `--payload`, `--poll`, `--timestamps`, `--memory-stats` and `--verdict-delay-ms`. `--only-logs`, `--no-conn` and `--no-bandwidth` are retained. Numeric values and ports are validated without truncation or wrapping. Display filters combine with AND, never change verdicts, and IP/port pairs must match the same endpoint. `--match` selects the normalized `remote` endpoint in both directions.

Duration/console-stop checks run at most 100 ms apart regardless of a longer `--poll`; requesting an enormous poll interval does not extend the requested monitoring period. The startup event wait also checks console-stop requests every 100 ms, without periodically reopening the device. In-progress I/O completion can still add bounded completion time. Ctrl+C requests session shutdown or cancels startup waiting. The independent singleton is `Global\HyperVXNdisFilterMonitor.Singleton`, so the WFP monitor's singleton is not reused.

## Wire format and NDIS semantics

* Event framing is unchanged: **`[u8 type][u32 body length LE][body]`**. Connection types 1/2 have no process-ID bytes; their complete prefixes, including the framing header, are 36/60 bytes for IPv4/IPv6. The `interface_index:u32` follows `id:u64`; this breaks compatibility with 0.3.1.0 and earlier. No compartment/sub-interface ID, TID or switch-port identity is exposed.
* `IOCTL_VERSION` is `CTL_CODE(40000, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)` and returns `[0,3,2,0]`. Shutdown uses function `0x801`. `IOCTL_FILTERED_DEVICE_COUNT` uses function `0x802` / code `0x9C40E008` with the same buffered read/write access, no input and exactly four little-endian output bytes (`uint32_t`). It does not change the policy session or bindings. There is **no thread-ID IOCTL** or thread-ID query/printing.
* `IOCTL_ADAPTER_INFO` uses function `0x803` / `0x9C40E00C`, with the same buffered read/write access and empty input. Reply: a 16-byte LE header (`schema_version=1`, `entry_size=1760`, `count<=32`, `running_count`) and exactly `count` entries, at most **56336 bytes**. This additive diagnostic does not change event version **0.3.2.0**. `adapter_info_tests` checks the kernel's portable encoder against the C++ decoder, name bounds/Unicode, malformed replies, unchanged failure outputs and monitor formatting, without opening a device.
* `Connection` contains **no `process_id`**: this NDIS layer cannot identify a process owner. `--filter-pid` is rejected; unused END compatibility types retain PID=0. `direction=0` is guest/Sandbox outbound (host NDIS receive); `1` is guest/Sandbox inbound (host NDIS send). `local` is the guest-side endpoint and `remote` the peer. Host-send source/destination are normalized without modifying the captured packet. The monitor requires device version **0.3.2.0** and rejects older SYS versions before reading events.
* Each `CONN`/verdict refers to **one owned NBL** (an original or a deep-copied resources receive), not a process-owned socket. Unsupported/mixed batches are dropped by the driver rather than representing just their first packet as the entire batch.
* `payload_layer=3`; `payload` contains the **complete observed IP packet**, without Ethernet/VLAN headers or padding. `payload_size` is its full length, not a 256-byte capture. The maximum payload is **1048576 bytes (1 MiB)** and maximum complete record **1048636 bytes**. Oversized logical packets are dropped, never truncated into a Connection event. LSO/RSC payloads describe NDIS logical packets, not necessarily wire segments. A homogeneous multi-NB NBL still has one verdict and the complete first NB packet, not concatenated payloads.
* RecordStream uses bounded heap storage to assemble records across the unchanged 65536-byte device reads. Kernel captures are copied outside the policy spin lock into fallibly allocated nonpaged storage with a **16 MiB global allocation budget**, including in-flight copies; queued records also have a 16 MiB byte budget. Event-buffer exhaustion uses the configured fallback without emitting a partial packet. Log records keep their 512-byte bound.
* Nonzero device reads **wait for data** in a bounded cancel-safe queue. They never succeed empty on an idle queue. Stop/deadline cancels and reaps the pending overlapped read; shutdown/cleanup/unload cancel queued requests. Zero-length requests still succeed empty. There is no 10 ms idle read polling. Unexpected empty reads are errors. Fragmented/coalesced records are handled using bounded storage; an oversized header terminates the session rather than inventing a synchronization boundary.
* Commands retain their original **unframed** byte IDs and fixed layouts. Supported IDs are Shutdown=0, Verdict=1, ClearCache=4, GetLogs=5, GetBandwidthStats=6, PrintMemoryStats=7, CleanEndedConnections=8. UpdateV4=2/UpdateV6=3 names remain for source compatibility, but **are rejected**, as requested.
* Verdict bytes **2..7** retain Accept/PermanentAccept/Block/PermanentBlock/Drop/PermanentDrop meanings. Redirect/undecided/failed values remain named in the enum for source compatibility but cannot be written. The entire command batch is validated before any write; the driver must independently validate at its own trust boundary.
* Permanent cache TTL is **60 seconds**. Pending timeout defaults to **2 seconds**, with **fail-open by default**. No new configuration wire protocol was introduced. `--no-verdicts` or a long delayed verdict may leave a packet pending until that timeout; they do not imply indefinite blocking.
* `GetBandwidthStats` emits compatible type-5/type-6 tuple records: `transmitted_bytes` counts admitted guest outbound IP bytes and `received_bytes` admitted guest inbound IP bytes, grouped by the normalized guest/peer tuple. Records contain no PID. These are guest-side admission counters on the host-vNIC path, not process/socket attribution or proof of final delivery.
* `PrintMemoryStats`/`GetLogs` use compatible `LogLine` records. `CleanEndedConnections` only sweeps expired cache state. **No fake END event** is generated for timeout, cache expiry or monitor shutdown. Legacy END/bandwidth structs and callbacks remain available for compatible real input records.

The default automatic verdict is `PermanentAccept`; `--verdict` without `--match` applies to every observed event. Block/drop decisions can interrupt target host-vNIC traffic, including remote sessions. Delayed verdicts use the existing queue and do not suspend any process. Delays do not extend the driver's pending lifetime, and unsent work is discarded at shutdown.

## Direct device transport

The monitor uses only the existing driver device. All complete raw device records are decoded and delivered to the local `Handlers`; local automatic/delayed verdicts write directly to that device. There is no named-pipe server, handshake, attached-client state, external command forwarding, trusted-client executable check, or exclusive external record ownership.

The standalone `winrpc/` source directory is not a dependency of this monitor. Removing it from a deployment or source bundle does not affect monitor targets. The required device API version is now **0.3.2.0** for adapter-index Connection records and blocking reads. Full packet delivery and the PID-free Connection layout require the matching rebuilt SYS and monitor; the older transport removal alone did not require a SYS change.

## Source provenance and license

These are independent copies/adaptations of the local `C:\portmaster_v3` source snapshot **`542b4e4`**:

* `kext_client\include\PortmasterKext.h`, `DelayedVerdicts.h`, `RecordOutput.h`;
* `kext_client\src\PortmasterKext.cpp`, `main.cpp`;
* `kext_client\tests\ip_address_tests.cpp`, `delayed_verdict_tests.cpp`, `record_output_tests.cpp`;

`DriverProtocol.*`, `MonitorOptions.*`, standalone CMake wiring and new codec/CLI tests were added during the HyperVXNdisFilter adaptation. The copied client's SCM lifecycle, PID suspension, thread-ID IOCTL and redirect support were intentionally removed/disabled. The monitor has no winrpc source, include, target or link dependency; the unused sibling sources are not built. No monitor source path points back to the original repository.

The original repository's **GNU GPL version 3** license is preserved verbatim as `LICENSE`; this adaptation retains that license. Source provenance does not imply that the original WFP driver's lifecycle or host process semantics apply to a host-adapter NDIS LWF.

## Full-packet/PID-free validation

The **0.3.0.0** Release build passed **17/17 no-driver CTest suites** and **44 Rust tests** (28 policy unit tests, five full-payload integration tests, four guest-direction tests and seven protocol tests). Codec coverage includes exact PID-free IPv4/IPv6 layouts, complete packets beyond 256 and 65536 bytes, maximum 1 MiB payloads, fragmented/coalesced reads, malformed bounds and version rejection. The codec suite also passed **50 consecutive offline repetitions**. Rust tests cover VLAN/padding exclusion, logical offload packets, queue byte pressure, allocation fallback, stale-event cleanup and partial reads surviving timeout. Formatting and strict host/kernel Clippy passed.

The rebuilt SYS, notify DLL, setup EXEs and catalog were signed; Authenticode and catalog membership passed, including the native setup tool's read-only package verification. No driver was installed, loaded, bound or opened, and no live monitor/traffic test was run. Actual NDIS full-buffer copies and filtering remain user-run validation; the matching SYS and monitor are both required.

## Historical startup-event validation

Before the full-packet/PID-free change, the startup-event/default-password Release build passed **17/17 no-driver CTest suites**, including **11** startup scenarios with fake device openers and private local events: duration/no-wait, already available, signal-before-event-open/wait, asynchronous signaling, stale/repeated signals, cancellation and named-object type collision. The startup suite also passed 50 consecutive offline repetitions; a separate build-options suite verifies eight default/environment/argument password-precedence cases. These tests do not open the installed device or exercise the real kernel notification/Ctrl+C path. That snapshot used wire version **0.2.1.0**; startup signaling required its rebuilt SYS.

## Device-only validation

Historical device-only snapshot (before native setup tool integration changed monitor help strings): on 2026-10-25, a fresh Release build in `build/monitor-device-only` passed **11/11 no-driver CTest suites**, including local device-session construction/cleanup and help/invalid-CLI checks that reject unsupported transport options. The compilation database and Ninja graph contain no winrpc/duplex-pipe sources, includes or link dependency. PE imports contain no named-pipe server APIs.

That snapshot executable was copied to `dist/hyperv_monitor.exe`: **94720 bytes**, SHA-256 **0737685EF30CFB12D0CA765B885672EAA4A0F024868CA2475F7188E3800D2087**. This supersedes the monitor hash in the earlier direction-fix report; driver wire version remains 0.2.1.0.

SYS, INF, CAT and the signed notify DLL in `dist/` were verified unchanged. No driver was installed, loaded or bound, no device was opened, and no live monitoring session was run. The user retains live traffic testing.

## Historical native setup integration

The initial native setup integration changed monitor help and unsupported-installation diagnostics to point to `dist/Install.exe` rather than the removed PowerShell installer. That Release build passed **14/14 no-driver CTest suites**, including the native setup workflow, INF and help/invalid-CLI tests. That snapshot's `dist/hyperv_monitor.exe`: **94720 bytes**, SHA-256 **6CB99E7BED9BD2825DAC12D17BFE18F80EDD5932DEE13E03BBC420DBFD2B56C9**. The driver protocol remained **0.2.1.0**; SYS/INF/CAT/notify DLL were unchanged in that snapshot. See [native setup validation](../install/console/README.md#offline-validation).

The later driver-store package **0.2.1.4** corrects setup/notify GUID inspection and non-PnP target lifecycle and passed **15/15** no-driver suites. Its authorized real installation completed with exit 0 and only the Default Switch binding enabled; this monitor and wire version 0.2.1.0 remain unchanged. No live monitor/traffic test was run. Historical package and retry instructions: [NetCfg identity fix](../docs/NETCFG-IDENTITY-FIX.md).
