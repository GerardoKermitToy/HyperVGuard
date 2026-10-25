# HyperVGuard monitor

Standalone C++20 monitor/client library for the Rust host-adapter NDIS LWF for the Default Switch host vNIC. It preserves the familiar `pmkext::Driver`, `Handlers`, `Connection`, verdict values, event fields and direct device access, without depending on a Portmaster source tree at build/run time.

## Build and no-driver tests

On Windows x64 with CMake and the Visual Studio C++ toolchain installed:

```powershell
cmake -S C:\hyperv\monitor -B C:\hyperv\monitor\build -G "Visual Studio 18 2026" -A x64 -DBUILD_TESTING=ON
cmake --build C:\hyperv\monitor\build --config Release --parallel
ctest --test-dir C:\hyperv\monitor\build -C Release --output-on-failure -L no-driver
```

For Visual Studio 2022 use `-G "Visual Studio 17 2022"`. Alternatively configure with Ninja from an x64 VS developer shell and add `-DCMAKE_BUILD_TYPE=Release`; the executable then appears directly in the build directory. A parent build can configure this CMake project without building a driver. Targets include `hyperv_monitor`, `pmkext`, and `hyperv_guard_notify` (the separate NetCfg binding-policy DLL, built but never registered by CMake).

With the VS generator the executable is `build\Release\hyperv_monitor.exe`. It deliberately uses an **as-invoker** manifest so `--help` and invalid-CLI tests need neither elevation nor a device. Actual device access still requires elevated Administrator/SYSTEM because of the driver's device ACL.

CTest registers **only no-driver tests**: exact IPv4/IPv6/event/command codecs and device-only lifecycle checks, fragmented streams and length limits, strict CLI/filter validation, delayed-verdict scheduling, output serialization, `--help`, and deliberately invalid CLI invocations. Additional offline tests cover LWF target/copy/ownership helpers, binding-policy decisions, mock management preflight and user-mode COM factory/lifetime. The notify DLL is loaded only as a normal DLL for that test; it is never registered. No test installs/loads/binds a driver, opens its device, or runs a monitoring session. The record-output test writes only in its CTest build working directory. Do not substitute a valid monitoring run when validating a build without explicit authorization.

## Explicit installation, bounded sessions

An NDIS LWF is a NetCfg network component, not a legacy demand-start service. Install explicitly using the native `dist/Install.exe`, which restricts the new component to the exact Default Switch host vNIC through a notify object and a separate kernel GUID/LUID gate. Use `Install.exe --enable` to resume after a requested reboot, `Uninstall.exe` for removal, and the optional `Set-Binding.ps1` for explicit rebind/unbind. Setup EXEs do not launch PowerShell/netcfg.exe. The monitor performs neither installation nor binding.

`Driver::Open()` opens the existing `\\.\HyperVGuard` device only; it does not start an IPC server. `Driver::Install(...)` keeps its old signature but returns a descriptive **not supported** error without touching SCM or registry state. `Stop()` sends the existing shutdown IOCTL to end the device session and release pending packets; `Cleanup()` closes handles. Neither disables, uninstalls or unloads the LWF.

Every monitoring run requires a **positive `--duration`**. No arguments, zero/negative/junk durations, `.sys` positional arguments, `--sys`, process-suspension options, redirect verdict names and unsupported options fail before taking a singleton, opening an output file or accessing a device. `--help` also stays entirely on this no-device path.

```powershell
# Help only: no device access.
.\build\Release\hyperv_monitor.exe --help

# Runtime examples only; require an explicitly installed/bound LWF,
# elevation, and separate permission to run against live host-vNIC traffic.
.\build\Release\hyperv_monitor.exe --duration 10 --only-logs
.\build\Release\hyperv_monitor.exe --duration 30 --out run.log --timestamps --payload
.\build\Release\hyperv_monitor.exe --duration 30 --filter-pid 0 --filter-protocol 17
.\build\Release\hyperv_monitor.exe --duration 30 --verdict block --match 192.0.2.10:53
```

Supported options include `--out`, `--filter-ip IP[:PORT]` (`[IPv6]:PORT` for IPv6), `--filter-protocol`, `--filter-pid 0`, `--match`, `--verdict`, `--no-verdicts`, `--payload`, `--poll`, `--timestamps`, `--memory-stats` and `--verdict-delay-ms`. `--only-logs`, `--no-conn` and `--no-bandwidth` are retained. Numeric values and ports are validated without truncation or wrapping. Display filters combine with AND, never change verdicts, and IP/port pairs must match the same endpoint. `--match` selects the normalized `remote` endpoint in both directions.

A duration check runs at most 100 ms apart regardless of a longer `--poll`; requesting an enormous poll interval does not extend the requested monitoring period. In-progress I/O completion can still add bounded completion time. Ctrl+C requests early session shutdown. The independent singleton is `Global\HyperVGuardMonitor.Singleton`, so the WFP monitor's singleton is not reused.

## Exact wire compatibility and NDIS semantics

* Event framing is unchanged: **`[u8 type][u32 payload length LE][payload]`**. Existing IPv4/IPv6 `Connection` field order and sizes are unchanged; no TID, switch, switch-port or NIC fields were added.
* `IOCTL_VERSION` is `CTL_CODE(40000, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)` and returns `[0,2,1,0]`. Shutdown uses function `0x801`. There is **no thread-ID IOCTL** or thread-ID query/printing.
* `process_id` is always **0**: this NDIS layer cannot identify a process owner. `direction=0` is guest/Sandbox outbound (host NDIS receive); `1` is guest/Sandbox inbound (host NDIS send). `local` is the guest-side endpoint and `remote` the peer. Host-send source/destination are normalized without modifying the captured packet. The 0.2.1.0 monitor rejects older SYS versions with host-oriented semantics.
* Each `CONN`/verdict refers to **one owned NBL** (an original or a deep-copied resources receive), not a process-owned socket. Unsupported/mixed batches are dropped by the driver rather than representing just their first packet as the entire batch.
* `payload_layer=3`; `payload` contains captured IP bytes (capture may be shortened). `payload_size` is the captured byte count, not the original full IP packet length. Current protocol limits are 256 captured bytes and a maximum 512-byte record.
* Device reads are **nonblocking**. A successful zero-byte read means the queue is empty, not EOF. `ReaderLoop` waits on its stop event for 10 ms before retrying. Fragmented/coalesced records are handled using bounded storage; an oversized header terminates the session rather than inventing a synchronization boundary.
* Commands retain their original **unframed** byte IDs and fixed layouts. Supported IDs are Shutdown=0, Verdict=1, ClearCache=4, GetLogs=5, GetBandwidthStats=6, PrintMemoryStats=7, CleanEndedConnections=8. UpdateV4=2/UpdateV6=3 names remain for source compatibility, but **are rejected**, as requested.
* Verdict bytes **2..7** retain Accept/PermanentAccept/Block/PermanentBlock/Drop/PermanentDrop meanings. Redirect/undecided/failed values remain named in the enum for source compatibility but cannot be written. The entire command batch is validated before any write; the driver must independently validate at its own trust boundary.
* Permanent cache TTL is **60 seconds**. Pending timeout defaults to **2 seconds**, with **fail-open by default**. No new configuration wire protocol was introduced. `--no-verdicts` or a long delayed verdict may leave a packet pending until that timeout; they do not imply indefinite blocking.
* `GetBandwidthStats` emits compatible type-5/type-6 tuple records: `transmitted_bytes` counts admitted guest outbound IP bytes and `received_bytes` admitted guest inbound IP bytes, grouped by the normalized guest/peer tuple. Records contain no PID; PID display filtering therefore suppresses them. These are guest-side admission counters on the host-vNIC path, not process/socket attribution or proof of final delivery.
* `PrintMemoryStats`/`GetLogs` use compatible `LogLine` records. `CleanEndedConnections` only sweeps expired cache state. **No fake END event** is generated for timeout, cache expiry or monitor shutdown. Legacy END/bandwidth structs and callbacks remain available for compatible real input records.

The default automatic verdict is `PermanentAccept`; `--verdict` without `--match` applies to every observed event. Block/drop decisions can interrupt target host-vNIC traffic, including remote sessions. Delayed verdicts use the existing queue and do not suspend any process. Delays do not extend the driver's pending lifetime, and unsent work is discarded at shutdown.

## Direct device transport

The monitor uses only the existing driver device. All complete raw device records are decoded and delivered to the local `Handlers`; local automatic/delayed verdicts write directly to that device. There is no named-pipe server, handshake, attached-client state, external command forwarding, trusted-client executable check, or exclusive external record ownership.

The standalone `winrpc/` source directory is not a dependency of this monitor. Removing it from a deployment or source bundle does not affect monitor targets. The driver wire format and required version remain **0.2.1.0**; this monitor-only change does not require rebuilding/reinstalling the SYS.

## Source provenance and license

These are independent copies/adaptations of the local `C:\portmaster_v3` source snapshot **`542b4e4`**:

* `kext_client\include\PortmasterKext.h`, `DelayedVerdicts.h`, `RecordOutput.h`;
* `kext_client\src\PortmasterKext.cpp`, `main.cpp`;
* `kext_client\tests\ip_address_tests.cpp`, `delayed_verdict_tests.cpp`, `record_output_tests.cpp`;

`DriverProtocol.*`, `MonitorOptions.*`, standalone CMake wiring and new codec/CLI tests were added during the HyperVGuard adaptation. The copied client's SCM lifecycle, PID suspension, thread-ID IOCTL and redirect support were intentionally removed/disabled. The monitor has no winrpc source, include, target or link dependency; the unused sibling sources are not built. No monitor source path points back to the original repository.

The original repository's **GNU GPL version 3** license is preserved verbatim as `LICENSE`; this adaptation retains that license. Source provenance does not imply that the original WFP driver's lifecycle or host process semantics apply to a host-adapter NDIS LWF.

## Device-only validation

Historical device-only snapshot (before native setup tool integration changed monitor help strings): on 2026-10-25, a fresh Release build in `build/monitor-device-only` passed **11/11 no-driver CTest suites**, including local device-session construction/cleanup and help/invalid-CLI checks that reject unsupported transport options. The compilation database and Ninja graph contain no winrpc/duplex-pipe sources, includes or link dependency. PE imports contain no named-pipe server APIs.

That snapshot executable was copied to `dist/hyperv_monitor.exe`: **94720 bytes**, SHA-256 **0737685EF30CFB12D0CA765B885672EAA4A0F024868CA2475F7188E3800D2087**. This supersedes the monitor hash in the earlier direction-fix report; driver wire version remains 0.2.1.0.

SYS, INF, CAT and the signed notify DLL in `dist/` were verified unchanged. No driver was installed, loaded or bound, no device was opened, and no live monitoring session was run. The user retains live traffic testing.

## Native setup integration

The current monitor help and unsupported-installation diagnostics point to `dist/Install.exe` rather than the removed PowerShell installer. A new Release build passed **14/14 no-driver CTest suites**, including the native setup workflow, INF and help/invalid-CLI tests. Current `dist/hyperv_monitor.exe`: **94720 bytes**, SHA-256 **6CB99E7BED9BD2825DAC12D17BFE18F80EDD5932DEE13E03BBC420DBFD2B56C9**. The driver protocol remains **0.2.1.0**; SYS/INF/CAT/notify DLL were unchanged. See [native setup validation](../install/console/README.md#offline-validation).

The later driver-store package **0.2.1.4** corrects setup/notify GUID inspection and non-PnP target lifecycle and passed **15/15** no-driver suites. Its authorized real installation completed with exit 0 and only the Default Switch binding enabled; this monitor and wire version 0.2.1.0 remain unchanged. No live monitor/traffic test was run. Current package and retry instructions: [NetCfg identity fix](../docs/NETCFG-IDENTITY-FIX.md).
