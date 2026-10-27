# HyperVXNdisFilter

Experimental Rust-based **NDIS Lightweight Filter (LWF)** and a C++ monitor with a `kext_monitor`-style API. The filter targets only the management-OS host adapter **`vEthernet (Default Switch)`**. It is not a Hyper-V switch extension or a WFP callout.

Driver package and device API: **0.3.2.0**. Connection records add the host adapter `interface_index:u32` immediately after `id:u64`. This breaks compatibility with 0.3.1.0 and earlier layouts; nonzero reads still wait for event data and support cancellation. Use a matching SYS and monitor; the monitor rejects older device versions.

Only traffic passing through the host vNIC is covered; VM-to-VM traffic is not guaranteed to be visible. The installer and kernel check the exact adapter GUID/NET_LUID, not its display name. The standalone setup tools do not automatically retarget a recreated adapter. A compatible controller can perform validated target-only recovery as described below; otherwise explicitly uninstall and reinstall.

## Build

Requires Windows x64 **build 25341+**, Hyper-V with Default Switch, Visual Studio C++ x64 tools with CMake/Ninja, Rust with the `x86_64-pc-windows-msvc` target, and WDK/SDK **10.0.28000.0**. Kernel builds are **release-only**.

Commands below use Git Bash at the repository root:

```bash
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/Build.ps1 -Test
```

This builds the package and runs offline tests without installing, loading, or binding the driver. Output goes to `dist/`: **`HyperVXNdisFilter.sys`**, `HyperVXNdisFilter.pdb`, `HyperVXNdisFilter.inf`, `HyperVXNdisFilter.cat`, `HyperVXNdisFilterNotify.dll`, `hyperv_monitor.exe`, `Install.exe`, and `Uninstall.exe`. Keep package files together; do not mix versions.

All product identities use the new name: service `HyperVXNdisFilter`, device `\\.\HyperVXNdisFilter`, startup event `Global\HyperVXNdisFilter.DriverReady`, NetCfg component `hyperv_xndis_filter`, and header-only client `HyperVXNdisFilter.hpp` / `hypervxndisfilter::Client`. The rename preserved the IOCTLs and product GUIDs; the current 0.3.2.0 Connection API additionally exposes the host adapter index; old header/namespace/device aliases are not provided. Use a clean `dist/` when rebuilding after the rename and deploy the entire new package, not individually renamed binaries. An existing installation under a previous name must first be removed with **its matching old `Uninstall.exe`**. The new installer rejects another component with the same filter GUID; it does not migrate, replace or remove it automatically.

The default build is unsigned. For signing, pass `-PfxPath` and `-RootCertificate` to the build script. The local test-PFX password defaults to `1`; a nonempty process environment variable `HYPERVXNDISFILTER_PFX_PASSWORD` overrides that default, and an explicit `-PfxPassword` overrides both (including an explicitly empty password). The script does not import certificates or change security policy. Installation requires trusted package signatures.

The separate [offline cache lookup benchmark](policy/examples/README.md) compares the actual driver cache with standard Rust `HashMap`/`BTreeMap` variants on generated IPv4/IPv6 TCP tuples within one protocol scope. Its signed user-mode runner does not build/install/open the driver or change the production cache.

## Install

Use an **elevated Administrator/SYSTEM console**, stop the monitor, and have local recovery access: network reconfiguration may interrupt connectivity. If already installed, use `Uninstall.exe` first; the installer does not replace a live driver.

```bash
./dist/Install.exe
```

The native installer reads the package beside its EXE and enables HyperVXNdisFilter only on the exact Default Switch host vNIC. `--what-if` performs read-only preflight; `--yes` skips confirmation only.

If installation returns **3010**, reboot, then resume explicitly:

```bash
./dist/Install.exe --enable
```

### Controller-managed binding recovery

`HKLM\SOFTWARE\HyperVXNdisFilter\Lwf` separates current attach admission (`AllowBindings`) from permission for runtime repair (`AutoRepairAllowed`). Setup durably writes `AutoRepairAllowed=0` before installation, resume or removal and publishes `1` only after the exact target paths have enabled successfully. A failed setup or a requested reboot remains installer-controlled; complete the reboot and explicit resume instead of overriding these flags.

A compatible controller such as FirewallX can use `AutoRepairAllowed=1` to retry a transient runtime failure, including `AllowBindings=0`, or refresh a recreated Default Switch host-vNIC GUID/LUID. It must resolve the switch through Hyper-V topology, hold the NetCfg write lock, refuse enabled foreign paths, disarm and disable only the target paths before updating identity, and revalidate before exact-target enable. A NetCfg reboot request must block subsequent automatic repair. Legacy installations without this flag are not permission to override an already disarmed configuration. Kernel GUID/LUID and notify-object gates remain unchanged; no new service is needed. NetCfg enabled state alone is not proof of a running NDIS module.

## Monitor

Start with the default PermanentAccept policy:

```bash
./dist/hyperv_monitor.exe --duration 15 --timestamps --memory-stats --out allow.log
```

Block only a test remote endpoint:

```bash
./dist/hyperv_monitor.exe --duration 10 --match 192.0.2.10:9000 --verdict permanent-block --out block.log
```

For an interactive session, omit `--duration` and exit with **Ctrl+C**:

```bash
./dist/hyperv_monitor.exe
```

Without `--duration`, an open failure makes the monitor create/open `Global\HyperVXNdisFilter.DriverReady` and wait for driver startup. Ctrl+C also cancels this wait. With a positive `--duration N`, it never waits for startup: an open failure exits immediately; a successful session stops after N seconds. Use `--duration` for automated/live tests; zero, negative and malformed values remain invalid.

The monitor prints `Filtered network devices: N (running NDIS modules)` after the version check and whenever the count changes, checking at the `--poll` interval (default 1000 ms). This is the driver's live attachment/running-state count, not the number of configured or enabled bindings. A loaded driver can report zero. Status lines honor `--out` and `--timestamps`. If the installed SYS lacks the new IOCTL or a query fails, the monitor warns that the count is unavailable rather than reporting zero; monitoring continues and later polls retry.

At startup it also prints `Attached network adapters: N` and one `[ADAPTER]` block per attached module: names, host indices/GUID/LUIDs, running state, MAC, media/link/duplex, speeds, MTU and available general NDIS attributes. Paused modules remain visible as not-running. Unknown fields and truncated names are labelled explicitly. This one-time diagnostic honors `--out`/`--timestamps`; an unavailable query warns without stopping monitoring. See the complete snapshot API below.

Each `[CONN v4]` / `[CONN v6]` header prints `interface_index=N` immediately after `id`, in both console output and `--out` files. This is the host adapter index from that event, not a guest interface index; traffic from different adapters retains its own value.

`--match` selects the remote endpoint in both directions; unmatched events receive PermanentAccept. `--filter-ip` only filters output, not verdicts. A blocking verdict without `--match` applies to every event and can disconnect the host-vNIC path.

The monitor never installs, unbinds, or uninstalls the filter. Exiting closes the policy session; the LWF remains installed and bound. Use `--help` for all options without opening the device.

## Remove

Stop the monitor, then run from an elevated console:

```bash
./dist/Uninstall.exe
```

Uninstall first disarms and removes the `hyperv_xndis_filter` NetCfg component, then removes **all identified HyperVXNdisFilter driver-package versions** from Driver Store, including old `HyperVXNdisFilter.sys` copies under `FileRepository`. Windows driver-installation APIs perform the deletion; the program never takes ownership of Driver Store folders or deletes them manually. Package ownership is checked from the original INF name, NetService class, every component model, filter instance GUID, and service/SYS identity, without requiring the current package version. Unrelated driver packages are not selected.

`--what-if` lists matching published OEM INFs without changing system state. Cleanup also works when the component is already absent and only old staged packages remain. Exit **0** requires a fresh inventory with no matching packages; partial failure is reported, not ignored. If component/package removal returns **3010**, reboot and run `Uninstall.exe` again before reinstalling. Busy packages are never forcibly deleted; no manual SCM service creation/deletion is needed.

## API

The public C++ interface is [PortmasterKext.h](monitor/include/PortmasterKext.h), namespace `pmkext`. The wire codec is [DriverProtocol.h](monitor/include/DriverProtocol.h); driver-side event/command encoding is defined in [protocol/src/lib.rs](protocol/src/lib.rs), with the separate adapter-snapshot codec in [adapter_info.h](driver/shim/adapter_info.h).

### Semantics and compatibility

- **ConnectionIpv4/ConnectionIpv6 have no `process_id` field.** The `interface_index:u32` after `id` identifies the host adapter at the interception point (`BaseMiniportIfIndex`), not an interface inside the guest. It is retained per attached module, so interleaved traffic from different adapters keeps its own index. There is no compartment/sub-interface ID, TID, switch/port/GUID/LUID field, and no host-process or individual-VM ownership is inferred. Interface indices can change or be reused after adapter recreation; they are not permanent identities. Existing exact-target binding restrictions are unchanged. Unused legacy END compatibility records retain their zero PID.
- `direction=0` is **guest/Sandbox outbound**, corresponding to host NDIS receive. `direction=1` is **guest/Sandbox inbound**, corresponding to host NDIS send. `local_*` describes the guest endpoint; `remote_*` describes the peer. NAT/forwarding can affect the addresses visible on this path.
- One connection event and its `id` represent **one pending NBL**, not a socket or a connection lifetime. A homogeneous multi-NB NBL has one verdict and the complete IP packet from its first NB, not a concatenation of all NBs. Mixed-flow or malformed batches are dropped rather than represented as one flow.
- `payload_layer=3`. `payload` contains the **complete observed IP packet**, including IP/transport headers, without Ethernet/VLAN headers or Ethernet padding. `payload_size` is its full byte count. No 256-byte capture truncation remains. Endpoint normalization does not rewrite packet bytes. For LSO/RSC, this is the logical packet observed at NDIS, not necessarily one frame on the wire.
- Non-IP traffic such as ARP does not produce connection events and is passed when its ownership/profile is supported. Cache hits are handled in the kernel without a new verdict event.
- Redirect verdicts, UpdateV4/V6, PID suspension, and a thread-ID IOCTL are **unsupported**. Some enum names remain in the C++ header only for source compatibility.
- NDIS has no socket/ALE teardown notification. **Connection-END events are never generated**, including on cache expiry, timeout, or disconnect.

Connection payloads are bounded at **1 MiB (1048576 bytes)**, covering ordinary IPv4/IPv6 packets and supported larger offload packets. Larger logical packets are dropped rather than reported with truncated payloads. Queued records and in-progress capture allocations share a **16 MiB nonpaged budget**; the event queue also has a 16 MiB byte limit, 512 record slots and 256 pending verdict slots. Event-buffer exhaustion follows the configured policy fallback without publishing a shortened event. Failed NDIS buffer copies remain drop paths. `--filter-pid` is no longer supported.

This is experimental kernel code. Offline tests and an enabled binding do not prove correct live filtering.

### Device session and IOCTLs

Open **`\\.\HyperVXNdisFilter`** as Administrator/SYSTEM with `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and exclusive sharing. The C++ client uses `FILE_FLAG_OVERLAPPED`; nonzero buffered reads wait for event bytes and are cancellable. Only **one controller** may hold the device. There is no named-pipe/winrpc transport.

Opening the device activates a policy session and resets its event queue, permanent cache, and bandwidth buckets. The client must verify the device version before relying on the protocol. `Driver::Open` only opens the session; the monitor separately checks the version.

All supported IOCTLs use `CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)` and take no input buffer:

| IOCTL | Function / numeric code | Output and effect |
|---|---|---|
| `IOCTL_VERSION` | `0x800` / `0x9C40E000` | Exactly four bytes: `00 03 02 00`. The output buffer must have at least four bytes. |
| `IOCTL_SHUTDOWN` | `0x801` / `0x9C40E004` | No output. Deactivates the policy session, discards queued events/cache/bandwidth, and resolves pending packets through the configured fallback. Does not unload, unbind, or uninstall the LWF. |
| `IOCTL_FILTERED_DEVICE_COUNT` | `0x802` / `0x9C40E008` | Exactly four bytes: an unsigned 32-bit little-endian count of running NDIS filter modules. The output buffer must have at least four bytes; input must be empty. No policy or binding side effects. |
| `IOCTL_ADAPTER_INFO` | `0x803` / `0x9C40E00C` | Versioned snapshot of every attached module, including not-running modules, with host adapter identity, names, MAC, link and general NDIS attributes. Empty input; allocate **56336 bytes** for the maximum reply. No policy, OID or binding side effects. |

The count includes only modules admitted by the kernel target gate that successfully restarted and have not begun pausing. Merely configured, rejected, attached-but-paused, failed-restart and detached modules do not count. Pause removes a module immediately, even while outstanding NBLs are draining; a later successful restart adds it again. The snapshot is independent of the controller's policy-session state, so shutdown does not reset it. It describes active interception on adapters, not packet delivery, link connectivity or proof that traffic was observed. Current target isolation normally allows zero or one running device. Polling can miss brief transitions.

All other IOCTLs are unsupported. After shutdown, close and reopen the handle to activate a new session. Closing the active handle also disconnects the controller and drains pending decisions. Shutdown does not itself close the handle or stop a custom application's read loop.

Reads return an event byte stream, at most **65536 bytes per driver read**. A nonzero read remains pending until bytes exist; it never succeeds empty merely because the queue is empty. Zero-length requests still complete with zero bytes. The cancel-safe queue allows at most 16 waiting reads; excess requests fail with `STATUS_DEVICE_BUSY`. Shutdown, cleanup and unload cancel waiting reads; new reads after session shutdown fail until close/reopen. `CancelIoEx` cancels a waiting read, but cancellation can race a successful completion. Always reap an outstanding OVERLAPPED operation before freeing its buffer/event. Reads can split a record or contain multiple records; retain incomplete bytes between reads. No read-polling delay is needed. A work item copies queued bytes and completes requests outside the policy/NDIS locks; stale-only queues leave the read pending instead of returning zero.

### Adapter information snapshot

`IOCTL_ADAPTER_INFO` is an additive diagnostic: event/command wire version remains **0.3.2.0**. Earlier SYS builds with that same event version may not support it; treat an unsupported/failed query as **unavailable**, never as an empty adapter list. At startup, after checking the device version, the monitor prints this snapshot once, respecting `--out` and `--timestamps`. It warns and continues monitoring if the query fails. The separate running-device count still updates at `--poll` intervals; the two queries can observe different instants.

The snapshot lists only modules accepted by the existing exact-target attach gate, not all Windows adapters or configured bindings. A module remains listed while attached but initially paused, pausing, or after a failed restart; flag `Running` means its admission gate is open. Detached modules disappear. `module_id` is an ephemeral internal module identifier, distinct from every Windows interface index/LUID. Interface identities describe the **host NDIS stack**, not guest adapters, switch ports or VM ownership. GUIDs/LUIDs are diagnostic only and do not broaden binding authorization.

The driver copies names and current MAC at attach, captures general attributes supplied during successful restart, and updates link state/speeds from valid `NDIS_STATUS_LINK_STATE` indications. Fields describe the **last NDIS-supplied values**, not a fresh hardware/OID interrogation. A new restart without general attributes retains the last supplied general values. The base connector flag is available only with attach revision 4. `LinkStateValid` indicates that auto-negotiation flags were supplied by a link-state indication; initial connection/duplex/speeds already come from attach. Speeds are bits/s; `UINT64_MAX` means unknown under the NDIS convention. `PauseValid` reports the last observed pause reason/flags, even after restarting. Pointer-bearing capabilities, kernel handles/addresses, IP configuration, routes, process/guest identities and arbitrary OID data are not exported.

The reply is **not an event record**. Its explicit byte codec is [adapter_info.h](driver/shim/adapter_info.h); do not serialize native structures. All integers and UTF-16 code units are little-endian. The first 16 bytes are four `u32` values:

| Offset | Field | Value |
|---:|---|---|
| 0 | Schema version | `1`, independent of the device/event version. |
| 4 | Entry size | `1760` bytes. |
| 8 | Attached module count | `0..32`. |
| 12 | Running module count | Number of entries with flag `Running`; `0..count`. |

Exactly `count` entries follow. Successful output length is **`16 + count * 1760`**, at most **56336** bytes; zero modules is a successful 16-byte reply. The whole list, entry state and running count are protected by one diagnostic lock, including detach lifetime. Nonempty input fails with `STATUS_INVALID_PARAMETER`. An output buffer smaller than the **complete current snapshot** fails with `STATUS_BUFFER_TOO_SMALL`, with no partial list or successful size-only response; use the fixed maximum to avoid probe/retry races. No kernel allocation is needed for the query. The existing exclusive Administrator/SYSTEM device access requirement applies, including after policy shutdown while the handle remains open.

Entry offsets are relative to each 1760-byte entry. C++ `AdapterInfo` has the following fields; header-only `Client::AdapterInfo` exposes the same data. These are owning decoded types, **not** native wire-layout views:

| Offset | C++ field(s) | Wire format / source |
|---:|---|---|
| 0 | `module_id` | `u64`, driver module identity. |
| 8, 12, 16 | `interface_index`, `filter_interface_index`, `lower_interface_index` | Three `u32`: base miniport (matches connection events), filter, and lower interface indices. |
| 20 | `flags` | `u32`, validity/state/truncation bits below. |
| 24, 32, 40 | `interface_luid`, `filter_interface_luid`, `lower_interface_luid` | Three `u64`, corresponding NET_LUID values. |
| 48 | `interface_guid` | 16 bytes: Windows GUID field order (`Data1:u32 LE`, `Data2:u16 LE`, `Data3:u16 LE`, `Data4[8]`). C++ uses `std::array<uint8_t,16>`. |
| 64, 68 | `media_type`, `physical_medium` | Two `u32`, NDIS medium / physical-medium enum values. |
| 72, 76 | `media_connect_state`, `media_duplex_state` | Two `u32`: connect unknown/connected/disconnected=`0/1/2`; duplex unknown/half/full=`0/1/2`. |
| 80, 88 | `xmit_link_speed`, `rcv_link_speed` | Two `u64`, last known TX/RX link speeds in bits/s. |
| 96, 100, 104, 108 | `mtu`, `mac_options`, `supported_packet_filters`, `max_multicast_list_size` | Four `u32`, general restart attributes; MTU in bytes, option/filter values are bitmasks. |
| 112, 120 | `max_xmit_link_speed`, `max_rcv_link_speed` | Two `u64`, general maximum TX/RX speeds in bits/s. |
| 128, 132, 136, 140 | `lookahead_size`, `access_type`, `connection_type`, `supported_statistics` | Four `u32`, general restart attributes: bytes, NET_IF access/connection enums, statistics bitmask. |
| 144, 148, 152, 156 | `data_backfill_size`, `context_backfill_size`, `restart_flags`, `attach_flags` | Four `u32`: backfill byte counts, general restart flags, attach flags. |
| 160, 164 | `connector_present`, `mac_address_length` | Two `u32`: `0/1` (only meaningful with connector-valid flag), MAC length `0..32`. |
| 168 | `mac_address` | 32 bytes, zero-padded; C++ `std::array<uint8_t,32>`, first `mac_address_length` bytes are meaningful. |
| 200, 204, 208 | `instance_name_length`, `base_name_length`, `filter_module_name_length` | Three `u32` UTF-16 **code-unit** counts `0..255`, excluding the terminator. Equal to the corresponding decoded string lengths. |
| 212, 216, 220 | `auto_negotiation_flags`, `pause_reason`, `pause_flags` | Three `u32`, meaningful with link-state / pause validity flags. |
| 224, 736, 1248 | `instance_name`, `base_name`, `filter_module_name` | Three 256-code-unit UTF-16LE arrays: `BaseMiniportInstanceName`, `BaseMiniportName`, `FilterModuleGuidName`. Each has a NUL at its counted length and zero-filled tail; C++ decodes to `std::wstring`. Empty means unavailable/empty. |

| Flag | Bit | C++ `AdapterInfo::` constant |
|---|---:|---|
| Admission open | `0x01` | `Running` |
| General restart fields available | `0x02` | `GeneralAttributesValid` |
| Connector-present field available | `0x04` | `ConnectorPresentValid` |
| Instance/base/filter-module name truncated | `0x08` / `0x10` / `0x20` | `InstanceNameTruncated` / `BaseNameTruncated` / `FilterModuleNameTruncated` |
| Link-state indication received | `0x40` | `LinkStateValid` |
| Pause reason/flags available | `0x80` | `PauseValid` |

Names longer than 255 UTF-16 code units are bounded explicitly, with the corresponding truncation bit; truncation never splits a surrogate pair. Unknown numeric NDIS enum values are preserved. Clients validate schema/entry sizes, exact total length, counts, flags, MAC length and counted-string bounds/terminators before publishing any result. On failure the caller's snapshot is unchanged. `AdapterSnapshot` contains `uint32_t running_count` and `std::vector<AdapterInfo> adapters`; an empty vector is meaningful only after a successful query. Monitor names are UTF-8 with control bytes escaped, and unavailable general/connector/auto-negotiation fields are labelled unknown rather than reported as real zeros.

### Driver-start notification

`Global\HyperVXNdisFilter.DriverReady` (kernel name `\BaseNamedObjects\HyperVXNdisFilter.DriverReady`) is a named manual-reset event, separate from the device byte stream and IOCTLs. New objects allow access only to Administrator/SYSTEM. At startup, after initializing the control device and timer, the driver creates/opens the event, signals it, and keeps its handle until unload; unload clears the event and closes the handle. This requires the updated SYS, not just the monitor. Event creation is best-effort if the global object directory is not yet available during early system boot; device initialization does not depend on notification success.

Only the console monitor's **unlimited mode** uses startup waiting. It first tries `Driver::Open`. On failure it creates/opens the event, clears it **before** retrying the device, and waits only if that retry also fails. A signal causes another reset/retry; a stale signal cannot cause a busy loop. Wait timeouts check Ctrl+C at 100 ms intervals without polling the device. A signal is only a retry hint, not proof of successful NDIS attachment, device authorization, compatible version or packet interception. The monitor never installs or loads the LWF while waiting; another application releasing an exclusive device handle does not itself generate a startup signal. No automatic reconnect is added after an established session ends.

### C++ client methods

Construct `Driver(std::wstring service_name = L"HyperVXNdisFilter")`; the argument selects the device basename, not a service to create. The class is non-copyable. Boolean methods report failures through `std::string& error`; sending a request does not imply a synchronous event response or confirmation that a verdict was applied.

| Method | Contract |
|---|---|
| `bool Open(std::string& error)` | Opens the already installed device. Fails if this client session is already open. Does not install, bind, or negotiate the version. |
| `bool GetVersion(uint8_t out[4], std::string& error)` | Reads the four-byte version; integrations should require `0.3.2.0`. |
| `bool GetFilteredDeviceCount(uint32_t& out, std::string& error)` | Synchronously reads the running-module snapshot through `IOCTL_FILTERED_DEVICE_COUNT`. Requires exactly four response bytes. On failure returns false and leaves `out` unchanged; an unsupported request means unavailable, not zero. |
| `bool GetAdapterInfo(AdapterSnapshot& out, std::string& error)` | Synchronously reads and validates the bounded attached-module snapshot described above. Includes not-running modules; owning strings/arrays remain valid after return. Leaves `out` unchanged on failure, including malformed output or allocation failure. |
| `void Run(const Handlers& handlers, unsigned poll_interval_ms = 1000)` | Starts a reader thread and blocks until stopped or the reader exits. Dispatches complete records and invokes `on_poll` on the calling thread. It does not automatically request logs/statistics or send verdicts. |
| `bool SendVerdict(uint64_t id, Verdict verdict, std::string& error)` | Sends one verdict for a pending event ID. Only verdict values 2–7 are accepted. |
| `bool RequestLogs(std::string& error)` | Sends `GetLogs`; existing log events are already queued for reading. |
| `bool RequestBandwidthStats(std::string& error)` | Requests asynchronous bandwidth records for active buckets. No active buckets means no bandwidth records. |
| `bool RequestMemoryStats(std::string& error)` | Requests a diagnostic `LogLine` with policy storage/counter statistics. |
| `bool RequestCleanEndedConnections(std::string& error)` | Requests a full asynchronous expiry sweep, coalesced with driver-scheduled cleanup. Does not migrate tables, discover socket teardown or emit END events; successful write does not acknowledge sweep completion. |
| `bool RequestClearCache(std::string& error)` | Invalidates all permanent verdict entries. Does not answer pending NBLs. |
| `bool RequestShutdown(std::string& error)` | Issues `IOCTL_SHUTDOWN`; does not signal the `Run` stop event or close the handle. |
| `void Stop()` | Signals `Run` and requests shutdown once. Safe to call from callbacks or another thread while `Run` is active. |
| `void Cleanup()` | Calls `Stop`, closes session handles, and resets the record parser. Join/return from `Run` before calling it or destroying the object. The destructor also calls `Cleanup`. |
| `bool Install(const std::wstring& sys_path, std::string& error, bool inbound_udp_pid_fallback = true)` | Compatibility stub: always returns an unsupported-operation error. Use the native installer instead. Neither argument enables a driver-loading or PID-fallback path. |

A typical integration opens the device, checks its version, installs handlers, answers `on_connection` events, and uses `on_poll` for periodic requests and a positive runtime deadline. Call `Stop`, wait for `Run` to finish, then call `Cleanup`. Keep callbacks short enough to answer before the pending timeout.

### Lightweight header-only client

[HyperVXNdisFilter.hpp](monitor/include/HyperVXNdisFilter.hpp) provides the separate **`hypervxndisfilter::Client`** namespace/API. Include just that file in a Windows x64 **C++20** application; no `pmkext` sources, codec, or client library are needed. It uses Kernel32 and Advapi32 (MSVC links Advapi32 through the header's pragma; other toolchains must link it explicitly). A compiled example is [callback_client.cpp](monitor/examples/callback_client.cpp), built as `build/monitor/callback_client.exe`. The example opens a real device if explicitly run; offline tests never run it.

`Run` uses one caller-owned thread: it blocks on overlapped read completion, Stop, or an optional runtime deadline. There is no second reader/poll thread, idle read polling, automatic statistics timer, or automatic verdict. The receive buffer is allocated once per Run; reads go directly into it. Connection headers, payloads, bandwidth arrays and log-message views borrow that storage: no per-event structure reconstruction, allocation or payload copy. Bandwidth dispatch calls once per nonempty record, not once per tuple. A head/tail cursor retains partial frames in place; compaction happens only when the writable tail is short, not after every read. Callback function pointers plus a `void*` context avoid type-erasure/capture allocations. Copy the actual data (not just its pointer) if it must outlive the callback. This minimizes idle wakeups and hot-path work, not a measured guarantee of zero CPU usage.

| Method | Contract (`DWORD`: 0 is success, otherwise a Win32 error) |
|---|---|
| `Open()` | Tries the existing exclusive Administrator/SYSTEM device. An exclusive-device `ERROR_SHARING_VIOLATION` is returned immediately on any attempt; the caller may retry after the other controller releases its handle. After any other open failure, creates/opens the protected `Global\HyperVXNdisFilter.DriverReady` event, resets it before retrying, then waits **indefinitely**, without device polling or a startup timeout. A signal only requests a retry. `Stop()` cancels this wait with `ERROR_OPERATION_ABORTED`. Never installs/loads the driver. Requires version `{0,3,2,0}` after opening; version/I/O errors are returned rather than treated as startup signals. |
| `Run(const Callbacks&, DWORD duration_ms = INFINITE)` | Blocking callback dispatch on the calling thread. A positive duration limits monitoring only, **not Open's unlimited startup wait**; zero is invalid. Stop/runtime expiry returns success after cancelling/reaping the outstanding read. Unexpected zero-byte reads are an error, not a retry loop. Callback exceptions propagate after pending I/O is reaped. |
| `Stop()` | Thread-safe local stop, usable during Open/Run; wakes the wait. Does not itself shut down policy, close handles or unload the LWF. |
| `Close()` | Returns `ERROR_BUSY` during Run. Otherwise closes handles; device cleanup disconnects policy and releases pending packets through fallback. Join Run and all other callers before Close/destruction. |
| `GetVersion(std::array<uint8_t,4>&)` / `GetFilteredDeviceCount(uint32_t&)` | Synchronous IOCTL queries; exact four-byte replies. Outputs are unchanged on failure. |
| `GetAdapterInfo(AdapterSnapshot&)` | Synchronous bounded attached-module query, including not-running modules. Owning `Client::AdapterSnapshot` / `Client::AdapterInfo` types have the fields and validity flags documented above. Leaves output unchanged on failure; malformed replies return `ERROR_INVALID_DATA`, allocation failure returns `ERROR_NOT_ENOUGH_MEMORY`. |
| `SendVerdict(uint64_t id, Verdict)` | Sends the fixed ten-byte verdict; values 2..7 only. No verdict-application acknowledgement. |
| `Send(Command)` | Single-byte ClearCache=4, GetLogs=5, GetBandwidthStats=6, PrintMemoryStats=7 or CleanEndedConnections=8. No automatic scheduling. |
| `Shutdown()` | Calls Stop and issues the policy shutdown IOCTL. Does not close, unload or unbind. |

`Callbacks` contains optional function pointers and their shared `context`:

| Callback | Arguments after `void* context` |
|---|---|
| `on_connection_v4` | `const ConnectionV4* header, const uint8_t* payload, uint32_t payload_size` |
| `on_connection_v6` | `const ConnectionV6* header, const uint8_t* payload, uint32_t payload_size` |
| `on_log` | `uint8_t severity, std::string_view message` |
| `on_bandwidth_v4` | `uint8_t protocol, const BandwidthV4* entries, uint32_t count` |
| `on_bandwidth_v6` | `uint8_t protocol, const BandwidthV6* entries, uint32_t count` |

Every header/array/payload pointer refers directly to the validated input buffer and expires when the callback returns. The callback table/context must remain alive throughout Run. Callbacks may send commands/verdicts or call Stop; do not close/destroy the client from a callback. Open/Close are not concurrent operations; only Stop is supported during startup, and commands may run concurrently once Open has succeeded. Slow callbacks still delay verdicts and shutdown.

| Packed type (`Client::`) | Size / fields in wire order |
|---|---|
| `ConnectionV4` / `ConnectionV6` | 27 / 51 bytes: `id:u64`, `interface_index:u32`, `direction:u8`, `protocol:u8`, `local_ip[4/16]`, `remote_ip[4/16]`, `local_port:u16`, `remote_port:u16`, `payload_layer:u8=3`. The following four-byte payload length is validated and passed separately with the complete-IP payload pointer. |
| `BandwidthV4` / `BandwidthV6` | 28 / 52 bytes per entry: `local_ip[4/16]`, `local_port:u16`, `remote_ip[4/16]`, `remote_port:u16`, `transmitted_bytes:u64`, `received_bytes:u64`. One callback receives the entire contiguous array; an empty array produces no callback. |

These fixed, trivially-copyable wire views use scoped `#pragma pack(push, 1)` / `pop`, with compile-time size, alignment and offset checks. All numbers are little-endian (native on supported Windows x64); addresses remain network-order bytes. Read packed scalar fields by value; do not pass a field's address/reference to an API expecting naturally aligned integers. IPv4/IPv6 is selected by the callback type, not an added `ipv6` field; no PID/thread ID is present. Guest direction and all policy/fallback semantics are unchanged. `Verdict` contains Accept=2, PermanentAccept=3, Block=4, PermanentBlock=5, Drop=6 and PermanentDrop=7.

**C++ source migration:** the former unified `on_connection(const Connection&)` and per-tuple `on_bandwidth(const Bandwidth&)` callbacks are replaced by the IPv4/IPv6 pointer callbacks above. Update consumers as in [callback_client.cpp](monitor/examples/callback_client.cpp); both clients now require wire version **0.3.2.0** and decode the added host adapter index. Older SYS/client generations must not be mixed.

For offline adapter replies, `Client::DecodeAdapterInfo(Bytes, AdapterSnapshot&)` performs the same owning validation/decoding as `GetAdapterInfo`, without device access. Its limits are `AdapterInfoVersion=1`, `AdapterInfoHeaderSize=16`, `AdapterInfoEntrySize=1760`, `MaxAdapters=32`, `AdapterNameCapacity=256`, `AdapterMacCapacity=32`, `MaxAdapterInfoSize=56336`. The `Client::Adapter*` flag constants correspond to the `AdapterInfo::` aliases above, with `AdapterKnownFlags=0xff`.

For offline/custom transports, `Client::DispatchRecord(Bytes, callbacks)` validates one complete record before exposing any packed views. The optional `Client::Stream` helper exposes a writable `Buffer()` (at most 65536 bytes), `Commit(written, callbacks)`, `PendingBytes()` and `Reset()`; an invalid stream stays failed until Reset. Fill the latest Buffer and Commit it before asking for another; Buffer may compact storage, so do not retain its pointer across calls. Record size is bounded by `MaxRecordSize=1048636`, payload by `MaxPayloadSize=1048576`, read size by `ReadSize=65536`. Legacy connection-END types are not exposed by this client: the driver never generates them.

### Callbacks and data types

All `Handlers` members are optional:

| Callback | Argument / execution context |
|---|---|
| `on_connection` | `const Connection&`, on the reader thread. Use `id` when sending a verdict. |
| `on_connection_end` | `const ConnectionEnd&`, compatibility decoder callback on the reader thread; this driver never emits the corresponding records. |
| `on_log` | `const LogLine&`, on the reader thread. |
| `on_bandwidth` | `const BandwidthStats&`, on the reader thread. |
| `on_warning` | `const std::string&`, client-side I/O/protocol diagnostics; may run on the reader or `Run` thread. Not a driver log record. |
| `on_poll` | No arguments, on the thread calling `Run`, once per poll iteration. |

Callback arguments are temporary; copy data needed after the callback returns. Synchronize state shared between reader callbacks and `on_poll`.

| Type | Public fields |
|---|---|
| `Connection` | `bool ipv6`; `uint64_t id`; `uint32_t interface_index`; `uint8_t direction, protocol`; `uint8_t local_ip[16], remote_ip[16]`; `uint16_t local_port, remote_port`; `uint8_t payload_layer`; `uint32_t payload_size`; `std::vector<uint8_t> payload`. |
| `ConnectionEnd` | `bool ipv6`; `uint64_t process_id`; `uint8_t direction, protocol`; `uint8_t local_ip[16], remote_ip[16]`; `uint16_t local_port, remote_port`. No verdict ID or payload. |
| `LogLine` | `Severity severity`; `std::string message`. |
| `BandwidthEntry` | `bool ipv6`; `uint8_t local_ip[16]`; `uint16_t local_port`; `uint8_t remote_ip[16]`; `uint16_t remote_port`; `uint64_t transmitted_bytes, received_bytes`. |
| `BandwidthStats` | `uint8_t protocol`; `std::vector<BandwidthEntry> entries`. |

IP arrays contain network-order address bytes. IPv4 uses the first four bytes; the C++ decoder leaves the remaining bytes zero. `ipv6` is derived from the record type, not a separate wire field. `protocol` is the IP protocol number, for example 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6. Transport ports are zero where unavailable/not applicable.

`Connection`, `ConnectionEnd`, and `BandwidthEntry` provide `LocalIpString()` and `RemoteIpString()`. `Connection::PayloadHexString()` produces lowercase hexadecimal without separators. Additional helpers are `FormatIpv4`, `FormatIpv6`, `NormalizeIpAddress`, `ProtocolToString`, `DirectionToString`, `PayloadLayerToString`, and `ToString` overloads for `Verdict`, `Severity`, and `InfoType`.

### Verdicts, timeout, and caching

| `Verdict` | Byte | Effect |
|---|---:|---|
| `Accept` | 2 | Allow this NBL. |
| `PermanentAccept` | 3 | Allow and cache the TCP/UDP tuple decision when cacheable; matching cache hits refresh its idle TTL. |
| `Block` | 4 | Silently discard this NBL. |
| `PermanentBlock` | 5 | Discard and cache the TCP/UDP tuple decision when cacheable. |
| `Drop` | 6 | Silently discard this NBL; same data-path action as Block. |
| `PermanentDrop` | 7 | Discard and cache the TCP/UDP tuple decision when cacheable. |

No TCP RST or ICMP rejection is generated. `Undecided=0`, `Undeterminable=1`, `RedirectNameServer=8`, `RedirectTunnel=9`, `Failed=10`, and `RedirectSplitTunnel=11` are not accepted as verdicts.

Pending decisions have a **8000 ms default deadline**, measured from classification, not from when an application reads the event. The driver checks timeouts every **1 second only while pending NBLs exist**, so fallback may run up to roughly one additional check interval after the deadline, plus DPC scheduling delay. Verdicts are still checked against the actual deadline and applied immediately when valid; they do not wait for the timer. The default fallback is **fail-open** on missing controller, disconnect/shutdown, timeout, or policy queue pressure. Pause/invalidated attachments, malformed packets, unsupported copy metadata, and unsafe ownership/copy-allocation cases can still be dropped regardless of fail-open.

A permanent decision is a **TTL cache entry for TCP/UDP only**, not lifetime socket permission. **Every host `interface_index` has four independent, dynamically growing hash tables: TCP/IPv4, UDP/IPv4, TCP/IPv6, and UDP/IPv6.** There is no configured maximum entry count and no capacity-driven eviction of live decisions. Other IP protocols (including ICMP/ICMPv6) never create or use permanent entries: a permanent verdict applies only to that NBL, and the next packet still needs a decision.

Within each table, the 64-bit lookup hash and full entry identity depend **exclusively on normalized `local_ip, local_port, remote_ip, remote_port`**. IPv4 uses four address bytes and IPv6 all sixteen. Full-tuple comparison resolves hash collisions. `interface_index`, transport protocol, and IP family select the table and are **not** part of its hash or stored tuple. NDIS path/direction, VLAN, module ID, epoch, and Ethernet MAC addresses are **not additional key fields or equality guards**. Both directions and different VLANs share a decision when their normalized guest/peer tuples match **within the same interface, protocol, and IP family**. TCP and UDP never share entries, even with identical IP addresses and ports; different interface indices and IP families are also independent.

Tables use a `no_std` SwissTable-style lookup: separate control bytes, 16-byte SSE2 groups on x64 with seven-bit hash fingerprints, triangular group probing, and a fast rotate/XOR/multiply word hash. Fingerprints only select candidates; full tuples still determine equality. The deterministic hash is not keyed protection against adversarial collisions. No standard-library map, AVX, or x87 is used in the driver. Baseline integer SSE2 follows Windows x64 compiler/ABI state preservation; no explicit extended-state save/restore is needed.

Table storage uses fallible nonpaged allocations **separate from the 16 MiB packet-event allocation budget**. Allocation/control-byte initialization and retired-table frees occur outside the policy spin lock. Growth/compaction is requested at 75% live/used load, preserving empty slots without evicting live entries. Migration advances only in the insertion path, at most 32 old-table slots per step, never from a background timer; ordinary insertion does not sweep expired entries. A cache hit performs one cache lookup on the normal driver path (also checking the old table while migration is active) and needs no event capture/allocation.

Every **10 seconds while nonempty cache banks exist**, the driver requests a **full expiry sweep of all four TCP/UDP IPv4/IPv6 caches of every candidate interface, including current and previous tables**. A system work item completes all ranges in the same cleanup run, not across later timer ticks. It releases the policy spin lock between ranges of at most 256 slots per table and frees retired buffers unlocked; control-group masks skip empty/deleted slots. One fixed expiry cutoff is taken at the start of the run. Concurrent refreshes and newly applied decisions remain valid, and growth cannot hide decisions already expired at that cutoff. Timer and explicit cleanup requests are coalesced so full scans do not overlap. Unload waits for queued/running cleanup work.

Expired entries stop matching immediately, independently of physical cleanup. The pending timer never services caches. Both timers are cancelled when their candidates disappear, are not reset on every packet/hit, and are not armed at idle startup; constant-time pending counts/cache-bank bits avoid candidate scans in the packet path. The monitor does not schedule cache cleanup. `CleanEndedConnections` is an optional explicit asynchronous request for the same full sweep; a successful command write does not acknowledge sweep completion.

Memory is not infinite: if table allocation/growth fails, the current packet still receives its requested verdict, but no new cache entry is retained and later traffic requires another decision. Existing live entries remain intact; `PrintMemoryStats` reports aggregate `cached_v4`, `cached_v6`, `cache_bytes` and `cache_alloc_fail` across interfaces (the per-family counts sum TCP and UDP). The latter counts failed cache insertions, not just allocator calls.

The default TTL is **60000 ms**. `PermanentAccept` uses a **sliding idle timeout**: the initial deadline is set when the verdict is applied, and each cacheable TCP/UDP packet actually admitted by that still-valid entry resets the deadline to its classification time plus `CacheTtlMs`. Either direction refreshes the matching tuple in that protocol-specific table; TCP traffic cannot refresh a UDP entry or vice versa. Preliminary cache checks and uncacheable packets do not refresh it. At or after the deadline, a packet needs a new decision rather than reviving the expired entry. `PermanentBlock` and `PermanentDrop` retain a **fixed TTL from verdict application**; matching traffic does not extend them.

Fragments, offloaded/incomplete transport headers, and multi-NB batches cannot seed or refresh permanent entries. Clear-cache and a new/disconnected controller session reset all four tables on every interface. Pause/attachment invalidation or detach immediately disables and discards all four caches of the affected interface; table storage is freed outside the policy lock. Other interfaces retain their entries. A recreated/reused interface starts without the prior cache.

Pending policy context identifies its NDIS interface **only by `interface_index`**; verdict processing stores or checks no adapter/module ID, epoch, path, or VLAN. Each attached index must be nonzero and unique. Pause/detach explicitly invalidates existing pending IDs for that index before draining their tokens, so restarting or reusing the index cannot revive an old request. The opaque C-shim token retains the original NBL owner and send/receive completion route; that ownership metadata is not a verdict identity or cache guard. Send cancellation uses an optional cancellation ID scoped to the interface; receive tokens are not send-cancellable. Diagnostic `module_id` remains available in adapter snapshots only.

Optional service `Parameters` values, all `REG_DWORD`, are read when the SYS loads: `DecisionTimeoutMs=8000` (clamped to 100–60000), `CacheTtlMs=60000` (1000–300000), and `FailClosed=0` (nonzero changes the controller/timeout/queue fallback to drop). These are driver configuration, not protocol commands.

Late, duplicate, unknown, cancelled, or already-completed IDs are harmless no-ops: a successful verdict write is **not an acknowledgement that the NBL still existed**. Such writes do not create cache entries. There is no per-verdict response record.

### Event framing and layouts

Events use explicit byte encoding, never native C++/Rust structure layout:

```text
[type:u8][body_size:u32 LE][body:body_size bytes]
```

The header is five bytes. `body_size` excludes the header; a complete record is at most **1048636 bytes** (`1 MiB + 60`, the IPv6 prefix). The IPv4 prefix is 36 bytes. Log records retain their separate 512-byte bound. All numeric fields, **including ports**, are little-endian. IP address bytes are in network order. There is no padding or implicit string terminator. In layouts below, `A=4` for IPv4 and `A=16` for IPv6.

| `InfoType` | Byte | Body layout / availability |
|---|---:|---|
| `LogLine` | 0 | `[severity:u8][message:remaining bytes]`. |
| `ConnectionIpv4` | 1 | Connection layout below, `A=4`. |
| `ConnectionIpv6` | 2 | Connection layout below, `A=16`. |
| `ConnectionEndEventV4` | 3 | Compatibility-only END layout, `A=4`; never emitted. |
| `ConnectionEndEventV6` | 4 | Compatibility-only END layout, `A=16`; never emitted. |
| `BandwidthStatsV4` | 5 | Bandwidth layout below, `A=4`. |
| `BandwidthStatsV6` | 6 | Bandwidth layout below, `A=16`. |

**Connection body**, in order:

| Field | Encoding / meaning |
|---|---|
| `id` | `u64`, pending NBL verdict ID. |
| `interface_index` | `u32`, host adapter index (`BaseMiniportIfIndex`) for this NBL, not the guest interface index. |
| `direction` | `u8`, guest outbound=0 / inbound=1. |
| `protocol` | `u8`, IP protocol number. |
| `local_ip` | `A` raw bytes, guest endpoint. |
| `remote_ip` | `A` raw bytes, peer endpoint. |
| `local_port` | `u16`. |
| `remote_port` | `u16`. |
| `payload_layer` | `u8`, always 3. |
| `payload_size` | `u32`, complete observed IP packet length, at most 1048576. |
| `payload` | Exactly `payload_size` bytes, starting with the original IP header; never a shortened capture. |

Body size is `31 + payload_size` for IPv4 or `55 + payload_size` for IPv6; total frame size is respectively `36 + payload_size` or `60 + payload_size`. No process-ID bytes or alignment padding are present. These layouts are not wire-compatible with 0.3.1.0 or earlier; command, verdict, bandwidth and legacy END layouts are unchanged.

**END compatibility body**, understood by the client but not produced by the LWF:

```text
[process_id:u64=0][direction:u8][protocol:u8]
[local_ip:A bytes][remote_ip:A bytes][local_port:u16][remote_port:u16]
```

Its body size is 22 bytes for IPv4 or 46 for IPv6. No ID, payload, or timestamp is present.

**Log body:** severity is `Trace=1`, `Debug=2`, `Info=3`, `Warning=4`, `Error=5`, `Critical=6`, or `Disabled=7`. The rest is the message, without a trailing NUL; driver-generated messages are UTF-8. The maximum message length is 506 bytes. Memory statistics are ordinary Info-level `LogLine` records, not a separate event type.

**Bandwidth body:**

```text
[protocol:u8][count:u32]
repeat count times:
  [local_ip:A bytes][local_port:u16]
  [remote_ip:A bytes][remote_port:u16]
  [transmitted_bytes:u64][received_bytes:u64]
```

Each entry is 28 bytes for IPv4 or 52 for IPv6; body size is `5 + count * entry_size`. The current driver emits **one entry per record**. Unlike connection records, each address is immediately followed by its port.

Bandwidth counts **admitted TCP/UDP IP bytes** while the controller is online, grouped by the normalized guest/peer tuple. `transmitted_bytes` means guest outbound; `received_bytes` means guest inbound. These are deltas since the bucket was created or last successfully queued by `GetBandwidthStats`, not cumulative per-socket totals. A bucket that cannot be queued is retained for a later request. Collection is bounded/best-effort, includes no PID, and does not prove delivery to the destination.

### Commands and write validation

Commands are **unframed**, unlike events. One write can concatenate complete commands, with a total size of **1–65536 bytes**. The whole batch is validated before any command is applied; a malformed/unsupported suffix prevents earlier commands in that batch from taking effect. This is syntactic validation, not a transactional acknowledgement of live event IDs.

| `CommandType` | Byte | Wire size | Effect |
|---|---:|---:|---|
| `Shutdown` | 0 | 1 | Same policy-session effect as `IOCTL_SHUTDOWN`. |
| `Verdict` | 1 | 10 | `[1:u8][id:u64 LE][verdict:u8]`. |
| `UpdateV4` | 2 | Unsupported | Rejected; no update layout is implemented. |
| `UpdateV6` | 3 | Unsupported | Rejected; no update layout is implemented. |
| `ClearCache` | 4 | 1 | Invalidates all permanent-cache entries. |
| `GetLogs` | 5 | 1 | Compatibility no-op; log records are already queued. |
| `GetBandwidthStats` | 6 | 1 | Queues bandwidth deltas for active buckets. |
| `PrintMemoryStats` | 7 | 1 | Queues an Info `LogLine` containing policy storage/counter statistics. |
| `CleanEndedConnections` | 8 | 1 | Requests a full asynchronous cache-expiry sweep; no migration or END events. |

Single-byte commands contain only their command byte. Request results are read asynchronously from the same event stream; there is no correlation ID or separate acknowledgement. Queue pressure can prevent diagnostic/statistics records from being queued.

Empty/oversized/truncated writes are rejected with `STATUS_INVALID_PARAMETER`; unsupported command/verdict values and unknown IOCTLs use `STATUS_NOT_SUPPORTED`. A second controller is rejected with `STATUS_SHARING_VIOLATION`. Version and filtered-device-count queries with an undersized output buffer use `STATUS_BUFFER_TOO_SMALL`. The filtered-device-count query rejects nonempty input with `STATUS_INVALID_PARAMETER`. The C++ client validates commands locally before writing and reports Windows I/O failures through `error`.

### Device-independent codec helpers

`pmkext::wire` exposes `IsCompatibleVersion`, `DecodeFilteredDeviceCount`, `DecodeAdapterInfo`, `IsSupportedVerdict`, `ValidateCommands`, `EncodeVerdict`, and `DispatchRecord`. `DecodeAdapterInfo(bytes, length, AdapterSnapshot&, error)` validates and decodes exactly one complete adapter snapshot, leaving output unchanged on failure. Its constants are `kIoctlAdapterInfo=0x9C40E00C`, `kAdapterInfoVersion=1`, `kAdapterInfoHeaderSize=16`, `kAdapterInfoEntrySize=1760`, `kMaxAdapters=32`, `kAdapterNameCapacity=256`, and `kMaxAdapterInfoSize=56336`. `IsCompatibleVersion` accepts exactly `kRequiredDeviceVersion={0,3,2,0}`; `Open` itself does not perform this check. `DecodeFilteredDeviceCount` requires a non-null, exactly four-byte little-endian reply and leaves its output unchanged on failure. `EncodeVerdict` fills a fixed ten-byte array; `DispatchRecord` validates exactly one complete frame before invoking its handler.

`RecordStream::Feed(bytes, length, callback, error)` accepts arbitrary read boundaries and invokes the callback for each complete frame. `PendingBytes()` reports buffered incomplete bytes; `Reset()` discards buffered state. An oversized header invalidates the stream until reset; it does not guess a new boundary. The stream keeps at most one bounded record in heap storage and assembles large records across multiple driver reads. Constants are `kRecordHeaderSize=5`, `kConnectionIpv4PrefixSize=36`, `kConnectionIpv6PrefixSize=60`, `kMaxPayloadSize=1048576`, `kMaxRecordSize=1048636`, `kMaxLogRecordSize=512`, `kMaxCommandBatchSize=65536`, and `kVerdictCommandSize=10`.

## License

Copyright (c) 2026 HyperVXNdisFilter contributors. Licensed under **GNU General Public License version 3 only** (`GPL-3.0-only`); see [LICENSE](LICENSE). The adapted monitor retains its original GPLv3 license and source-provenance notices; see [monitor/README.md](monitor/README.md) and [monitor/LICENSE](monitor/LICENSE).
