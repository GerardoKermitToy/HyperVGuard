# HyperVGuard

Experimental Rust-based **NDIS Lightweight Filter (LWF)** and a C++ monitor with a `kext_monitor`-compatible API. The filter targets only the management-OS host adapter **`vEthernet (Default Switch)`**. It is not a Hyper-V switch extension or a WFP callout.

Driver package: **0.2.1.4**. Device/wire protocol: **0.2.1.0**.

Only traffic passing through the host vNIC is covered; VM-to-VM traffic is not guaranteed to be visible. The installer and kernel check the exact adapter GUID/NET_LUID, not its display name. If Windows recreates the adapter with a new identity, explicitly uninstall and reinstall.

## Build

Requires Windows x64 **build 25341+**, Hyper-V with Default Switch, Visual Studio C++ x64 tools with CMake/Ninja, Rust with the `x86_64-pc-windows-msvc` target, and WDK/SDK **10.0.28000.0**. Kernel builds are **release-only**.

Commands below use Git Bash at the repository root:

```bash
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/Build.ps1 -Test
```

This builds the package and runs offline tests without installing, loading, or binding the driver. Output goes to `dist/`: SYS/PDB/INF/CAT, `HyperVGuardNotify.dll`, `hyperv_monitor.exe`, `Install.exe`, and `Uninstall.exe`. Keep package files together; do not mix versions.

The default build is unsigned. For signing, pass `-PfxPath` and `-RootCertificate` to the build script and provide the PFX password through the process environment variable `HYPERVGUARD_PFX_PASSWORD`. The script does not import certificates or change security policy. Installation requires trusted package signatures.

## Install

Use an **elevated Administrator/SYSTEM console**, stop the monitor, and have local recovery access: network reconfiguration may interrupt connectivity. If already installed, use `Uninstall.exe` first; the installer does not replace a live driver.

```bash
./dist/Install.exe
```

The native installer reads the package beside its EXE and enables HyperVGuard only on the exact Default Switch host vNIC. `--what-if` performs read-only preflight; `--yes` skips confirmation only.

If installation returns **3010**, reboot, then resume explicitly:

```bash
./dist/Install.exe --enable
```

## Monitor

Start with the default PermanentAccept policy:

```bash
./dist/hyperv_monitor.exe --duration 15 --timestamps --memory-stats --out allow.log
```

Block only a test remote endpoint:

```bash
./dist/hyperv_monitor.exe --duration 10 --match 192.0.2.10:9000 --verdict permanent-block --out block.log
```

**Always use a positive `--duration`.** `--match` selects the remote endpoint in both directions; unmatched events receive PermanentAccept. `--filter-ip` only filters output, not verdicts. A blocking verdict without `--match` applies to every event and can disconnect the host-vNIC path.

The monitor never installs, unbinds, or uninstalls the filter. Exiting closes the policy session; the LWF remains installed and bound. Use `--help` for all options without opening the device.

## Remove

Stop the monitor, then run from an elevated console:

```bash
./dist/Uninstall.exe
```

Only HyperVGuard is removed. If removal returns **3010**, reboot before reinstalling. No manual SCM service creation or deletion is needed.

## API

The public C++ interface is [PortmasterKext.h](monitor/include/PortmasterKext.h), namespace `pmkext`. The wire codec is [DriverProtocol.h](monitor/include/DriverProtocol.h); the driver-side encoding is defined in [protocol/src/lib.rs](protocol/src/lib.rs).

### Semantics and compatibility

- **PID is always 0.** There is no TID or public switch/port/NIC/GUID/LUID field, and no host-process or individual-VM ownership is inferred.
- `direction=0` is **guest/Sandbox outbound**, corresponding to host NDIS receive. `direction=1` is **guest/Sandbox inbound**, corresponding to host NDIS send. `local_*` describes the guest endpoint; `remote_*` describes the peer. NAT/forwarding can affect the addresses visible on this path.
- One connection event and its `id` represent **one pending NBL**, not a socket or a connection lifetime. A homogeneous multi-NB NBL has one verdict and a representative capture from its first NB. Mixed-flow or malformed batches are dropped rather than represented as one flow.
- `payload_layer=3`. Captures contain up to **256 IP bytes**, without Ethernet/VLAN headers. `payload_size` is the captured byte count, not the original packet length. Endpoint normalization does not rewrite captured packet bytes.
- Non-IP traffic such as ARP does not produce connection events and is passed when its ownership/profile is supported. Cache hits are handled in the kernel without a new verdict event.
- Redirect verdicts, UpdateV4/V6, PID suspension, and a thread-ID IOCTL are **unsupported**. Some enum names remain in the C++ header only for source compatibility.
- NDIS has no socket/ALE teardown notification. **Connection-END events are never generated**, including on cache expiry, timeout, or disconnect.

This is experimental kernel code. Offline tests and an enabled binding do not prove correct live filtering.

### Device session and IOCTLs

Open **`\\.\HyperVGuard`** as Administrator/SYSTEM with `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and exclusive sharing. The C++ client uses `FILE_FLAG_OVERLAPPED`; the driver completes buffered reads without waiting for future events. Only **one controller** may hold the device. There is no named-pipe/winrpc transport.

Opening the device activates a policy session and resets its event queue, permanent cache, and bandwidth buckets. The client must verify the device version before relying on the protocol. `Driver::Open` only opens the session; the monitor separately checks the version.

Both IOCTLs use `CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)` and take no input buffer:

| IOCTL | Function / numeric code | Output and effect |
|---|---|---|
| `IOCTL_VERSION` | `0x800` / `0x9C40E000` | Exactly four bytes: `00 02 01 00`. The output buffer must have at least four bytes. |
| `IOCTL_SHUTDOWN` | `0x801` / `0x9C40E004` | No output. Deactivates the policy session, discards queued events/cache/bandwidth, and resolves pending packets through the configured fallback. Does not unload, unbind, or uninstall the LWF. |

All other IOCTLs are unsupported. After shutdown, close and reopen the handle to activate a new session. Closing the active handle also disconnects the controller and drains pending decisions. Shutdown does not itself close the handle or stop a custom application's read loop.

Reads return an event byte stream, at most **65536 bytes per driver read**. A successful zero-byte read means **empty queue, not EOF**. Reads can split a record or contain multiple records; retain incomplete bytes between reads. The supplied client waits interruptibly for 10 ms on empty reads.

### C++ client methods

Construct `Driver(std::wstring service_name = L"HyperVGuard")`; the argument selects the device basename, not a service to create. The class is non-copyable. Boolean methods report failures through `std::string& error`; sending a request does not imply a synchronous event response or confirmation that a verdict was applied.

| Method | Contract |
|---|---|
| `bool Open(std::string& error)` | Opens the already installed device. Fails if this client session is already open. Does not install, bind, or negotiate the version. |
| `bool GetVersion(uint8_t out[4], std::string& error)` | Reads the four-byte version; integrations should require `0.2.1.0`. |
| `void Run(const Handlers& handlers, unsigned poll_interval_ms = 1000)` | Starts a reader thread and blocks until stopped or the reader exits. Dispatches complete records and invokes `on_poll` on the calling thread. It does not automatically request logs/statistics or send verdicts. |
| `bool SendVerdict(uint64_t id, Verdict verdict, std::string& error)` | Sends one verdict for a pending event ID. Only verdict values 2–7 are accepted. |
| `bool RequestLogs(std::string& error)` | Sends `GetLogs`; existing log events are already queued for reading. |
| `bool RequestBandwidthStats(std::string& error)` | Requests asynchronous bandwidth records for active buckets. No active buckets means no bandwidth records. |
| `bool RequestMemoryStats(std::string& error)` | Requests a diagnostic `LogLine` with policy storage/counter statistics. |
| `bool RequestCleanEndedConnections(std::string& error)` | Sweeps expired permanent-cache entries. Does not discover socket teardown or emit END events. |
| `bool RequestClearCache(std::string& error)` | Invalidates all permanent verdict entries. Does not answer pending NBLs. |
| `bool RequestShutdown(std::string& error)` | Issues `IOCTL_SHUTDOWN`; does not signal the `Run` stop event or close the handle. |
| `void Stop()` | Signals `Run` and requests shutdown once. Safe to call from callbacks or another thread while `Run` is active. |
| `void Cleanup()` | Calls `Stop`, closes session handles, and resets the record parser. Join/return from `Run` before calling it or destroying the object. The destructor also calls `Cleanup`. |
| `bool Install(const std::wstring& sys_path, std::string& error, bool inbound_udp_pid_fallback = true)` | Compatibility stub: always returns an unsupported-operation error. Use the native installer instead. Neither argument enables a driver-loading or PID-fallback path. |

A typical integration opens the device, checks its version, installs handlers, answers `on_connection` events, and uses `on_poll` for periodic requests and a positive runtime deadline. Call `Stop`, wait for `Run` to finish, then call `Cleanup`. Keep callbacks short enough to answer before the pending timeout.

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
| `Connection` | `bool ipv6`; `uint64_t id, process_id`; `uint8_t direction, protocol`; `uint8_t local_ip[16], remote_ip[16]`; `uint16_t local_port, remote_port`; `uint8_t payload_layer`; `uint32_t payload_size`; `std::vector<uint8_t> payload`. |
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
| `PermanentAccept` | 3 | Allow and cache the directional decision when the packet is cacheable. |
| `Block` | 4 | Silently discard this NBL. |
| `PermanentBlock` | 5 | Discard and cache the directional decision when cacheable. |
| `Drop` | 6 | Silently discard this NBL; same data-path action as Block. |
| `PermanentDrop` | 7 | Discard and cache the directional decision when cacheable. |

No TCP RST or ICMP rejection is generated. `Undecided=0`, `Undeterminable=1`, `RedirectNameServer=8`, `RedirectTunnel=9`, `Failed=10`, and `RedirectSplitTunnel=11` are not accepted as verdicts.

Pending decisions time out after **2000 ms by default**, measured from classification, not from when an application reads the event. The default fallback is **fail-open** on missing controller, disconnect/shutdown, timeout, or policy queue pressure. Pause/invalidated attachments, malformed packets, unsupported copy metadata, and unsafe ownership/copy-allocation cases can still be dropped regardless of fail-open.

A permanent decision is a **directional TTL cache entry**, not lifetime socket permission. The default TTL is **60000 ms**; the key includes the internal module/epoch, NDIS send/receive path, VLAN, and flow. It does not authorize the reverse direction. Fragments, offloaded/incomplete transport headers, and multi-NB batches cannot seed permanent entries. Clear-cache, a new/disconnected controller session, and attachment invalidation discard cached decisions.

Optional service `Parameters` values, all `REG_DWORD`, are read when the SYS loads: `DecisionTimeoutMs=2000` (clamped to 100–60000), `CacheTtlMs=60000` (1000–300000), and `FailClosed=0` (nonzero changes the controller/timeout/queue fallback to drop). These are driver configuration, not protocol commands.

Late, duplicate, unknown, cancelled, or already-completed IDs are harmless no-ops: a successful verdict write is **not an acknowledgement that the NBL still existed**. Such writes do not create cache entries. There is no per-verdict response record.

### Event framing and layouts

Events use explicit byte encoding, never native C++/Rust structure layout:

```text
[type:u8][body_size:u32 LE][body:body_size bytes]
```

The header is five bytes. `body_size` excludes the header; a complete record is at most **512 bytes**. All numeric fields, **including ports**, are little-endian. IP address bytes are in network order. There is no padding or implicit string terminator. In layouts below, `A=4` for IPv4 and `A=16` for IPv6.

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
| `process_id` | `u64`, always 0. |
| `direction` | `u8`, guest outbound=0 / inbound=1. |
| `protocol` | `u8`, IP protocol number. |
| `local_ip` | `A` raw bytes, guest endpoint. |
| `remote_ip` | `A` raw bytes, peer endpoint. |
| `local_port` | `u16`. |
| `remote_port` | `u16`. |
| `payload_layer` | `u8`, always 3. |
| `payload_size` | `u32`, number of captured IP bytes, at most 256. |
| `payload` | Exactly `payload_size` bytes. |

Body size is `35 + payload_size` for IPv4 or `59 + payload_size` for IPv6; total frame size is respectively `40 + payload_size` or `64 + payload_size`.

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
| `CleanEndedConnections` | 8 | 1 | Removes expired cache entries only; does not emit END. |

Single-byte commands contain only their command byte. Request results are read asynchronously from the same event stream; there is no correlation ID or separate acknowledgement. Queue pressure can prevent diagnostic/statistics records from being queued.

Empty/oversized/truncated writes are rejected with `STATUS_INVALID_PARAMETER`; unsupported command/verdict values and unknown IOCTLs use `STATUS_NOT_SUPPORTED`. A second controller is rejected with `STATUS_SHARING_VIOLATION`. Version queries with an undersized output buffer use `STATUS_BUFFER_TOO_SMALL`. The C++ client validates commands locally before writing and reports Windows I/O failures through `error`.

### Device-independent codec helpers

`pmkext::wire` exposes `IsSupportedVerdict`, `ValidateCommands`, `EncodeVerdict`, and `DispatchRecord`. `EncodeVerdict` fills a fixed ten-byte array; `DispatchRecord` validates exactly one complete frame before invoking its handler.

`RecordStream::Feed(bytes, length, callback, error)` accepts arbitrary read boundaries and invokes the callback for each complete frame. `PendingBytes()` reports buffered incomplete bytes; `Reset()` discards buffered state. An oversized header invalidates the stream until reset; it does not guess a new boundary. Constants are `kRecordHeaderSize=5`, `kMaxRecordSize=512`, `kMaxCommandBatchSize=65536`, and `kVerdictCommandSize=10`.

## License

Copyright (c) 2026 HyperV Guard contributors. Licensed under **GNU General Public License version 3 only** (`GPL-3.0-only`); see [LICENSE](LICENSE). The adapted monitor retains its original GPLv3 license and source-provenance notices; see [monitor/README.md](monitor/README.md) and [monitor/LICENSE](monitor/LICENSE).
