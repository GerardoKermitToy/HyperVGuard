# Offline cache lookup benchmark

`cache_lookup_bench.rs` compares the actual `policy/src/cache.rs` implementation
with standard-library Rust containers. It is a user-mode synthetic experiment:
no driver/device access, installation, bindings, packet injection, or network
traffic. The production cache is not replaced by this example.

## Candidates

| Output name | Implementation |
|---|---|
| `driver_grouped` | Actual `no_std` driver cache: separate control bytes, 16-byte SSE2 fingerprint groups on x64 (eight-byte scalar fallback elsewhere), triangular group probing, and the selected word hash. IPv4/IPv6 tables remain separate. |
| `legacy_linear` | Frozen pre-adaptation driver cache in `cache_lookup_bench/linear_cache.rs`, with its original linear probing and hash. Benchmark-only; never linked into the driver. |
| `hashmap_randomstate` | `std::collections::HashMap<Key, Decision>` with the standard randomized `RandomState` hasher. |
| `hashmap_driver_hash` | Standard `HashMap` with the exact current driver tuple hash; full tuple equality is retained. |
| `hashmap_word_hash` | Standard `HashMap` with a simple rotate/XOR/multiply word hasher implemented in this example. No third-party dependencies. |
| `btree_tuple` | `std::collections::BTreeMap<Key, Decision>` ordered by the complete tuple. |
| `btree_hash_tuple` | Standard `BTreeMap<(driver_hash, Key), Decision>`: hash first, then complete tuple comparison. |

No sorted `Vec` candidate is included. `Vec` is used only to store input datasets,
queries, and measurement samples. Hashes alone are never connection identities.

The standard library's `HashMap` uses SwissTable in the tested toolchain. The
current production word hash exactly matches `hashmap_word_hash`, verified by
an offline parity test; `hashmap_driver_hash` uses a different key adapter with
the same hash result. These deterministic hashes are non-cryptographic and do
not provide keyed protection against deliberately chosen collisions.

`driver_grouped` is a `no_std` SwissTable-style adaptation, not a vendored standard
map: one allocation holds an allocator-aligned payload array followed by control
bytes; a mirrored control prefix supports wrapped group loads. Private
entry layout keeps the tuple and verdict adjacent without shifting the payload
base by the control header. A hit retains its bucket address through TTL handling. Seven-bit matches
always receive a full tuple comparison. Growth starts at 75% live/used load;
migration and expiry scanning retain the 32-slot work budget per table/pass.
Only the controls require initialization outside the policy lock. Entry payloads
are initialized before publishing a full fingerprint; their hashes are recomputed
only when migrating. Windows x64 uses baseline integer SSE2 only, with compiler/ABI state preservation,
not AVX/x87 or extra extended-state management. See the [Microsoft x64 WDM guidance](https://learn.microsoft.com/windows-hardware/drivers/kernel/using-floating-point-or-mmx-in-a-wdm-driver#x64-systems).

## Build and run

Use Git Bash in the repository root, with Rust's MSVC target and the Windows SDK
available. The runner builds **release only**, signs the standalone benchmark
using the supplied existing certificates, verifies its Authenticode signature,
and runs it. It never imports/copies certificates or changes security settings.
Use the signing inputs authorized for the local workspace; the paths below are
placeholders, not bundled certificates.

```bash
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\hyperv\scripts\Benchmark-Cache.ps1' -Entries 1000000 -Queries 1000000 -Rounds 7 -PfxPath 'C:\path\to\test-signing.pfx' -RootCertificate 'C:\path\to\test-root.der'
```

`-Entries` is the number of live entries **per family and distribution**, not
the combined IPv4/IPv6 count. Defaults are one million entries, one million
probes per sample, seven rounds, and both address distributions. `-Seed` changes
deterministic datasets and execution order; standard `RandomState` deliberately
uses its own OS-generated seeds. `-Pattern random` or `-Pattern shared` limits a
run. A quick correctness/smoke run can use `-Entries 10000 -Queries 10000 -Rounds 3`.

The script uses a new timestamped directory under `build/cache-bench/` by default.
`-OutputDirectory` accepts a different new/empty directory; prior results are
never overwritten. Outputs:

- `report.md`: methodology, measured container allocations, construction time,
  median/min/max lookup latency, throughput, relative speedups, and ranking;
- `samples.tsv`: every measured sample, before aggregation;
- `environment.txt`: machine/toolchain, parameters, source/executable SHA-256,
  release settings, and signature status;
- `run.log`: correctness/build summaries and per-workload winners.

## What is timed

Each lookup starts from a normalized `Connection`. All candidates perform the
TCP/UDP admission check, create the same local-IP/local-port/remote-IP/remote-port
key, compare the complete tuple, and check expiration. Applied hits extend only
allow decisions using saturating TTL addition. TCP/UDP and opposite directions
can intentionally reuse the same normalized tuple. One interface cache has
already been selected; interface lookup, packet parsing, NDIS operations, the
policy lock, bandwidth accounting, and packet/event capture are not measured.

Each table contains 50% allow and 50% deny decisions. Workloads are:

| Workload | Probes |
|---|---|
| `hit_read` | Shuffled full-working-set hits, read-only TTL check. |
| `hit_apply` | Shuffled full-working-set hits; allows refresh idle TTL, denies do not. |
| `miss_apply` | Disjoint missing tuples, mutable applied-lookup path. |
| `mixed90_apply` | 90% existing / 10% missing tuples, applied path; hit decisions remain 50/50 allow/deny. |
| `hot4096_apply` | Random repeated hits in a working set of up to 4096 tuples inside the full table, applied path. |

`random` uses pseudorandom addresses/ports and a bijective 32-bit address component
to guarantee unique entries and disjoint misses. `shared` uses common prefixes,
64 local and 251 remote addresses, and bijective port pairs. Generation and
Fisher-Yates shuffling happen before measurements. For the default query/entry
counts, full-working-set hit and miss workloads visit each tuple exactly once
per measured sample.

Both current and frozen-legacy caches finish incremental growth before steady-state timing.
Reported speedups use `legacy_linear` as the baseline.
`HashMap` reserves the final capacity before population. Construction times are
reported as context only, not as a fair insertion/growth comparison. No measured
lookup allocates memory. Expiration boundaries, protocol/direction reuse, exact
answers for all existing/missing tuples, and saturating accept refresh are checked
before timing. Every timed sample verifies its consumed answer checksum.

On Windows, only the benchmark thread is pinned (logical CPU 2 when allowed,
otherwise the first allowed CPU). Affinity is restored on exit; priority and
system settings are unchanged. Candidate order is shuffled for every round.
Each sample has up to 65,536 untimed warm-up probes. Inputs use `black_box`,
loops use static dispatch, and checksums are consumed outside the timed region.
The runner uses the repository release profile (`opt-level=2`, LTO, one codegen
unit, panic abort) plus the driver's `no-redzone` flag.

The benchmark generator and container adapters also have offline regression tests (including disjoint datasets, the exact 90/10 mix, TTL behavior, and forced hash collisions):

```bash
RUSTFLAGS="" cargo test --release -p hyperv-policy --example cache_lookup_bench --locked
```

## Interpretation and limits

Lower median nanoseconds per lookup is better. Throughput is the reciprocal of
that **single-threaded** mean operation latency within each sample; it is not
kernel packet throughput or a per-operation tail-latency measurement. Min/max
are sample spread, not confidence bounds. The geometric-mean ranking assigns
equal weight to every workload, family, and distribution; it is not a measured
real-traffic workload mix. Repeat with different seeds/processes before relying
on a small difference, and avoid concurrent builds or other CPU-heavy jobs.

Allocation figures count live requested bytes for the container alone, excluding
datasets, allocator bookkeeping, and resident-set effects. Driver capacity is
physical slots, HashMap capacity is supported entries, and trees have no reported
capacity. Tables may therefore have different entry sizes and load factors: that
is part of the implementation comparison, not a constant-memory experiment.

These tests do not measure cache mutation/churn, expiry sweeping, in-progress
rehashing, OOM, adversarial collision sets, lock contention, or real NDIS traffic.
The production cache's separate offline unit tests cover its correctness under
growth, tombstones, allocation failure, invalidation, and hash collisions.

`std::HashMap` is not a drop-in kernel replacement: the driver is `no_std`, and
production must retain fallible nonpaged allocation, unlocked table allocation
and free, bounded incremental growth/cleanup, no capacity eviction, and existing
TTL/interface lifecycle semantics. The current grouped adaptation retains these
requirements; comparing it directly with the frozen legacy implementation
checks the actual new code, rather than assuming that host HashMap results
transfer to the kernel. No synthetic result proves live-driver performance.
