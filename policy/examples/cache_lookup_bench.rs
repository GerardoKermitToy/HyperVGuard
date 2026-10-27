//! Offline, single-threaded cache lookup benchmark. Never opens the driver.
extern crate alloc;

use hyperv_protocol::{Connection, Direction};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    collections::{BTreeMap, HashMap},
    fs::{self, File},
    hash::{BuildHasher, BuildHasherDefault, Hash, Hasher},
    hint::black_box,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

// Compile the actual driver cache source, including its fallible allocation and
// incremental growth. These inspection helpers do not change its lookup code.
#[allow(dead_code)]
mod driver {
    include!("../src/cache.rs");

    pub(super) fn hash<const N: usize>(key: &super::Key<N>) -> u64 {
        Tuple {
            local_ip: key.local_ip,
            remote_ip: key.remote_ip,
            local_port: key.local_port,
            remote_port: key.remote_port,
        }
        .hash()
    }
    pub(super) fn settle(caches: &mut Caches, now: u64) {
        while caches.ipv4.previous.capacity != 0 || caches.ipv6.previous.capacity != 0 {
            let mut work = CacheWork::empty();
            caches.maintain(now, &mut work);
        }
    }
    pub(super) fn capacity<const N: usize>(caches: &Caches) -> usize {
        if N == 4 {
            caches.ipv4.current.capacity
        } else {
            caches.ipv6.current.capacity
        }
    }
}

// Frozen pre-adaptation baseline, never linked into the driver.
#[allow(dead_code)]
mod legacy {
    include!("cache_lookup_bench/linear_cache.rs");

    pub(super) fn settle(caches: &mut Caches, now: u64) {
        while caches.ipv4.previous.capacity != 0 || caches.ipv6.previous.capacity != 0 {
            let mut work = CacheWork::empty();
            caches.maintain(now, &mut work);
        }
    }
    pub(super) fn capacity<const N: usize>(caches: &Caches) -> usize {
        if N == 4 {
            caches.ipv4.current.capacity
        } else {
            caches.ipv6.current.capacity
        }
    }
}

struct CountedAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
#[global_allocator]
static ALLOCATOR: CountedAllocator = CountedAllocator;
unsafe impl GlobalAlloc for CountedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            CALLS.fetch_add(1, Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            CALLS.fetch_add(1, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(p, layout, size) };
        if !result.is_null() {
            LIVE.fetch_add(size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            CALLS.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key<const N: usize> {
    local_ip: [u8; N],
    remote_ip: [u8; N],
    local_port: u16,
    remote_port: u16,
}
impl<const N: usize> Key<N> {
    fn from_connection(c: &Connection) -> Self {
        let mut local_ip = [0; N];
        let mut remote_ip = [0; N];
        local_ip.copy_from_slice(&c.local_ip[..N]);
        remote_ip.copy_from_slice(&c.remote_ip[..N]);
        Self {
            local_ip,
            remote_ip,
            local_port: c.local_port,
            remote_port: c.remote_port,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DriverHashKey<const N: usize>(Key<N>);
impl<const N: usize> Hash for DriverHashKey<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(driver::hash(&self.0));
    }
}

#[derive(Default)]
struct IdentityHasher(u64);
impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
    fn write(&mut self, _: &[u8]) {
        panic!("identity hasher accepts exactly one precomputed u64");
    }
}

// A deliberately simple, non-cryptographic word hasher, not an external crate.
// It is an experimental speed baseline, not a HashDoS-resistant recommendation.
#[derive(Default)]
struct WordHasher(u64);
impl WordHasher {
    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(0x517cc1b727220a95);
    }
}
impl Hasher for WordHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.add(u64::from_le_bytes(*chunk));
        }
        if !remainder.is_empty() {
            let mut tail = [0; 8];
            tail[..remainder.len()].copy_from_slice(remainder);
            self.add(u64::from_le_bytes(tail));
        }
    }
    fn write_u16(&mut self, value: u16) {
        self.add(u64::from(value));
    }
    fn write_u64(&mut self, value: u64) {
        self.add(value);
    }
    fn write_usize(&mut self, value: usize) {
        self.add(value as u64);
    }
}

type DriverMap<const N: usize> =
    HashMap<DriverHashKey<N>, driver::Decision, BuildHasherDefault<IdentityHasher>>;
type WordMap<const N: usize> = HashMap<Key<N>, driver::Decision, BuildHasherDefault<WordHasher>>;

const NOW: u64 = 1_000;
const TTL: u64 = 60_000;
const EXPIRES: u64 = 120_000;
const NAMES: [&str; 7] = [
    "driver_grouped",
    "legacy_linear",
    "hashmap_randomstate",
    "hashmap_driver_hash",
    "hashmap_word_hash",
    "btree_tuple",
    "btree_hash_tuple",
];

fn valid<const N: usize>(c: &Connection) -> bool {
    matches!(c.protocol, 6 | 17) && c.ipv6 == (N == 16)
}
fn read_decision(value: Option<&driver::Decision>, now: u64) -> Option<bool> {
    value.and_then(|v| (v.expires > now).then_some(v.allow))
}
fn apply_decision(value: Option<&mut driver::Decision>, now: u64, ttl: u64) -> Option<bool> {
    let value = value?;
    if value.expires <= now {
        return None;
    }
    if value.allow {
        value.expires = now.saturating_add(ttl);
    }
    Some(value.allow)
}
trait Lookup {
    fn read(&self, c: &Connection, now: u64) -> Option<bool>;
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool>;
}
impl Lookup for driver::Caches {
    fn read(&self, c: &Connection, now: u64) -> Option<bool> {
        self.get(c, now)
    }
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        self.apply(c, now, ttl)
    }
}
impl Lookup for legacy::Caches {
    fn read(&self, c: &Connection, now: u64) -> Option<bool> {
        self.get(c, now)
    }
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        self.apply(c, now, ttl)
    }
}
impl<const N: usize, S: BuildHasher> Lookup for HashMap<Key<N>, driver::Decision, S> {
    fn read(&self, c: &Connection, now: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        read_decision(self.get(&Key::from_connection(c)), now)
    }
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        apply_decision(self.get_mut(&Key::from_connection(c)), now, ttl)
    }
}
impl<const N: usize> Lookup for DriverMap<N> {
    fn read(&self, c: &Connection, now: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        read_decision(self.get(&DriverHashKey(Key::from_connection(c))), now)
    }
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        apply_decision(
            self.get_mut(&DriverHashKey(Key::from_connection(c))),
            now,
            ttl,
        )
    }
}
impl<const N: usize> Lookup for BTreeMap<Key<N>, driver::Decision> {
    fn read(&self, c: &Connection, now: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        read_decision(self.get(&Key::from_connection(c)), now)
    }
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        apply_decision(self.get_mut(&Key::from_connection(c)), now, ttl)
    }
}
impl<const N: usize> Lookup for BTreeMap<(u64, Key<N>), driver::Decision> {
    fn read(&self, c: &Connection, now: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        let key = Key::from_connection(c);
        read_decision(self.get(&(driver::hash(&key), key)), now)
    }
    fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        if !valid::<N>(c) {
            return None;
        }
        let key = Key::from_connection(c);
        apply_decision(self.get_mut(&(driver::hash(&key), key)), now, ttl)
    }
}

// Dispatch happens outside the timed loop. Keep all container headers inline:
// boxing only the driver would add asymmetric heap allocation/indirection.
#[allow(clippy::large_enum_variant)]
enum Store<const N: usize> {
    Driver(driver::Caches),
    Legacy(legacy::Caches),
    Random(HashMap<Key<N>, driver::Decision>),
    DriverHash(DriverMap<N>),
    WordHash(WordMap<N>),
    Tree(BTreeMap<Key<N>, driver::Decision>),
    HashTree(BTreeMap<(u64, Key<N>), driver::Decision>),
}
impl<const N: usize> Store<N> {
    fn build(kind: usize, entries: &[Connection]) -> Self {
        let mut store = match kind {
            0 => Self::Driver(driver::Caches::global()),
            1 => Self::Legacy(legacy::Caches::global()),
            2 => Self::Random(HashMap::with_capacity(entries.len())),
            3 => Self::DriverHash(DriverMap::with_capacity_and_hasher(
                entries.len(),
                Default::default(),
            )),
            4 => Self::WordHash(WordMap::with_capacity_and_hasher(
                entries.len(),
                Default::default(),
            )),
            5 => Self::Tree(BTreeMap::new()),
            6 => Self::HashTree(BTreeMap::new()),
            _ => unreachable!(),
        };
        for (i, c) in entries.iter().enumerate() {
            store.insert(
                c,
                driver::Decision {
                    allow: i % 2 == 0,
                    expires: EXPIRES,
                },
            );
        }
        match &mut store {
            Self::Driver(cache) => driver::settle(cache, NOW),
            Self::Legacy(cache) => legacy::settle(cache, NOW),
            _ => {}
        }
        assert_eq!(
            store.len(),
            entries.len(),
            "generated tuples must be unique"
        );
        store
    }
    fn insert(&mut self, c: &Connection, decision: driver::Decision) {
        let key = Key::from_connection(c);
        match self {
            Self::Driver(cache) => {
                let mut work = driver::CacheWork::prepare(cache.plan(c));
                assert!(cache.insert(c, decision, NOW, &mut work));
            }
            Self::Legacy(cache) => {
                let mut work = legacy::CacheWork::prepare(cache.plan(c));
                let decision = legacy::Decision {
                    allow: decision.allow,
                    expires: decision.expires,
                };
                assert!(cache.insert(c, decision, NOW, &mut work));
            }
            Self::Random(map) => {
                map.insert(key, decision);
            }
            Self::DriverHash(map) => {
                map.insert(DriverHashKey(key), decision);
            }
            Self::WordHash(map) => {
                map.insert(key, decision);
            }
            Self::Tree(map) => {
                map.insert(key, decision);
            }
            Self::HashTree(map) => {
                map.insert((driver::hash(&key), key), decision);
            }
        }
    }
    fn len(&self) -> usize {
        match self {
            Self::Driver(c) => {
                let (v4, v6) = c.counts();
                v4 + v6
            }
            Self::Legacy(c) => {
                let (v4, v6) = c.counts();
                v4 + v6
            }
            Self::Random(c) => c.len(),
            Self::DriverHash(c) => c.len(),
            Self::WordHash(c) => c.len(),
            Self::Tree(c) => c.len(),
            Self::HashTree(c) => c.len(),
        }
    }
    fn capacity(&self) -> usize {
        match self {
            Self::Driver(c) => driver::capacity::<N>(c),
            Self::Legacy(c) => legacy::capacity::<N>(c),
            Self::Random(c) => c.capacity(),
            Self::DriverHash(c) => c.capacity(),
            Self::WordHash(c) => c.capacity(),
            Self::Tree(_) | Self::HashTree(_) => 0,
        }
    }
    fn check(&mut self, entries: &[Connection], misses: &[Connection]) {
        match self {
            Self::Driver(c) => check(c, entries, misses),
            Self::Legacy(c) => check(c, entries, misses),
            Self::Random(c) => check(c, entries, misses),
            Self::DriverHash(c) => check(c, entries, misses),
            Self::WordHash(c) => check(c, entries, misses),
            Self::Tree(c) => check(c, entries, misses),
            Self::HashTree(c) => check(c, entries, misses),
        }
    }
    fn sample(&mut self, workload: &Workload, warmup: bool) -> f64 {
        match self {
            Self::Driver(c) => sample(c, workload, warmup),
            Self::Legacy(c) => sample(c, workload, warmup),
            Self::Random(c) => sample(c, workload, warmup),
            Self::DriverHash(c) => sample(c, workload, warmup),
            Self::WordHash(c) => sample(c, workload, warmup),
            Self::Tree(c) => sample(c, workload, warmup),
            Self::HashTree(c) => sample(c, workload, warmup),
        }
    }
}

fn check<L: Lookup>(store: &mut L, entries: &[Connection], misses: &[Connection]) {
    for (i, c) in entries.iter().enumerate() {
        let mut other = *c;
        other.protocol = if c.protocol == 6 { 17 } else { 6 };
        other.direction = Direction::Inbound;
        assert_eq!(store.read(c, NOW), Some(i % 2 == 0));
        assert_eq!(store.read(&other, NOW), Some(i % 2 == 0));
        assert_eq!(store.read(c, EXPIRES), None);
    }
    for c in misses {
        assert_eq!(store.read(c, NOW), None, "miss must compare the full tuple");
    }
    let mut c = entries[0];
    c.protocol = 1;
    assert_eq!(store.read(&c, NOW), None);
    assert_eq!(store.apply(&c, NOW, TTL), None);
    c = entries[0];
    assert_eq!(
        store.apply(&c, EXPIRES, TTL),
        None,
        "expired allow cannot revive"
    );
    assert_eq!(store.apply(&c, NOW, TTL), Some(true));
    assert_eq!(store.read(&c, NOW + TTL), None, "TTL boundary is exclusive");
    assert_eq!(store.apply(&c, 0, u64::MAX), Some(true));
    assert_eq!(store.read(&c, u64::MAX - 1), Some(true));
    assert_eq!(store.apply(&entries[1], NOW, TTL), Some(false));
    assert_eq!(store.read(&entries[1], EXPIRES - 1), Some(false));
    assert_eq!(store.read(&entries[1], EXPIRES), None);
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut v = self.0;
        v = (v ^ (v >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        v = (v ^ (v >> 27)).wrapping_mul(0x94d049bb133111eb);
        v ^ (v >> 31)
    }
    fn shuffle<T>(&mut self, values: &mut [T]) {
        for i in (1..values.len()).rev() {
            values.swap(i, self.next() as usize % (i + 1));
        }
    }
}
fn permute(mut v: u32) -> u32 {
    v ^= v >> 16;
    v = v.wrapping_mul(0x7feb352d);
    v ^= v >> 15;
    v = v.wrapping_mul(0x846ca68b);
    v ^ (v >> 16)
}
fn connection<const N: usize>(id: u32, shared: bool, seed: u64) -> Connection {
    let mut rng = Rng(seed ^ u64::from(id));
    let mut c = Connection::EMPTY;
    c.ipv6 = N == 16;
    c.protocol = if id.is_multiple_of(2) { 6 } else { 17 };
    if shared {
        if N == 4 {
            c.local_ip[..4].copy_from_slice(&[10, 24, 0, (id % 64 + 1) as u8]);
            c.remote_ip[..4].copy_from_slice(&[203, 0, 113, (id % 251 + 1) as u8]);
        } else {
            c.local_ip[..8].copy_from_slice(&0xfd00000000000001u64.to_be_bytes());
            c.remote_ip[..8].copy_from_slice(&0x20010db800000002u64.to_be_bytes());
            c.local_ip[15] = (id % 64 + 1) as u8;
            c.remote_ip[15] = (id % 251 + 1) as u8;
        }
        // The port pair is a bijection of id, so hit/miss sets are disjoint
        // even when addresses have very low entropy and shared prefixes.
        c.local_port = ((id >> 16) as u16) ^ 0x4000;
        c.remote_port = id as u16;
    } else {
        for ip in [&mut c.local_ip, &mut c.remote_ip] {
            for chunk in ip[..N].chunks_mut(8) {
                let word = rng.next().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        }
        // A 32-bit permutation guarantees uniqueness independently of the RNG.
        c.remote_ip[N - 4..N].copy_from_slice(&permute(id ^ seed as u32).to_be_bytes());
        c.local_port = rng.next() as u16;
        c.remote_port = rng.next() as u16;
    }
    c
}

#[derive(Clone, Copy)]
struct Query {
    connection: Connection,
    answer: u8,
}
struct Workload {
    name: &'static str,
    apply: bool,
    queries: Vec<Query>,
    checksum: u64,
}
fn workloads(
    entries: &[Connection],
    misses: &[Connection],
    count: usize,
    seed: u64,
) -> Vec<Workload> {
    let mut rng = Rng(seed);
    let hot = entries.len().min(4096);
    [
        ("hit_read", false),
        ("hit_apply", true),
        ("miss_apply", true),
        ("mixed90_apply", true),
        ("hot4096_apply", true),
    ]
    .into_iter()
    .map(|(name, apply)| {
        let mut queries: Vec<_> = (0..count)
            .map(|i| {
                // Two adjacent misses per twenty probes preserve the 50/50
                // allow/deny ratio instead of selecting only even (allow) IDs.
                let missing = name == "miss_apply" || (name == "mixed90_apply" && i % 20 < 2);
                let index = if name == "hot4096_apply" {
                    rng.next() as usize % hot
                } else {
                    i % entries.len()
                };
                let mut connection = if missing {
                    misses[index]
                } else {
                    entries[index]
                };
                // Some probes use the other transport/path: neither is identity.
                if i % 3 == 0 {
                    connection.protocol = if connection.protocol == 6 { 17 } else { 6 };
                    connection.direction = Direction::Inbound;
                }
                Query {
                    connection,
                    answer: if missing {
                        0
                    } else {
                        1 + u8::from(index % 2 == 0)
                    },
                }
            })
            .collect();
        rng.shuffle(&mut queries);
        let checksum = queries.iter().map(|q| u64::from(q.answer)).sum();
        Workload {
            name,
            apply,
            queries,
            checksum,
        }
    })
    .collect()
}
fn encode(value: Option<bool>) -> u64 {
    value.map_or(0, |allow| 1 + u64::from(allow))
}
// Static dispatch; no trait-object call or enum match in the measured loop.
// Hashing, full equality, expiry check, and applied accept-TTL writes ARE timed.
#[inline(never)]
fn read_loop<L: Lookup>(store: &L, queries: &[Query], now: u64) -> u64 {
    let mut checksum = 0u64;
    for query in queries {
        checksum = checksum.wrapping_add(encode(store.read(black_box(&query.connection), now)));
    }
    black_box(checksum)
}
#[inline(never)]
fn apply_loop<L: Lookup>(store: &mut L, queries: &[Query], now: u64, ttl: u64) -> u64 {
    let mut checksum = 0u64;
    for query in queries {
        checksum =
            checksum.wrapping_add(encode(store.apply(black_box(&query.connection), now, ttl)));
    }
    black_box(checksum)
}
fn sample<L: Lookup>(store: &mut L, workload: &Workload, warmup: bool) -> f64 {
    let queries = if warmup {
        &workload.queries[..workload.queries.len().min(65_536)]
    } else {
        &workload.queries
    };
    let now = black_box(NOW);
    let ttl = black_box(TTL);
    let allocations = CALLS.load(Ordering::Relaxed);
    let started = Instant::now();
    let checksum = if workload.apply {
        apply_loop(store, queries, now, ttl)
    } else {
        read_loop(store, queries, now)
    };
    let elapsed = started.elapsed();
    assert_eq!(
        CALLS.load(Ordering::Relaxed),
        allocations,
        "lookup allocated memory"
    );
    if !warmup {
        assert_eq!(
            checksum, workload.checksum,
            "timed lookup returned a wrong decision"
        );
    }
    elapsed.as_nanos() as f64 / queries.len() as f64
}

struct Config {
    entries: usize,
    queries: usize,
    rounds: usize,
    seed: u64,
    pattern: String,
    output: PathBuf,
}
impl Config {
    fn parse() -> Self {
        let mut c = Self {
            entries: 1_000_000,
            queries: 1_000_000,
            rounds: 7,
            seed: 0x4859564341434845,
            pattern: "both".into(),
            output: PathBuf::from("build/cache-bench"),
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--help" {
                println!(
                    "Offline cache benchmark (no driver/device/network access).\n\
                    --entries N --queries N --rounds N --seed N \
                    --pattern both|random|shared --out DIRECTORY\n\
                    Use scripts/Benchmark-Cache.ps1 to build and sign before running."
                );
                std::process::exit(0);
            }
            let value = args.next().expect("option requires a value");
            match arg.as_str() {
                "--entries" => c.entries = value.parse().unwrap(),
                "--queries" => c.queries = value.parse().unwrap(),
                "--rounds" => c.rounds = value.parse().unwrap(),
                "--seed" => c.seed = value.parse().unwrap(),
                "--pattern" => c.pattern = value,
                "--out" => c.output = value.into(),
                _ => panic!("unknown option: {arg}"),
            }
        }
        assert!((2..=100_000_000).contains(&c.entries));
        assert!(c.queries > 0 && (3..=101).contains(&c.rounds));
        assert!(["both", "random", "shared"].contains(&c.pattern.as_str()));
        c
    }
}

#[cfg(windows)]
mod affinity {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetCurrentThread() -> *mut c_void;
        fn GetProcessAffinityMask(
            process: *mut c_void,
            process_mask: *mut usize,
            system_mask: *mut usize,
        ) -> i32;
        fn SetThreadAffinityMask(thread: *mut c_void, mask: usize) -> usize;
    }
    pub struct Guard(usize);
    impl Guard {
        pub fn pin() -> (Self, String) {
            let (mut allowed, mut system) = (0usize, 0usize);
            assert_ne!(
                unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut allowed, &mut system) },
                0
            );
            // Prefer logical CPU 2 when allowed; never change system affinity.
            let cpu = if allowed & 4 != 0 {
                2
            } else {
                allowed.trailing_zeros()
            };
            let old = unsafe { SetThreadAffinityMask(GetCurrentThread(), 1usize << cpu) };
            assert_ne!(old, 0, "failed to pin benchmark thread");
            (
                Self(old),
                format!("logical CPU {cpu}, inherited priority (not changed or queried)"),
            )
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                SetThreadAffinityMask(GetCurrentThread(), self.0);
            }
        }
    }
}
#[cfg(not(windows))]
mod affinity {
    pub struct Guard;
    impl Guard {
        pub fn pin() -> (Self, String) {
            (Self, "not pinned".into())
        }
    }
}

struct Row {
    family: usize,
    pattern: &'static str,
    workload: &'static str,
    kind: usize,
    bytes: usize,
    capacity: usize,
    build_ms: f64,
    samples: Vec<f64>,
}
fn percentile(samples: &[f64], p: usize) -> f64 {
    samples[(samples.len() - 1) * p / 100]
}
fn run<const N: usize>(config: &Config, shared: bool, raw: &mut impl Write) -> Vec<Row> {
    let pattern = if shared { "shared" } else { "random" };
    let family = if N == 4 { 4 } else { 6 };
    println!(
        "Preparing IPv{family}/{pattern}: {} entries",
        config.entries
    );
    let entries: Vec<_> = (0..config.entries)
        .map(|i| connection::<N>(i as u32, shared, config.seed))
        .collect();
    let misses: Vec<_> = (config.entries..config.entries * 2)
        .map(|i| connection::<N>(i as u32, shared, config.seed))
        .collect();
    let mut stores = Vec::with_capacity(NAMES.len());
    let mut stats = Vec::with_capacity(NAMES.len());
    for (kind, name) in NAMES.iter().enumerate() {
        let before = LIVE.load(Ordering::Relaxed);
        let start = Instant::now();
        let mut store = Store::<N>::build(kind, &entries);
        let build_ms = start.elapsed().as_secs_f64() * 1000.0;
        let bytes = LIVE.load(Ordering::Relaxed) - before;
        let capacity = store.capacity();
        store.check(&entries, &misses);
        println!(
            "  {name}: verified, {:.2} MiB, build {build_ms:.1} ms",
            bytes as f64 / 1048576.0
        );
        stores.push(store);
        stats.push((bytes, capacity, build_ms));
    }
    let workloads = workloads(
        &entries,
        &misses,
        config.queries,
        config.seed ^ 0x7175657279,
    );
    let mut rows = Vec::new();
    let mut rng = Rng(config.seed ^ N as u64 ^ u64::from(shared));
    for workload in &workloads {
        let mut samples: Vec<Vec<f64>> = (0..NAMES.len())
            .map(|_| Vec::with_capacity(config.rounds))
            .collect();
        for round in 0..config.rounds {
            let mut order: [usize; NAMES.len()] = std::array::from_fn(|i| i);
            rng.shuffle(&mut order);
            for kind in order {
                stores[kind].sample(workload, true);
                let ns = stores[kind].sample(workload, false);
                samples[kind].push(ns);
                writeln!(
                    raw,
                    "{family}\t{pattern}\t{}\t{}\t{round}\t{ns:.6}",
                    workload.name, NAMES[kind]
                )
                .unwrap();
            }
        }
        let mut fastest = ("", f64::INFINITY);
        for (kind, mut samples) in samples.into_iter().enumerate() {
            samples.sort_unstable_by(f64::total_cmp);
            let median = percentile(&samples, 50);
            if median < fastest.1 {
                fastest = (NAMES[kind], median);
            }
            let (bytes, capacity, build_ms) = stats[kind];
            rows.push(Row {
                family,
                pattern,
                workload: workload.name,
                kind,
                bytes,
                capacity,
                build_ms,
                samples,
            });
        }
        println!(
            "  {}: fastest {} at {:.2} ns/lookup",
            workload.name, fastest.0, fastest.1
        );
        raw.flush().unwrap();
    }
    rows
}
fn main() {
    let config = Config::parse();
    fs::create_dir_all(&config.output).unwrap();
    let raw_path = config.output.join("samples.tsv");
    let report_path = config.output.join("report.md");
    assert!(
        !raw_path.exists() && !report_path.exists(),
        "refusing to overwrite prior results"
    );
    let (_affinity, affinity) = affinity::Guard::pin();
    let mut raw = BufWriter::new(File::create(raw_path).unwrap());
    writeln!(
        raw,
        "family\tpattern\tworkload\timplementation\tround\tns_per_lookup"
    )
    .unwrap();
    let mut rows = Vec::new();
    for shared in [false, true] {
        if config.pattern == "random" && shared || config.pattern == "shared" && !shared {
            continue;
        }
        rows.extend(run::<4>(&config, shared, &mut raw));
        rows.extend(run::<16>(&config, shared, &mut raw));
    }
    let mut report = BufWriter::new(File::create(&report_path).unwrap());
    writeln!(report, "# Offline TCP/UDP cache lookup benchmark\n").unwrap();
    writeln!(report, "- {} unique entries **per IP family and address distribution**; {} probes per sample, {} rounds.", config.entries, config.queries, config.rounds).unwrap();
    writeln!(report, "- Dataset/order seed: `{}`. `RandomState` intentionally uses its own OS-generated hash seeds.", config.seed).unwrap();
    writeln!(report, "- One selected interface cache, one thread pinned to {affinity}. No device, driver loading, or network traffic.").unwrap();
    writeln!(report, "- Actual `policy/src/cache.rs` compiled directly, without lookup modifications. The frozen pre-adaptation cache is `legacy_linear`. Current+previous migration is settled before measurement.").unwrap();
    writeln!(report, "- All candidates: TCP/UDP guard, normalized IP/port tuple construction, full equality, expiry check; apply refreshes only accepts. Entries are 50% allow, 50% deny.").unwrap();
    writeln!(report, "- Random shuffled full-working-set hits, misses, 90/10 mix; hot set up to 4096 entries. Shared distribution: 64 local/251 remote addresses, fixed prefixes, unique port pairs.").unwrap();
    writeln!(report, "- `hit_read` is read-only; all other workloads use mutable verdict lookup/TTL logic. Hash computation is included; no prehashed probes.").unwrap();
    writeln!(report, "- Generation, allocation, insertion, growth, and correctness checks excluded from lookup timing. Every existing/missing tuple checked before timing; timed checksums and zero allocations asserted.").unwrap();
    writeln!(report, "- Candidate order shuffled each round; 65536 untimed warm-up probes before every sample. `black_box` inputs and consumed checksums prevent dead-code elimination.").unwrap();
    writeln!(report, "- Memory is measured live requested allocation bytes (container only), excluding allocator overhead and datasets. Capacity means slots for driver, usable entries for HashMap, n/a for BTreeMap.").unwrap();
    writeln!(report, "- Min/max show sample spread, not a confidence interval. Mlookups/s is single-thread throughput, not NDIS packet throughput. No lock, packet parsing/capture, bandwidth aggregation, churn, or kernel IRQL costs are included.\n").unwrap();
    writeln!(report, "## Container allocation and construction\n\n| IP | Distribution | Implementation | MiB | Capacity | Build ms |\n|---|---|---|---:|---:|---:|").unwrap();
    for row in rows.iter().filter(|r| r.workload == "hit_read") {
        writeln!(
            report,
            "| IPv{} | {} | {} | {:.2} | {} | {:.1} |",
            row.family,
            row.pattern,
            NAMES[row.kind],
            row.bytes as f64 / 1048576.0,
            row.capacity,
            row.build_ms
        )
        .unwrap();
    }
    writeln!(report, "\n## Lookup results\n\nSpeedup is legacy-linear median / candidate median; greater than 1 is faster.\n\n| IP | Distribution | Workload | Implementation | Median ns | Min ns | Max ns | Mlookups/s | vs legacy |\n|---|---|---|---|---:|---:|---:|---:|---:|").unwrap();
    for row in &rows {
        let median = percentile(&row.samples, 50);
        let baseline = rows
            .iter()
            .find(|r| {
                r.family == row.family
                    && r.pattern == row.pattern
                    && r.workload == row.workload
                    && r.kind == 1
            })
            .unwrap();
        let speedup = percentile(&baseline.samples, 50) / median;
        writeln!(
            report,
            "| IPv{} | {} | {} | {} | {median:.2} | {:.2} | {:.2} | {:.2} | {speedup:.3}x |",
            row.family,
            row.pattern,
            row.workload,
            NAMES[row.kind],
            row.samples[0],
            row.samples.last().unwrap(),
            1000.0 / median
        )
        .unwrap();
    }
    writeln!(report, "\n## Relative ranking\n\nGeometric mean of per-workload speedups; equal weight per family/distribution/workload, not a real traffic model.\n\n| Implementation | Geomean speedup vs legacy | Wins |\n|---|---:|---:|").unwrap();
    let groups = rows.len() / NAMES.len();
    for (kind, name) in NAMES.iter().enumerate() {
        let mut log_sum = 0.0;
        let mut wins = 0;
        for row in rows.iter().filter(|r| r.kind == kind) {
            let group: Vec<_> = rows
                .iter()
                .filter(|r| {
                    r.family == row.family && r.pattern == row.pattern && r.workload == row.workload
                })
                .collect();
            let base = group.iter().find(|r| r.kind == 1).unwrap();
            let median = percentile(&row.samples, 50);
            log_sum += (percentile(&base.samples, 50) / median).ln();
            if group.iter().all(|r| median <= percentile(&r.samples, 50)) {
                wins += 1;
            }
        }
        writeln!(
            report,
            "| {name} | {:.3}x | {wins}/{groups} |",
            (log_sum / groups as f64).exp()
        )
        .unwrap();
    }
    writeln!(report, "\n`std::HashMap` uses SwissTable in this Rust toolchain. Deterministic driver/word hashes are not keyed HashDoS protection. BTreeMap hash+tuple still compares the full tuple after equal hashes; no hash-only identity is used. Standard-library maps are host baselines, not drop-in `no_std` kernel containers: fallible nonpaged allocation, unlocked growth/free, bounded migration/expiry, and OOM behavior must be preserved in any production adaptation. See `environment.txt` and `samples.tsv` for toolchain/machine/source fingerprints and raw measurements.").unwrap();
    report.flush().unwrap();
    println!("Saved {}", report_path.display());
}

#[cfg(test)]
#[path = "cache_lookup_bench/tests.rs"]
mod tests;
