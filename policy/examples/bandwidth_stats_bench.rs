//! Offline benchmark of the kernel-side bandwidth aggregation path.
//!
//! It never installs, loads, binds, opens, or sends traffic through the driver.
//! The legacy baseline uses the production `List` storage primitive. The driver
//! adapter includes the actual indexed-page source; other stores are host references.
extern crate alloc;

#[allow(dead_code)]
#[path = "../src/storage.rs"]
mod storage;

#[allow(dead_code)]
#[path = "../src/cache.rs"]
mod cache;
#[allow(dead_code)]
#[path = "../src/bandwidth.rs"]
mod driver_bandwidth;

use hyperv_protocol::{
    BandwidthEntry, Connection, Direction, bandwidth_entry_len, bandwidth_record_len,
    encode_bandwidth_entry,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    boxed::Box,
    collections::HashMap,
    fs::{self, File, OpenOptions},
    hash::{BuildHasherDefault, Hash, Hasher},
    hint::black_box,
    io::{BufWriter, Write},
    mem,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use storage::List;

#[path = "bandwidth_stats_bench/indexed.rs"]
mod indexed;

const NAMES: [&str; 8] = [
    "list_256_legacy",
    "list_4096",
    "list_16384",
    "paged_4096x256",
    "flat_hash_host_upper_bound",
    "std_hashmap_host_reference",
    "indexed_pages_incremental",
    "driver_indexed_pages_incremental",
];
const PAGE_SIZE: usize = 256;
const DEFAULT_RECORDS: usize = 1_000_000;
const DEFAULT_FLOWS: usize = 250_000;
const DEFAULT_ROUNDS: usize = 5;
const DEFAULT_SEED: u64 = 0x4859_4257_5354_4154;

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn record_peak(value: usize) {
    let mut old = PEAK.load(Ordering::Relaxed);
    while value > old {
        match PEAK.compare_exchange_weak(old, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => old = observed,
        }
    }
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding the valid layout to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            CALLS.fetch_add(1, Ordering::Relaxed);
            record_peak(live);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding the valid layout to the system allocator.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            CALLS.fetch_add(1, Ordering::Relaxed);
            record_peak(live);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: pointer/layout are the pair returned by this allocator.
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: forwarding the original allocation and requested size.
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            if size >= layout.size() {
                let delta = size - layout.size();
                let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
                record_peak(live);
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
            CALLS.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    interface_index: u32,
    protocol: u8,
    ipv6: bool,
    local_ip: [u8; 16],
    local_port: u16,
    remote_ip: [u8; 16],
    remote_port: u16,
}
impl Key {
    fn new(interface_index: u32, connection: &Connection) -> Self {
        Self {
            interface_index,
            protocol: connection.protocol,
            ipv6: connection.ipv6,
            local_ip: connection.local_ip,
            local_port: connection.local_port,
            remote_ip: connection.remote_ip,
            remote_port: connection.remote_port,
        }
    }
    fn from_record(record: &TrafficRecord) -> Self {
        Self::new(record.interface_index, &record.connection)
    }
    fn connection(self) -> Connection {
        Connection {
            direction: Direction::Outbound,
            ipv6: self.ipv6,
            protocol: self.protocol,
            local_ip: self.local_ip,
            remote_ip: self.remote_ip,
            local_port: self.local_port,
            remote_port: self.remote_port,
        }
    }
    fn hash_value(self) -> u64 {
        tuple_hash(&self.connection()).rotate_left(5)
            ^ u64::from(self.protocol)
            ^ u64::from(self.interface_index).wrapping_mul(0x9e37_79b9)
    }
    fn group(self) -> Group {
        Group {
            interface_index: self.interface_index,
            protocol: self.protocol,
            ipv6: self.ipv6,
        }
    }
}
impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash_value());
    }
}

// All candidates use the actual production tuple hash.
fn tuple_hash(connection: &Connection) -> u64 {
    cache::tuple_hash(connection)
}

#[derive(Clone, Copy, Debug)]
struct TrafficRecord {
    // Dataset-only oracle index; stores never read this field.
    flow_id: usize,
    interface_index: u32,
    connection: Connection,
    bytes: u64,
}
#[derive(Clone, Copy, Debug)]
struct Stat {
    interface_index: u32,
    connection: Connection,
    tx: u64,
    rx: u64,
}
impl Stat {
    fn new(record: &TrafficRecord) -> Self {
        let mut stat = Self {
            interface_index: record.interface_index,
            connection: record.connection,
            tx: 0,
            rx: 0,
        };
        stat.add(record);
        stat
    }
    fn add(&mut self, record: &TrafficRecord) {
        match record.connection.direction {
            Direction::Outbound => self.tx = self.tx.saturating_add(record.bytes),
            Direction::Inbound => self.rx = self.rx.saturating_add(record.bytes),
        }
    }
    fn key(self) -> Key {
        Key::from_record(&TrafficRecord {
            flow_id: 0,
            interface_index: self.interface_index,
            connection: self.connection,
            bytes: 0,
        })
    }
    fn group(self) -> Group {
        self.key().group()
    }
    fn wire(self) -> BandwidthEntry {
        BandwidthEntry {
            local_ip: self.connection.local_ip,
            local_port: self.connection.local_port,
            remote_ip: self.connection.remote_ip,
            remote_port: self.connection.remote_port,
            transmitted_bytes: self.tx,
            received_bytes: self.rx,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Group {
    interface_index: u32,
    protocol: u8,
    ipv6: bool,
}
struct Layouts {
    groups: Vec<Group>,
}
impl Layouts {
    fn new(interfaces: u32) -> Self {
        let mut groups = Vec::with_capacity(interfaces as usize * 4);
        for interface_index in 1..=interfaces {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    groups.push(Group {
                        interface_index,
                        protocol,
                        ipv6,
                    });
                }
            }
        }
        Self { groups }
    }
    fn slot(&self, group: Group) -> usize {
        let interface = group.interface_index as usize - 1;
        let protocol = match group.protocol {
            6 => 0,
            17 => 1,
            _ => panic!("only TCP/UDP are generated"),
        };
        interface * 4 + protocol * 2 + usize::from(group.ipv6)
    }
}

struct Snapshot {
    counts: Vec<usize>,
    entries: usize,
    checksum: u64,
}
impl Snapshot {
    fn new(layouts: &Layouts) -> Self {
        Self {
            counts: vec![0; layouts.groups.len()],
            entries: 0,
            checksum: 0,
        }
    }
    fn push(&mut self, layouts: &Layouts, stat: Stat) {
        let group = stat.group();
        self.counts[layouts.slot(group)] += 1;
        self.entries += 1;
        let size = bandwidth_entry_len(group.ipv6);
        let mut bytes = [0; 52];
        encode_bandwidth_entry(&mut bytes[..size], group.ipv6, &stat.wire()).unwrap();
        for byte in &bytes[..size] {
            self.checksum = (self.checksum ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3);
        }
    }
    fn wire_bytes(&self, layouts: &Layouts) -> usize {
        layouts
            .groups
            .iter()
            .zip(&self.counts)
            .filter(|(_, count)| **count != 0)
            .map(|(group, count)| bandwidth_record_len(group.ipv6, *count).unwrap())
            .sum()
    }
    fn groups(&self) -> usize {
        self.counts.iter().filter(|count| **count != 0).count()
    }
}

trait Store: Default {
    fn add(&mut self, record: &TrafficRecord) -> bool;
    fn len(&self) -> usize;
    fn visit(&self, visitor: &mut dyn FnMut(Stat));
    fn snapshot(&self, layouts: &Layouts) -> Snapshot {
        let mut snapshot = Snapshot::new(layouts);
        self.visit(&mut |stat| snapshot.push(layouts, stat));
        snapshot
    }
}

struct DriverIndexed {
    store: driver_bandwidth::BandwidthStore,
}
impl Default for DriverIndexed {
    fn default() -> Self {
        Self {
            store: driver_bandwidth::BandwidthStore::new(),
        }
    }
}
impl Store for DriverIndexed {
    fn add(&mut self, record: &TrafficRecord) -> bool {
        // Same unlocked prepare/install/one-accounting-operation sequence as
        // the bridge. No policy lock or NDIS costs are timed in this example.
        let mut work = driver_bandwidth::BandwidthWork::prepare(self.store.plan());
        self.store.install(&mut work);
        self.store
            .add(
                record.interface_index,
                &record.connection,
                record.bytes,
                &mut work,
            )
            .is_some()
    }
    fn len(&self) -> usize {
        self.store.len()
    }
    fn visit(&self, visitor: &mut dyn FnMut(Stat)) {
        self.store
            .visit_totals(&mut |interface_index, connection, tx, rx| {
                visitor(Stat {
                    interface_index,
                    connection: *connection,
                    tx,
                    rx,
                });
            });
    }
}

fn same(left: &Stat, right: &TrafficRecord) -> bool {
    left.key() == Key::from_record(right)
}

// Frozen pre-indexed production shape: stable list buckets and one fallible
// stable node per distinct traffic tuple.
struct Lists<const BUCKETS: usize> {
    buckets: [List<Stat>; BUCKETS],
    count: usize,
}
impl<const BUCKETS: usize> Default for Lists<BUCKETS> {
    fn default() -> Self {
        Self {
            buckets: [const { List::new() }; BUCKETS],
            count: 0,
        }
    }
}
impl<const BUCKETS: usize> Lists<BUCKETS> {
    fn index(record: &TrafficRecord) -> usize {
        (tuple_hash(&record.connection).rotate_left(5)
            ^ u64::from(record.connection.protocol)
            ^ u64::from(record.interface_index).wrapping_mul(0x9e37_79b9)) as usize
            & (BUCKETS - 1)
    }
}
impl<const BUCKETS: usize> Store for Lists<BUCKETS> {
    fn add(&mut self, record: &TrafficRecord) -> bool {
        let bucket = &mut self.buckets[Self::index(record)];
        if let Some(stat) = bucket.iter_mut().find(|stat| same(stat, record)) {
            stat.add(record);
            return true;
        }
        if bucket.try_push_back(Stat::new(record)).is_err() {
            return false;
        }
        self.count += 1;
        true
    }
    fn len(&self) -> usize {
        self.count
    }
    fn visit(&self, visitor: &mut dyn FnMut(Stat)) {
        for bucket in &self.buckets {
            for stat in bucket.iter() {
                visitor(*stat);
            }
        }
    }
    fn snapshot(&self, layouts: &Layouts) -> Snapshot {
        // Match BandwidthTable::report's repeated group scans. This is the
        // report behavior that the current detached table actually exercises.
        let mut groups = Vec::new();
        self.visit(&mut |stat| {
            let group = stat.group();
            if !groups.contains(&group) {
                groups.push(group);
            }
        });
        groups.sort_unstable();
        let mut snapshot = Snapshot::new(layouts);
        for group in groups {
            self.visit(&mut |stat| {
                if stat.group() == group {
                    snapshot.push(layouts, stat);
                }
            });
        }
        snapshot
    }
}

#[derive(Clone, Copy)]
struct PageNode {
    next: u32,
    key: Key,
    tx: u64,
    rx: u64,
}
impl PageNode {
    const EMPTY: Self = Self {
        next: 0,
        key: Key {
            interface_index: 0,
            protocol: 0,
            ipv6: false,
            local_ip: [0; 16],
            local_port: 0,
            remote_ip: [0; 16],
            remote_port: 0,
        },
        tx: 0,
        rx: 0,
    };
    fn stat(self) -> Stat {
        Stat {
            interface_index: self.key.interface_index,
            connection: self.key.connection(),
            tx: self.tx,
            rx: self.rx,
        }
    }
}

// Stable pages reduce per-entry allocator calls while keeping entry addresses
// stable. The page-pointer Vec is only a benchmark simplification; production
// would prepare/retire its page directory outside PolicyLock.
struct Paged<const BUCKETS: usize, const PAGE: usize> {
    heads: Vec<u32>,
    pages: Vec<Box<[PageNode; PAGE]>>,
    count: usize,
}
impl<const BUCKETS: usize, const PAGE: usize> Default for Paged<BUCKETS, PAGE> {
    fn default() -> Self {
        Self {
            heads: vec![0; BUCKETS],
            pages: Vec::new(),
            count: 0,
        }
    }
}
impl<const BUCKETS: usize, const PAGE: usize> Paged<BUCKETS, PAGE> {
    fn node(&self, index: u32) -> &PageNode {
        let position = index as usize - 1;
        &self.pages[position / PAGE][position % PAGE]
    }
    fn node_mut(&mut self, index: u32) -> &mut PageNode {
        let position = index as usize - 1;
        &mut self.pages[position / PAGE][position % PAGE]
    }
    fn allocate(&mut self) -> u32 {
        let position = self.count;
        if position.is_multiple_of(PAGE) {
            self.pages.push(Box::new([PageNode::EMPTY; PAGE]));
        }
        self.count += 1;
        (position + 1) as u32
    }
}
impl<const BUCKETS: usize, const PAGE: usize> Store for Paged<BUCKETS, PAGE> {
    fn add(&mut self, record: &TrafficRecord) -> bool {
        let key = Key::from_record(record);
        let hash = key.hash_value();
        let bucket = (hash as usize) & (BUCKETS - 1);
        let mut index = self.heads[bucket];
        while index != 0 {
            let next = self.node(index).next;
            if self.node(index).key == key {
                let node = self.node_mut(index);
                match record.connection.direction {
                    Direction::Outbound => node.tx = node.tx.saturating_add(record.bytes),
                    Direction::Inbound => node.rx = node.rx.saturating_add(record.bytes),
                }
                return true;
            }
            index = next;
        }
        let index = self.allocate();
        let next = self.heads[bucket];
        let node = self.node_mut(index);
        node.next = next;
        node.key = key;
        match record.connection.direction {
            Direction::Outbound => node.tx = record.bytes,
            Direction::Inbound => node.rx = record.bytes,
        }
        self.heads[bucket] = index;
        true
    }
    fn len(&self) -> usize {
        self.count
    }
    fn visit(&self, visitor: &mut dyn FnMut(Stat)) {
        for position in 0..self.count {
            visitor(self.pages[position / PAGE][position % PAGE].stat());
        }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    hash: u64,
    key: Key,
    tx: u64,
    rx: u64,
}
impl Slot {
    const EMPTY: Self = Self {
        used: false,
        hash: 0,
        key: PageNode::EMPTY.key,
        tx: 0,
        rx: 0,
    };
    fn stat(self) -> Stat {
        Stat {
            interface_index: self.key.interface_index,
            connection: self.key.connection(),
            tx: self.tx,
            rx: self.rx,
        }
    }
}
#[derive(Default)]
struct Flat {
    slots: Vec<Slot>,
    count: usize,
}
impl Flat {
    fn find(&self, key: Key, hash: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut index = hash as usize & mask;
        for _ in 0..self.slots.len() {
            let slot = self.slots[index];
            if !slot.used {
                return None;
            }
            if slot.hash == hash && slot.key == key {
                return Some(index);
            }
            index = (index + 1) & mask;
        }
        None
    }
    fn grow(&mut self) {
        let capacity = self.slots.len().max(128) * 2;
        let old = mem::replace(&mut self.slots, vec![Slot::EMPTY; capacity]);
        self.count = 0;
        for slot in old.into_iter().filter(|slot| slot.used) {
            let mask = self.slots.len() - 1;
            let mut index = slot.hash as usize & mask;
            loop {
                if !self.slots[index].used {
                    self.slots[index] = slot;
                    self.count += 1;
                    break;
                }
                index = (index + 1) & mask;
            }
        }
    }
}
impl Store for Flat {
    fn add(&mut self, record: &TrafficRecord) -> bool {
        let key = Key::from_record(record);
        let hash = key.hash_value();
        if let Some(index) = self.find(key, hash) {
            let slot = &mut self.slots[index];
            match record.connection.direction {
                Direction::Outbound => slot.tx = slot.tx.saturating_add(record.bytes),
                Direction::Inbound => slot.rx = slot.rx.saturating_add(record.bytes),
            }
            return true;
        }
        if self.slots.is_empty() || (self.count + 1) * 4 > self.slots.len() * 3 {
            self.grow();
        }
        let mut slot = Slot::EMPTY;
        slot.used = true;
        slot.hash = hash;
        slot.key = key;
        match record.connection.direction {
            Direction::Outbound => slot.tx = record.bytes,
            Direction::Inbound => slot.rx = record.bytes,
        }
        let mask = self.slots.len() - 1;
        let mut index = hash as usize & mask;
        loop {
            if !self.slots[index].used {
                self.slots[index] = slot;
                self.count += 1;
                return true;
            }
            index = (index + 1) & mask;
        }
    }
    fn len(&self) -> usize {
        self.count
    }
    fn visit(&self, visitor: &mut dyn FnMut(Stat)) {
        for slot in &self.slots {
            if slot.used {
                visitor(slot.stat());
            }
        }
    }
}

#[derive(Default)]
struct IdentityHasher(u64);
impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        panic!("complete tuple hash required")
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}
struct Standard(HashMap<Key, (u64, u64), BuildHasherDefault<IdentityHasher>>);
impl Default for Standard {
    fn default() -> Self {
        Self(HashMap::with_hasher(BuildHasherDefault::default()))
    }
}
impl Store for Standard {
    fn add(&mut self, record: &TrafficRecord) -> bool {
        let counters = self.0.entry(Key::from_record(record)).or_default();
        match record.connection.direction {
            Direction::Outbound => counters.0 = counters.0.saturating_add(record.bytes),
            Direction::Inbound => counters.1 = counters.1.saturating_add(record.bytes),
        }
        true
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn visit(&self, visitor: &mut dyn FnMut(Stat)) {
        for (key, &(tx, rx)) in &self.0 {
            visitor(Stat {
                interface_index: key.interface_index,
                connection: key.connection(),
                tx,
                rx,
            });
        }
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
    fn shuffle<T>(&mut self, values: &mut [T]) {
        for i in (1..values.len()).rev() {
            values.swap(i, self.next() as usize % (i + 1));
        }
    }
}
fn connection(flow: usize, interfaces: u32) -> (u32, Connection) {
    let id = flow as u32;
    let interface_index = id % interfaces + 1;
    let ipv6 = id.is_multiple_of(4);
    let protocol = if id % 10 < 7 { 6 } else { 17 };
    let local_slot = id % 64;
    let remote_slot = id / 64;
    let mut c = Connection::EMPTY;
    c.ipv6 = ipv6;
    c.protocol = protocol;
    c.local_port = 1_024 + (id % 60_000) as u16;
    c.remote_port = if protocol == 17 && id % 10 >= 8 {
        53
    } else if id % 10 == 7 {
        80
    } else {
        443
    };
    if ipv6 {
        c.local_ip[..8].copy_from_slice(&0xfd00_0000_0000_0001u64.to_be_bytes());
        c.remote_ip[..8].copy_from_slice(&0x2001_0db8_0000_0002u64.to_be_bytes());
        c.local_ip[12..].copy_from_slice(&local_slot.to_be_bytes());
        c.remote_ip[12..].copy_from_slice(&remote_slot.to_be_bytes());
    } else {
        c.local_ip[..4].copy_from_slice(&[10, 24, 0, local_slot as u8]);
        c.remote_ip[..4].copy_from_slice(&[
            203,
            (remote_slot >> 16) as u8,
            (remote_slot >> 8) as u8,
            remote_slot as u8,
        ]);
    }
    (interface_index, c)
}
fn bytes(rng: &mut Rng) -> u64 {
    match rng.next() % 1_000 {
        0..=479 => 64 + rng.next() % 193,
        480..=899 => 512 + rng.next() % 989,
        900..=984 => 1_501 + rng.next() % 14_500,
        _ => 64 * 1024 + rng.next() % (512 * 1024),
    }
}
fn select_flow(index: usize, flows: usize, rng: &mut Rng) -> usize {
    if index < flows {
        return index;
    }
    match rng.next() % 1_000 {
        0..=349 => rng.next() as usize % flows.clamp(1, 64),
        350..=699 => rng.next() as usize % flows.clamp(1, 4_096),
        700..=919 if flows > 4_096 => {
            4_096 + rng.next() as usize % (flows - 4_096).clamp(1, 50_000)
        }
        _ => rng.next() as usize % flows,
    }
}

struct Dataset {
    records: Vec<TrafficRecord>,
    expected: Vec<(Key, u64, u64)>,
    wire_bytes: usize,
    groups: usize,
}
impl Dataset {
    fn new(record_count: usize, flow_count: usize, interfaces: u32, seed: u64) -> Self {
        let flows: Vec<_> = (0..flow_count)
            .map(|id| connection(id, interfaces))
            .collect();
        let mut rng = Rng(seed);
        let records: Vec<_> = (0..record_count)
            .map(|index| {
                let flow = select_flow(index, flow_count, &mut rng);
                let (interface_index, mut c) = flows[flow];
                c.direction = if rng.next() % 100 < 55 {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                };
                TrafficRecord {
                    flow_id: flow,
                    interface_index,
                    connection: c,
                    bytes: bytes(&mut rng),
                }
            })
            .collect();
        let mut expected: Vec<(Key, u64, u64)> = flows
            .iter()
            .map(|&(interface_index, c)| (Key::new(interface_index, &c), 0, 0))
            .collect();
        for record in &records {
            let entry = &mut expected[record.flow_id];
            match record.connection.direction {
                Direction::Outbound => entry.1 = entry.1.saturating_add(record.bytes),
                Direction::Inbound => entry.2 = entry.2.saturating_add(record.bytes),
            }
        }
        expected.sort_unstable();
        let mut group_counts: HashMap<Group, usize> = HashMap::new();
        for &(key, _, _) in &expected {
            *group_counts.entry(key.group()).or_default() += 1;
        }
        let wire_bytes = group_counts
            .iter()
            .map(|(group, count)| bandwidth_record_len(group.ipv6, *count).unwrap())
            .sum();
        Self {
            records,
            expected,
            wire_bytes,
            groups: group_counts.len(),
        }
    }
}

struct Row {
    name: &'static str,
    fill_ms: Vec<f64>,
    update_ns: Vec<f64>,
    report_ms: Vec<f64>,
    memory: usize,
    peak: usize,
    allocations: usize,
}
fn add_all<S: Store>(store: &mut S, records: &[TrafficRecord]) {
    for record in records {
        assert!(store.add(black_box(record)));
    }
    black_box(store.len());
}
fn canonical<S: Store>(store: &S) -> Vec<(Key, u64, u64)> {
    let mut values = Vec::with_capacity(store.len());
    store.visit(&mut |stat| values.push((stat.key(), stat.tx, stat.rx)));
    values.sort_unstable();
    values
}
fn measure<S: Store>(
    dataset: &Dataset,
    layouts: &Layouts,
    rounds: usize,
    name: &'static str,
) -> Row {
    let mut fills = Vec::with_capacity(rounds);
    let mut updates = Vec::with_capacity(rounds);
    let mut reports = Vec::with_capacity(rounds);
    let base_calls = CALLS.load(Ordering::Relaxed);
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let started = Instant::now();
    let mut store = Box::new(S::default());
    add_all(&mut *store, &dataset.records);
    let initial_fill = started.elapsed().as_secs_f64() * 1_000.0;
    let memory = LIVE.load(Ordering::Relaxed) - base;
    let peak = PEAK.load(Ordering::Relaxed) - base;
    let calls_after_fill = CALLS.load(Ordering::Relaxed);
    assert_eq!(
        canonical(&*store),
        dataset.expected,
        "{name}: fill mismatch"
    );
    assert_eq!(
        store.len(),
        dataset.expected.len(),
        "{name}: entry count mismatch"
    );
    fills.push(initial_fill);
    for round in 0..rounds {
        if round != 0 {
            let started = Instant::now();
            let mut fresh = Box::new(S::default());
            add_all(&mut *fresh, &dataset.records);
            fills.push(started.elapsed().as_secs_f64() * 1_000.0);
            assert_eq!(
                canonical(&*fresh),
                dataset.expected,
                "{name}: repeat fill mismatch"
            );
            store = fresh;
        }
        let existing_len = store.len();
        let update_calls = CALLS.load(Ordering::Relaxed);
        let started = Instant::now();
        add_all(&mut *store, &dataset.records);
        assert_eq!(
            store.len(),
            existing_len,
            "{name}: steady update inserted a new key"
        );
        let elapsed =
            started.elapsed().as_secs_f64() * 1_000_000_000.0 / dataset.records.len() as f64;
        if !cfg!(test) {
            assert_eq!(
                CALLS.load(Ordering::Relaxed),
                update_calls,
                "{name}: existing-key update allocated"
            );
        }
        let mut expected_twice = dataset.expected.clone();
        for (_, tx, rx) in &mut expected_twice {
            *tx = tx.saturating_mul(2);
            *rx = rx.saturating_mul(2);
        }
        assert_eq!(
            canonical(&*store),
            expected_twice,
            "{name}: update mismatch"
        );
        updates.push(elapsed);
        let started = Instant::now();
        let snapshot = store.snapshot(layouts);
        let report_elapsed = started.elapsed().as_secs_f64() * 1_000.0;
        assert_eq!(
            snapshot.entries,
            dataset.expected.len(),
            "{name}: report entries mismatch"
        );
        assert_eq!(
            snapshot.groups(),
            dataset.groups,
            "{name}: report groups mismatch"
        );
        assert_eq!(
            snapshot.wire_bytes(layouts),
            dataset.wire_bytes,
            "{name}: report size mismatch"
        );
        black_box(snapshot.checksum);
        reports.push(report_elapsed);
    }
    drop(store);
    if !cfg!(test) {
        assert_eq!(LIVE.load(Ordering::Relaxed), base, "{name}: storage leak");
    }
    Row {
        name,
        fill_ms: fills,
        update_ns: updates,
        report_ms: reports,
        memory,
        peak,
        allocations: calls_after_fill - base_calls,
    }
}
fn median(values: impl Iterator<Item = f64>) -> f64 {
    let mut copy: Vec<_> = values.collect();
    copy.sort_unstable_by(f64::total_cmp);
    copy[copy.len() / 2]
}
fn dispatch(index: usize, dataset: &Dataset, layouts: &Layouts, rounds: usize) -> Row {
    match index {
        0 => measure::<Lists<256>>(dataset, layouts, rounds, NAMES[index]),
        1 => measure::<Lists<4096>>(dataset, layouts, rounds, NAMES[index]),
        2 => measure::<Lists<16384>>(dataset, layouts, rounds, NAMES[index]),
        3 => measure::<Paged<4096, PAGE_SIZE>>(dataset, layouts, rounds, NAMES[index]),
        4 => measure::<Flat>(dataset, layouts, rounds, NAMES[index]),
        5 => measure::<Standard>(dataset, layouts, rounds, NAMES[index]),
        6 => measure::<indexed::IndexedPages>(dataset, layouts, rounds, NAMES[index]),
        7 => measure::<DriverIndexed>(dataset, layouts, rounds, NAMES[index]),
        _ => unreachable!(),
    }
}

struct Config {
    records: usize,
    flows: usize,
    interfaces: u32,
    rounds: usize,
    seed: u64,
    scenario: String,
    output: PathBuf,
}
impl Config {
    fn parse() -> Self {
        let mut config = Self {
            records: DEFAULT_RECORDS,
            flows: DEFAULT_FLOWS,
            interfaces: 1,
            rounds: DEFAULT_ROUNDS,
            seed: DEFAULT_SEED,
            scenario: "realistic".into(),
            output: "build/bandwidth-bench".into(),
        };
        let mut args = std::env::args().skip(1);
        while let Some(option) = args.next() {
            if option == "--help" {
                println!(
                    "Offline driver bandwidth benchmark; no device/network access.\n--records N --flows N --interfaces N --rounds N --seed N --scenario realistic|unique --out NEW_DIRECTORY"
                );
                std::process::exit(0);
            }
            let value = args.next().expect("option requires a value");
            match option.as_str() {
                "--records" => config.records = value.parse().unwrap(),
                "--flows" => config.flows = value.parse().unwrap(),
                "--interfaces" => config.interfaces = value.parse().unwrap(),
                "--rounds" => config.rounds = value.parse().unwrap(),
                "--seed" => config.seed = value.parse().unwrap(),
                "--scenario" => config.scenario = value,
                "--out" => config.output = value.into(),
                _ => panic!("unknown option: {option}"),
            }
        }
        assert!((128..=10_000_000).contains(&config.records));
        assert!(config.flows > 0 && config.flows <= config.records);
        assert!((1..=64).contains(&config.interfaces));
        assert!((1..=31).contains(&config.rounds));
        assert!(matches!(config.scenario.as_str(), "realistic" | "unique"));
        config
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

fn main() {
    let config = Config::parse();
    let (_affinity, affinity) = affinity::Guard::pin();
    println!("Benchmark thread pinned to {affinity}");
    let flow_count = if config.scenario == "unique" {
        config.records
    } else {
        config.flows
    };
    fs::create_dir_all(&config.output).unwrap();
    let report_path = config.output.join("report.md");
    let samples_path = config.output.join("samples.tsv");
    assert!(
        !report_path.exists() && !samples_path.exists(),
        "refusing to overwrite prior results"
    );
    println!(
        "Generating {} records over {} distinct flows",
        config.records, flow_count
    );
    let layouts = Layouts::new(config.interfaces);
    let dataset = Dataset::new(config.records, flow_count, config.interfaces, config.seed);
    println!(
        "Dataset has {} groups and {:.1} MiB of observations",
        dataset.groups,
        dataset.records.len() as f64 * mem::size_of::<TrafficRecord>() as f64 / 1_048_576.0
    );
    let mut raw = BufWriter::new(File::create(&samples_path).unwrap());
    writeln!(raw, "container\tround\tfill_ms\tupdate_ns_per_record\treport_ms\tmemory_bytes\tpeak_bytes\tallocation_calls").unwrap();
    let mut rows = Vec::new();
    let mut order_rng = Rng(config.seed ^ 0x0051_5545_5259);
    for round in 0..config.rounds {
        let mut order: [usize; NAMES.len()] = std::array::from_fn(|i| i);
        order_rng.shuffle(&mut order);
        for index in order {
            // Each row rebuilds after the first round so fill includes growth.
            let row = dispatch(index, &dataset, &layouts, 1);
            let sample = Row {
                fill_ms: vec![median(row.fill_ms.iter().copied())],
                update_ns: vec![median(row.update_ns.iter().copied())],
                report_ms: vec![median(row.report_ms.iter().copied())],
                ..row
            };
            println!(
                "{} round {}: fill {:.1} ms, update {:.2} ns/record, report {:.1} ms, {:.2} MiB",
                sample.name,
                round + 1,
                sample.fill_ms[0],
                sample.update_ns[0],
                sample.report_ms[0],
                sample.memory as f64 / 1_048_576.0
            );
            writeln!(
                raw,
                "{}\t{}\t{:.6}\t{:.6}\t{:.6}\t{}\t{}\t{}",
                sample.name,
                round,
                sample.fill_ms[0],
                sample.update_ns[0],
                sample.report_ms[0],
                sample.memory,
                sample.peak,
                sample.allocations
            )
            .unwrap();
            rows.push(sample);
        }
    }
    raw.flush().unwrap();
    let current_updates: Vec<_> = rows
        .iter()
        .filter(|row| row.name == NAMES[0])
        .map(|row| row.update_ns[0])
        .collect();
    let baseline = median(current_updates.iter().copied());
    let mut report = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&report_path)
            .unwrap(),
    );
    writeln!(report, "# Offline kernel bandwidth aggregation benchmark\n").unwrap();
    writeln!(report, "- No driver/device/network access. The test models the Rust policy data path after admission, not monitor-side `BandwidthStats` vector filling.\n- Dataset: {} observations, {} distinct normalized TCP/UDP flows, {} host interface index scope(s), seed `{}`. Default realistic mode uses 35% hottest 64 flows, 35% hottest 4096, 22% next 50,000 and 8% cold pool; first distinct flows are introduced once. Direction is 55% guest outbound / 45% inbound; protocol is 70% TCP / 30% UDP; family is 75% IPv4 / 25% IPv6; sizes are mostly small/MTU packets with occasional offload-sized records.\n- Key equality is `(interface_index, protocol, family, normalized local IP/port, normalized remote IP/port)`; direction only chooses TX/RX. The hash is the production tuple hash plus interface/protocol bucket mixing.\n- Fill includes new-entry allocation and growth. Update replays existing keys and independently asserts that the number of stored keys is unchanged; the allocation-call column is fill allocation telemetry, not a proof about unrelated process allocations. Report encodes every entry with the real explicit wire codec; current lists use repeated group scans like `BandwidthTable::report`, alternatives use one pass. All counters, full identities, group counts and complete wire sizes are checked.\n", config.records, flow_count, config.interfaces, config.seed).unwrap();
    writeln!(report, "## Containers\n\n| Container | Suitability | Design |\n|---|---|---|\n| `list_256_legacy` | Frozen baseline | Previous 256 stable intrusive lists; one allocation per entry. |\n| `list_4096` / `list_16384` | Stable-list alternatives | Same ownership semantics; more fixed bucket headers shorten chains. |\n| `paged_4096x256` | Kernel-compatible candidate | Stable index-linked entries in 256-entry pages; fewer allocations, no entry relocation. Page-directory growth must be prepared/retired outside PolicyLock in production. |\n| `flat_hash_host_upper_bound` | Not a drop-in kernel option | Fast contiguous open addressing, but growth moves entries and allocates a replacement table. |\n| `std_hashmap_host_reference` | Not a kernel option | Host `std::HashMap` reference only; no `no_std`/nonpaged/fallible driver semantics. |\n| `indexed_pages_incremental` | Stable-storage algorithm prototype | Growing open-addressing handle index; stable 128-entry pages, fallible reservation and at most 32 old index slots migrated on each insertion. Benchmark-only directory-based reference; not the integrated driver source. |
| `driver_indexed_pages_incremental` | Actual production storage source | Stable 128-entry linked pages and direct-pointer handles; prepared page/index/owner allocation, insertion-only migration of 32 slots and unlocked index retirement. |\n").unwrap();
    writeln!(report, "## Results\n\nLower is better. Fill and report are milliseconds; update is nanoseconds per observation. Speedups use the median current-list update row.\n\n| Container | Fill median ms | Update ns/record | vs current | Report median ms | Memory MiB | Peak MiB |\n|---|---:|---:|---:|---:|---:|---:|").unwrap();
    for name in NAMES {
        let selected: Vec<_> = rows.iter().filter(|row| row.name == name).collect();
        let fill = median(selected.iter().map(|row| row.fill_ms[0]));
        let update = median(selected.iter().map(|row| row.update_ns[0]));
        let report_ms = median(selected.iter().map(|row| row.report_ms[0]));
        let memory = selected[selected.len() / 2].memory;
        let peak = selected[selected.len() / 2].peak;
        writeln!(
            report,
            "| `{name}` | {fill:.2} | {update:.2} | {:.2}x | {report_ms:.2} | {:.2} | {:.2} |",
            baseline / update,
            memory as f64 / 1_048_576.0,
            peak as f64 / 1_048_576.0
        )
        .unwrap();
    }
    let eligible = [NAMES[0], NAMES[1], NAMES[2], NAMES[3], NAMES[7]];
    let winner = eligible
        .iter()
        .min_by(|left, right| {
            let left_value = median(
                rows.iter()
                    .filter(|row| row.name == **left)
                    .map(|row| row.update_ns[0]),
            );
            let right_value = median(
                rows.iter()
                    .filter(|row| row.name == **right)
                    .map(|row| row.update_ns[0]),
            );
            left_value.total_cmp(&right_value)
        })
        .unwrap();
    writeln!(report, "\n## Selection\n\nThe measured production-eligible winner for the **write path** is **`{winner}`**, selected by lowest median steady-state update latency among the current and stable-storage candidates. `flat_hash_host_upper_bound` and `std_hashmap_host_reference` must not be selected solely because they win a host microbenchmark: they relocate/grow differently or use host-only allocation. The driver source adapter is integrated into the engine/bridge with unlocked preparation and retirement. Host adapters do not measure the bridge lock, detached-report retry consolidation, NDIS callbacks or live lifecycle safety.\n\nThis benchmark is synthetic and single-threaded. It does not prove NDIS throughput, lock contention, IRQL cost, allocator contention, OOM behavior or live pause/restart/uninstall safety.\n").unwrap();
    report.flush().unwrap();
    println!("Saved {}", report_path.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generator_has_unique_full_keys_and_both_directions() {
        let dataset = Dataset::new(2_000, 500, 2, DEFAULT_SEED);
        let mut keys = HashMap::new();
        for (key, _, _) in dataset.expected {
            assert!(keys.insert(key, ()).is_none());
        }
        assert!(
            dataset
                .records
                .iter()
                .any(|record| record.connection.direction == Direction::Inbound)
        );
    }
    #[test]
    fn all_containers_match_oracle() {
        let dataset = Dataset::new(2_000, 500, 1, DEFAULT_SEED ^ 1);
        let layouts = Layouts::new(1);
        for index in 0..NAMES.len() {
            let row = dispatch(index, &dataset, &layouts, 1);
            assert!(row.update_ns[0].is_finite());
        }
    }
}
