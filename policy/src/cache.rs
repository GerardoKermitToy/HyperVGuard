use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, mem, ptr};
use hyperv_protocol::Connection;
use likely_stable::unlikely;

const INITIAL_CAPACITY: usize = 128;
const WORK_PER_PASS: usize = 32;
pub const CLEANUP_SLOTS_PER_BATCH: usize = 256;
#[path = "cache/group.rs"]
mod group;
use group::{Group, WIDTH as GROUP_WIDTH};

const EMPTY: u8 = 0x80;
const DELETED: u8 = 0xfe;

fn fingerprint(hash: u64) -> u8 {
    (hash >> 57) as u8
}

// Cache storage has its own fallible allocator for unlocked preparation/retirement.
#[derive(Clone, Copy)]
pub struct CacheAllocator {
    allocate: unsafe fn(usize) -> *mut u8,
    free: unsafe fn(*mut u8, usize),
}
impl CacheAllocator {
    /// # Safety
    /// Functions must allocate/free nonpaged, 16-byte-aligned storage, accept the
    /// original allocation size on free, and remain valid for every cache buffer.
    /// Allocation failure must return null rather than panic or bugcheck.
    pub const unsafe fn new(
        allocate: unsafe fn(usize) -> *mut u8,
        free: unsafe fn(*mut u8, usize),
    ) -> Self {
        Self { allocate, free }
    }
    pub(crate) const GLOBAL: Self = Self {
        allocate: global_allocate,
        free: global_free,
    };
}
unsafe fn global_allocate(size: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(size, 16) else {
        return ptr::null_mut();
    };
    unsafe { alloc(layout) }
}
unsafe fn global_free(data: *mut u8, size: usize) {
    if let Ok(layout) = Layout::from_size_align(size, 16) {
        unsafe { dealloc(data, layout) };
    }
}

struct Buffer {
    data: *mut u8,
    size: usize,
    allocator: CacheAllocator,
}
impl Buffer {
    const EMPTY: Self = Self {
        data: ptr::null_mut(),
        size: 0,
        allocator: CacheAllocator::GLOBAL,
    };
    fn allocate(
        size: usize,
        control_offset: usize,
        controls: usize,
        allocator: CacheAllocator,
    ) -> Option<Self> {
        Layout::from_size_align(size, 16).ok()?;
        if control_offset.checked_add(controls)? > size {
            return None;
        }
        let data = unsafe { (allocator.allocate)(size) };
        if unlikely(data.is_null()) {
            return None;
        }
        // Only control bytes (including the wrap mirror) need initialization.
        // Payloads stay uninitialized until insertion publishes a fingerprint.
        // Allocation/initialization is OUTSIDE the policy spin lock.
        unsafe { ptr::write_bytes(data.add(control_offset), EMPTY, controls) };
        Some(Self {
            data,
            size,
            allocator,
        })
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.data.is_null() {
            unsafe { (self.allocator.free)(self.data, self.size) };
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tuple<const N: usize> {
    local_ip: [u8; N],
    remote_ip: [u8; N],
    local_port: u16,
    remote_port: u16,
}
impl<const N: usize> Tuple<N> {
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
    fn hash(&self) -> u64 {
        // The benchmarked word hash of ONLY the normalized tuple. Fixed array
        // lengths match Rust's Hash encoding; full equality resolves collisions.
        // This deterministic speed-oriented hash is not keyed HashDoS protection.
        fn mix(h: u64, word: u64) -> u64 {
            (h.rotate_left(5) ^ word).wrapping_mul(0x517cc1b727220a95)
        }
        let mut h = 0;
        for ip in [&self.local_ip, &self.remote_ip] {
            h = mix(h, N as u64);
            for chunk in ip.chunks(8) {
                let mut word = [0; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                h = mix(h, u64::from_le_bytes(word));
            }
        }
        h = mix(h, u64::from(self.local_port));
        mix(h, u64::from(self.remote_port))
    }
}

pub(crate) fn tuple_hash(connection: &Connection) -> u64 {
    if unlikely(connection.ipv6) {
        Tuple::<16>::from_connection(connection).hash()
    } else {
        Tuple::<4>::from_connection(connection).hash()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Decision {
    pub allow: bool,
    pub expires: u64,
}
// Keep tuple and verdict together, with the same stride as a standard map pair.
// This is private cache storage, never the wire layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry<const N: usize> {
    tuple: Tuple<N>,
    expires: u64,
    allow: bool,
}
struct Table<const N: usize> {
    buffer: Buffer,
    capacity: usize,
    len: usize,
    used: usize,
    marker: core::marker::PhantomData<Entry<N>>,
}
impl<const N: usize> Table<N> {
    const fn new() -> Self {
        Self {
            buffer: Buffer::EMPTY,
            capacity: 0,
            len: 0,
            used: 0,
            marker: core::marker::PhantomData,
        }
    }
    fn layout(capacity: usize) -> Option<Layout> {
        if capacity < GROUP_WIDTH || !capacity.is_power_of_two() {
            return None;
        }
        let controls = capacity.checked_add(GROUP_WIDTH)?;
        let entries = Layout::array::<Entry<N>>(capacity).ok()?;
        let (layout, offset) = entries.extend(Layout::array::<u8>(controls).ok()?).ok()?;
        // Put payloads first so the control prefix cannot shift their alignment.
        // The allocator guarantees 16-byte alignment (Entry needs only eight).
        (offset == entries.size()).then_some(layout)
    }
    fn controls(&self) -> *mut u8 {
        unsafe {
            self.buffer
                .data
                .add(self.capacity * mem::size_of::<Entry<N>>())
        }
    }
    fn control(&self, index: usize) -> u8 {
        debug_assert!(index < self.capacity);
        unsafe { *self.controls().add(index) }
    }
    fn set_control(&mut self, index: usize, control: u8) {
        debug_assert!(index < self.capacity);
        unsafe {
            *self.controls().add(index) = control;
            if index < GROUP_WIDTH {
                *self.controls().add(self.capacity + index) = control;
            }
        }
    }
    fn is_full(&self, index: usize) -> bool {
        self.control(index) & 0x80 == 0
    }
    fn group(&self, index: usize) -> Group {
        debug_assert!(index < self.capacity);
        // The mirrored prefix permits an unaligned word read across the end.
        unsafe { Group::load(self.controls().add(index)) }
    }
    fn entries(&self) -> *mut Entry<N> {
        // layout() checked size/alignment before allocation; entries are read
        // only after a full control byte is observed under the policy lock.
        self.buffer.data.cast()
    }
    #[inline]
    fn lookup(&self, tuple: &Tuple<N>, hash: u64) -> Option<ptr::NonNull<Entry<N>>> {
        let mask = self.capacity.checked_sub(1)?;
        let mut offset = hash as usize & mask;
        let mut stride = 0;
        for _ in 0..self.capacity / GROUP_WIDTH {
            let group = self.group(offset);
            let mut matches = group.matches(fingerprint(hash));
            while matches != 0 {
                let index = (offset + matches.trailing_zeros() as usize) & mask;
                // The matching full control byte proves initialization. Keep the
                // bucket address through the hit path instead of recalculating
                // index * entry-size after choosing current/previous table.
                let entry = unsafe { ptr::NonNull::new_unchecked(self.entries().add(index)) };
                if unsafe { entry.as_ref() }.tuple == *tuple {
                    return Some(entry);
                }
                matches &= matches - 1;
            }
            if group.matches(EMPTY) != 0 {
                return None;
            }
            // Triangular group probing visits every group of a power-of-two
            // table once. A deleted slot never terminates a lookup chain.
            stride += GROUP_WIDTH;
            offset = (offset + stride) & mask;
        }
        None
    }
    fn find(&self, tuple: &Tuple<N>, hash: u64) -> Option<usize> {
        self.lookup(tuple, hash)
            .map(|entry| unsafe { entry.as_ptr().offset_from(self.entries()) as usize })
    }
    #[inline]
    fn get_entry(&self, tuple: &Tuple<N>, hash: u64) -> Option<&Entry<N>> {
        self.lookup(tuple, hash)
            .map(|entry| unsafe { entry.as_ref() })
    }
    #[inline]
    fn get_entry_mut(&mut self, tuple: &Tuple<N>, hash: u64) -> Option<&mut Entry<N>> {
        // The exclusive table borrow keeps the returned initialized bucket unique.
        self.lookup(tuple, hash)
            .map(|mut entry| unsafe { entry.as_mut() })
    }
    fn entry(&self, index: usize) -> &Entry<N> {
        debug_assert!(self.is_full(index));
        unsafe { &*self.entries().add(index) }
    }
    fn entry_mut(&mut self, index: usize) -> &mut Entry<N> {
        debug_assert!(self.is_full(index));
        unsafe { &mut *self.entries().add(index) }
    }
    fn insert(&mut self, entry: Entry<N>, hash: u64) -> bool {
        let Some(mask) = self.capacity.checked_sub(1) else {
            return false;
        };
        let mut offset = hash as usize & mask;
        let mut stride = 0;
        for _ in 0..self.capacity / GROUP_WIDTH {
            let available = self.group(offset).available();
            if available != 0 {
                let index = (offset + available.trailing_zeros() as usize) & mask;
                if self.control(index) == EMPTY {
                    self.used += 1;
                }
                // Callers have already excluded existing tuples. Initialize the
                // complete payload before publishing its seven-bit fingerprint.
                unsafe { self.entries().add(index).write(entry) };
                self.set_control(index, fingerprint(hash));
                self.len += 1;
                return true;
            }
            stride += GROUP_WIDTH;
            offset = (offset + stride) & mask;
        }
        false
    }
    fn remove(&mut self, index: usize) {
        debug_assert!(self.is_full(index));
        self.set_control(index, DELETED);
        self.len -= 1;
    }
    fn retire(&mut self, work: &mut CacheWork) {
        if work.retire(&mut self.buffer) {
            self.capacity = 0;
            self.len = 0;
            self.used = 0;
        }
    }
}

#[derive(Clone, Copy)]
pub struct CachePlan {
    ipv6: bool,
    capacity: usize,
    allocator: CacheAllocator,
}
struct Allocation {
    ipv6: bool,
    capacity: usize,
    buffer: Buffer,
}
impl CachePlan {
    fn allocate(self) -> Option<Allocation> {
        let layout = if unlikely(self.ipv6) {
            Table::<16>::layout(self.capacity)?
        } else {
            Table::<4>::layout(self.capacity)?
        };
        Some(Allocation {
            ipv6: self.ipv6,
            capacity: self.capacity,
            buffer: Buffer::allocate(
                layout.size(),
                layout
                    .size()
                    .checked_sub(self.capacity.checked_add(GROUP_WIDTH)?)?,
                self.capacity.checked_add(GROUP_WIDTH)?,
                self.allocator,
            )?,
        })
    }
}

// Prepare before acquiring the policy lock; drop AFTER releasing it. At most
// current/previous tables for all four caches can retire in one cleanup batch.
pub struct CacheWork {
    growth: Option<Allocation>,
    retired: [Buffer; 8],
}
impl CacheWork {
    pub const fn empty() -> Self {
        Self {
            growth: None,
            retired: [const { Buffer::EMPTY }; 8],
        }
    }
    pub fn prepare(plan: Option<CachePlan>) -> Self {
        Self {
            growth: plan.and_then(CachePlan::allocate),
            ..Self::empty()
        }
    }
    fn retire(&mut self, buffer: &mut Buffer) -> bool {
        if buffer.data.is_null() {
            return true;
        }
        if let Some(slot) = self.retired.iter_mut().find(|b| b.data.is_null()) {
            *slot = mem::replace(buffer, Buffer::EMPTY);
            true
        } else {
            false // Keep ownership in the table until a fresh work batch arrives.
        }
    }
}

struct Cache<const N: usize> {
    current: Table<N>,
    previous: Table<N>,
    migrate: usize,
}
impl<const N: usize> Cache<N> {
    const fn new() -> Self {
        Self {
            current: Table::new(),
            previous: Table::new(),
            migrate: 0,
        }
    }
    fn len(&self) -> usize {
        self.current.len + self.previous.len
    }
    fn plan(&self, allocator: CacheAllocator) -> Option<CachePlan> {
        if self.previous.capacity != 0 {
            return None;
        }
        let capacity = self.current.capacity;
        if capacity == 0 {
            return Some(CachePlan {
                ipv6: N == 16,
                capacity: INITIAL_CAPACITY,
                allocator,
            });
        }
        if self.current.used < capacity / 4 * 3 {
            return None;
        }
        Some(CachePlan {
            ipv6: N == 16,
            capacity: if self.current.len < capacity / 2 {
                capacity
            } else {
                capacity.checked_mul(2)?
            },
            allocator,
        })
    }
    fn get(&self, tuple: &Tuple<N>, hash: u64, now: u64) -> Option<bool> {
        for table in [&self.current, &self.previous] {
            if let Some(entry) = table.get_entry(tuple, hash) {
                return (entry.expires > now).then_some(entry.allow);
            }
        }
        None
    }
    fn apply(&mut self, tuple: &Tuple<N>, hash: u64, now: u64, ttl: u64) -> Option<bool> {
        for table in [&mut self.current, &mut self.previous] {
            if let Some(entry) = table.get_entry_mut(tuple, hash) {
                if entry.expires <= now {
                    return None;
                }
                if entry.allow {
                    entry.expires = now.saturating_add(ttl);
                }
                return Some(entry.allow);
            }
        }
        None
    }
    fn insert(&mut self, entry: Entry<N>, now: u64, work: &mut CacheWork) -> bool {
        let hash = entry.tuple.hash();
        for table in [&mut self.current, &mut self.previous] {
            if let Some(index) = table.find(&entry.tuple, hash) {
                *table.entry_mut(index) = entry;
                return true;
            }
        }
        if self.previous.capacity == 0 {
            let desired = self.plan(CacheAllocator::GLOBAL).map(|p| p.capacity);
            if let Some(capacity) = desired {
                let usable = work
                    .growth
                    .as_ref()
                    .is_some_and(|a| a.ipv6 == (N == 16) && a.capacity == capacity);
                if usable {
                    let allocation = work.growth.take().unwrap();
                    let new = Table {
                        buffer: allocation.buffer,
                        capacity,
                        ..Table::new()
                    };
                    self.previous = mem::replace(&mut self.current, new);
                    self.migrate = 0;
                }
            }
        }
        // Keep empty slots for bounded expected probes, including entries which
        // have not migrated yet. Failure does not evict any other live verdict.
        let capacity = self.current.capacity;
        let inserted = capacity != 0
            && self.len() < capacity / 4 * 3
            && self.current.used < capacity / 4 * 3
            && self.current.insert(entry, hash);
        self.migrate(now, work);
        inserted
    }
    fn migrate(&mut self, now: u64, work: &mut CacheWork) {
        let end = self
            .migrate
            .saturating_add(WORK_PER_PASS)
            .min(self.previous.capacity);
        while self.migrate < end {
            let index = self.migrate;
            if self.previous.is_full(index) {
                let entry = *self.previous.entry(index);
                let hash = entry.tuple.hash();
                if entry.expires > now && !self.current.insert(entry, hash) {
                    break;
                }
                self.previous.remove(index);
            }
            self.migrate += 1;
        }
        if self.previous.capacity != 0
            && (self.previous.len == 0 || self.migrate == self.previous.capacity)
        {
            self.previous.retire(work);
            self.migrate = 0;
        }
    }
    fn cleanup_slots(&self) -> usize {
        self.current.capacity.max(self.previous.capacity)
    }
    fn maintain_range(&mut self, start: usize, now: u64, work: &mut CacheWork) {
        // Scan control groups, reading expiry only for initialized entries. The
        // caller releases PolicyLock between ranges, not between timer ticks.
        for table in [&mut self.current, &mut self.previous] {
            let end = start
                .saturating_add(CLEANUP_SLOTS_PER_BATCH)
                .min(table.capacity);
            for base in (start..end).step_by(GROUP_WIDTH) {
                let width = (end - base).min(GROUP_WIDTH);
                let mut occupied = !table.group(base).available() & ((1u32 << width) - 1);
                while occupied != 0 {
                    let index = base + occupied.trailing_zeros() as usize;
                    if table.entry(index).expires <= now {
                        table.remove(index);
                    }
                    occupied &= occupied - 1;
                }
            }
        }
        if self.previous.len == 0 {
            self.previous.retire(work);
            self.migrate = 0;
        }
        // Keep a destination for insertion-side migration while old entries live.
        if self.current.len == 0 && self.previous.capacity == 0 {
            self.current.retire(work);
        }
    }
    fn maintain(&mut self, now: u64, work: &mut CacheWork) {
        for start in (0..self.cleanup_slots()).step_by(CLEANUP_SLOTS_PER_BATCH) {
            self.maintain_range(start, now, work);
        }
    }
    fn bytes(&self) -> usize {
        self.current.buffer.size + self.previous.buffer.size
    }
}

// Four independent caches per host interface: TCP/UDP, each with IPv4/IPv6.
// Inside each table identity is only the normalized IP/port tuple. Protocol and
// interface select the table; neither is hashed or stored in its entries.
// No fixed entry count and no capacity-driven eviction.
pub struct Caches {
    ipv4: [Cache<4>; 2],
    ipv6: [Cache<16>; 2],
    allocator: CacheAllocator,
}
impl Caches {
    pub const fn new(allocator: CacheAllocator) -> Self {
        Self {
            ipv4: [const { Cache::new() }; 2],
            ipv6: [const { Cache::new() }; 2],
            allocator,
        }
    }
    pub(crate) fn clear(&mut self) -> Self {
        mem::replace(self, Self::new(self.allocator))
    }
    fn transport(protocol: u8) -> Option<usize> {
        if unlikely(!matches!(protocol, 6 | 17)) {
            return None;
        }
        Some(usize::from(protocol == 17))
    }
    pub(crate) fn plan(&self, c: &Connection) -> Option<CachePlan> {
        let protocol = Self::transport(c.protocol)?;
        if unlikely(c.ipv6) {
            let cache = &self.ipv6[protocol];
            let tuple = Tuple::from_connection(c);
            let hash = tuple.hash();
            if cache.current.find(&tuple, hash).is_some()
                || cache.previous.find(&tuple, hash).is_some()
            {
                None
            } else {
                cache.plan(self.allocator)
            }
        } else {
            let cache = &self.ipv4[protocol];
            let tuple = Tuple::from_connection(c);
            let hash = tuple.hash();
            if cache.current.find(&tuple, hash).is_some()
                || cache.previous.find(&tuple, hash).is_some()
            {
                None
            } else {
                cache.plan(self.allocator)
            }
        }
    }
    pub(crate) fn get(&self, c: &Connection, now: u64) -> Option<bool> {
        let protocol = Self::transport(c.protocol)?;
        if unlikely(c.ipv6) {
            let tuple = Tuple::from_connection(c);
            self.ipv6[protocol].get(&tuple, tuple.hash(), now)
        } else {
            let tuple = Tuple::from_connection(c);
            self.ipv4[protocol].get(&tuple, tuple.hash(), now)
        }
    }
    pub(crate) fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        let protocol = Self::transport(c.protocol)?;
        if unlikely(c.ipv6) {
            let tuple = Tuple::from_connection(c);
            self.ipv6[protocol].apply(&tuple, tuple.hash(), now, ttl)
        } else {
            let tuple = Tuple::from_connection(c);
            self.ipv4[protocol].apply(&tuple, tuple.hash(), now, ttl)
        }
    }
    pub(crate) fn insert(
        &mut self,
        c: &Connection,
        decision: Decision,
        now: u64,
        work: &mut CacheWork,
    ) -> bool {
        let Some(protocol) = Self::transport(c.protocol) else {
            return false;
        };
        if unlikely(c.ipv6) {
            self.ipv6[protocol].insert(
                Entry {
                    tuple: Tuple::from_connection(c),
                    allow: decision.allow,
                    expires: decision.expires,
                },
                now,
                work,
            )
        } else {
            self.ipv4[protocol].insert(
                Entry {
                    tuple: Tuple::from_connection(c),
                    allow: decision.allow,
                    expires: decision.expires,
                },
                now,
                work,
            )
        }
    }
    pub(crate) fn cleanup_slots(&self) -> usize {
        self.ipv4
            .iter()
            .map(Cache::cleanup_slots)
            .chain(self.ipv6.iter().map(Cache::cleanup_slots))
            .max()
            .unwrap_or(0)
    }
    pub(crate) fn maintain_range(&mut self, start: usize, now: u64, work: &mut CacheWork) {
        for cache in &mut self.ipv4 {
            cache.maintain_range(start, now, work);
        }
        for cache in &mut self.ipv6 {
            cache.maintain_range(start, now, work);
        }
    }
    pub(crate) fn maintain(&mut self, now: u64, work: &mut CacheWork) {
        for cache in &mut self.ipv4 {
            cache.maintain(now, work);
        }
        for cache in &mut self.ipv6 {
            cache.maintain(now, work);
        }
    }
    pub(crate) fn has_entries(&self) -> bool {
        self.ipv4.iter().any(|c| c.len() != 0) || self.ipv6.iter().any(|c| c.len() != 0)
    }
    pub fn counts(&self) -> (usize, usize) {
        (
            self.ipv4.iter().map(Cache::len).sum(),
            self.ipv6.iter().map(Cache::len).sum(),
        )
    }
    pub fn bytes(&self) -> usize {
        self.ipv4.iter().map(Cache::bytes).sum::<usize>()
            + self.ipv6.iter().map(Cache::bytes).sum::<usize>()
    }
}

#[cfg(test)]
#[path = "cache/tests.rs"]
mod tests;
