// Frozen pre-grouped cache for offline A/B comparison only.
// This source is never included by the policy or driver library.

use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, mem, ptr, slice};
use hyperv_protocol::Connection;

const INITIAL_CAPACITY: usize = 128;
const WORK_PER_PASS: usize = 32;
const EMPTY: u8 = 0;
const FULL: u8 = 1;
const DELETED: u8 = 2;

// Cache storage has its own allocator in the driver, not the packet-record budget.
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
    fn allocate(size: usize, allocator: CacheAllocator) -> Option<Self> {
        Layout::from_size_align(size, 16).ok()?;
        let data = unsafe { (allocator.allocate)(size) };
        if data.is_null() {
            return None;
        }
        // Slot state and hash are integers; the entry is MaybeUninit until FULL.
        // Initialization is done by the caller OUTSIDE the policy spin lock.
        unsafe { ptr::write_bytes(data, 0, size) };
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
        // Word-at-a-time mixing of ONLY the requested normalized tuple. The full
        // tuple is compared too: a hash collision never aliases another connection.
        fn mix(h: u64, word: u64) -> u64 {
            (h ^ word.wrapping_mul(0xa0761d6478bd642f))
                .rotate_left(27)
                .wrapping_mul(0xe7037ed1a0b428db)
        }
        let mut h = 0x8ebc6af09c88c6e3;
        for ip in [&self.local_ip, &self.remote_ip] {
            for chunk in ip.chunks(8) {
                let mut word = [0; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                h = mix(h, u64::from_le_bytes(word));
            }
        }
        h = mix(
            h,
            u64::from(self.local_port) << 16 | u64::from(self.remote_port),
        );
        h ^= h >> 29;
        h = h.wrapping_mul(0x165667919e3779f9);
        h ^ (h >> 32)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Decision {
    pub allow: bool,
    pub expires: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry<const N: usize> {
    tuple: Tuple<N>,
    expires: u64,
    allow: bool,
}
struct Slot<const N: usize> {
    hash: u64,
    state: u8,
    entry: mem::MaybeUninit<Entry<N>>,
}
struct Table<const N: usize> {
    buffer: Buffer,
    capacity: usize,
    len: usize,
    used: usize,
}
impl<const N: usize> Table<N> {
    const fn new() -> Self {
        Self {
            buffer: Buffer::EMPTY,
            capacity: 0,
            len: 0,
            used: 0,
        }
    }
    fn slots(&self) -> &[Slot<N>] {
        if self.capacity == 0 {
            return &[];
        }
        // Buffer owns an aligned, initialized Slot array. Entries are read only
        // in FULL slots, and neither pointers nor references escape the cache.
        unsafe { slice::from_raw_parts(self.buffer.data.cast(), self.capacity) }
    }
    fn slots_mut(&mut self) -> &mut [Slot<N>] {
        if self.capacity == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts_mut(self.buffer.data.cast(), self.capacity) }
    }
    fn find(&self, tuple: &Tuple<N>, hash: u64) -> Option<usize> {
        let mask = self.capacity.checked_sub(1)?;
        let slots = self.slots();
        let mut index = hash as usize & mask;
        for _ in 0..self.capacity {
            let slot = &slots[index];
            if slot.state == EMPTY {
                return None;
            }
            if slot.state == FULL && slot.hash == hash {
                let entry = unsafe { slot.entry.assume_init_ref() };
                if entry.tuple == *tuple {
                    return Some(index);
                }
            }
            index = (index + 1) & mask;
        }
        None
    }
    fn entry(&self, index: usize) -> &Entry<N> {
        unsafe { self.slots()[index].entry.assume_init_ref() }
    }
    fn entry_mut(&mut self, index: usize) -> &mut Entry<N> {
        unsafe { self.slots_mut()[index].entry.assume_init_mut() }
    }
    fn insert(&mut self, entry: Entry<N>, hash: u64) -> bool {
        let Some(mask) = self.capacity.checked_sub(1) else {
            return false;
        };
        let mut index = hash as usize & mask;
        let mut deleted = None;
        for _ in 0..self.capacity {
            match self.slots()[index].state {
                EMPTY => {
                    let target = deleted.unwrap_or(index);
                    if deleted.is_none() {
                        self.used += 1;
                    }
                    let slot = &mut self.slots_mut()[target];
                    slot.hash = hash;
                    slot.entry.write(entry);
                    slot.state = FULL;
                    self.len += 1;
                    return true;
                }
                DELETED if deleted.is_none() => deleted = Some(index),
                _ => {}
            }
            index = (index + 1) & mask;
        }
        if let Some(index) = deleted {
            let slot = &mut self.slots_mut()[index];
            slot.hash = hash;
            slot.entry.write(entry);
            slot.state = FULL;
            self.len += 1;
            return true;
        }
        false
    }
    fn remove(&mut self, index: usize) {
        self.slots_mut()[index].state = DELETED;
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
        let size = if self.ipv6 {
            Layout::array::<Slot<16>>(self.capacity).ok()?.size()
        } else {
            Layout::array::<Slot<4>>(self.capacity).ok()?.size()
        };
        Some(Allocation {
            ipv6: self.ipv6,
            capacity: self.capacity,
            buffer: Buffer::allocate(size, self.allocator)?,
        })
    }
}

// Prepare before acquiring the policy lock; drop AFTER releasing it. At most
// two tables per IP family can be retired in one bounded maintenance pass.
pub struct CacheWork {
    growth: Option<Allocation>,
    retired: [Buffer; 4],
}
impl CacheWork {
    pub const fn empty() -> Self {
        Self {
            growth: None,
            retired: [const { Buffer::EMPTY }; 4],
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
    sweep: usize,
}
impl<const N: usize> Cache<N> {
    const fn new() -> Self {
        Self {
            current: Table::new(),
            previous: Table::new(),
            migrate: 0,
            sweep: 0,
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
            if let Some(index) = table.find(tuple, hash) {
                let entry = table.entry(index);
                return (entry.expires > now).then_some(entry.allow);
            }
        }
        None
    }
    fn apply(&mut self, tuple: &Tuple<N>, hash: u64, now: u64, ttl: u64) -> Option<bool> {
        for table in [&mut self.current, &mut self.previous] {
            if let Some(index) = table.find(tuple, hash) {
                let entry = table.entry_mut(index);
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
                        len: 0,
                        used: 0,
                    };
                    self.previous = mem::replace(&mut self.current, new);
                    self.migrate = 0;
                    self.sweep = 0;
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
        self.maintain(now, work);
        inserted
    }
    fn maintain(&mut self, now: u64, work: &mut CacheWork) {
        let end = self
            .migrate
            .saturating_add(WORK_PER_PASS)
            .min(self.previous.capacity);
        while self.migrate < end {
            let index = self.migrate;
            if self.previous.slots()[index].state == FULL {
                let entry = *self.previous.entry(index);
                let hash = self.previous.slots()[index].hash;
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
        let capacity = self.current.capacity;
        if capacity != 0 {
            for _ in 0..WORK_PER_PASS.min(capacity) {
                let index = self.sweep;
                if self.current.slots()[index].state == FULL
                    && self.current.entry(index).expires <= now
                {
                    self.current.remove(index);
                }
                self.sweep = (index + 1) & (capacity - 1);
            }
            if self.len() == 0 {
                self.current.retire(work);
                self.sweep = 0;
            }
        }
    }
    fn bytes(&self) -> usize {
        self.current.buffer.size + self.previous.buffer.size
    }
}

// One pair per host interface index. IPv4 slots contain only four address bytes.
// Identity is exclusively the normalized IP/port tuple; no hidden scope fields.
// No fixed entry count and no capacity-driven eviction.
pub struct Caches {
    ipv4: Cache<4>,
    ipv6: Cache<16>,
    allocator: CacheAllocator,
}
impl Caches {
    pub const fn new(allocator: CacheAllocator) -> Self {
        Self {
            ipv4: Cache::new(),
            ipv6: Cache::new(),
            allocator,
        }
    }
    pub(crate) const fn global() -> Self {
        Self::new(CacheAllocator::GLOBAL)
    }
    pub(crate) fn clear(&mut self) -> Self {
        mem::replace(self, Self::new(self.allocator))
    }
    pub(crate) fn plan(&self, c: &Connection) -> Option<CachePlan> {
        if !matches!(c.protocol, 6 | 17) {
            return None;
        }
        if c.ipv6 {
            let tuple = Tuple::from_connection(c);
            let hash = tuple.hash();
            if self.ipv6.current.find(&tuple, hash).is_some()
                || self.ipv6.previous.find(&tuple, hash).is_some()
            {
                None
            } else {
                self.ipv6.plan(self.allocator)
            }
        } else {
            let tuple = Tuple::from_connection(c);
            let hash = tuple.hash();
            if self.ipv4.current.find(&tuple, hash).is_some()
                || self.ipv4.previous.find(&tuple, hash).is_some()
            {
                None
            } else {
                self.ipv4.plan(self.allocator)
            }
        }
    }
    pub(crate) fn get(&self, c: &Connection, now: u64) -> Option<bool> {
        if !matches!(c.protocol, 6 | 17) {
            return None;
        }
        if c.ipv6 {
            let tuple = Tuple::from_connection(c);
            self.ipv6.get(&tuple, tuple.hash(), now)
        } else {
            let tuple = Tuple::from_connection(c);
            self.ipv4.get(&tuple, tuple.hash(), now)
        }
    }
    pub(crate) fn apply(&mut self, c: &Connection, now: u64, ttl: u64) -> Option<bool> {
        if !matches!(c.protocol, 6 | 17) {
            return None;
        }
        if c.ipv6 {
            let tuple = Tuple::from_connection(c);
            self.ipv6.apply(&tuple, tuple.hash(), now, ttl)
        } else {
            let tuple = Tuple::from_connection(c);
            self.ipv4.apply(&tuple, tuple.hash(), now, ttl)
        }
    }
    pub(crate) fn insert(
        &mut self,
        c: &Connection,
        decision: Decision,
        now: u64,
        work: &mut CacheWork,
    ) -> bool {
        if !matches!(c.protocol, 6 | 17) {
            return false;
        }
        if c.ipv6 {
            self.ipv6.insert(
                Entry {
                    tuple: Tuple::from_connection(c),
                    allow: decision.allow,
                    expires: decision.expires,
                },
                now,
                work,
            )
        } else {
            self.ipv4.insert(
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
    pub(crate) fn maintain(&mut self, now: u64, work: &mut CacheWork) {
        self.ipv4.maintain(now, work);
        self.ipv6.maintain(now, work);
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.ipv4.len(), self.ipv6.len())
    }
    pub fn bytes(&self) -> usize {
        self.ipv4.bytes() + self.ipv6.bytes()
    }
}

