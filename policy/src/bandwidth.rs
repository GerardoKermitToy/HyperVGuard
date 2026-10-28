//! Stable-page bandwidth aggregation. Preparation, consolidation and destruction
//! belong outside PolicyLock; installation/accounting only transfer small owners
//! and write individual entries/index slots.

use crate::{cache::tuple_hash, storage::List};
use alloc::{
    alloc::{alloc, dealloc},
    vec::Vec,
};
use core::{
    alloc::Layout,
    mem::{self, MaybeUninit},
    ptr::{self, NonNull},
};
use hyperv_protocol::{BandwidthEntry, Connection, Direction};
use likely_stable::unlikely;

const PAGE_ENTRIES: usize = 128;
const INITIAL_INDEX_CAPACITY: usize = 64;
const MIGRATE_SLOTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BandwidthGroup {
    pub(crate) interface_index: u32,
    pub(crate) protocol: u8,
    pub(crate) ipv6: bool,
}

/// Resources needed for at most one new key. A hit never needs preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandwidthPlan {
    owner: bool,
    page: bool,
    index_capacity: usize,
}

#[derive(Clone, Copy)]
struct Entry {
    interface_index: u32,
    connection: Connection,
    tx: u64,
    rx: u64,
    hash: u64,
    active: bool,
}
impl Entry {
    fn matches(&self, interface_index: u32, connection: &Connection) -> bool {
        self.active
            && self.interface_index == interface_index
            && self.connection.protocol == connection.protocol
            && self.connection.ipv6 == connection.ipv6
            && self.connection.local_ip == connection.local_ip
            && self.connection.remote_ip == connection.remote_ip
            && self.connection.local_port == connection.local_port
            && self.connection.remote_port == connection.remote_port
    }
    fn group(&self) -> BandwidthGroup {
        BandwidthGroup {
            interface_index: self.interface_index,
            protocol: self.connection.protocol,
            ipv6: self.connection.ipv6,
        }
    }
}

fn bandwidth_hash(interface_index: u32, connection: &Connection) -> u64 {
    tuple_hash(connection).rotate_left(5)
        ^ u64::from(connection.protocol)
        ^ u64::from(interface_index).wrapping_mul(0x9e37_79b9)
}

struct PageHeader {
    next: Option<NonNull<Page>>,
    len: usize,
}
struct Page {
    header: PageHeader,
    entries: [MaybeUninit<Entry>; PAGE_ENTRIES],
}

// An unlinked, empty page. Never construct a Page value, even temporarily: its
// uninitialized entry array is deliberately left untouched in the allocation.
struct PreparedPage(NonNull<Page>);
impl PreparedPage {
    fn prepare() -> Option<Self> {
        // SAFETY: Page has a nonzero layout and this pointer is uniquely owned.
        let page = unsafe { alloc(Layout::new::<Page>()) }.cast::<Page>();
        if unlikely(page.is_null()) {
            return None;
        }
        // SAFETY: the fallible allocation was checked for null above.
        let page = unsafe { NonNull::new_unchecked(page) };
        // SAFETY: only the header needs initialization. MaybeUninit<Entry> may
        // remain uninitialized, and no reference to an Entry is created here.
        unsafe {
            ptr::addr_of_mut!((*page.as_ptr()).header).write(PageHeader { next: None, len: 0 });
        }
        Some(Self(page))
    }
    fn into_raw(self) -> NonNull<Page> {
        let page = self.0;
        mem::forget(self);
        page
    }
}
impl Drop for PreparedPage {
    fn drop(&mut self) {
        // SAFETY: this page was never linked or populated, and uses this layout.
        unsafe { dealloc(self.0.as_ptr().cast(), Layout::new::<Page>()) };
        #[cfg(test)]
        allocation_tracking::freed_page();
    }
}

struct Pages {
    head: Option<NonNull<Page>>,
    tail: Option<NonNull<Page>>,
    count: usize,
}
impl Pages {
    const fn new() -> Self {
        Self {
            head: None,
            tail: None,
            count: 0,
        }
    }
    fn needs_page(&self) -> bool {
        let Some(page) = self.tail else {
            return true;
        };
        // SAFETY: only the initialized header field is read. No reference to the
        // whole allocation is created, so stored Entry pointers remain valid.
        unsafe { ptr::addr_of!((*page.as_ptr()).header.len).read() == PAGE_ENTRIES }
    }
    fn install(&mut self, prepared: &mut Option<PreparedPage>) {
        if !self.needs_page() {
            return;
        }
        let Some(count) = self.count.checked_add(1) else {
            return;
        };
        let Some(page) = prepared.take() else {
            return;
        };
        let page = page.into_raw();
        if let Some(tail) = self.tail {
            // SAFETY: tail is uniquely owned by this chain and page is unlinked;
            // write only the initialized header field, not a &mut Page.
            unsafe { ptr::addr_of_mut!((*tail.as_ptr()).header.next).write(Some(page)) };
        } else {
            self.head = Some(page);
        }
        self.tail = Some(page);
        self.count = count;
    }
    fn push(&mut self, entry: Entry) -> Option<NonNull<Entry>> {
        let tail = self.tail?;
        // SAFETY: the header is initialized and len is within the fixed entry
        // array. Raw writes avoid borrowing the entire page allocation.
        let len = unsafe { ptr::addr_of!((*tail.as_ptr()).header.len).read() };
        if len >= PAGE_ENTRIES {
            return None;
        }
        let entries =
            unsafe { ptr::addr_of_mut!((*tail.as_ptr()).entries) }.cast::<MaybeUninit<Entry>>();
        let slot = unsafe { entries.add(len).cast::<Entry>() };
        unsafe {
            slot.write(entry);
            // Publish the initialized prefix only AFTER Entry::write.
            ptr::addr_of_mut!((*tail.as_ptr()).header.len).write(len + 1);
            Some(NonNull::new_unchecked(slot))
        }
    }
    fn visit(&self, visitor: &mut impl FnMut(&Entry)) {
        let mut next = self.head;
        while let Some(page) = next {
            // SAFETY: only initialized header fields and initialized Entry slots
            // are read. No reference to the whole page is formed.
            let (next_page, len) = unsafe {
                (
                    ptr::addr_of!((*page.as_ptr()).header.next).read(),
                    ptr::addr_of!((*page.as_ptr()).header.len).read(),
                )
            };
            next = next_page;
            let entries =
                unsafe { ptr::addr_of!((*page.as_ptr()).entries) }.cast::<MaybeUninit<Entry>>();
            for index in 0..len {
                let entry = unsafe { &*entries.add(index).cast::<Entry>() };
                if entry.active {
                    visitor(entry);
                }
            }
        }
    }
    fn visit_mut(&mut self, visitor: &mut impl FnMut(&mut Entry)) {
        let mut next = self.head;
        while let Some(page) = next {
            // SAFETY: exclusive chain access is narrowed to one initialized Entry
            // at a time. No &mut Page can invalidate stored index pointers.
            let (next_page, len) = unsafe {
                (
                    ptr::addr_of!((*page.as_ptr()).header.next).read(),
                    ptr::addr_of!((*page.as_ptr()).header.len).read(),
                )
            };
            next = next_page;
            let entries =
                unsafe { ptr::addr_of_mut!((*page.as_ptr()).entries) }.cast::<MaybeUninit<Entry>>();
            for index in 0..len {
                let entry = unsafe { &mut *entries.add(index).cast::<Entry>() };
                visitor(entry);
            }
        }
    }
    fn bytes(&self) -> usize {
        self.count.saturating_mul(mem::size_of::<Page>())
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        let mut next = self.head;
        while let Some(page) = next {
            // SAFETY: each allocation is visited/freed once with its original
            // layout. Entry is Copy and has no destructor. Destruction is
            // iterative, so chain length does not consume kernel stack.
            unsafe {
                next = (*page.as_ptr()).header.next;
                dealloc(page.as_ptr().cast(), Layout::new::<Page>());
            }
            #[cfg(test)]
            allocation_tracking::freed_page();
        }
    }
}

// None is the only empty marker. No tombstones are needed: migration leaves the
// ENTIRE previous probe chain intact until its index is retired. Eight-byte
// alignment also keeps slots 16 bytes on 32-bit host policy-test targets.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct IndexSlot {
    hash: u64,
    entry: Option<NonNull<Entry>>,
}
const _: [(); 16] = [(); mem::size_of::<IndexSlot>()];
impl IndexSlot {
    const EMPTY: Self = Self {
        hash: 0,
        entry: None,
    };
}

struct Index {
    slots: Vec<IndexSlot>,
}
impl Index {
    const fn new() -> Self {
        Self { slots: Vec::new() }
    }
    // This is called ONLY by unlocked BandwidthWork::prepare.
    fn prepare(capacity: usize) -> Option<Self> {
        if capacity < INITIAL_INDEX_CAPACITY || !capacity.is_power_of_two() {
            return None;
        }
        Layout::array::<IndexSlot>(capacity).ok()?;
        let mut slots = Vec::new();
        if unlikely(slots.try_reserve_exact(capacity).is_err()) {
            return None;
        }
        slots.resize(capacity, IndexSlot::EMPTY);
        Some(Self { slots })
    }
    fn capacity(&self) -> usize {
        self.slots.len()
    }
    fn bytes(&self) -> usize {
        self.slots
            .capacity()
            .saturating_mul(mem::size_of::<IndexSlot>())
    }
    fn find(
        &self,
        hash: u64,
        interface_index: u32,
        connection: &Connection,
    ) -> Option<NonNull<Entry>> {
        let mask = self.capacity().checked_sub(1)?;
        let mut position = hash as usize & mask;
        for _ in 0..self.capacity() {
            let slot = self.slots[position];
            let entry = slot.entry?;
            if slot.hash == hash {
                // SAFETY: index handles refer to initialized entries in this
                // bank's stable pages, which outlive both lookup indexes.
                if unsafe { entry.as_ref() }.matches(interface_index, connection) {
                    return Some(entry);
                }
            }
            position = (position + 1) & mask;
        }
        None
    }
    fn vacant(&self, hash: u64) -> Option<usize> {
        let mask = self.capacity().checked_sub(1)?;
        let mut position = hash as usize & mask;
        for _ in 0..self.capacity() {
            if self.slots[position].entry.is_none() {
                return Some(position);
            }
            position = (position + 1) & mask;
        }
        None
    }
    fn write(&mut self, position: usize, hash: u64, entry: NonNull<Entry>) {
        debug_assert!(self.slots[position].entry.is_none());
        self.slots[position] = IndexSlot {
            hash,
            entry: Some(entry),
        };
    }
    fn insert(&mut self, hash: u64, entry: NonNull<Entry>) -> bool {
        let Some(position) = self.vacant(hash) else {
            return false;
        };
        self.write(position, hash, entry);
        true
    }
}
#[cfg(test)]
impl Drop for Index {
    fn drop(&mut self) {
        if self.slots.capacity() != 0 {
            allocation_tracking::freed_index();
        }
    }
}

// Only this small header is a List node. Pages have direct stable-pointer links;
// there is no growing page directory to copy or initialize under PolicyLock.
struct Bank {
    pages: Pages,
    count: usize,
    current: Index,
    previous: Index,
    spare: Index,
    cursor: usize,
    sealed: bool,
}
impl Bank {
    const fn new() -> Self {
        Self {
            pages: Pages::new(),
            count: 0,
            current: Index::new(),
            previous: Index::new(),
            spare: Index::new(),
            cursor: 0,
            sealed: false,
        }
    }
    fn bytes(&self) -> usize {
        self.pages
            .bytes()
            .saturating_add(self.current.bytes())
            .saturating_add(self.previous.bytes())
            .saturating_add(self.spare.bytes())
    }
    fn load_limit(&self) -> usize {
        self.current.capacity() - self.current.capacity() / 4
    }
    fn needed_index_capacity(&self) -> Option<usize> {
        if self.current.capacity() == 0 {
            Some(INITIAL_INDEX_CAPACITY)
        } else if self.previous.capacity() == 0 && self.count >= self.load_limit() {
            self.current.capacity().checked_mul(2)
        } else {
            Some(0)
        }
    }
    fn plan(&self) -> Option<BandwidthPlan> {
        if self.sealed {
            return None;
        }
        let needed = self.needed_index_capacity()?;
        let index_capacity = if self.spare.capacity() < needed {
            needed
        } else {
            0
        };
        let page = self.pages.needs_page();
        (page || index_capacity != 0).then_some(BandwidthPlan {
            owner: false,
            page,
            index_capacity,
        })
    }
    fn install(&mut self, work: &mut BandwidthWork) {
        if self.sealed {
            return;
        }
        self.pages.install(&mut work.page);
        // A stale preparation can be redundant or too small. A larger prepared
        // reserve may replace a smaller spare only by moving that old allocation
        // into Work; it is then freed after PolicyLock. Hits retain the reserve
        // for a later NEW insertion and cannot start migration themselves.
        if work.index.capacity() > self.spare.capacity() && work.retired.capacity() == 0 {
            mem::swap(&mut self.spare, &mut work.retired);
            mem::swap(&mut self.spare, &mut work.index);
        }
        if self.spare.capacity() == 0 && work.index.capacity() > self.current.capacity() {
            mem::swap(&mut self.spare, &mut work.index);
        }
    }
    fn find(
        &self,
        hash: u64,
        interface_index: u32,
        connection: &Connection,
    ) -> Option<NonNull<Entry>> {
        self.current
            .find(hash, interface_index, connection)
            .or_else(|| self.previous.find(hash, interface_index, connection))
    }
    fn add(&mut self, value: Entry, work: &mut BandwidthWork) -> Option<bool> {
        if self.sealed {
            return None;
        }
        if let Some(mut entry) = self.find(value.hash, value.interface_index, &value.connection) {
            // SAFETY: exclusive bank access and a stable, initialized entry.
            let entry = unsafe { entry.as_mut() };
            entry.tx = entry.tx.saturating_add(value.tx);
            entry.rx = entry.rx.saturating_add(value.rx);
            return Some(false);
        }
        let count = self.count.checked_add(1)?;
        let needed = self.needed_index_capacity()?;
        if self.pages.needs_page()
            || (needed != 0 && self.spare.capacity() < needed)
            || (self.previous.capacity() != 0 && self.count >= self.load_limit())
        {
            return None;
        }
        // Locate a slot before publishing an entry. Nothing fallible remains
        // after push, so a failed preparation cannot leave an orphan active key.
        let position = if needed != 0 {
            self.spare.vacant(value.hash)?
        } else {
            self.current.vacant(value.hash)?
        };
        let entry = self.pages.push(value)?;
        if needed != 0 {
            debug_assert_eq!(self.previous.capacity(), 0);
            mem::swap(&mut self.current, &mut self.spare);
            mem::swap(&mut self.previous, &mut self.spare);
            self.cursor = 0;
        }
        self.current.write(position, value.hash, entry);
        self.count = count;
        self.migrate(work);
        Some(true)
    }
    fn migrate(&mut self, work: &mut BandwidthWork) {
        let capacity = self.previous.capacity();
        if capacity == 0 {
            return;
        }
        // Bound SLOTS SCANNED, not occupied entries found. Sparse ranges must
        // not turn one insertion into an unbounded old-index walk.
        let end = self.cursor.saturating_add(MIGRATE_SLOTS).min(capacity);
        while self.cursor < end {
            let slot = self.previous.slots[self.cursor];
            if let Some(entry) = slot.entry {
                // The operation MUST execute in release builds as well.
                let inserted = self.current.insert(slot.hash, entry);
                debug_assert!(inserted, "bandwidth migration index unexpectedly full");
                if unlikely(!inserted) {
                    // Preserve the old handle and cursor even if an invariant
                    // is violated; lookup can still find every old key.
                    return;
                }
            }
            self.cursor += 1;
        }
        if self.cursor == capacity && work.retired.capacity() == 0 {
            // No Vec assignment/clear/shrink: the entire retired allocation is
            // transferred to work, whose caller drops it after releasing lock.
            mem::swap(&mut self.previous, &mut work.retired);
            self.cursor = 0;
        }
    }
    fn remove_group(&mut self, group: BandwidthGroup) -> usize {
        // Reported/detached pages are never reactivated for live insertion.
        self.sealed = true;
        let mut removed = 0;
        self.pages.visit_mut(&mut |entry| {
            if entry.active && entry.group() == group {
                entry.active = false;
                removed += 1;
            }
        });
        self.count -= removed;
        // Detached indexes are never searched again. In particular, removing a
        // reported entry need not disturb either old or current probe chains.
        removed
    }
}

/// Prepared resources and one retired index for a single locked accounting
/// callback. Construct and DROP this value outside PolicyLock, even on a hit,
/// stale preparation or failed allocation. Preparation only builds requested
/// resources and may return a partial reserve after OOM.
pub struct BandwidthWork {
    owner: List<Bank>,
    page: Option<PreparedPage>,
    index: Index,
    retired: Index,
    failed: bool,
}
impl BandwidthWork {
    pub const fn empty() -> Self {
        Self {
            owner: List::new(),
            page: None,
            index: Index::new(),
            retired: Index::new(),
            failed: false,
        }
    }
    pub fn prepare(plan: Option<BandwidthPlan>) -> Self {
        let mut work = Self::empty();
        if let Some(plan) = plan {
            if plan.owner && unlikely(work.owner.try_push_back(Bank::new()).is_err()) {
                work.failed = true;
            }
            if plan.page {
                work.page = PreparedPage::prepare();
                work.failed |= work.page.is_none();
            }
            if plan.index_capacity != 0 {
                match Index::prepare(plan.index_capacity) {
                    Some(index) => work.index = index,
                    None => work.failed = true,
                }
            }
        }
        work
    }
    pub fn satisfies(&self, plan: BandwidthPlan) -> bool {
        (!plan.owner || !self.owner.is_empty())
            && (!plan.page || self.page.is_some())
            && self.index.capacity() >= plan.index_capacity
    }
    pub fn allocation_failed(&self) -> bool {
        self.failed
    }
}

pub(crate) struct BandwidthStore {
    banks: List<Bank>,
    count: usize,
    // Payload storage only; List::bytes accounts for the small owner nodes.
    // Maintained in O(1), including whole-chain retry/retirement transfers.
    payload_bytes: usize,
    #[cfg(test)]
    pub(crate) fail_allocations: bool,
}
impl BandwidthStore {
    pub(crate) const fn new() -> Self {
        Self {
            banks: List::new(),
            count: 0,
            payload_bytes: 0,
            #[cfg(test)]
            fail_allocations: false,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.count
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub(crate) fn has_storage(&self) -> bool {
        !self.banks.is_empty()
    }
    pub(crate) fn bytes(&self) -> usize {
        self.payload_bytes.saturating_add(self.banks.bytes())
    }
    pub(crate) fn plan(&self) -> Option<BandwidthPlan> {
        #[cfg(test)]
        if self.fail_allocations {
            return None;
        }
        if self.banks.is_empty() {
            Some(BandwidthPlan {
                owner: true,
                page: true,
                index_capacity: INITIAL_INDEX_CAPACITY,
            })
        } else if self.banks.len() == 1 {
            self.banks.front()?.plan()
        } else {
            // Whole chains may only accumulate in detached/retry/retired stores.
            None
        }
    }
    pub(crate) fn install(&mut self, work: &mut BandwidthWork) {
        #[cfg(test)]
        if self.fail_allocations {
            return;
        }
        if self.banks.is_empty() {
            self.banks.append(&mut work.owner);
        }
        if self.banks.len() != 1 {
            return;
        }
        let bank = self.banks.front_mut().expect("one bandwidth bank");
        let before = bank.bytes();
        bank.install(work);
        self.payload_bytes = self
            .payload_bytes
            .saturating_sub(before)
            .saturating_add(bank.bytes());
    }
    pub(crate) fn add(
        &mut self,
        interface_index: u32,
        connection: &Connection,
        bytes: u64,
        work: &mut BandwidthWork,
    ) -> Option<bool> {
        let (tx, rx) = match connection.direction {
            Direction::Outbound => (bytes, 0),
            Direction::Inbound => (0, bytes),
        };
        self.add_value(
            Entry {
                interface_index,
                connection: *connection,
                tx,
                rx,
                hash: bandwidth_hash(interface_index, connection),
                active: true,
            },
            work,
        )
    }
    fn add_value(&mut self, value: Entry, work: &mut BandwidthWork) -> Option<bool> {
        self.install(work);
        if self.banks.len() != 1 {
            return None;
        }
        let bank = self.banks.front_mut()?;
        let before = bank.bytes();
        let result = bank.add(value, work);
        self.payload_bytes = self
            .payload_bytes
            .saturating_sub(before)
            .saturating_add(bank.bytes());
        self.count = bank.count;
        result
    }
    /// O(1) ownership transfer for retry/retirement, never a live-key merge.
    pub(crate) fn append(&mut self, other: &mut Self) {
        self.banks.append(&mut other.banks);
        // Distinct allocated entries cannot number more than usize::MAX. The
        // saturating diagnostic arithmetic also avoids overflow during teardown.
        self.count = self.count.saturating_add(other.count);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        other.count = 0;
        other.payload_bytes = 0;
    }
    /// Outside-lock, failure-atomic consolidation of detached bank chains. Only
    /// active entries are copied; failed preparation leaves every source delta
    /// and allocation intact. The successful swap destroys old banks unlocked.
    pub(crate) fn consolidate(&mut self) -> bool {
        if self.banks.len() <= 1 {
            return true;
        }
        let mut combined = Self::new();
        #[cfg(test)]
        {
            combined.fail_allocations = self.fail_allocations;
        }
        let mut complete = true;
        self.visit(&mut |entry| {
            if complete {
                let mut work = BandwidthWork::prepare(combined.plan());
                complete = combined.add_value(*entry, &mut work).is_some();
                // Both unused reserves and migrated indexes are freed here,
                // outside lock, before preparing the next entry's work.
            }
        });
        if !complete {
            return false;
        }
        mem::swap(self, &mut combined);
        true
    }
    fn visit(&self, visitor: &mut impl FnMut(&Entry)) {
        for bank in self.banks.iter() {
            bank.pages.visit(visitor);
        }
    }
    pub(crate) fn visit_totals(&self, visitor: &mut impl FnMut(u32, &Connection, u64, u64)) {
        self.visit(&mut |entry| {
            visitor(entry.interface_index, &entry.connection, entry.tx, entry.rx);
        });
    }
    pub(crate) fn next_group(&self, after: Option<BandwidthGroup>) -> Option<BandwidthGroup> {
        let mut result = None;
        self.visit(&mut |entry| {
            let group = entry.group();
            if after.is_none_or(|after| group > after) && result.is_none_or(|best| group < best) {
                result = Some(group);
            }
        });
        result
    }
    pub(crate) fn visit_group(
        &self,
        group: BandwidthGroup,
        visitor: &mut impl FnMut(BandwidthEntry),
    ) {
        self.visit_totals(&mut |interface_index, connection, tx, rx| {
            if interface_index == group.interface_index
                && connection.protocol == group.protocol
                && connection.ipv6 == group.ipv6
            {
                visitor(BandwidthEntry {
                    local_ip: connection.local_ip,
                    local_port: connection.local_port,
                    remote_ip: connection.remote_ip,
                    remote_port: connection.remote_port,
                    transmitted_bytes: tx,
                    received_bytes: rx,
                });
            }
        });
    }
    pub(crate) fn remove_group(&mut self, group: BandwidthGroup) {
        for bank in self.banks.iter_mut() {
            self.count -= bank.remove_group(group);
        }
    }
}

#[cfg(test)]
mod allocation_tracking {
    extern crate std;
    use core::cell::Cell;

    std::thread_local! {
        static FREES: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }
    pub(super) fn freed_page() {
        FREES.with(|counts| {
            let (pages, indexes) = counts.get();
            counts.set((pages + 1, indexes));
        });
    }
    pub(super) fn freed_index() {
        FREES.with(|counts| {
            let (pages, indexes) = counts.get();
            counts.set((pages, indexes + 1));
        });
    }
    pub(super) fn counts() -> (usize, usize) {
        FREES.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn connection(n: u32) -> Connection {
        let mut connection = Connection::EMPTY;
        connection.protocol = 6;
        connection.local_ip[..4].copy_from_slice(&[10, 1, 2, 3]);
        connection.remote_ip[..4].copy_from_slice(&n.to_le_bytes());
        connection.local_port = 1234;
        connection.remote_port = 443;
        connection
    }
    fn add(
        store: &mut BandwidthStore,
        interface: u32,
        connection: &Connection,
        bytes: u64,
    ) -> bool {
        let plan = store.plan();
        let mut work = BandwidthWork::prepare(plan);
        assert!(!work.allocation_failed());
        assert!(plan.is_none_or(|plan| work.satisfies(plan)));
        store.add(interface, connection, bytes, &mut work).unwrap()
    }
    fn find(store: &BandwidthStore, interface: u32, connection: &Connection) -> NonNull<Entry> {
        store
            .banks
            .front()
            .unwrap()
            .find(bandwidth_hash(interface, connection), interface, connection)
            .unwrap()
    }
    fn forced_value(interface_index: u32, connection: Connection, tx: u64, rx: u64) -> Entry {
        Entry {
            interface_index,
            connection,
            tx,
            rx,
            hash: 63,
            active: true,
        }
    }
    fn add_forced(store: &mut BandwidthStore, value: Entry) -> bool {
        let mut work = BandwidthWork::prepare(store.plan());
        assert!(!work.allocation_failed());
        store.add_value(value, &mut work).unwrap()
    }

    #[test]
    fn grows_stable_pages_and_indexes_without_moving_entries() {
        let mut store = BandwidthStore::new();
        assert!(store.is_empty());
        assert!(!store.has_storage());
        assert_eq!(store.bytes(), 0);
        let mut addresses = Vec::new();
        for n in 0..10_001 {
            let connection = connection(n);
            let (old_capacity, old_cursor) = store
                .banks
                .front()
                .map_or((0, 0), |bank| (bank.previous.capacity(), bank.cursor));
            let mut work = BandwidthWork::prepare(store.plan());
            assert_eq!(
                store.add(17, &connection, u64::from(n) + 1, &mut work),
                Some(true)
            );
            let bank = store.banks.front().unwrap();
            if bank.previous.capacity() != 0 {
                let scanned = if old_capacity == 0 {
                    bank.cursor
                } else {
                    bank.cursor - old_cursor
                };
                assert!(scanned <= MIGRATE_SLOTS);
            } else if old_capacity != 0 {
                assert!(old_capacity - old_cursor <= MIGRATE_SLOTS);
                assert_eq!(work.retired.capacity(), old_capacity);
            }
            addresses.push(find(&store, 17, &connection));
        }
        assert_eq!(store.len(), addresses.len());
        assert_eq!(store.banks.len(), 1);
        let bank = store.banks.front().unwrap();
        assert_eq!(bank.pages.count, addresses.len().div_ceil(PAGE_ENTRIES));
        assert_eq!(store.bytes(), store.banks.bytes() + bank.bytes());
        for (n, &address) in addresses.iter().enumerate() {
            let connection = connection(n as u32);
            assert_eq!(find(&store, 17, &connection), address);
            let entry = unsafe { address.as_ref() };
            assert_eq!(entry.tx, n as u64 + 1);
            assert_eq!(entry.rx, 0);
        }
    }

    #[test]
    fn equal_hashes_require_every_full_key_field_but_not_direction() {
        let mut store = BandwidthStore::new();
        let original = connection(9);
        let mut keys = Vec::new();
        keys.push((7, original));
        keys.push((8, original));
        for change in 0..8 {
            let mut connection = original;
            match change {
                0 => connection.protocol = 17,
                1 => connection.ipv6 = true,
                2 => connection.local_ip[0] ^= 1,
                3 => connection.local_ip[15] = 1,
                4 => connection.remote_ip[0] ^= 1,
                5 => connection.remote_ip[15] = 1,
                6 => connection.local_port += 1,
                7 => connection.remote_port += 1,
                _ => unreachable!(),
            }
            keys.push((7, connection));
        }
        // Force a wraparound probe chain long enough to migrate over several
        // growths. All entries have exactly the same 64-bit index hash.
        for n in 100..300 {
            keys.push((7, connection(n)));
        }
        let mut addresses = Vec::new();
        for (n, &(interface, connection)) in keys.iter().enumerate() {
            assert!(add_forced(
                &mut store,
                forced_value(interface, connection, n as u64 + 1, 0)
            ));
            addresses.push(
                store
                    .banks
                    .front()
                    .unwrap()
                    .find(63, interface, &connection)
                    .unwrap(),
            );
        }
        for (n, &(interface, mut connection)) in keys.iter().enumerate() {
            connection.direction = Direction::Inbound;
            assert!(!add_forced(
                &mut store,
                forced_value(interface, connection, 0, 99)
            ));
            let pointer = store
                .banks
                .front()
                .unwrap()
                .find(63, interface, &connection)
                .unwrap();
            assert_eq!(pointer, addresses[n]);
            let entry = unsafe { pointer.as_ref() };
            assert_eq!(entry.tx, n as u64 + 1);
            assert_eq!(entry.rx, 99);
        }
        assert_eq!(store.len(), keys.len());
    }

    #[test]
    fn ipv4_hash_collisions_in_unused_address_bytes_still_compare_full_arrays() {
        let mut store = BandwidthStore::new();
        let original = connection(123);
        let mut local_tail = original;
        local_tail.local_ip[15] = 42;
        let mut remote_tail = original;
        remote_tail.remote_ip[15] = 42;
        assert_eq!(bandwidth_hash(7, &original), bandwidth_hash(7, &local_tail));
        assert_eq!(
            bandwidth_hash(7, &original),
            bandwidth_hash(7, &remote_tail)
        );
        for connection in [&original, &local_tail, &remote_tail] {
            assert!(add(&mut store, 7, connection, 5));
        }
        assert_eq!(store.len(), 3);
        assert_ne!(find(&store, 7, &original), find(&store, 7, &local_tail));
        assert_ne!(find(&store, 7, &original), find(&store, 7, &remote_tail));
    }

    #[test]
    fn hits_never_start_or_advance_migration_and_previous_probe_chains_remain_intact() {
        let mut store = BandwidthStore::new();
        for n in 0..48 {
            assert!(add_forced(&mut store, forced_value(7, connection(n), 1, 0)));
        }
        let plan = store.plan().unwrap();
        assert_eq!(plan.index_capacity, 128);
        let mut work = BandwidthWork::prepare(Some(plan));
        store.install(&mut work);
        let bank = store.banks.front().unwrap();
        assert_eq!(bank.current.capacity(), 64);
        assert_eq!(bank.spare.capacity(), 128);
        assert_eq!(bank.previous.capacity(), 0);
        let old_slots: Vec<_> = bank.current.slots.iter().map(|slot| slot.entry).collect();
        for _ in 0..100 {
            assert!(!add_forced(
                &mut store,
                forced_value(7, connection(40), 0, 2)
            ));
            let bank = store.banks.front().unwrap();
            assert_eq!(bank.current.capacity(), 64);
            assert_eq!(bank.previous.capacity(), 0);
            assert_eq!(bank.cursor, 0);
        }
        assert!(add_forced(
            &mut store,
            forced_value(7, connection(48), 1, 0)
        ));
        let bank = store.banks.front().unwrap();
        assert_eq!(bank.current.capacity(), 128);
        assert_eq!(bank.previous.capacity(), 64);
        assert_eq!(bank.cursor, 32);
        assert!(
            bank.previous
                .slots
                .iter()
                .map(|slot| slot.entry)
                .eq(old_slots)
        );
        for _ in 0..100 {
            // This key is beyond the migrated range of a chain starting at 63.
            assert!(!add_forced(
                &mut store,
                forced_value(7, connection(40), 0, 3)
            ));
            assert_eq!(store.banks.front().unwrap().cursor, 32);
        }
        let mut work = BandwidthWork::empty();
        assert_eq!(
            store.add_value(forced_value(7, connection(49), 1, 0), &mut work),
            Some(true)
        );
        assert_eq!(work.retired.capacity(), 64);
        assert_eq!(store.banks.front().unwrap().previous.capacity(), 0);
        for n in 0..50 {
            assert!(
                store
                    .banks
                    .front()
                    .unwrap()
                    .find(63, 7, &connection(n))
                    .is_some()
            );
        }
        let entry = store
            .banks
            .front()
            .unwrap()
            .find(63, 7, &connection(40))
            .unwrap();
        assert_eq!(unsafe { entry.as_ref() }.rx, 500);
    }

    #[test]
    fn work_prepares_only_requested_resources_and_install_preserves_reserves_for_misses() {
        let mut store = BandwidthStore::new();
        let plan = store.plan().unwrap();
        assert_eq!(
            plan,
            BandwidthPlan {
                owner: true,
                page: true,
                index_capacity: 64
            }
        );
        let empty = BandwidthWork::empty();
        assert!(!empty.allocation_failed());
        assert!(!empty.satisfies(plan));
        let mut work = BandwidthWork::prepare(Some(plan));
        assert!(work.satisfies(plan));
        let frees = allocation_tracking::counts();
        store.install(&mut work);
        assert_eq!(allocation_tracking::counts(), frees);
        assert!(work.owner.is_empty());
        assert!(work.page.is_none());
        assert_eq!(work.index.capacity(), 0);
        assert_eq!(store.plan(), None);
        let bank = store.banks.front().unwrap();
        assert_eq!(bank.current.capacity(), 0);
        assert_eq!(bank.spare.capacity(), 64);
        assert_eq!(
            store.add(1, &connection(1), 10, &mut BandwidthWork::empty()),
            Some(true)
        );
        for n in 2..=128 {
            assert!(add(&mut store, 1, &connection(n), 10));
        }
        let page_plan = store.plan().unwrap();
        assert_eq!(
            page_plan,
            BandwidthPlan {
                owner: false,
                page: true,
                index_capacity: 0
            }
        );
        let page_work = BandwidthWork::prepare(Some(page_plan));
        assert!(page_work.satisfies(page_plan));
        assert!(page_work.owner.is_empty());
        assert!(page_work.page.is_some());
        assert_eq!(page_work.index.capacity(), 0);
        let index_plan = BandwidthPlan {
            owner: false,
            page: false,
            index_capacity: 256,
        };
        let index_work = BandwidthWork::prepare(Some(index_plan));
        assert!(index_work.satisfies(index_plan));
        assert!(index_work.owner.is_empty());
        assert!(index_work.page.is_none());
        assert_eq!(index_work.index.capacity(), 256);
        assert!(!index_work.satisfies(BandwidthPlan {
            index_capacity: 512,
            ..index_plan
        }));
        let none = BandwidthWork::prepare(None);
        assert!(none.owner.is_empty());
        assert!(none.page.is_none());
        assert_eq!(none.index.capacity(), 0);
        assert!(!none.allocation_failed());
    }

    #[test]
    fn failed_or_stale_preparation_does_not_publish_unindexed_entries() {
        let invalid = BandwidthPlan {
            owner: true,
            page: true,
            index_capacity: usize::MAX,
        };
        let mut failed = BandwidthWork::prepare(Some(invalid));
        assert!(failed.allocation_failed());
        assert!(!failed.satisfies(invalid));
        let mut store = BandwidthStore::new();
        assert_eq!(store.add(1, &connection(1), 7, &mut failed), None);
        assert_eq!(store.len(), 0);
        let bank = store.banks.front().unwrap();
        assert_eq!(unsafe { bank.pages.tail.unwrap().as_ref() }.header.len, 0);
        let mut work = BandwidthWork::prepare(store.plan());
        store.fail_allocations = true;
        assert_eq!(store.plan(), None);
        assert_eq!(store.add(1, &connection(1), 7, &mut work), None);
        assert_eq!(work.index.capacity(), 64);
        store.fail_allocations = false;
        assert_eq!(store.add(1, &connection(1), 7, &mut work), Some(true));
        let address = find(&store, 1, &connection(1));
        store.fail_allocations = true;
        assert_eq!(
            store.add(1, &connection(1), 8, &mut BandwidthWork::empty()),
            Some(false)
        );
        assert_eq!(find(&store, 1, &connection(1)), address);
        assert_eq!(unsafe { address.as_ref() }.tx, 15);
    }

    #[test]
    fn migration_retirement_and_chain_transfer_do_not_free_under_lock() {
        let mut store = BandwidthStore::new();
        for n in 0..49 {
            assert!(add(&mut store, 1, &connection(n), 1));
        }
        let address = find(&store, 1, &connection(0));
        let before = allocation_tracking::counts();
        let mut work = BandwidthWork::prepare(store.plan());
        assert_eq!(store.add(1, &connection(49), 1, &mut work), Some(true));
        assert_eq!(work.retired.capacity(), 64);
        assert_eq!(allocation_tracking::counts(), before);
        let mut retired = BandwidthStore::new();
        retired.append(&mut store);
        assert!(!store.has_storage());
        assert!(retired.has_storage());
        assert_eq!(store.bytes(), 0);
        assert_eq!(retired.len(), 50);
        assert_eq!(allocation_tracking::counts(), before);
        assert_eq!(unsafe { address.as_ref() }.tx, 1);
        drop(work);
        assert_eq!(allocation_tracking::counts(), (before.0, before.1 + 1));
        drop(retired);
        assert_eq!(allocation_tracking::counts(), (before.0 + 1, before.1 + 2));
    }

    #[test]
    fn detached_consolidation_sums_deltas_saturates_and_skips_reported_slots() {
        let mut first = BandwidthStore::new();
        let mut second = BandwidthStore::new();
        let outbound = connection(1);
        let mut inbound = outbound;
        inbound.direction = Direction::Inbound;
        assert!(add(&mut first, 9, &outbound, u64::MAX - 1));
        assert!(!add(&mut first, 9, &inbound, 15));
        assert!(add(&mut second, 9, &outbound, 5));
        assert!(!add(&mut second, 9, &inbound, u64::MAX));
        assert!(add(&mut first, 3, &connection(5), 123));
        assert!(add(&mut second, 3, &connection(6), 456));
        let removed = BandwidthGroup {
            interface_index: 3,
            protocol: 6,
            ipv6: false,
        };
        first.remove_group(removed);
        assert_eq!(first.len(), 1);
        assert_eq!(
            first.add(9, &outbound, 1, &mut BandwidthWork::empty()),
            None
        );
        first.append(&mut second);
        assert_eq!(first.len(), 3);
        assert_eq!(first.banks.len(), 2);
        assert_eq!(first.plan(), None);
        assert_eq!(
            first.add(9, &outbound, 1, &mut BandwidthWork::empty()),
            None
        );
        assert!(first.consolidate());
        assert_eq!(first.banks.len(), 1);
        assert_eq!(first.len(), 2);
        let group = first.next_group(None).unwrap();
        assert_eq!(group, removed);
        let mut entries = Vec::new();
        first.visit_group(group, &mut |entry| entries.push(entry));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].remote_ip, connection(6).remote_ip);
        assert_eq!(entries[0].transmitted_bytes, 456);
        let group = first.next_group(Some(group)).unwrap();
        assert_eq!(group.interface_index, 9);
        entries.clear();
        first.visit_group(group, &mut |entry| entries.push(entry));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].transmitted_bytes, u64::MAX);
        assert_eq!(entries[0].received_bytes, u64::MAX);
        assert_eq!(first.next_group(Some(group)), None);
        first.remove_group(group);
        assert_eq!(first.len(), 1);
        first.remove_group(group);
        assert_eq!(first.len(), 1);
        first.remove_group(removed);
        assert!(first.is_empty());
        assert!(first.has_storage());
        assert_eq!(first.next_group(None), None);
        let mut visits = 0;
        first.visit_totals(&mut |_, _, _, _| visits += 1);
        assert_eq!(visits, 0);
    }

    #[test]
    fn failed_consolidation_preserves_original_banks_deltas_and_addresses() {
        let mut store = BandwidthStore::new();
        let mut other = BandwidthStore::new();
        assert!(add(&mut store, 1, &connection(1), 7));
        assert!(add(&mut other, 1, &connection(1), 11));
        let address = find(&store, 1, &connection(1));
        store.append(&mut other);
        let bytes = store.bytes();
        let frees = allocation_tracking::counts();
        store.fail_allocations = true;
        assert!(!store.consolidate());
        assert_eq!(allocation_tracking::counts(), frees);
        assert_eq!(store.banks.len(), 2);
        assert_eq!(store.len(), 2);
        assert_eq!(store.bytes(), bytes);
        assert_eq!(unsafe { address.as_ref() }.tx, 7);
        let mut totals = 0;
        store.visit_totals(&mut |_, _, tx, _| totals += tx);
        assert_eq!(totals, 18);
        store.fail_allocations = false;
        assert!(store.consolidate());
        assert_eq!(store.len(), 1);
        let mut totals = 0;
        store.visit_totals(&mut |_, _, tx, _| totals += tx);
        assert_eq!(totals, 18);
    }
}
