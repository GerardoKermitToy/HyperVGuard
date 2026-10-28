use crate::{
    bandwidth::{BandwidthGroup, BandwidthStore},
    cache::{CacheAllocator, CachePlan, CacheWork, Caches, Decision},
    packet::Packet,
    storage::{Handle, List},
};
use alloc::vec::Vec;
use core::fmt::{self, Write};
use hyperv_protocol::{
    BANDWIDTH_HEADER, MAX_LOG_RECORD, MAX_PAYLOAD, MAX_RECORD, Verdict, bandwidth_entry_len,
    bandwidth_record_len, connection_header_len, encode_bandwidth_entry, encode_bandwidth_header,
    encode_connection_header, encode_log,
};

pub use crate::bandwidth::{BandwidthPlan, BandwidthWork};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    Allow,
    Drop,
    Cancel,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub token: usize,
    pub finish: Finish,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    Pending(u64),
    Finish(Action),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictError {
    NotFound,
}

struct Interface {
    interface_index: u32,
    running: bool,
    dirty: bool,
    candidate: bool,
    caches: Caches,
}
#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    token: usize,
    cancel: Option<usize>,
    deadline: u64,
    interface_index: u32,
    invalidated: bool,
    event: Option<Handle<Event>>,
    packet: Packet,
}
struct Event {
    read: usize,
    pending: Option<Handle<Pending>>,
    data: Vec<u8>,
}

// Only fallible allocation is used. Records and metadata have no aggregate
// byte quota; the per-record payload limit remains part of the wire contract.
pub fn allocate_record(len: usize) -> Option<Vec<u8>> {
    if len > MAX_RECORD {
        return None;
    }
    allocate_event(len)
}
fn allocate_event(len: usize) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(len).ok()?;
    data.resize(len, 0);
    Some(data)
}
pub struct BandwidthTable {
    store: BandwidthStore,
    epoch: u64,
}
impl Default for BandwidthTable {
    fn default() -> Self {
        Self::new()
    }
}
impl BandwidthTable {
    pub fn new() -> Self {
        Self {
            store: BandwidthStore::new(),
            epoch: 0,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    fn next_group(&self, after: Option<BandwidthGroup>) -> Option<BandwidthGroup> {
        self.store.next_group(after)
    }
    fn encode_group(&self, group: BandwidthGroup) -> Option<Vec<u8>> {
        let mut count = 0;
        self.store.visit_group(group, &mut |_| count += 1);
        let len = bandwidth_record_len(group.ipv6, count)?;
        let mut data = allocate_event(len)?;
        encode_bandwidth_header(
            &mut data,
            group.interface_index,
            group.ipv6,
            group.protocol,
            count,
        )
        .expect("valid bandwidth event layout");
        let entry_size = bandwidth_entry_len(group.ipv6);
        let mut offset = BANDWIDTH_HEADER;
        self.store.visit_group(group, &mut |entry| {
            encode_bandwidth_entry(&mut data[offset..offset + entry_size], group.ipv6, &entry)
                .expect("valid bandwidth entry layout");
            offset += entry_size;
        });
        Some(data)
    }
    fn remove_group(&mut self, group: BandwidthGroup) {
        self.store.remove_group(group);
    }
    // Reporting and any detached-bank consolidation run outside PolicyLock in
    // the driver path. A failed consolidation leaves all deltas retryable.
    pub fn report(&mut self, mut submit: impl FnMut(Vec<u8>) -> bool) {
        if !self.store.consolidate() {
            return;
        }
        let mut after = None;
        while let Some(group) = self.next_group(after) {
            after = Some(group);
            let Some(data) = self.encode_group(group) else {
                break;
            };
            if !submit(data) {
                break;
            }
            self.remove_group(group);
        }
    }
}

// Opaque ownership returned to the driver for destruction outside PolicyLock.
pub struct RetiredStorage {
    _events: List<Event>,
    _bandwidth: BandwidthStore,
}
#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    pub received: u64,
    pub allowed: u64,
    pub dropped: u64,
    pub queued: u64,
    pub cache_hits: u64,
    pub cache_allocation_failures: u64,
    pub timeouts: u64,
    pub overflow: u64,
    pub cancelled: u64,
    pub invalidated: u64,
    pub malformed: u64,
    pub non_ip: u64,
}
impl Stats {
    const EMPTY: Self = Self {
        received: 0,
        allowed: 0,
        dropped: 0,
        queued: 0,
        cache_hits: 0,
        cache_allocation_failures: 0,
        timeouts: 0,
        overflow: 0,
        cancelled: 0,
        invalidated: 0,
        malformed: 0,
        non_ip: 0,
    };
}

// Each metadata allocation is fixed-size; there is no item-count ceiling or
// growing-array relocation under PolicyLock. Packet capture and cache table
// allocation/initialization/retirement still happen OUTSIDE that lock.
pub struct Engine {
    pending: List<Pending>,
    pending_count: usize,
    interfaces: List<Interface>,
    cache_candidate_count: usize,
    cache_allocator: CacheAllocator,
    events: List<Event>,
    retired_events: List<Event>,
    bandwidth: BandwidthStore,
    retry_bandwidth: BandwidthStore,
    retired_bandwidth: BandwidthStore,
    bandwidth_count: usize,
    bandwidth_epoch: u64,
    queued_bytes: usize,
    next_id: u64,
    online: bool,
    fail_closed: bool,
    timeout: u64,
    cache_ttl: u64,
    stats: Stats,
}
impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
impl Engine {
    pub const fn new() -> Self {
        Self::with_cache_allocator(CacheAllocator::GLOBAL)
    }
    pub const fn with_cache_allocator(allocator: CacheAllocator) -> Self {
        Self {
            pending: List::new(),
            pending_count: 0,
            interfaces: List::new(),
            cache_candidate_count: 0,
            cache_allocator: allocator,
            events: List::new(),
            retired_events: List::new(),
            bandwidth: BandwidthStore::new(),
            retry_bandwidth: BandwidthStore::new(),
            retired_bandwidth: BandwidthStore::new(),
            bandwidth_count: 0,
            bandwidth_epoch: 0,
            queued_bytes: 0,
            next_id: 1,
            online: false,
            fail_closed: true,
            timeout: 8000,
            cache_ttl: 60000,
            stats: Stats::EMPTY,
        }
    }
    pub fn configure(&mut self, timeout: u32, cache_ttl: u32, fail_closed: bool) {
        self.timeout = u64::from(timeout.clamp(100, 60000));
        self.cache_ttl = u64::from(cache_ttl.clamp(1000, 300000));
        self.fail_closed = fail_closed;
    }
    pub fn fallback(&self) -> Finish {
        if self.fail_closed {
            Finish::Drop
        } else {
            Finish::Allow
        }
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }
    pub fn is_online(&self) -> bool {
        self.online
    }
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }
    pub fn cache_candidates(&self) -> usize {
        self.cache_candidate_count
    }
    fn update_cache_candidates(&mut self, handle: Handle<Interface>) {
        // SAFETY: callers just found this live interface under exclusive access.
        let interface = unsafe { self.interfaces.get_mut(handle) };
        let candidate = !interface.dirty && interface.caches.has_entries();
        if candidate != interface.candidate {
            if candidate {
                self.cache_candidate_count += 1;
            } else {
                self.cache_candidate_count -= 1;
            }
            interface.candidate = candidate;
        }
    }
    fn clear_events(&mut self) {
        for event in self.events.iter() {
            if let Some(handle) = event.pending {
                // SAFETY: detach every event back-reference before retiring the
                // chain. Only the one partially read, already claimed request
                // can be inactive here; unread claims are removed immediately.
                let pending = unsafe { self.pending.get_mut(handle) };
                pending.event = None;
                if pending.id == 0 {
                    unsafe { self.pending.remove(handle) };
                }
            }
        }
        self.retired_events.append(&mut self.events);
        self.queued_bytes = 0;
    }
    pub fn take_retired_storage(&mut self) -> Option<RetiredStorage> {
        if !self.retired_events.is_empty() {
            return Some(RetiredStorage {
                _events: core::mem::replace(&mut self.retired_events, List::new()),
                _bandwidth: BandwidthStore::new(),
            });
        }
        self.retired_bandwidth
            .has_storage()
            .then(|| RetiredStorage {
                _events: List::new(),
                _bandwidth: core::mem::replace(&mut self.retired_bandwidth, BandwidthStore::new()),
            })
    }
    fn has_room(&self, len: usize) -> bool {
        self.queued_bytes.checked_add(len).is_some()
    }
    fn push_event(
        &mut self,
        data: Vec<u8>,
        pending: Option<Handle<Pending>>,
    ) -> Option<Handle<Event>> {
        let queued_bytes = self.queued_bytes.checked_add(data.len())?;
        let handle = self
            .events
            .try_push_back(Event {
                read: 0,
                pending,
                data,
            })
            .ok()?;
        self.queued_bytes = queued_bytes;
        Some(handle)
    }
    fn pop_event(&mut self) {
        if let Some(event) = self.events.pop_front() {
            self.queued_bytes -= event.data.len();
            if let Some(handle) = event.pending {
                // SAFETY: a pending node is retained until BOTH its event has
                // left the queue and its NBL token has been claimed. No event
                // handle escapes; there is exactly one event per pending node.
                let pending = unsafe { self.pending.get_mut(handle) };
                pending.event = None;
                if pending.id == 0 {
                    unsafe { self.pending.remove(handle) };
                }
            }
        }
    }
    pub fn connect(&mut self) {
        self.bandwidth_epoch = self.bandwidth_epoch.wrapping_add(1);
        self.online = true;
        self.clear_events();
        self.clear_cache();
        self.clear_bandwidth();
        self.log(3, "HyperVXNdisFilter LWF: full IP packets; no process ID; direction=0 outbound/1 inbound from guest side (host receive/send); no TID, redirects, UpdateV4/V6 or synthetic END");
    }
    // Complete actions using take_due() after dropping the lock.
    pub fn disconnect(&mut self) {
        self.bandwidth_epoch = self.bandwidth_epoch.wrapping_add(1);
        self.online = false;
        self.clear_events();
        self.clear_cache();
        self.clear_bandwidth();
    }
    pub fn attach(&mut self, interface_index: u32) -> bool {
        if interface_index == 0
            || self
                .interfaces
                .iter()
                .any(|s| s.interface_index == interface_index)
        {
            return false;
        }
        self.interfaces
            .try_push_back(Interface {
                interface_index,
                running: false,
                dirty: false,
                candidate: false,
                caches: Caches::new(self.cache_allocator),
            })
            .is_ok()
    }
    pub fn restart(&mut self, interface_index: u32) -> bool {
        if let Some(interface) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index && interface_index != 0)
        {
            interface.running = true;
            true
        } else {
            false
        }
    }
    pub fn invalidate(&mut self, interface_index: u32, pause: bool) {
        if let Some(interface) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index && interface_index != 0)
        {
            interface.dirty = interface.caches.bytes() != 0;
            if interface.candidate {
                interface.candidate = false;
                self.cache_candidate_count -= 1;
            }
            if pause {
                interface.running = false;
            }
            // A restart or reuse of the same index must not revive these IDs.
            for pending in self.pending.iter_mut() {
                if pending.id != 0 && pending.interface_index == interface_index {
                    pending.invalidated = true;
                }
            }
        }
    }
    pub fn detach(&mut self, interface_index: u32) {
        self.invalidate(interface_index, true);
        if let Some(handle) = self
            .interfaces
            .find(|s| s.interface_index == interface_index && interface_index != 0)
        {
            // SAFETY: handle was found in this list, with exclusive engine access.
            let interface = unsafe { self.interfaces.get_mut(handle) };
            interface.interface_index = 0;
            if !interface.dirty {
                // Empty cache banks have nothing to free under PolicyLock.
                unsafe { self.interfaces.remove(handle) };
            }
        }
    }
    fn running(&self, interface_index: u32) -> bool {
        self.interfaces
            .iter()
            .any(|s| s.interface_index == interface_index && s.running)
    }
    // Immediately disable all old tables; retire one bank at a time outside the
    // driver lock rather than returning a large per-interface array on its stack.
    pub fn clear_cache(&mut self) {
        self.cache_candidate_count = 0;
        for interface in self.interfaces.iter_mut() {
            interface.candidate = false;
            interface.dirty = interface.caches.bytes() != 0;
        }
    }
    pub fn take_retired_caches(&mut self) -> Option<Caches> {
        let handle = self.interfaces.find(|c| c.dirty)?;
        // SAFETY: found in this exclusively borrowed list; removal only happens
        // after moving out the cache allocations, which the caller frees unlocked.
        let interface = unsafe { self.interfaces.get_mut(handle) };
        interface.dirty = false;
        let detached = interface.interface_index == 0;
        let retired = interface.caches.clear();
        if detached {
            unsafe { self.interfaces.remove(handle) };
        }
        Some(retired)
    }
    pub fn cache_cleanup_limit(&self) -> u32 {
        self.interfaces
            .iter()
            .filter(|s| s.candidate)
            .map(|s| s.interface_index)
            .max()
            .unwrap_or(0)
    }
    // A scalar cursor survives unlocked ranges without holding node pointers or
    // allocating a snapshot. The initial upper bound makes each pass finite even
    // if interfaces attach concurrently. Reused indices cannot revive old caches.
    pub fn next_cache_candidate(&self, after: u32, through: u32) -> Option<(u32, usize)> {
        self.interfaces
            .iter()
            .filter(|s| s.candidate && s.interface_index > after && s.interface_index <= through)
            .min_by_key(|s| s.interface_index)
            .map(|s| (s.interface_index, s.caches.cleanup_slots()))
    }
    pub fn cache_cleanup_slots(&self, interface_index: u32) -> usize {
        self.interfaces
            .iter()
            .find(|s| s.interface_index == interface_index && s.candidate)
            .map_or(0, |s| s.caches.cleanup_slots())
    }
    pub fn clean_range_with_work(
        &mut self,
        interface_index: u32,
        start: usize,
        now: u64,
        work: &mut CacheWork,
    ) -> bool {
        let Some(handle) = self
            .interfaces
            .find(|s| s.interface_index == interface_index && s.candidate)
        else {
            return false;
        };
        // SAFETY: this handle was just found; no mutation can remove it here.
        unsafe { self.interfaces.get_mut(handle) }
            .caches
            .maintain_range(start, now, work);
        self.update_cache_candidates(handle);
        unsafe { self.interfaces.get(handle) }.candidate
    }
    // Host helper. The kernel worker uses ranges to release PolicyLock between
    // batches while completing every candidate bank in the same cleanup run.
    pub fn clean(&mut self, now: u64) {
        while let Some(retired) = self.take_retired_caches() {
            drop(retired);
        }
        let limit = self.cache_cleanup_limit();
        let mut after = 0;
        while let Some((index, _)) = self.next_cache_candidate(after, limit) {
            after = index;
            let handle = self
                .interfaces
                .find(|s| s.interface_index == index)
                .unwrap();
            let mut work = CacheWork::empty();
            // SAFETY: found in this list; the bank stays live throughout this call.
            unsafe { self.interfaces.get_mut(handle) }
                .caches
                .maintain(now, &mut work);
            self.update_cache_candidates(handle);
        }
    }
    fn cache_bank(&self, interface_index: u32, packet: &Packet) -> Option<Handle<Interface>> {
        if !packet.cacheable
            || !matches!(packet.connection.protocol, 6 | 17)
            || packet.flow.protocol != packet.connection.protocol
            || packet.flow.ipv6 != packet.connection.ipv6
        {
            return None;
        }
        self.interfaces.find(|interface| {
            interface.interface_index == interface_index && interface.running && !interface.dirty
        })
    }
    pub fn cache_plan(&self, id: u64, verdict: Verdict, now: u64) -> Option<CachePlan> {
        if !verdict.permanent() || !self.online {
            return None;
        }
        let pending = self
            .pending
            .iter()
            .find(|p| p.id == id && id != 0 && !p.invalidated && p.deadline > now)?;
        let bank = self.cache_bank(pending.interface_index, &pending.packet)?;
        // SAFETY: cache_bank returned a live handle in this borrowed list.
        unsafe { self.interfaces.get(bank) }
            .caches
            .plan(&pending.packet.connection)
    }
    fn cache_counts(&self) -> (usize, usize) {
        self.interfaces
            .iter()
            .filter(|c| !c.dirty)
            .fold((0, 0), |(v4, v6), c| {
                let counts = c.caches.counts();
                (v4 + counts.0, v6 + counts.1)
            })
    }
    fn cache_bytes(&self) -> usize {
        self.interfaces.iter().map(|c| c.caches.bytes()).sum()
    }
    fn account(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        allow: bool,
        work: &mut BandwidthWork,
    ) {
        if allow {
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            if self.online && matches!(packet.connection.protocol, 6 | 17) {
                self.bandwidth_add_with_work(interface_index, packet, work);
            }
        } else {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
        }
    }
    pub fn non_ip(&mut self) {
        self.stats.received = self.stats.received.saturating_add(1);
        self.stats.non_ip = self.stats.non_ip.saturating_add(1);
        self.stats.allowed = self.stats.allowed.saturating_add(1);
    }
    pub fn malformed(&mut self) {
        self.stats.received = self.stats.received.saturating_add(1);
        self.stats.malformed = self.stats.malformed.saturating_add(1);
        self.stats.dropped = self.stats.dropped.saturating_add(1);
    }
    pub fn resource_drop(&mut self) {
        self.stats.received = self.stats.received.saturating_add(1);
        self.stats.overflow = self.stats.overflow.saturating_add(1);
        self.stats.dropped = self.stats.dropped.saturating_add(1);
    }
    fn event_room(&self, packet: &Packet) -> bool {
        self.has_room(connection_header_len(&packet.connection) + packet.payload_len as usize)
            && self.next_id != u64::MAX
    }
    // Read-only allocation hint: this cannot refresh idle expiry or admit traffic.
    pub fn wants_event(&self, interface_index: u32, packet: &Packet, now: u64) -> bool {
        self.running(interface_index)
            && self.online
            && self.cache_bank(interface_index, packet).is_none_or(|bank| {
                // SAFETY: the handle belongs to this borrowed interface list.
                unsafe { self.interfaces.get(bank) }
                    .caches
                    .get(&packet.connection, now)
                    .is_none()
            })
            && self.event_room(packet)
    }
    fn immediate(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        token: usize,
        now: u64,
        work: &mut BandwidthWork,
    ) -> Option<Action> {
        let allow = if !self.running(interface_index) {
            false
        } else if !self.online {
            self.fallback() == Finish::Allow
        } else {
            let bank = self.cache_bank(interface_index, packet)?;
            // SAFETY: cache_bank found this live node under exclusive engine access.
            let allow = unsafe { self.interfaces.get_mut(bank) }.caches.apply(
                &packet.connection,
                now,
                self.cache_ttl,
            )?;
            self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
            allow
        };
        self.stats.received = self.stats.received.saturating_add(1);
        self.account(interface_index, packet, allow, work);
        Some(Action {
            token,
            finish: if allow { Finish::Allow } else { Finish::Drop },
        })
    }
    // The driver returns cache hits here: one lookup, no packet capture or second
    // policy-lock acquisition. Only misses proceed to the unlocked event copy.
    pub fn preflight(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        token: usize,
        now: u64,
    ) -> Result<bool, Action> {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.preflight_with_work(interface_index, packet, token, now, &mut work)
    }
    pub fn preflight_with_work(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        token: usize,
        now: u64,
        work: &mut BandwidthWork,
    ) -> Result<bool, Action> {
        if let Some(action) = self.immediate(interface_index, packet, token, now, work) {
            Err(action)
        } else {
            Ok(self.event_room(packet))
        }
    }
    fn overflow(
        &mut self,
        interface_index: u32,
        packet: &Packet,
        token: usize,
        work: &mut BandwidthWork,
    ) -> Submission {
        self.stats.overflow = self.stats.overflow.saturating_add(1);
        let finish = self.fallback();
        self.account(interface_index, packet, finish == Finish::Allow, work);
        Submission::Finish(Action { token, finish })
    }
    pub fn submit(
        &mut self,
        interface_index: u32,
        packet: Packet,
        token: usize,
        cancel: Option<usize>,
        now: u64,
        record: Option<Vec<u8>>,
    ) -> Submission {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.submit_with_work(
            interface_index,
            packet,
            token,
            cancel,
            now,
            record,
            &mut work,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn submit_with_work(
        &mut self,
        interface_index: u32,
        packet: Packet,
        token: usize,
        cancel: Option<usize>,
        now: u64,
        record: Option<Vec<u8>>,
        work: &mut BandwidthWork,
    ) -> Submission {
        if let Some(action) = self.immediate(interface_index, &packet, token, now, work) {
            return Submission::Finish(action);
        }
        self.stats.received = self.stats.received.saturating_add(1);
        let payload_len = packet.payload_len as usize;
        let expected = connection_header_len(&packet.connection) + payload_len;
        if payload_len > MAX_PAYLOAD || record.as_ref().is_some_and(|data| data.len() != expected) {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            self.account(interface_index, &packet, false, work);
            return Submission::Finish(Action {
                token,
                finish: Finish::Drop,
            });
        }
        if !self.has_room(expected) || self.next_id == u64::MAX || record.is_none() {
            return self.overflow(interface_index, &packet, token, work);
        }
        let id = self.next_id;
        let mut data = record.unwrap_or_default();
        if encode_connection_header(
            &mut data,
            id,
            interface_index,
            &packet.connection,
            payload_len,
        )
        .is_err()
        {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            self.account(interface_index, &packet, false, work);
            return Submission::Finish(Action {
                token,
                finish: Finish::Drop,
            });
        }
        let Ok(handle) = self.pending.try_push_back(Pending {
            id,
            token,
            cancel,
            deadline: now.saturating_add(self.timeout),
            interface_index,
            invalidated: false,
            event: None,
            packet,
        }) else {
            return self.overflow(interface_index, &packet, token, work);
        };
        let Some(event) = self.push_event(data, Some(handle)) else {
            // SAFETY: the event was not published, so only this new handle exists.
            unsafe { self.pending.remove(handle) };
            return self.overflow(interface_index, &packet, token, work);
        };
        // SAFETY: both nodes are live and no handles escape the locked engine.
        unsafe { self.pending.get_mut(handle) }.event = Some(event);
        self.next_id += 1;
        self.pending_count += 1;
        self.stats.queued = self.stats.queued.saturating_add(1);
        Submission::Pending(id)
    }
    fn claim(
        &mut self,
        handle: Handle<Pending>,
        finish: Finish,
        bandwidth: &mut BandwidthWork,
    ) -> Action {
        // SAFETY: callers found a live, active node under exclusive engine access.
        let pending = unsafe { self.pending.get_mut(handle) };
        let p = *pending;
        pending.id = 0;
        let retain = if let Some(event) = p.event {
            // SAFETY: a pending event handle stays live until pop_event clears
            // it. Unread stale events can be unlinked in O(1), avoiding repeated
            // scans of claimed nodes when a large timeout/cancel batch drains.
            if unsafe { self.events.get(event) }.read == 0 {
                let event = unsafe { self.events.remove(event) };
                self.queued_bytes -= event.data.len();
                false
            } else {
                true // Finish a partial frame before freeing its pending node.
            }
        } else {
            false
        };
        if !retain {
            unsafe { self.pending.remove(handle) };
        }
        self.pending_count -= 1;
        self.account(
            p.interface_index,
            &p.packet,
            finish == Finish::Allow,
            bandwidth,
        );
        Action {
            token: p.token,
            finish,
        }
    }
    pub fn verdict(&mut self, id: u64, verdict: Verdict, now: u64) -> Result<Action, VerdictError> {
        while let Some(retired) = self.take_retired_caches() {
            drop(retired);
        }
        let mut work = CacheWork::prepare(self.cache_plan(id, verdict, now));
        let mut bandwidth = BandwidthWork::prepare(self.bandwidth_plan());
        self.verdict_with_work(id, verdict, now, &mut work, &mut bandwidth)
    }
    pub fn verdict_with_work(
        &mut self,
        id: u64,
        verdict: Verdict,
        now: u64,
        work: &mut CacheWork,
        bandwidth: &mut BandwidthWork,
    ) -> Result<Action, VerdictError> {
        let handle = self
            .pending
            .find(|p| p.id == id && id != 0)
            .ok_or(VerdictError::NotFound)?;
        // SAFETY: the handle was found in this list and no node is removed here.
        let p = *unsafe { self.pending.get(handle) };
        if p.deadline <= now || !self.online || p.invalidated {
            return Err(VerdictError::NotFound);
        }
        if verdict.permanent()
            && let Some(bank) = self.cache_bank(p.interface_index, &p.packet)
        {
            // SAFETY: cache_bank returned this live node; insertion cannot detach it.
            if !unsafe { self.interfaces.get_mut(bank) }.caches.insert(
                &p.packet.connection,
                Decision {
                    allow: verdict.allows(),
                    expires: now.saturating_add(self.cache_ttl),
                },
                now,
                work,
            ) {
                self.stats.cache_allocation_failures =
                    self.stats.cache_allocation_failures.saturating_add(1);
            }
            self.update_cache_candidates(bank);
        }
        Ok(self.claim(
            handle,
            if verdict.allows() {
                Finish::Allow
            } else {
                Finish::Drop
            },
            bandwidth,
        ))
    }
    // One owned token at a time, never an unbounded array on the kernel stack.
    pub fn take_due(&mut self, now: u64) -> Option<Action> {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.take_due_with_work(now, &mut work)
    }
    pub fn take_due_with_work(&mut self, now: u64, work: &mut BandwidthWork) -> Option<Action> {
        if self.pending_count == 0 {
            return None;
        }
        let handle = self
            .pending
            .find(|p| p.id != 0 && (p.invalidated || !self.online || p.deadline <= now))?;
        // SAFETY: the handle was just found under exclusive engine access.
        let p = *unsafe { self.pending.get(handle) };
        let finish = if p.invalidated {
            self.stats.invalidated = self.stats.invalidated.saturating_add(1);
            Finish::Drop
        } else if !self.online {
            self.fallback()
        } else {
            self.stats.timeouts = self.stats.timeouts.saturating_add(1);
            self.fallback()
        };
        Some(self.claim(handle, finish, work))
    }
    pub fn cancel(&mut self, interface_index: u32, cancel: usize) -> Option<Action> {
        let handle = self.pending.find(|p| {
            p.id != 0 && p.interface_index == interface_index && p.cancel == Some(cancel)
        })?;
        self.stats.cancelled = self.stats.cancelled.saturating_add(1);
        // Cancellation never admits bytes and cannot consume bandwidth storage.
        Some(self.claim(handle, Finish::Cancel, &mut BandwidthWork::empty()))
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        while written < out.len() {
            let Some(event) = self.events.front() else {
                break;
            };
            let stale = event.read == 0
                && event.pending.is_some_and(|handle| {
                    // SAFETY: queued events retain their pending node even after claim.
                    unsafe { self.pending.get(handle) }.id == 0
                });
            if stale {
                self.pop_event();
                continue;
            }
            let event = self.events.front_mut().unwrap();
            let n = (event.data.len() - event.read).min(out.len() - written);
            out[written..written + n].copy_from_slice(&event.data[event.read..event.read + n]);
            event.read += n;
            written += n;
            if event.read == event.data.len() {
                self.pop_event();
            }
        }
        written
    }
    pub fn log(&mut self, severity: u8, message: &str) {
        if !self.online {
            return;
        }
        let mut bytes = [0; MAX_LOG_RECORD];
        let Ok(len) = encode_log(&mut bytes, severity, message) else {
            return;
        };
        if !self.has_room(len) {
            return;
        }
        if let Some(mut data) = allocate_record(len) {
            data.copy_from_slice(&bytes[..len]);
            let _ = self.push_event(data, None);
        }
    }
    fn clear_bandwidth(&mut self) {
        self.retired_bandwidth.append(&mut self.bandwidth);
        self.retired_bandwidth.append(&mut self.retry_bandwidth);
        self.bandwidth_count = 0;
    }
    // Read-only capacity hint. The driver prepares these allocations unlocked,
    // then rechecks the hint before invoking a single accounting operation.
    pub fn bandwidth_plan(&self) -> Option<BandwidthPlan> {
        self.online.then(|| self.bandwidth.plan()).flatten()
    }
    pub fn install_bandwidth_work(&mut self, work: &mut BandwidthWork) {
        if self.online {
            self.bandwidth.install(work);
        }
    }
    #[cfg(test)]
    fn bandwidth_add(&mut self, interface_index: u32, p: &Packet) {
        let mut work = BandwidthWork::prepare(self.bandwidth_plan());
        self.bandwidth_add_with_work(interface_index, p, &mut work);
    }
    fn bandwidth_add_with_work(
        &mut self,
        interface_index: u32,
        p: &Packet,
        work: &mut BandwidthWork,
    ) {
        match self
            .bandwidth
            .add(interface_index, &p.connection, p.ip_len, work)
        {
            Some(added) => self.bandwidth_count += usize::from(added),
            None => self.stats.overflow = self.stats.overflow.saturating_add(1),
        }
    }
    pub fn begin_bandwidth(&mut self, table: &mut BandwidthTable) -> bool {
        if (self.bandwidth_count == 0 && self.retry_bandwidth.is_empty())
            || table.store.has_storage()
        {
            return false;
        }
        // Move only ownership headers. Pages/entries/index buffers never move.
        core::mem::swap(&mut self.bandwidth, &mut table.store);
        table.store.append(&mut self.retry_bandwidth);
        table.epoch = self.bandwidth_epoch;
        self.bandwidth_count = 0;
        true
    }
    pub fn queue_bandwidth(&mut self, epoch: u64, data: Vec<u8>) -> Result<(), Vec<u8>> {
        if !self.online || epoch != self.bandwidth_epoch || !self.has_room(data.len()) {
            return Err(data);
        }
        let queued_bytes = self.queued_bytes + data.len();
        match self.events.try_push_back(Event {
            read: 0,
            pending: None,
            data,
        }) {
            Ok(_) => {
                self.queued_bytes = queued_bytes;
                Ok(())
            }
            Err(event) => Err(event.data),
        }
    }
    pub fn finish_bandwidth(&mut self, table: &mut BandwidthTable) -> bool {
        if !self.online || table.epoch != self.bandwidth_epoch {
            return false;
        }
        // Keep unqueued deltas as whole retry banks, without a bulk locked
        // merge. The next detached report combines duplicate keys unlocked.
        if !table.store.is_empty() {
            self.retry_bandwidth.append(&mut table.store);
        }
        self.bandwidth_count = self.bandwidth.len() + self.retry_bandwidth.len();
        true
    }
    // Offline policy tests use the same detached-table path as the kernel bridge.
    pub fn bandwidth(&mut self) {
        let mut table = BandwidthTable::new();
        if !self.begin_bandwidth(&mut table) {
            return;
        }
        let epoch = table.epoch();
        table.report(|data| match self.queue_bandwidth(epoch, data) {
            Ok(()) => true,
            Err(data) => {
                drop(data);
                false
            }
        });
        let _ = self.finish_bandwidth(&mut table);
    }
    pub fn memory_stats(&mut self) {
        let mut text = Text {
            bytes: [0; 400],
            len: 0,
        };
        let s = self.stats;
        let metadata = self.pending.bytes()
            + self.events.bytes()
            + self.interfaces.bytes()
            + self.bandwidth.bytes()
            + self.retry_bandwidth.bytes();
        let _ = write!(
            text,
            "HyperVXNdisFilter: fixed_bytes={} metadata_bytes={} event_bytes={} pending={} events={} bandwidth={} cached_v4={} cached_v6={} cache_bytes={} cache_alloc_fail={} rx={} allow={} drop={} queued={} cache_hits={} timeout={} overflow={} cancel={} invalidated={} malformed={} non_ip={}",
            core::mem::size_of::<Self>(),
            metadata,
            self.queued_bytes,
            self.pending_count(),
            self.events.len(),
            self.bandwidth_count,
            self.cache_counts().0,
            self.cache_counts().1,
            self.cache_bytes(),
            s.cache_allocation_failures,
            s.received,
            s.allowed,
            s.dropped,
            s.queued,
            s.cache_hits,
            s.timeouts,
            s.overflow,
            s.cancelled,
            s.invalidated,
            s.malformed,
            s.non_ip
        );
        self.log(3, text.as_str());
    }
}
struct Text {
    bytes: [u8; 400],
    len: usize,
}
impl Text {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("statistics formatting error")
    }
}
impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        if n == s.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::packet::NdisPath;
    use hyperv_protocol::Direction;
    use std::{boxed::Box, vec};
    fn engine() -> Box<Engine> {
        let mut e = default_engine();
        e.configure(2000, 60000, false); // Explicit fail-open/short deadline for these fixtures.
        e
    }
    fn default_engine() -> Box<Engine> {
        let mut e = Box::new(Engine::new());
        assert!(e.attach(101));
        assert!(e.restart(101));
        e.connect();
        e
    }
    fn packet() -> Packet {
        let mut p = Packet::EMPTY;
        p.cacheable = true;
        p.flow.protocol = 17;
        p.connection.protocol = 17;
        p.ip_len = 100;
        p.payload_len = 100;
        p
    }
    fn record(p: &Packet) -> Option<Vec<u8>> {
        allocate_record(connection_header_len(&p.connection) + p.payload_len as usize)
    }
    fn submit(e: &mut Engine, interface_index: u32, t: usize) -> u64 {
        let p = packet();
        match e.submit(interface_index, p, t, None, 100, record(&p)) {
            Submission::Pending(id) => id,
            _ => panic!("expected pending"),
        }
    }
    #[test]
    fn pending_events_grow_past_old_counts_and_preserve_every_id_and_packet() {
        const COUNT: usize = 4097;
        let mut e = default_engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut ids = Vec::new();
        for token in 1..=COUNT {
            let mut p = packet();
            p.flow.source_port = token as u16;
            p.orient(NdisPath::Receive);
            let Submission::Pending(id) = e.submit(101, p, token, None, 100, record(&p)) else {
                panic!("small packets must not hit a fixed item limit");
            };
            ids.push(id);
        }
        assert_eq!(e.pending_count(), COUNT);
        assert_eq!(e.events.len(), COUNT);
        assert_eq!(e.stats().overflow, 0);
        let mut bytes = Vec::new();
        let mut chunk = [0; 65536];
        loop {
            let n = e.read(&mut chunk);
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        let size = connection_header_len(&packet().connection) + 100;
        assert_eq!(bytes.len(), COUNT * size);
        for (i, event) in bytes.chunks_exact(size).enumerate() {
            assert_eq!(event[0], 1);
            assert_eq!(u64::from_le_bytes(event[5..13].try_into().unwrap()), ids[i]);
            assert_eq!(u32::from_le_bytes(event[13..17].try_into().unwrap()), 101);
            assert_eq!(
                u16::from_le_bytes(event[27..29].try_into().unwrap()),
                (i + 1) as u16
            );
            assert_eq!(u32::from_le_bytes(event[32..36].try_into().unwrap()), 100);
            assert!(event[36..].iter().all(|byte| *byte == 0));
        }
        for &i in &[COUNT - 1, 1, 2048] {
            assert_eq!(e.verdict(ids[i], Verdict::Drop, 101).unwrap().token, i + 1);
            assert!(e.verdict(ids[i], Verdict::PermanentAccept, 102).is_err());
        }
        let mut expired = 0;
        while let Some(action) = e.take_due(8100) {
            assert_eq!(action.finish, Finish::Drop);
            expired += 1;
        }
        assert_eq!(expired, COUNT - 3);
        assert_eq!(e.pending_count(), 0);
        assert!(e.pending.is_empty());
        assert!(e.events.is_empty());
        assert_eq!(e.stats().dropped, COUNT as u64);
    }

    #[test]
    fn large_unread_drains_unlink_nodes_but_finish_the_one_partial_frame() {
        const COUNT: usize = 4097;
        for mode in 0..4 {
            let mut e = default_engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            let mut p = packet();
            p.orient(NdisPath::Send);
            let mut prefix = [0; 3];
            for token in 0..COUNT {
                assert!(matches!(
                    e.submit(101, p, token, Some(42), 100, record(&p)),
                    Submission::Pending(_)
                ));
                if token == 0 {
                    assert_eq!(e.read(&mut prefix), 3);
                }
            }
            if mode == 2 {
                e.disconnect();
            }
            if mode == 3 {
                e.invalidate(101, true);
            }
            let mut seen = vec![false; COUNT];
            loop {
                let action = if mode == 1 {
                    e.cancel(101, 42)
                } else {
                    e.take_due(8100)
                };
                let Some(action) = action else { break };
                assert!(!seen[action.token]);
                seen[action.token] = true;
                assert_eq!(
                    action.finish,
                    if mode == 1 {
                        Finish::Cancel
                    } else {
                        Finish::Drop
                    }
                );
            }
            assert!(seen.into_iter().all(|seen| seen));
            assert_eq!(e.pending_count(), 0);
            assert_eq!(e.events.len(), usize::from(mode != 2));
            assert_eq!(e.pending.len(), usize::from(mode != 2));
            let mut tail = [0; 256];
            let n = e.read(&mut tail);
            assert_eq!(n, if mode == 2 { 0 } else { 133 });
            assert_eq!(prefix[0], 1);
            assert!(e.events.is_empty());
            assert!(e.pending.is_empty());
            assert_eq!(e.queued_bytes, 0);
        }
    }

    #[test]
    fn bandwidth_and_report_events_grow_without_splitting_groups() {
        const COUNT: usize = 1025;
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for port in 1..=COUNT {
            let mut p = packet();
            p.flow.source_port = port as u16;
            p.flow.ipv6 = port % 2 == 0;
            p.connection.ipv6 = p.flow.ipv6;
            p.orient(NdisPath::Receive);
            let Submission::Pending(id) = e.submit(101, p, port, None, 100, record(&p)) else {
                panic!("expected a distinct tuple");
            };
            assert_eq!(
                e.read(&mut [0; 256]),
                connection_header_len(&p.connection) + 100
            );
            e.verdict(id, Verdict::Accept, 101).unwrap();
        }
        assert_eq!(e.bandwidth_count, COUNT);
        e.bandwidth();
        assert_eq!(e.bandwidth_count, 0);
        assert_eq!(e.events.len(), 2);
        let mut bytes = vec![0; COUNT * 66];
        let n = e.read(&mut bytes);
        let mut offset = 0;
        let mut records = 0;
        let mut seen = vec![false; COUNT];
        while offset < n {
            let event = &bytes[offset..];
            let size = 5 + u32::from_le_bytes(event[1..5].try_into().unwrap()) as usize;
            assert!(matches!(event[0], 5 | 6));
            let ipv6 = event[0] == 6;
            let count = u32::from_le_bytes(event[10..14].try_into().unwrap()) as usize;
            assert_eq!(count, if ipv6 { COUNT / 2 } else { COUNT.div_ceil(2) });
            assert_eq!(u32::from_le_bytes(event[6..10].try_into().unwrap()), 101);
            assert_eq!(event[5], 17);
            let entry_size = bandwidth_entry_len(ipv6);
            let address_size = if ipv6 { 16 } else { 4 };
            assert_eq!(size, BANDWIDTH_HEADER + count * entry_size);
            for entry in event[BANDWIDTH_HEADER..size].chunks_exact(entry_size) {
                let port =
                    u16::from_le_bytes(entry[address_size..address_size + 2].try_into().unwrap())
                        as usize;
                assert!((1..=COUNT).contains(&port));
                assert_eq!(port.is_multiple_of(2), ipv6);
                assert!(!seen[port - 1]);
                seen[port - 1] = true;
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 16..entry_size - 8].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 8..].try_into().unwrap()),
                    0
                );
            }
            offset += size;
            records += 1;
        }
        assert_eq!(offset, n);
        assert_eq!(records, 2);
        assert!(seen.into_iter().all(|seen| seen));
        assert!(e.events.is_empty());
    }

    #[test]
    fn bandwidth_table_reports_after_detach() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for port in 1..=3 {
            let mut p = packet();
            p.connection.local_port = port;
            e.bandwidth_add(101, &p);
        }
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        assert_eq!(e.bandwidth_count, 0);
        let epoch = table.epoch();
        table.report(|data| match e.queue_bandwidth(epoch, data) {
            Ok(()) => true,
            Err(data) => {
                drop(data);
                false
            }
        });
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(e.bandwidth_count, 0);
        assert_eq!(e.events.len(), 1);
        let mut out = [0; 128];
        assert_eq!(
            e.read(&mut out),
            BANDWIDTH_HEADER + 3 * bandwidth_entry_len(false)
        );
    }

    fn bandwidth_rows(e: &mut Engine) -> Vec<(u32, u8, bool, u16, u64, u64)> {
        let mut out = vec![0; 4096];
        let len = e.read(&mut out);
        let mut offset = 0;
        let mut rows = Vec::new();
        while offset < len {
            let data = &out[offset..len];
            assert!(matches!(data[0], 5 | 6));
            let ipv6 = data[0] == 6;
            let record_len = 5 + u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
            let index = u32::from_le_bytes(data[6..10].try_into().unwrap());
            let count = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
            let size = bandwidth_entry_len(ipv6);
            assert_eq!(record_len, BANDWIDTH_HEADER + count * size);
            let address_size = if ipv6 { 16 } else { 4 };
            for entry in data[BANDWIDTH_HEADER..record_len].chunks_exact(size) {
                rows.push((
                    index,
                    data[5],
                    ipv6,
                    u16::from_le_bytes(entry[address_size..address_size + 2].try_into().unwrap()),
                    u64::from_le_bytes(entry[size - 16..size - 8].try_into().unwrap()),
                    u64::from_le_bytes(entry[size - 8..].try_into().unwrap()),
                ));
            }
            offset += record_len;
        }
        assert_eq!(offset, len);
        rows.sort_unstable();
        rows
    }

    #[test]
    fn partial_bandwidth_report_retains_deltas_and_merges_concurrent_full_keys() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut tcp = packet();
        tcp.connection.protocol = 6;
        tcp.connection.local_port = 11;
        let mut udp = packet();
        udp.connection.local_port = 22;
        e.bandwidth_add(101, &tcp);
        e.bandwidth_add(101, &udp);
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));

        tcp.ip_len = 7;
        e.bandwidth_add(101, &tcp);
        udp.connection.direction = Direction::Inbound;
        udp.ip_len = 13;
        e.bandwidth_add(101, &udp);
        let mut new_udp = udp;
        new_udp.connection.local_port = 33;
        new_udp.ip_len = 19;
        e.bandwidth_add(101, &new_udp);

        let epoch = table.epoch();
        let mut groups = 0;
        table.report(|data| {
            groups += 1;
            if groups == 2 {
                return false;
            }
            e.queue_bandwidth(epoch, data).unwrap();
            true
        });
        assert_eq!(groups, 2);
        assert!(e.finish_bandwidth(&mut table));
        assert_eq!(bandwidth_rows(&mut e), [(101, 6, false, 11, 100, 0)]);
        // The retry bank can contain the same UDP key as new live traffic. It
        // must become one entry, not two rows or a lost/duplicated delta.
        e.bandwidth();
        assert_eq!(
            bandwidth_rows(&mut e),
            [
                (101, 6, false, 11, 7, 0),
                (101, 17, false, 22, 100, 13),
                (101, 17, false, 33, 0, 19),
            ]
        );
        assert_eq!(e.bandwidth_count, 0);
        e.bandwidth();
        assert!(!e.has_events());
    }

    #[test]
    fn bandwidth_queue_rejection_keeps_every_delta_for_a_later_report() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let p = packet();
        e.bandwidth_add(101, &p);
        e.events.fail_allocations = true;
        e.bandwidth();
        assert!(!e.has_events());
        assert_eq!(e.bandwidth_count, 1);
        e.bandwidth(); // Repeated failure must neither lose nor duplicate deltas.
        assert_eq!(e.bandwidth_count, 1);
        e.events.fail_allocations = false;
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 100, 0)]);
        assert_eq!(e.bandwidth_count, 0);
    }

    #[test]
    fn detached_bandwidth_cannot_cross_a_controller_session_reset() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        e.bandwidth_add(101, &p);
        let mut table = BandwidthTable::new();
        assert!(e.begin_bandwidth(&mut table));
        let old_epoch = table.epoch();
        e.disconnect();
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        p.ip_len = 17;
        e.bandwidth_add(101, &p);
        let mut attempted = false;
        table.report(|data| {
            attempted = true;
            assert!(e.queue_bandwidth(old_epoch, data).is_err());
            false
        });
        assert!(attempted);
        assert!(!e.finish_bandwidth(&mut table));
        e.bandwidth();
        assert_eq!(bandwidth_rows(&mut e), [(101, 17, false, 0, 17, 0)]);
    }

    #[test]
    fn bandwidth_queues_the_entire_large_group_without_count_caps_or_splitting() {
        const COUNT: usize = 40000;
        for ipv6 in [false, true] {
            let mut e = engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            for port in 1..=COUNT {
                let mut p = packet();
                p.connection.ipv6 = ipv6;
                p.connection.local_port = port as u16;
                e.bandwidth_add(101, &p);
            }
            assert_eq!(e.bandwidth_count, COUNT);
            e.bandwidth();
            assert_eq!(e.bandwidth_count, 0);
            assert_eq!(e.events.len(), 1);
            // Successfully queued reports release their detached nodes after
            // serialization, so no large list is retired under the policy lock.
            assert!(!e.retired_bandwidth.has_storage());
            while let Some(retired) = e.take_retired_storage() {
                drop(retired);
            }
            let len = bandwidth_record_len(ipv6, COUNT).unwrap();
            assert!(len > MAX_RECORD);
            let mut out = vec![0; len];
            assert_eq!(e.read(&mut out), len);
            assert_eq!(out[0], if ipv6 { 6 } else { 5 });
            assert_eq!(
                u32::from_le_bytes(out[1..5].try_into().unwrap()) as usize,
                len - 5
            );
            assert_eq!(out[5], 17);
            assert_eq!(u32::from_le_bytes(out[6..10].try_into().unwrap()), 101);
            assert_eq!(
                u32::from_le_bytes(out[10..14].try_into().unwrap()) as usize,
                COUNT
            );
            let entry_size = bandwidth_entry_len(ipv6);
            let address_size = if ipv6 { 16 } else { 4 };
            let mut seen = vec![false; COUNT];
            for entry in out[BANDWIDTH_HEADER..].chunks_exact(entry_size) {
                let port =
                    u16::from_le_bytes(entry[address_size..address_size + 2].try_into().unwrap())
                        as usize;
                assert!((1..=COUNT).contains(&port));
                assert!(!seen[port - 1]);
                seen[port - 1] = true;
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 16..entry_size - 8].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(entry[entry_size - 8..].try_into().unwrap()),
                    0
                );
            }
            assert!(seen.into_iter().all(|seen| seen));
            e.bandwidth();
            assert!(!e.has_events());
        }
    }

    #[test]
    fn metadata_allocation_failure_uses_fallback_without_publishing_or_losing_a_token() {
        for fail_closed in [false, true] {
            for fail_pending in [false, true] {
                let mut e = default_engine();
                e.configure(8000, 60000, fail_closed);
                e.read(&mut [0; MAX_LOG_RECORD]);
                e.pending.fail_allocations = fail_pending;
                e.events.fail_allocations = !fail_pending;
                let p = packet();
                assert_eq!(
                    e.submit(101, p, 7, None, 100, record(&p)),
                    Submission::Finish(Action {
                        token: 7,
                        finish: if fail_closed {
                            Finish::Drop
                        } else {
                            Finish::Allow
                        },
                    })
                );
                assert_eq!(e.pending_count(), 0);
                assert!(e.pending.is_empty());
                assert!(!e.has_events());
                assert_eq!(e.queued_bytes, 0);
                assert_eq!(e.stats().overflow, 1);
                assert!(e.take_due(u64::MAX).is_none());
                e.pending.fail_allocations = false;
                e.events.fail_allocations = false;
                let id = submit(&mut e, 101, 8);
                assert_eq!(id, 1);
                assert_eq!(e.verdict(id, Verdict::Drop, 101).unwrap().token, 8);
                e.read(&mut [0; 256]);
                assert!(e.pending.is_empty());
            }
        }
    }

    #[test]
    fn bandwidth_separates_interfaces_protocols_and_families_but_not_directions() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        // 101 and 357 also exercise identical low hash bits for the same tuple.
        for index in [357, u32::MAX] {
            assert!(e.attach(index));
            assert!(e.restart(index));
        }
        let mut expected = Vec::new();
        for (ordinal, interface_index) in [101, 357, u32::MAX].into_iter().enumerate() {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    let tx = ((ordinal as u64 + 1) << 32) + 123;
                    let rx = tx + 456;
                    for (direction, bytes) in [(Direction::Outbound, tx), (Direction::Inbound, rx)]
                    {
                        let mut p = packet();
                        p.connection.protocol = protocol;
                        p.flow.protocol = protocol;
                        p.connection.ipv6 = ipv6;
                        p.flow.ipv6 = ipv6;
                        p.connection.direction = direction;
                        p.ip_len = bytes;
                        let Submission::Pending(id) =
                            e.submit(interface_index, p, 1, None, 100, record(&p))
                        else {
                            panic!("expected an uncached packet");
                        };
                        assert_eq!(
                            e.verdict(id, Verdict::Accept, 101).unwrap().finish,
                            Finish::Allow
                        );
                    }
                    expected.push((interface_index, protocol, ipv6, tx, rx));
                }
            }
        }
        assert_eq!(e.bandwidth_count, expected.len());
        e.bandwidth();
        assert_eq!(e.bandwidth_count, 0);
        let mut out = vec![0; expected.len() * 66];
        let n = e.read(&mut out);
        let mut offset = 0;
        let mut seen = vec![false; expected.len()];
        while offset < n {
            let event = &out[offset..];
            let ipv6 = event[0] == 6;
            assert!(matches!(event[0], 5 | 6));
            let len = if ipv6 { 66 } else { 42 };
            assert_eq!(
                u32::from_le_bytes(event[1..5].try_into().unwrap()) as usize,
                len - 5
            );
            assert_eq!(u32::from_le_bytes(event[10..14].try_into().unwrap()), 1);
            let index = u32::from_le_bytes(event[6..10].try_into().unwrap());
            let i = expected
                .iter()
                .position(|&(iface, protocol, family, _, _)| {
                    (iface, protocol, family) == (index, event[5], ipv6)
                })
                .expect("unexpected bandwidth key");
            assert!(!seen[i]);
            seen[i] = true;
            assert_eq!(
                u64::from_le_bytes(event[len - 16..len - 8].try_into().unwrap()),
                expected[i].3
            );
            assert_eq!(
                u64::from_le_bytes(event[len - 8..len].try_into().unwrap()),
                expected[i].4
            );
            offset += len;
        }
        assert_eq!(offset, n);
        assert!(seen.into_iter().all(|seen| seen));
        e.bandwidth();
        assert!(!e.has_events());
        // Successfully queued reports reset only their deltas.
        let mut p = packet();
        p.ip_len = 33;
        let Submission::Pending(id) = e.submit(357, p, 1, None, 100, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 101).unwrap();
        e.bandwidth();
        assert_eq!(e.read(&mut out), 42);
        assert_eq!(u32::from_le_bytes(out[6..10].try_into().unwrap()), 357);
        assert_eq!(u64::from_le_bytes(out[26..34].try_into().unwrap()), 33);
        assert_eq!(u64::from_le_bytes(out[34..42].try_into().unwrap()), 0);
    }

    #[test]
    fn bandwidth_keeps_the_interface_on_cached_allows_and_fail_open_fallbacks() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        assert!(e.attach(357));
        assert!(e.restart(357));
        for interface_index in [101, 357] {
            let id = submit(&mut e, interface_index, 1);
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            let mut p = packet();
            p.connection.direction = Direction::Inbound;
            p.ip_len = 75;
            assert_eq!(
                e.preflight(interface_index, &p, 2, 102).unwrap_err().finish,
                Finish::Allow
            );
            p.connection.direction = Direction::Outbound;
            p.cacheable = false;
            p.ip_len = 125;
            assert_eq!(
                e.submit(interface_index, p, 3, None, 103, None),
                Submission::Finish(Action {
                    token: 3,
                    finish: Finish::Allow
                })
            );
            p.ip_len = 150;
            assert!(matches!(
                e.submit(interface_index, p, 4, None, 104, record(&p)),
                Submission::Pending(_)
            ));
            assert_eq!(
                e.take_due(2104),
                Some(Action {
                    token: 4,
                    finish: Finish::Allow
                })
            );
        }
        assert_eq!(e.stats().cache_hits, 2);
        assert_eq!(e.stats().overflow, 2);
        assert_eq!(e.stats().timeouts, 2);
        assert_eq!(e.bandwidth_count, 2);
        e.bandwidth();
        let mut out = [0; 128];
        assert_eq!(e.read(&mut out), 84);
        let mut indices = [0; 2];
        for (i, event) in out[..84].as_chunks::<42>().0.iter().enumerate() {
            indices[i] = u32::from_le_bytes(event[6..10].try_into().unwrap());
            assert_eq!(u64::from_le_bytes(event[26..34].try_into().unwrap()), 375);
            assert_eq!(u64::from_le_bytes(event[34..42].try_into().unwrap()), 75);
        }
        indices.sort_unstable();
        assert_eq!(indices, [101, 357]);
    }

    #[test]
    fn bandwidth_oom_does_not_change_a_verdict_or_cached_allow() {
        let mut e = engine();
        let id = submit(&mut e, 101, 1);
        e.bandwidth.fail_allocations = true;
        assert_eq!(
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap().finish,
            Finish::Allow
        );
        assert_eq!(
            e.preflight(101, &packet(), 2, 102),
            Err(Action {
                token: 2,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.stats().overflow, 2);
        assert_eq!(e.stats().cache_hits, 1);
        assert!(e.bandwidth_count == 0);
        e.bandwidth.fail_allocations = false;
        assert!(e.preflight(101, &packet(), 3, 103).is_err());
        assert_eq!(e.bandwidth_count, 1);
    }

    #[test]
    fn interface_oom_rejects_only_that_attach_and_cleanup_covers_more_than_one_word() {
        let mut e = Box::new(Engine::new());
        e.interfaces.fail_allocations = true;
        assert!(!e.attach(101));
        assert!(!e.restart(101));
        assert!(e.interfaces.is_empty());
        e.interfaces.fail_allocations = false;
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for index in (1..=129).chain([u32::MAX]) {
            assert!(e.attach(index));
            assert!(e.restart(index));
            let id = submit(&mut e, index, index as usize);
            e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        }
        assert_eq!(e.cache_candidates(), 130);
        let limit = e.cache_cleanup_limit();
        assert_eq!(limit, u32::MAX);
        let mut after = 0;
        let mut visited = 0;
        while let Some((index, slots)) = e.next_cache_candidate(after, limit) {
            after = index;
            for start in (0..slots).step_by(crate::cache::CLEANUP_SLOTS_PER_BATCH) {
                let mut work = CacheWork::empty();
                e.clean_range_with_work(index, start, 60101, &mut work);
            }
            visited += 1;
        }
        assert_eq!(visited, 130);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.cache_bytes(), 0);
        assert!(e.next_cache_candidate(after, limit).is_none());
        for index in (1..=129).chain([u32::MAX]) {
            e.detach(index);
        }
        assert!(e.interfaces.is_empty());
        e.read(&mut [0; 256]);
        assert!(e.pending.is_empty());
    }

    #[test]
    fn cleared_event_and_bandwidth_chains_retire_without_bulk_locked_destruction() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        for port in 1..=2049 {
            let mut p = packet();
            p.flow.source_port = port;
            p.orient(NdisPath::Receive);
            let Submission::Pending(id) = e.submit(101, p, port as usize, None, 100, record(&p))
            else {
                panic!();
            };
            e.read(&mut [0; 256]);
            e.verdict(id, Verdict::Accept, 101).unwrap();
            e.log(3, "queued diagnostic");
        }
        assert_eq!(e.bandwidth_count, 2049);
        e.disconnect();
        assert!(!e.has_events());
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.bandwidth_count, 0);
        assert!(!e.retired_events.is_empty());
        assert!(e.retired_bandwidth.has_storage());
        // A second reset appends to the retired chain rather than destroying it.
        e.connect();
        e.disconnect();
        assert_eq!(e.retired_events.len(), 2);
        let mut banks = 0;
        while let Some(storage) = e.take_retired_storage() {
            drop(storage); // Driver performs the same drop after hv_unlock().
            banks += 1;
        }
        assert!(banks > 1);
        assert!(e.retired_events.is_empty());
        assert!(!e.retired_bandwidth.has_storage());
        assert!(core::mem::size_of::<RetiredStorage>() < 128);
    }

    #[test]
    fn default_pending_deadline_is_eight_seconds_and_drops_unanswered_packets() {
        let mut e = default_engine();
        let id = submit(&mut e, 101, 1);
        assert!(e.take_due(2100).is_none());
        assert!(e.take_due(8099).is_none());
        assert!(e.verdict(id, Verdict::PermanentAccept, 8100).is_err());
        assert!(e.cache_plan(id, Verdict::PermanentAccept, 8100).is_none());
        assert_eq!(
            e.take_due(8100),
            Some(Action {
                token: 1,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(e.stats().timeouts, 1);
    }

    #[test]
    fn default_fallback_drops_ip_traffic_without_a_controller() {
        let mut e = Box::new(Engine::new());
        assert_eq!(e.fallback(), Finish::Drop);
        assert!(e.attach(101));
        assert!(e.restart(101));
        for ipv6 in [false, true] {
            for protocol in [1, 6, 17, 58] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut p = packet();
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.orient(path);
                    assert!(!e.wants_event(101, &p, 100));
                    assert_eq!(
                        e.preflight(101, &p, 1, 100),
                        Err(Action {
                            token: 1,
                            finish: Finish::Drop
                        })
                    );
                    assert_eq!(
                        e.submit(101, p, 2, None, 100, None),
                        Submission::Finish(Action {
                            token: 2,
                            finish: Finish::Drop
                        })
                    );
                }
            }
        }
        assert_eq!(e.pending_count(), 0);
        assert!(!e.has_events());
        assert_eq!(e.stats().allowed, 0);
    }

    #[test]
    fn default_disconnect_drops_pending_and_clears_prior_allow_cache() {
        let mut e = default_engine();
        let id = submit(&mut e, 101, 1);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_eq!(
            e.preflight(101, &packet(), 1, 102),
            Err(Action {
                token: 1,
                finish: Finish::Allow
            })
        );
        let mut p = packet();
        p.flow.source_port = 12345;
        p.orient(NdisPath::Receive);
        let Submission::Pending(pending) = e.submit(101, p, 2, None, 102, record(&p)) else {
            panic!()
        };
        e.disconnect();
        assert_eq!(e.cache_counts(), (0, 0));
        assert!(!e.has_events());
        assert!(e.verdict(pending, Verdict::PermanentAccept, 103).is_err());
        assert_eq!(
            e.take_due(103),
            Some(Action {
                token: 2,
                finish: Finish::Drop
            })
        );
        assert_eq!(
            e.submit(101, packet(), 3, None, 103, None),
            Submission::Finish(Action {
                token: 3,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        e.connect();
        assert!(e.wants_event(101, &packet(), 104));
    }

    #[test]
    fn default_capture_failure_drops_but_queue_grows_past_16_mib() {
        let mut e = default_engine();
        assert_eq!(
            e.submit(101, packet(), 999, None, 100, None),
            Submission::Finish(Action {
                token: 999,
                finish: Finish::Drop
            })
        );
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        const COUNT: usize = 32;
        for token in 1..=COUNT {
            assert!(matches!(
                e.submit(101, p, token, None, 100, record(&p)),
                Submission::Pending(_)
            ));
        }
        assert!(e.queued_bytes > 16 * 1024 * 1024);
        assert_eq!(e.pending_count(), COUNT);
        let mut count = 0;
        while let Some(action) = e.take_due(8100) {
            assert_eq!(action.finish, Finish::Drop);
            count += 1;
        }
        assert_eq!(count, COUNT);
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.stats().overflow, 1);
        assert_eq!(e.stats().allowed, 0);
        assert_eq!(e.stats().dropped, COUNT as u64 + 1);
    }

    #[test]
    fn default_fail_closed_applies_timely_userspace_verdicts() {
        for verdict in [
            Verdict::Accept,
            Verdict::PermanentAccept,
            Verdict::Block,
            Verdict::PermanentBlock,
            Verdict::Drop,
            Verdict::PermanentDrop,
        ] {
            let mut e = default_engine();
            assert_eq!(e.fallback(), Finish::Drop);
            let id = submit(&mut e, 101, 1);
            assert_eq!(
                e.verdict(id, verdict, 8099),
                Ok(Action {
                    token: 1,
                    finish: if verdict.allows() {
                        Finish::Allow
                    } else {
                        Finish::Drop
                    },
                })
            );
            assert_eq!(e.pending_count(), 0);
            if verdict.permanent() {
                assert_eq!(
                    e.preflight(101, &packet(), 2, 8100),
                    Err(Action {
                        token: 2,
                        finish: if verdict.allows() {
                            Finish::Allow
                        } else {
                            Finish::Drop
                        },
                    })
                );
            } else {
                assert!(e.wants_event(101, &packet(), 8100));
            }
        }
    }

    #[test]
    fn fail_open_requires_an_explicit_configuration_override() {
        let mut e = default_engine();
        assert_eq!(e.fallback(), Finish::Drop);
        e.configure(8000, 60000, false);
        assert_eq!(e.fallback(), Finish::Allow);
        let id = submit(&mut e, 101, 1);
        assert_eq!(
            e.take_due(8100),
            Some(Action {
                token: 1,
                finish: Finish::Allow
            })
        );
        assert!(e.verdict(id, Verdict::PermanentAccept, 8100).is_err());
        submit(&mut e, 101, 2);
        e.disconnect();
        assert_eq!(
            e.take_due(101),
            Some(Action {
                token: 2,
                finish: Finish::Allow
            })
        );
        assert_eq!(
            e.submit(101, packet(), 3, None, 102, None),
            Submission::Finish(Action {
                token: 3,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.cache_counts(), (0, 0));
    }

    #[test]
    fn one_cleanup_run_scans_all_interfaces_protocols_and_families() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    for port in 0..1025 {
                        let mut p = packet();
                        p.flow.protocol = protocol;
                        p.connection.protocol = protocol;
                        p.flow.ipv6 = ipv6;
                        p.connection.ipv6 = ipv6;
                        p.flow.source_port = port;
                        p.orient(NdisPath::Receive);
                        let Submission::Pending(id) =
                            e.submit(interface_index, p, 1, None, 100, record(&p))
                        else {
                            panic!()
                        };
                        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
                        e.read(&mut [0; 512]);
                    }
                }
            }
        }
        assert_eq!(e.cache_candidates(), 2);
        let mut batches = 0;
        let limit = e.cache_cleanup_limit();
        let mut after = 0;
        while let Some((index, slots)) = e.next_cache_candidate(after, limit) {
            after = index;
            assert_eq!(slots, e.cache_cleanup_slots(index));
            assert!(slots > crate::cache::CLEANUP_SLOTS_PER_BATCH);
            for start in (0..slots).step_by(crate::cache::CLEANUP_SLOTS_PER_BATCH) {
                let mut work = CacheWork::empty();
                let active = e.clean_range_with_work(index, start, 60101, &mut work);
                drop(work);
                batches += 1;
                if !active {
                    break;
                }
            }
        }
        assert!(batches > 2);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(e.cache_bytes(), 0);
        assert_eq!(e.cache_cleanup_slots(u32::MAX), 0);
        assert!(!e.clean_range_with_work(u32::MAX, 0, 60101, &mut CacheWork::empty()));
    }

    #[test]
    fn pending_candidates_follow_verdict_timeout_cancel_and_invalidation() {
        let mut e = engine();
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 0);
        assert!(e.take_due(u64::MAX).is_none());
        let first = submit(&mut e, 101, 1);
        let second = submit(&mut e, 101, 2);
        assert_eq!(e.pending_count(), 2);
        e.verdict(first, Verdict::Accept, 101).unwrap();
        assert_eq!(e.pending_count(), 1);
        assert!(e.verdict(first, Verdict::Accept, 101).is_err());
        assert!(e.take_due(2099).is_none());
        assert_eq!(e.take_due(2100).unwrap().token, 2);
        assert_eq!(e.pending_count(), 0);
        assert!(e.verdict(second, Verdict::Accept, 2100).is_err());
        assert!(e.take_due(u64::MAX).is_none());
        let p = packet();
        assert!(matches!(
            e.submit(101, p, 3, Some(42), 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.cancel(101, 42).unwrap().finish, Finish::Cancel);
        assert_eq!(e.pending_count(), 0);
        submit(&mut e, 101, 4);
        assert!(e.cancel(101, 42).is_none());
        assert_eq!(e.pending_count(), 1);
        e.invalidate(101, true);
        assert_eq!(e.take_due(101).unwrap().finish, Finish::Drop);
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn cache_candidates_track_nonempty_interfaces_and_expiry() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            let id = submit(&mut e, interface_index, interface_index as usize);
            e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        }
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 2);
        e.invalidate(101, true);
        assert_eq!(e.cache_candidates(), 1);
        e.clean(1101);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(e.cache_bytes(), 0);
        e.clean(u64::MAX);
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn pending_timeout_does_not_sweep_cache_entries() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        let k = 101;
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        let mut p = packet();
        p.flow.source_port = 123;
        p.orient(NdisPath::Receive);
        let other = k;
        assert!(matches!(
            e.submit(other, p, 2, None, 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.take_due(3000).unwrap().token, 2);
        assert!(e.take_due(3000).is_none());
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_counts(), (1, 0));
        assert_ne!(e.cache_candidates(), 0);
        for _ in 0..4 {
            e.clean(3000);
        }
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn failed_cache_insertion_and_session_reset_disable_cache_candidates() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        let mut bandwidth = BandwidthWork::prepare(e.bandwidth_plan());
        e.verdict_with_work(
            id,
            Verdict::PermanentAccept,
            101,
            &mut CacheWork::empty(),
            &mut bandwidth,
        )
        .unwrap();
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.cache_candidates(), 0);
        assert_eq!(e.stats().cache_allocation_failures, 1);
        let id = submit(&mut e, k, 2);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_ne!(e.cache_candidates(), 0);
        e.clear_cache();
        assert_eq!(e.cache_candidates(), 0);
        let id = submit(&mut e, k, 3);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_ne!(e.cache_candidates(), 0);
        e.disconnect();
        assert_eq!(e.cache_candidates(), 0);
        e.connect();
        assert_eq!(e.cache_candidates(), 0);
    }

    #[test]
    fn connection_indices_follow_each_interface_across_paths_and_slot_reuse() {
        let mut e = engine();
        e.read(&mut [0; 512]);
        assert!(e.attach(0x12345678));
        assert!(e.restart(0x12345678));
        let mut previous_id = 0;
        for interface_index in [101, 0x12345678, 101, 0x87654321, 0x12345678] {
            if interface_index == 0x87654321 {
                e.detach(101);
                assert!(e.attach(interface_index));
                assert!(e.restart(interface_index));
            }
            for ipv6 in [false, true] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut p = packet();
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.orient(path);
                    let token = interface_index as usize;
                    let Submission::Pending(id) =
                        e.submit(interface_index, p, token, None, 100, record(&p))
                    else {
                        panic!("each interface must produce its own event");
                    };
                    assert!(id > previous_id);
                    previous_id = id;
                    let mut bytes = [0; 256];
                    let n = e.read(&mut bytes);
                    assert_eq!(
                        n,
                        connection_header_len(&p.connection) + p.payload_len as usize
                    );
                    assert_eq!(bytes[0], if ipv6 { 2 } else { 1 });
                    assert_eq!(u64::from_le_bytes(bytes[5..13].try_into().unwrap()), id);
                    assert_eq!(
                        u32::from_le_bytes(bytes[13..17].try_into().unwrap()),
                        interface_index
                    );
                    assert_eq!(bytes[17], path.direction() as u8);
                    assert_eq!(e.verdict(id, Verdict::Accept, 101).unwrap().token, token);
                }
            }
        }
    }

    #[test]
    fn permanent_cache_isolates_interface_protocol_and_family_not_direction_or_l2() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            for ipv6 in [false, true] {
                for protocol in [6, 17] {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.source[0] = 10;
                    p.flow.destination[0] = 20;
                    p.flow.source_port = 12345;
                    p.flow.destination_port = 443;
                    p.orient(NdisPath::Receive);
                    let allow = (interface_index == 101) ^ ipv6 ^ (protocol == 6);
                    let Submission::Pending(id) =
                        e.submit(interface_index, p, 11, None, 100, record(&p))
                    else {
                        panic!(
                            "other interface/protocol/family entries must not answer this tuple"
                        );
                    };
                    e.verdict(
                        id,
                        if allow {
                            Verdict::PermanentAccept
                        } else {
                            Verdict::PermanentDrop
                        },
                        101,
                    )
                    .unwrap();
                }
            }
        }
        assert_eq!(e.cache_counts(), (4, 4));
        for interface_index in [101, 102] {
            for ipv6 in [false, true] {
                for protocol in [6, 17] {
                    for path in [NdisPath::Receive, NdisPath::Send] {
                        let mut p = packet();
                        p.flow.protocol = protocol;
                        p.connection.protocol = protocol;
                        p.flow.ipv6 = ipv6;
                        p.connection.ipv6 = ipv6;
                        p.flow.source[0] = 10;
                        p.flow.destination[0] = 20;
                        p.flow.source_port = 12345;
                        p.flow.destination_port = 443;
                        // A different Ethernet/VLAN snapshot never partitions a verdict.
                        p.flow.l2 = [42; 22];
                        p.flow.l2_len = 18;
                        if path == NdisPath::Send {
                            core::mem::swap(&mut p.flow.source, &mut p.flow.destination);
                            core::mem::swap(&mut p.flow.source_port, &mut p.flow.destination_port);
                        }
                        p.orient(path);
                        let allow = (interface_index == 101) ^ ipv6 ^ (protocol == 6);
                        assert_eq!(
                            e.preflight(interface_index, &p, 12, 102),
                            Err(Action {
                                token: 12,
                                finish: if allow { Finish::Allow } else { Finish::Drop },
                            })
                        );
                    }
                }
            }
        }
        assert_eq!(e.cache_counts(), (4, 4));
    }

    #[test]
    fn temporary_verdict_never_caches_and_duplicate_rejected() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        assert_eq!(
            e.verdict(id, Verdict::Accept, 101).unwrap().finish,
            Finish::Allow
        );
        assert_eq!(
            e.verdict(id, Verdict::Drop, 102),
            Err(VerdictError::NotFound)
        );
        let _ = submit(&mut e, k, 2);
    }
    #[test]
    fn timeout_and_disconnect_are_bounded_and_clear_cache() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        assert!(e.take_due(2099).is_none());
        assert_eq!(e.take_due(2100).unwrap().finish, Finish::Allow);
        assert_eq!(
            e.verdict(id, Verdict::Accept, 2100),
            Err(VerdictError::NotFound)
        );
        let _ = submit(&mut e, k, 2);
        e.disconnect();
        assert_eq!(e.take_due(101).unwrap().token, 2);
        assert_eq!(e.pending_count(), 0);
        e.configure(2000, 60000, true);
        e.connect();
        let _ = submit(&mut e, k, 3);
        e.disconnect();
        assert_eq!(e.take_due(102).unwrap().finish, Finish::Drop);
    }
    #[test]
    fn pause_cancels_existing_ids_without_generations_and_restart_accepts_new_ids() {
        let mut e = engine();
        let old = submit(&mut e, 101, 1);
        e.invalidate(101, true);
        assert!(e.cache_plan(old, Verdict::PermanentAccept, 101).is_none());
        assert_eq!(
            e.verdict(old, Verdict::PermanentAccept, 101),
            Err(VerdictError::NotFound)
        );
        assert_eq!(
            e.preflight(101, &packet(), 9, 101),
            Err(Action {
                token: 9,
                finish: Finish::Drop
            })
        );
        assert!(e.restart(101));
        let new = submit(&mut e, 101, 2);
        assert_ne!(old, new);
        // Even restart-before-drain cannot resurrect the old ID on the same index.
        assert!(e.verdict(old, Verdict::PermanentAccept, 101).is_err());
        assert_eq!(
            e.take_due(101),
            Some(Action {
                token: 1,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 1);
        assert_eq!(e.verdict(new, Verdict::Accept, 101).unwrap().token, 2);
        assert_eq!(e.cache_counts(), (0, 0));
    }

    #[test]
    fn cancellation_and_event_slot_reuse_do_not_expose_stale_ids() {
        let mut e = engine();
        let p = packet();
        let Submission::Pending(old) = e.submit(101, p, 1, Some(42), 100, record(&p)) else {
            panic!()
        };
        assert_eq!(e.cancel(101, 42).unwrap().finish, Finish::Cancel);
        let new = submit(&mut e, 101, 2);
        assert_ne!(old, new);
        assert!(e.verdict(old, Verdict::PermanentAccept, 101).is_err());
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        let mut i = 0;
        let mut seen = 0;
        while i < n {
            let len = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap()) as usize;
            if matches!(b[i], 1 | 2) {
                assert_eq!(
                    u64::from_le_bytes(b[i + 5..i + 13].try_into().unwrap()),
                    new
                );
                seen += 1;
            }
            i += 5 + len;
        }
        assert_eq!(seen, 1);
    }

    #[test]
    fn cancel_send_is_interface_scoped_and_does_not_claim_receive_ownership() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        let mut p = packet();
        p.orient(NdisPath::Receive);
        assert!(matches!(
            e.submit(101, p, 1, None, 100, record(&p)),
            Submission::Pending(_)
        ));
        p.orient(NdisPath::Send);
        assert!(matches!(
            e.submit(101, p, 2, Some(0), 100, record(&p)),
            Submission::Pending(_)
        ));
        assert!(matches!(
            e.submit(102, p, 3, Some(0), 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.cancel(101, 0).unwrap().token, 2);
        assert!(e.cancel(101, 0).is_none());
        assert_eq!(e.pending_count(), 2);
        assert_eq!(e.cancel(102, 0).unwrap().token, 3);
        assert_eq!(e.pending_count(), 1);
        e.disconnect();
        assert_eq!(e.take_due(101).unwrap().token, 1);
    }

    #[test]
    fn partial_reads_remain_a_valid_stream_after_timeout() {
        let mut e = engine();
        let k = 101;
        let _ = submit(&mut e, k, 1);
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        assert!(n > 40);
        let id = submit(&mut e, k, 2);
        let mut prefix = [0; 3];
        assert_eq!(e.read(&mut prefix), 3);
        e.take_due(2100);
        let n = e.read(&mut b);
        assert_eq!(prefix[0], 1);
        assert_eq!(n, 133);
        assert_eq!(u64::from_le_bytes(b[2..10].try_into().unwrap()), id);
    }
    #[test]
    fn queue_accounting_overflow_falls_back_without_losing_owned_token() {
        for fail_closed in [false, true] {
            let mut e = engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            e.configure(2000, 60000, fail_closed);
            let p = packet();
            e.queued_bytes = usize::MAX;
            assert!(!e.wants_event(101, &p, 100));
            assert_eq!(
                e.submit(101, p, 999, None, 100, record(&p)),
                Submission::Finish(Action {
                    token: 999,
                    finish: e.fallback()
                })
            );
            assert_eq!(e.queued_bytes, usize::MAX);
            assert_eq!(e.pending_count(), 0);
            assert!(e.events.is_empty());
            assert_eq!(e.stats().overflow, 1);
            e.queued_bytes = 0;
        }
    }

    #[test]
    fn maximum_packets_survive_chunked_reads_and_timeout_without_truncation() {
        for ipv6 in [false, true] {
            let mut e = engine();
            assert!(e.read(&mut [0; MAX_LOG_RECORD]) > 0);
            let k = 101;
            let mut p = packet();
            p.connection.ipv6 = ipv6;
            p.payload_len = MAX_PAYLOAD as u32;
            p.ip_len = u64::from(p.payload_len);
            p.cacheable = false;
            let prefix = connection_header_len(&p.connection);
            let mut data = record(&p).unwrap();
            for (i, byte) in data[prefix..].iter_mut().enumerate() {
                *byte = (i % 251) as u8;
            }
            let Submission::Pending(id) = e.submit(k, p, 7, None, 100, Some(data)) else {
                panic!("expected full-packet event");
            };
            assert_eq!(e.queued_bytes, prefix + MAX_PAYLOAD);
            let mut chunk = vec![0; 65536];
            let mut received = Vec::new();
            assert_eq!(e.read(&mut chunk), chunk.len());
            received.extend_from_slice(&chunk);
            assert_eq!(e.take_due(2100).unwrap().token, 7);
            loop {
                let n = e.read(&mut chunk);
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(received.len(), prefix + MAX_PAYLOAD);
            assert_eq!(u64::from_le_bytes(received[5..13].try_into().unwrap()), id);
            assert_eq!(
                u32::from_le_bytes(received[13..17].try_into().unwrap()),
                101
            );
            assert_eq!(received[17], 0);
            assert_eq!(
                u32::from_le_bytes(received[prefix - 4..prefix].try_into().unwrap()) as usize,
                MAX_PAYLOAD
            );
            assert!(
                received[prefix..]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == (i % 251) as u8)
            );
            assert_eq!(e.queued_bytes, 0);
            assert!(e.events.is_empty());
            assert_eq!(e.pending_count(), 0);
        }
    }
    #[test]
    fn unread_expired_full_packet_releases_its_queue_bytes() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let k = 101;
        let mut p = packet();
        p.payload_len = 70000;
        let _ = e.submit(k, p, 9, None, 100, record(&p));
        assert!(e.queued_bytes > 65536);
        assert_eq!(e.take_due(2100).unwrap().token, 9);
        assert_eq!(e.read(&mut [0; 16]), 0);
        assert_eq!(e.queued_bytes, 0);
        assert!(e.events.is_empty());
    }
    #[test]
    fn event_queue_exceeds_16_mib_and_disconnect_retires_all_records() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        p.cacheable = false;
        let size = connection_header_len(&p.connection) + MAX_PAYLOAD;
        const COUNT: usize = 32;
        for token in 1..=COUNT {
            assert!(e.wants_event(101, &p, 100));
            assert!(matches!(
                e.submit(101, p, token, None, 100, record(&p)),
                Submission::Pending(_)
            ));
        }
        assert!(e.wants_event(101, &p, 100));
        assert_eq!(e.queued_bytes, COUNT * size);
        assert!(e.queued_bytes > 16 * 1024 * 1024);
        assert_eq!(e.stats().overflow, 0);
        e.disconnect();
        assert_eq!(e.queued_bytes, 0);
        assert!(e.events.is_empty());
        let retired = e.take_retired_storage().unwrap();
        assert_eq!(retired._events.len(), COUNT);
        drop(retired);
        let mut released = 0;
        while e.take_due(101).is_some() {
            released += 1;
        }
        assert_eq!(released, COUNT);
    }
    #[test]
    fn read_above_64_kib_coalesces_complete_records_without_truncation() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        let size = connection_header_len(&p.connection) + MAX_PAYLOAD;
        let mut ids = Vec::new();
        for token in 1..=2 {
            let Submission::Pending(id) = e.submit(101, p, token, None, 100, record(&p)) else {
                panic!("full packet must be queued");
            };
            ids.push(id);
        }
        let mut out = vec![0; 2 * size];
        assert_eq!(e.read(&mut out), out.len());
        for (frame, id) in out.chunks_exact(size).zip(ids) {
            assert_eq!(u64::from_le_bytes(frame[5..13].try_into().unwrap()), id);
            assert_eq!(
                u32::from_le_bytes(frame[32..36].try_into().unwrap()),
                MAX_PAYLOAD as u32
            );
            assert_eq!(
                e.verdict(id, Verdict::Accept, 101).unwrap().finish,
                Finish::Allow
            );
        }
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.pending_count(), 0);
    }
    #[test]
    fn bandwidth_preserves_a_batch_above_u32_max() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let mut p = packet();
        p.ip_len = u64::from(u32::MAX) + 123;
        e.bandwidth_add(101, &p);
        e.bandwidth();
        let mut out = [0; 128];
        let len = e.read(&mut out);
        assert_eq!(out[0], 5);
        assert_eq!(
            u64::from_le_bytes(out[len - 16..len - 8].try_into().unwrap()),
            p.ip_len
        );
        assert_eq!(u64::from_le_bytes(out[len - 8..len].try_into().unwrap()), 0);
    }

    #[test]
    fn missing_capture_uses_fallback_without_publishing_a_short_packet() {
        for fail_closed in [false, true] {
            let mut e = engine();
            e.read(&mut [0; MAX_LOG_RECORD]);
            e.configure(2000, 60000, fail_closed);
            let k = 101;
            assert_eq!(
                e.submit(k, packet(), 77, None, 100, None),
                Submission::Finish(Action {
                    token: 77,
                    finish: if fail_closed {
                        Finish::Drop
                    } else {
                        Finish::Allow
                    },
                })
            );
            assert_eq!(e.pending_count(), 0);
            assert_eq!(e.queued_bytes, 0);
            assert_eq!(e.stats().overflow, 1);
            assert_eq!(e.stats().malformed, 0);
        }
    }
    #[test]
    fn truncated_capture_is_dropped_not_encoded_as_a_complete_packet() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let k = 101;
        let p = packet();
        let mut data = record(&p).unwrap();
        data.pop();
        assert_eq!(
            e.submit(k, p, 88, None, 100, Some(data)),
            Submission::Finish(Action {
                token: 88,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.stats().malformed, 1);
    }
    #[test]
    fn allocation_preflight_does_not_bypass_disconnect_or_invalidation() {
        let mut e = engine();
        let k = 101;
        let p = packet();
        assert!(e.wants_event(k, &p, 100));
        let data = record(&p);
        e.disconnect();
        assert_eq!(
            e.submit(k, p, 1, None, 100, data),
            Submission::Finish(Action {
                token: 1,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.queued_bytes, 0);
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        assert!(e.wants_event(k, &p, 100));
        let data = record(&p);
        e.invalidate(101, true);
        assert_eq!(
            e.submit(k, p, 2, None, 100, data),
            Submission::Finish(Action {
                token: 2,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.pending_count(), 0);
    }
    #[test]
    fn read_readiness_tracks_partial_reads_and_disconnect() {
        let mut engine = Box::new(Engine::new());
        assert!(!engine.is_online() && !engine.has_events());
        engine.connect();
        assert!(engine.is_online() && engine.has_events());
        assert_eq!(engine.read(&mut []), 0);
        assert!(engine.has_events());
        assert_eq!(engine.read(&mut [0; 1]), 1);
        assert!(engine.has_events());
        while engine.read(&mut [0; 512]) != 0 {}
        assert!(!engine.has_events() && engine.is_online());
        engine.log(3, "queued");
        assert!(engine.has_events());
        engine.disconnect();
        assert!(!engine.has_events() && !engine.is_online());
        engine.log(3, "offline");
        assert!(!engine.has_events());
    }
    #[test]
    fn pending_metadata_does_not_contain_packet_sized_arrays() {
        assert!(core::mem::size_of::<Packet>() < 256);
        assert!(core::mem::size_of::<Pending>() < 512);
        assert!(core::mem::size_of::<Engine>() < 512 * 1024);
        assert!(allocate_record(MAX_RECORD + 1).is_none());
    }
    #[test]
    fn uncacheable_fragments_always_request_even_permanent() {
        let mut e = engine();
        let k = 101;
        let mut p = packet();
        p.cacheable = false;
        let Submission::Pending(id) = e.submit(k, p, 1, None, 0, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::PermanentAccept, 1).unwrap();
        assert!(matches!(
            e.submit(k, p, 2, None, 2, record(&p)),
            Submission::Pending(_)
        ));
    }
    #[test]
    fn permanent_accept_ttl_refreshes_on_matching_inbound_and_outbound_packets() {
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                let mut e = engine();
                e.configure(2000, 1000, false);
                let mut guest = [0; 16];
                let mut peer = [0; 16];
                if ipv6 {
                    guest = [0x11; 16];
                    peer = [0x22; 16];
                } else {
                    guest[..4].copy_from_slice(&[10, 0, 0, 2]);
                    peer[..4].copy_from_slice(&[192, 0, 2, 1]);
                }
                let mut outbound = packet();
                outbound.flow.protocol = protocol;
                outbound.connection.protocol = protocol;
                outbound.flow.ipv6 = ipv6;
                outbound.connection.ipv6 = ipv6;
                outbound.flow.source = guest;
                outbound.flow.destination = peer;
                outbound.flow.source_port = 40000;
                outbound.flow.destination_port = 443;
                // Host receive is guest outbound.
                outbound.orient(NdisPath::Receive);

                let mut inbound = outbound;
                inbound.flow.source = peer;
                inbound.flow.destination = guest;
                inbound.flow.source_port = 443;
                inbound.flow.destination_port = 40000;
                // Host send is guest inbound and must normalize to the same tuple.
                inbound.orient(NdisPath::Send);

                let k = 101;
                let Submission::Pending(id) =
                    e.submit(k, outbound, 1, None, 100, record(&outbound))
                else {
                    panic!("expected initial decision");
                };
                e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                e.read(&mut [0; 512]);

                for (token, p, now) in [
                    (2, inbound, 1100),
                    (3, outbound, 2099),
                    (4, inbound, 3098),
                    (5, outbound, 4097),
                ] {
                    assert!(!e.wants_event(k, &p, now));
                    let action = e.preflight(k, &p, token, now).unwrap_err();
                    assert_eq!(
                        action,
                        Action {
                            token,
                            finish: Finish::Allow,
                        }
                    );
                }
                assert_eq!(e.stats().cache_hits, 4);
                assert!(e.wants_event(k, &inbound, 5097));
            }
        }
    }

    #[test]
    fn permanent_accept_tcp_udp_ttl_tracks_last_cache_hit() {
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut e = engine();
                    e.configure(2000, 1000, false);
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.orient(path);
                    let k = 101;
                    let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                        panic!("expected initial decision");
                    };
                    e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                    e.read(&mut [0; 512]);
                    for (token, now) in [(2, 1100), (3, 2099), (4, 3098)] {
                        e.clean(now);
                        assert!(!e.wants_event(k, &p, now));
                        assert_eq!(
                            e.submit(k, p, token, None, now, None),
                            Submission::Finish(Action {
                                token,
                                finish: Finish::Allow
                            })
                        );
                    }
                    assert_eq!(e.stats().cache_hits, 3);
                    assert_eq!(e.stats().queued, 1);
                    assert_eq!(e.pending_count(), 0);
                    assert!(!e.has_events());
                    assert!(!e.wants_event(k, &p, 4097));
                    e.clean(4098);
                    assert!(e.wants_event(k, &p, 4098));
                    assert!(matches!(
                        e.submit(k, p, 5, None, 4098, record(&p)),
                        Submission::Pending(_)
                    ));
                }
            }
        }
    }
    #[test]
    fn preflight_and_uncacheable_packets_do_not_refresh_accept_ttl() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        let p = packet();
        let k = 101;
        let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
            panic!();
        };
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert!(!e.wants_event(k, &p, 1100));
        assert_eq!(e.stats().cache_hits, 0);
        let mut uncacheable = p;
        uncacheable.cacheable = false;
        assert!(e.wants_event(k, &uncacheable, 1100));
        let Submission::Pending(id) = e.submit(k, uncacheable, 2, None, 1100, record(&uncacheable))
        else {
            panic!("uncacheable traffic must still request a verdict");
        };
        e.verdict(id, Verdict::PermanentAccept, 1100).unwrap();
        assert_eq!(e.stats().cache_hits, 0);
        assert!(e.wants_event(k, &p, 1101));
        assert!(matches!(
            e.submit(k, p, 3, None, 1101, record(&p)),
            Submission::Pending(_)
        ));
    }
    #[test]
    fn cache_activity_refreshes_only_matching_tuple_interface_protocol_and_family() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        assert!(e.attach(102));
        assert!(e.restart(102));
        let p = packet();
        for variant in 0..7 {
            e.clear_cache();
            let mut other = p;
            let interface_index = if variant == 0 { 102 } else { 101 };
            match variant {
                0 => {}
                1 => other.flow.source_port = 1234,
                2 => other.flow.destination_port = 53,
                3 => other.flow.source = [1; 16],
                4 => other.flow.destination = [2; 16],
                5 => {
                    other.flow.protocol = 6;
                    other.connection.protocol = 6;
                }
                6 => {
                    other.flow.ipv6 = true;
                    other.connection.ipv6 = true;
                }
                _ => unreachable!(),
            }
            other.orient(NdisPath::Receive);
            for (index, packet) in [(101, p), (interface_index, other)] {
                let Submission::Pending(id) =
                    e.submit(index, packet, 1, None, 100, record(&packet))
                else {
                    panic!()
                };
                e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            }
            e.read(&mut [0; 512]);
            assert_eq!(
                e.submit(101, p, 2, None, 1100, None),
                Submission::Finish(Action {
                    token: 2,
                    finish: Finish::Allow
                })
            );
            e.clean(1101);
            assert!(!e.wants_event(101, &p, 1101));
            assert!(e.wants_event(interface_index, &other, 1101));
        }
    }

    #[test]
    fn expired_accept_is_not_revived_by_new_traffic() {
        for sweep in [false, true] {
            let mut e = engine();
            e.configure(2000, 1000, false);
            let p = packet();
            let k = 101;
            let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                panic!();
            };
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
            if sweep {
                e.clean(1101);
            }
            assert!(e.wants_event(k, &p, 1101));
            let Submission::Pending(id) = e.submit(k, p, 2, None, 1101, record(&p)) else {
                panic!("expired cache entry must require a new verdict");
            };
            assert_eq!(e.stats().cache_hits, 0);
            e.verdict(id, Verdict::PermanentAccept, 1102).unwrap();
            assert!(!e.wants_event(k, &p, 2101));
            assert!(e.wants_event(k, &p, 2102));
        }
    }
    #[test]
    fn accept_ttl_refresh_saturates_instead_of_wrapping() {
        let mut e = engine();
        e.configure(2000, 1000, false);
        let p = packet();
        let k = 101;
        let now = u64::MAX - 1500;
        let Submission::Pending(id) = e.submit(k, p, 1, None, now, record(&p)) else {
            panic!();
        };
        e.verdict(id, Verdict::PermanentAccept, now + 1).unwrap();
        assert!(matches!(
            e.submit(k, p, 2, None, u64::MAX - 600, None),
            Submission::Finish(Action {
                finish: Finish::Allow,
                ..
            })
        ));
        assert!(!e.wants_event(k, &p, u64::MAX - 1));
        assert!(e.wants_event(k, &p, u64::MAX));
    }
    #[test]
    fn ttl_expiry_requires_a_new_decision() {
        for verdict in [Verdict::PermanentBlock, Verdict::PermanentDrop] {
            for protocol in [6, 17] {
                let mut e = engine();
                let mut p = packet();
                p.flow.protocol = protocol;
                p.connection.protocol = protocol;
                let k = 101;
                let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                    panic!();
                };
                e.verdict(id, verdict, 101).unwrap();
                assert!(matches!(
                    e.submit(k, p, 2, None, 60100, None),
                    Submission::Finish(Action {
                        finish: Finish::Drop,
                        ..
                    })
                ));
                assert!(matches!(
                    e.submit(k, p, 3, None, 60101, record(&p)),
                    Submission::Pending(_)
                ));
            }
        }
    }
    #[test]
    fn invalidation_clears_only_that_interface_bank_and_reclaims_all_four_caches() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        for interface_index in [101, 102] {
            for protocol in [6, 17] {
                for ipv6 in [false, true] {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    let Submission::Pending(id) =
                        e.submit(interface_index, p, 1, None, 100, record(&p))
                    else {
                        panic!()
                    };
                    e.verdict(
                        id,
                        if interface_index == 101 {
                            Verdict::PermanentAccept
                        } else {
                            Verdict::PermanentDrop
                        },
                        101,
                    )
                    .unwrap();
                }
            }
        }
        assert_eq!(e.cache_counts(), (4, 4));
        e.invalidate(101, false);
        assert_eq!(e.preflight(101, &packet(), 2, 102), Ok(true));
        assert_eq!(
            e.preflight(102, &packet(), 3, 102),
            Err(Action {
                token: 3,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.cache_counts(), (2, 2));
        let retired = e.take_retired_caches().unwrap();
        assert_eq!(retired.counts(), (2, 2));
        assert!(retired.bytes() > 0);
        drop(retired);
        assert!(e.take_retired_caches().is_none());
        assert_eq!(e.preflight(101, &packet(), 4, 102), Ok(true));
        assert_eq!(
            e.preflight(102, &packet(), 5, 102),
            Err(Action {
                token: 5,
                finish: Finish::Drop
            })
        );
    }

    #[test]
    fn only_tcp_udp_can_create_or_consume_permanent_cache() {
        for ipv6 in [false, true] {
            for protocol in [0, 1, 2, 47, 50, 58, 255] {
                for verdict in [
                    Verdict::PermanentAccept,
                    Verdict::PermanentBlock,
                    Verdict::PermanentDrop,
                ] {
                    let mut e = engine();
                    let mut p = packet();
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    // Deliberately set cacheable: the engine enforces TCP/UDP too.
                    let k = 101;
                    let Submission::Pending(id) = e.submit(k, p, 1, None, 100, record(&p)) else {
                        panic!();
                    };
                    assert!(e.cache_plan(id, verdict, 101).is_none());
                    e.verdict(id, verdict, 101).unwrap();
                    assert_eq!(e.cache_counts(), (0, 0));
                    assert_eq!(e.cache_bytes(), 0);
                    assert_eq!(e.preflight(k, &p, 2, 102), Ok(true));
                    assert!(matches!(
                        e.submit(k, p, 2, None, 102, record(&p)),
                        Submission::Pending(_)
                    ));
                    assert_eq!(e.stats().cache_hits, 0);
                }
            }
        }
    }
    #[test]
    fn dynamic_cache_keeps_more_than_1024_verdicts_per_protocol_and_family() {
        let mut e = engine();
        e.read(&mut [0; 512]);
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                for n in 0..1536u32 {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.source[..4].copy_from_slice(&n.to_le_bytes());
                    p.orient(NdisPath::Receive);
                    let Submission::Pending(id) = e.submit(101, p, 1, None, 100, record(&p)) else {
                        panic!()
                    };
                    e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
                    e.read(&mut [0; 256]);
                }
            }
        }
        assert_eq!(e.cache_counts(), (3072, 3072));
        for protocol in [6, 17] {
            for ipv6 in [false, true] {
                for n in 0..1536u32 {
                    let mut p = packet();
                    p.flow.protocol = protocol;
                    p.connection.protocol = protocol;
                    p.flow.ipv6 = ipv6;
                    p.connection.ipv6 = ipv6;
                    p.flow.source[..4].copy_from_slice(&n.to_le_bytes());
                    p.orient(NdisPath::Receive);
                    assert_eq!(
                        e.preflight(101, &p, 2, 102),
                        Err(Action {
                            token: 2,
                            finish: Finish::Allow
                        })
                    );
                }
            }
        }
        assert_eq!(e.stats().cache_hits, 6144);
        assert_eq!(e.stats().received, 12288);
        assert_eq!(e.stats().cache_allocation_failures, 0);
    }

    #[test]
    fn reused_interface_index_starts_with_empty_caches() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        e.invalidate(101, false);
        let k = 101;
        let id = submit(&mut e, k, 2);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        assert_eq!(
            e.preflight(k, &packet(), 3, 102),
            Err(Action {
                token: 3,
                finish: Finish::Allow
            })
        );
        e.detach(101);
        assert!(e.attach(101));
        assert!(e.restart(101));
        let k = 101;
        assert_eq!(e.preflight(k, &packet(), 4, 102), Ok(true));
        e.clear_cache();
        e.clean(102);
        assert_eq!(e.cache_bytes(), 0);
    }
    #[test]
    fn cache_allocation_failure_does_not_change_current_packet_verdict() {
        unsafe fn fail(_: usize) -> *mut u8 {
            core::ptr::null_mut()
        }
        unsafe fn free(_: *mut u8, _: usize) {
            panic!("no allocation should exist");
        }
        for verdict in [
            Verdict::PermanentAccept,
            Verdict::PermanentBlock,
            Verdict::PermanentDrop,
        ] {
            let allocator = unsafe { CacheAllocator::new(fail, free) };
            let mut e = Box::new(Engine::with_cache_allocator(allocator));
            assert!(e.attach(101));
            assert!(e.restart(101));
            e.connect();
            let k = 101;
            let id = submit(&mut e, k, 1);
            let action = e.verdict(id, verdict, 101).unwrap();
            assert_eq!(
                action.finish,
                if verdict.allows() {
                    Finish::Allow
                } else {
                    Finish::Drop
                }
            );
            assert_eq!(e.cache_bytes(), 0);
            assert_eq!(e.stats().cache_allocation_failures, 1);
            assert_eq!(e.preflight(k, &packet(), 2, 102), Ok(true));
        }
    }
    #[test]
    fn cache_ignores_ethernet_but_separates_protocol_and_interface() {
        let mut e = engine();
        let id = submit(&mut e, 101, 1);
        e.verdict(id, Verdict::PermanentAccept, 101).unwrap();
        let mut p = packet();
        p.flow.l2 = [42; 22];
        p.flow.l2_len = 14;
        assert_eq!(
            e.preflight(101, &p, 2, 102),
            Err(Action {
                token: 2,
                finish: Finish::Allow
            })
        );
        p.flow.protocol = 6;
        p.connection.protocol = 6;
        assert_eq!(e.preflight(101, &p, 3, 102), Ok(true));
        let Submission::Pending(id) = e.submit(101, p, 3, None, 102, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::PermanentDrop, 103).unwrap();
        assert_eq!(
            e.preflight(101, &p, 4, 104),
            Err(Action {
                token: 4,
                finish: Finish::Drop
            })
        );
        assert_eq!(
            e.preflight(101, &packet(), 5, 104),
            Err(Action {
                token: 5,
                finish: Finish::Allow
            })
        );
        assert!(e.attach(102));
        assert!(e.restart(102));
        assert_eq!(e.preflight(102, &p, 6, 104), Ok(true));
    }

    #[test]
    fn bandwidth_combines_guest_normalized_tx_and_rx() {
        let mut e = engine();
        let k = 101;
        let tx = packet();
        let mut rx = tx;
        rx.orient(NdisPath::Send);
        rx.ip_len = 75;
        let Submission::Pending(id) = e.submit(k, tx, 1, None, 100, record(&tx)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 101).unwrap();
        let inbound = k;
        let Submission::Pending(id) = e.submit(inbound, rx, 2, None, 102, record(&rx)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 103).unwrap();
        e.bandwidth();
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        let mut i = 0;
        let mut seen = 0;
        while i < n {
            let len = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap()) as usize;
            if b[i] == 5 {
                assert_eq!(
                    u64::from_le_bytes(b[i + 26..i + 34].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(b[i + 34..i + 42].try_into().unwrap()),
                    75
                );
                seen += 1;
            }
            i += 5 + len;
        }
        assert_eq!(seen, 1);
    }
    #[test]
    fn bandwidth_counts_admitted_bytes_and_reports_the_interface_index() {
        let mut e = engine();
        let k = 101;
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::Accept, 101).unwrap();
        e.bandwidth();
        let mut b = [0; 2048];
        let n = e.read(&mut b);
        let mut i = 0;
        let mut seen = false;
        while i < n {
            let len = u32::from_le_bytes(b[i + 1..i + 5].try_into().unwrap()) as usize;
            if b[i] == 5 {
                assert_eq!(len, 37);
                assert_eq!(u32::from_le_bytes(b[i + 6..i + 10].try_into().unwrap()), k);
                seen = true;
                assert_eq!(
                    u64::from_le_bytes(b[i + 26..i + 34].try_into().unwrap()),
                    100
                );
            }
            i += 5 + len;
        }
        assert!(seen);
    }

    #[test]
    fn interface_indices_are_unique_nonzero_and_have_no_slot_count_limit() {
        let mut e = Box::new(Engine::new());
        assert!(!e.attach(0));
        assert!(!e.restart(0));
        for index in (1..=129).chain([u32::MAX]) {
            assert!(e.attach(index));
            assert!(e.restart(index));
            assert!(!e.attach(index));
        }
        assert_eq!(e.interfaces.len(), 130);
        assert!(e.attach(1000));
        e.detach(1);
        assert!(e.attach(1));
        assert!(e.restart(1));
        e.detach(1000);
        assert!(!e.restart(1000));
    }

    #[test]
    fn reused_index_does_not_revive_pending_ids_or_invalidate_other_interfaces() {
        let mut e = engine();
        assert!(e.attach(102));
        assert!(e.restart(102));
        let old = submit(&mut e, 101, 1);
        let other = submit(&mut e, 102, 2);
        let mut work = CacheWork::prepare(e.cache_plan(old, Verdict::PermanentAccept, 101));
        e.detach(101);
        assert!(e.attach(101));
        assert!(e.restart(101));
        let new = submit(&mut e, 101, 3);
        assert!(
            e.verdict_with_work(
                old,
                Verdict::PermanentAccept,
                101,
                &mut work,
                &mut BandwidthWork::empty()
            )
            .is_err()
        );
        assert_eq!(e.cache_counts(), (0, 0));
        assert_eq!(
            e.take_due(101),
            Some(Action {
                token: 1,
                finish: Finish::Drop
            })
        );
        assert!(e.take_due(101).is_none());
        assert_eq!(
            e.verdict(other, Verdict::PermanentDrop, 101).unwrap().token,
            2
        );
        assert_eq!(
            e.verdict(new, Verdict::PermanentAccept, 101).unwrap().token,
            3
        );
        assert_eq!(e.stats().invalidated, 1);
        assert_eq!(e.cache_counts(), (2, 0));
    }
}
