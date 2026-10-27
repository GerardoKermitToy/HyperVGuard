use crate::{
    cache::{CacheAllocator, CachePlan, CacheWork, Caches, Decision},
    packet::Packet,
};
use alloc::vec::Vec;
use core::fmt::{self, Write};
use hyperv_protocol::{
    Connection, Direction, MAX_LOG_RECORD, MAX_PAYLOAD, MAX_RECORD, Verdict, connection_header_len,
    encode_bandwidth, encode_connection_header, encode_log,
};

pub const MAX_PENDING: usize = 256;
pub const MAX_EVENTS: usize = 512;
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ADAPTERS: usize = hyperv_protocol::ADAPTER_INFO_MAX_ADAPTERS;
const _: () = assert!(MAX_ADAPTERS <= u32::BITS as usize);
const MAX_BANDWIDTH: usize = 256;
const NO_SLOT: u16 = u16::MAX;

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
    caches: Caches,
}
impl Interface {
    const fn empty() -> Self {
        Self {
            interface_index: 0,
            running: false,
            dirty: false,
            caches: Caches::global(),
        }
    }
}
#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    token: usize,
    cancel: Option<usize>,
    deadline: u64,
    interface_index: u32,
    invalidated: bool,
    packet: Packet,
}
impl Pending {
    const EMPTY: Self = Self {
        id: 0,
        token: 0,
        cancel: None,
        deadline: 0,
        interface_index: 0,
        invalidated: false,
        packet: Packet::EMPTY,
    };
}
struct Event {
    read: usize,
    slot: u16,
    id: u64,
    data: Vec<u8>,
}
impl Event {
    const EMPTY: Self = Self {
        read: 0,
        slot: NO_SLOT,
        id: 0,
        data: Vec::new(),
    };
}

// Only fallible allocation is used. In the driver the allocator enforces a
// separate 16 MiB nonpaged budget, including records not yet in the event queue.
pub fn allocate_record(len: usize) -> Option<Vec<u8>> {
    if len > MAX_RECORD {
        return None;
    }
    let mut data = Vec::new();
    data.try_reserve_exact(len).ok()?;
    data.resize(len, 0);
    Some(data)
}
#[derive(Clone, Copy)]
struct Bandwidth {
    active: bool,
    connection: Connection,
    tx: u64,
    rx: u64,
}
impl Bandwidth {
    const EMPTY: Self = Self {
        active: false,
        connection: Connection::EMPTY,
        tx: 0,
        rx: 0,
    };
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

// Packet metadata is fixed-size; records have a separate bounded allocator.
// Cache growth/zeroing and retired-table frees happen OUTSIDE the policy lock.
pub struct Engine {
    pending: [Pending; MAX_PENDING],
    pending_count: usize,
    interfaces: [Interface; MAX_ADAPTERS],
    cache_candidates: u32,
    cache_allocator: CacheAllocator,
    events: [Event; MAX_EVENTS],
    bandwidth: [Bandwidth; MAX_BANDWIDTH],
    head: usize,
    count: usize,
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
            pending: [Pending::EMPTY; MAX_PENDING],
            pending_count: 0,
            interfaces: [const { Interface::empty() }; MAX_ADAPTERS],
            cache_candidates: 0,
            cache_allocator: allocator,
            events: [const { Event::EMPTY }; MAX_EVENTS],
            bandwidth: [Bandwidth::EMPTY; MAX_BANDWIDTH],
            head: 0,
            count: 0,
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
        self.count != 0
    }
    pub fn is_online(&self) -> bool {
        self.online
    }
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }
    pub fn cache_candidates(&self) -> u32 {
        self.cache_candidates
    }
    fn update_cache_candidates(&mut self, slot: usize) {
        let interface = &self.interfaces[slot];
        let bit = 1 << slot;
        if !interface.dirty && interface.caches.has_entries() {
            self.cache_candidates |= bit;
        } else {
            self.cache_candidates &= !bit;
        }
    }
    fn clear_events(&mut self) {
        for event in &mut self.events {
            *event = Event::EMPTY;
        }
        self.head = 0;
        self.count = 0;
        self.queued_bytes = 0;
    }
    fn has_room(&self, len: usize) -> bool {
        self.count < MAX_EVENTS && len <= MAX_EVENT_BYTES - self.queued_bytes
    }
    fn push_event(&mut self, data: Vec<u8>, slot: u16, id: u64) {
        self.queued_bytes += data.len();
        self.events[(self.head + self.count) % MAX_EVENTS] = Event {
            read: 0,
            slot,
            id,
            data,
        };
        self.count += 1;
    }
    fn pop_event(&mut self) {
        self.queued_bytes -= self.events[self.head].data.len();
        self.events[self.head] = Event::EMPTY;
        self.head = (self.head + 1) % MAX_EVENTS;
        self.count -= 1;
    }
    pub fn connect(&mut self) {
        self.online = true;
        self.clear_events();
        self.clear_cache();
        self.bandwidth.fill(Bandwidth::EMPTY);
        self.log(3, "HyperVXNdisFilter LWF: full IP packets; no process ID; direction=0 outbound/1 inbound from guest side (host receive/send); no TID, redirects, UpdateV4/V6 or synthetic END");
    }
    // Complete actions using take_due() after dropping the lock.
    pub fn disconnect(&mut self) {
        self.online = false;
        self.clear_events();
        self.clear_cache();
        self.bandwidth.fill(Bandwidth::EMPTY);
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
        let Some(slot) = self.interfaces.iter().position(|s| s.interface_index == 0) else {
            return false;
        };
        let interface = &mut self.interfaces[slot];
        interface.interface_index = interface_index;
        interface.running = false;
        interface.dirty = interface.caches.bytes() != 0;
        if !interface.dirty {
            interface.caches = Caches::new(self.cache_allocator);
        }
        self.cache_candidates &= !(1 << slot);
        true
    }
    pub fn restart(&mut self, interface_index: u32) -> bool {
        if let Some(s) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index && interface_index != 0)
        {
            s.running = true;
            true
        } else {
            false
        }
    }
    pub fn invalidate(&mut self, interface_index: u32, pause: bool) {
        if let Some(slot) = self
            .interfaces
            .iter()
            .position(|s| s.interface_index == interface_index && interface_index != 0)
        {
            let interface = &mut self.interfaces[slot];
            interface.dirty = interface.caches.bytes() != 0;
            self.cache_candidates &= !(1 << slot);
            if pause {
                interface.running = false;
            }
            // A restart or reuse of the same index must not revive these IDs.
            for pending in &mut self.pending {
                if pending.id != 0 && pending.interface_index == interface_index {
                    pending.invalidated = true;
                }
            }
        }
    }
    pub fn detach(&mut self, interface_index: u32) {
        self.invalidate(interface_index, true);
        if let Some(s) = self
            .interfaces
            .iter_mut()
            .find(|s| s.interface_index == interface_index)
        {
            s.interface_index = 0;
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
        self.cache_candidates = 0;
        for interface in &mut self.interfaces {
            interface.dirty = interface.caches.bytes() != 0;
        }
    }
    pub fn take_retired_caches(&mut self) -> Option<Caches> {
        let interface = self.interfaces.iter_mut().find(|c| c.dirty)?;
        interface.dirty = false;
        Some(interface.caches.clear())
    }
    pub fn cache_cleanup_slots(&self, slot: usize) -> usize {
        if slot >= MAX_ADAPTERS || self.cache_candidates & (1 << slot) == 0 {
            return 0;
        }
        self.interfaces[slot].caches.cleanup_slots()
    }
    pub fn clean_range_with_work(
        &mut self,
        slot: usize,
        start: usize,
        now: u64,
        work: &mut CacheWork,
    ) -> bool {
        if slot >= MAX_ADAPTERS || self.cache_candidates & (1 << slot) == 0 {
            return false;
        }
        self.interfaces[slot]
            .caches
            .maintain_range(start, now, work);
        self.update_cache_candidates(slot);
        self.cache_candidates & (1 << slot) != 0
    }
    // Host helper. The kernel worker uses ranges to release PolicyLock between
    // batches while completing every candidate bank in the same cleanup run.
    pub fn clean(&mut self, now: u64) {
        while let Some(retired) = self.take_retired_caches() {
            drop(retired);
        }
        let mut candidates = self.cache_candidates;
        while candidates != 0 {
            let slot = candidates.trailing_zeros() as usize;
            candidates &= candidates - 1;
            let mut work = CacheWork::empty();
            self.interfaces[slot].caches.maintain(now, &mut work);
            self.update_cache_candidates(slot);
        }
    }
    fn cache_bank(&self, interface_index: u32, packet: &Packet) -> Option<usize> {
        if !packet.cacheable
            || !matches!(packet.connection.protocol, 6 | 17)
            || packet.flow.protocol != packet.connection.protocol
            || packet.flow.ipv6 != packet.connection.ipv6
        {
            return None;
        }
        self.interfaces.iter().position(|interface| {
            interface.interface_index == interface_index && interface.running && !interface.dirty
        })
    }
    pub fn cache_plan(&self, id: u64, verdict: Verdict, now: u64) -> Option<CachePlan> {
        if !verdict.permanent() || !self.online {
            return None;
        }
        let p = self
            .pending
            .iter()
            .find(|p| p.id == id && id != 0 && !p.invalidated && p.deadline > now)?;
        let bank = self.cache_bank(p.interface_index, &p.packet)?;
        self.interfaces[bank].caches.plan(&p.packet.connection)
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
    fn account(&mut self, packet: &Packet, allow: bool) {
        if allow {
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            if self.online && matches!(packet.connection.protocol, 6 | 17) {
                self.bandwidth_add(packet);
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
            && self.pending_count() < MAX_PENDING
            && self.next_id != u64::MAX
    }
    // Read-only allocation hint: this cannot refresh idle expiry or admit traffic.
    pub fn wants_event(&self, interface_index: u32, packet: &Packet, now: u64) -> bool {
        self.running(interface_index)
            && self.online
            && self.cache_bank(interface_index, packet).is_none_or(|bank| {
                self.interfaces[bank]
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
    ) -> Option<Action> {
        let allow = if !self.running(interface_index) {
            false
        } else if !self.online {
            self.fallback() == Finish::Allow
        } else {
            let bank = self.cache_bank(interface_index, packet)?;
            let allow =
                self.interfaces[bank]
                    .caches
                    .apply(&packet.connection, now, self.cache_ttl)?;
            self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
            allow
        };
        self.stats.received = self.stats.received.saturating_add(1);
        self.account(packet, allow);
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
        if let Some(action) = self.immediate(interface_index, packet, token, now) {
            Err(action)
        } else {
            Ok(self.event_room(packet))
        }
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
        if let Some(action) = self.immediate(interface_index, &packet, token, now) {
            return Submission::Finish(action);
        }
        self.stats.received = self.stats.received.saturating_add(1);
        let payload_len = packet.payload_len as usize;
        let expected = connection_header_len(&packet.connection) + payload_len;
        if payload_len > MAX_PAYLOAD || record.as_ref().is_some_and(|data| data.len() != expected) {
            self.stats.malformed = self.stats.malformed.saturating_add(1);
            self.account(&packet, false);
            return Submission::Finish(Action {
                token,
                finish: Finish::Drop,
            });
        }
        let slot = self.pending.iter().position(|p| p.id == 0);
        if !self.has_room(expected)
            || slot.is_none()
            || self.next_id == u64::MAX
            || record.is_none()
        {
            self.stats.overflow = self.stats.overflow.saturating_add(1);
            let finish = self.fallback();
            self.account(&packet, finish == Finish::Allow);
            return Submission::Finish(Action { token, finish });
        }
        let slot = slot.unwrap_or(0);
        let id = self.next_id;
        self.next_id += 1;
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
            self.account(&packet, false);
            return Submission::Finish(Action {
                token,
                finish: Finish::Drop,
            });
        }
        self.push_event(data, slot as u16, id);
        self.pending[slot] = Pending {
            id,
            token,
            cancel,
            deadline: now.saturating_add(self.timeout),
            interface_index,
            invalidated: false,
            packet,
        };
        self.pending_count += 1;
        self.stats.queued = self.stats.queued.saturating_add(1);
        Submission::Pending(id)
    }
    fn claim(&mut self, slot: usize, finish: Finish) -> Action {
        let p = self.pending[slot];
        self.pending[slot].id = 0;
        self.pending_count -= 1;
        self.account(&p.packet, finish == Finish::Allow);
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
        self.verdict_with_work(id, verdict, now, &mut work)
    }
    pub fn verdict_with_work(
        &mut self,
        id: u64,
        verdict: Verdict,
        now: u64,
        work: &mut CacheWork,
    ) -> Result<Action, VerdictError> {
        let slot = self
            .pending
            .iter()
            .position(|p| p.id == id && id != 0)
            .ok_or(VerdictError::NotFound)?;
        let p = self.pending[slot];
        if p.deadline <= now || !self.online || p.invalidated {
            return Err(VerdictError::NotFound);
        }
        if verdict.permanent()
            && let Some(bank) = self.cache_bank(p.interface_index, &p.packet)
        {
            if !self.interfaces[bank].caches.insert(
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
            slot,
            if verdict.allows() {
                Finish::Allow
            } else {
                Finish::Drop
            },
        ))
    }
    // Taking one item at a time avoids putting a MAX_PENDING action array on the
    // small kernel stack. Invalidation is recorded on each existing request.
    pub fn take_due(&mut self, now: u64) -> Option<Action> {
        if self.pending_count == 0 {
            return None;
        }
        for i in 0..MAX_PENDING {
            let p = self.pending[i];
            if p.id == 0 {
                continue;
            }
            let finish = if p.invalidated {
                self.stats.invalidated = self.stats.invalidated.saturating_add(1);
                Finish::Drop
            } else if !self.online {
                self.fallback()
            } else if p.deadline <= now {
                self.stats.timeouts = self.stats.timeouts.saturating_add(1);
                self.fallback()
            } else {
                continue;
            };
            return Some(self.claim(i, finish));
        }
        None
    }
    pub fn cancel(&mut self, interface_index: u32, cancel: usize) -> Option<Action> {
        let slot = self.pending.iter().position(|p| {
            p.id != 0 && p.interface_index == interface_index && p.cancel == Some(cancel)
        })?;
        self.stats.cancelled = self.stats.cancelled.saturating_add(1);
        Some(self.claim(slot, Finish::Cancel))
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        while written < out.len() && self.count != 0 {
            let e = &mut self.events[self.head];
            let stale =
                e.slot != NO_SLOT && e.read == 0 && self.pending[usize::from(e.slot)].id != e.id;
            if stale {
                self.pop_event();
                continue;
            }
            let n = (e.data.len() - e.read).min(out.len() - written);
            out[written..written + n].copy_from_slice(&e.data[e.read..e.read + n]);
            e.read += n;
            written += n;
            if e.read == e.data.len() {
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
            self.push_event(data, NO_SLOT, 0);
        }
    }
    fn bandwidth_add(&mut self, p: &Packet) {
        let same = |b: &Bandwidth| {
            let a = &b.connection;
            let c = &p.connection;
            b.active
                && a.ipv6 == c.ipv6
                && a.protocol == c.protocol
                && a.local_ip == c.local_ip
                && a.remote_ip == c.remote_ip
                && a.local_port == c.local_port
                && a.remote_port == c.remote_port
        };
        let index = self
            .bandwidth
            .iter()
            .position(same)
            .or_else(|| self.bandwidth.iter().position(|b| !b.active));
        if let Some(i) = index {
            let b = &mut self.bandwidth[i];
            if !b.active {
                b.active = true;
                b.connection = p.connection;
                b.tx = 0;
                b.rx = 0;
            }
            match p.connection.direction {
                Direction::Outbound => b.tx = b.tx.saturating_add(u64::from(p.ip_len)),
                Direction::Inbound => b.rx = b.rx.saturating_add(u64::from(p.ip_len)),
            }
        } else {
            self.stats.overflow = self.stats.overflow.saturating_add(1);
        }
    }
    pub fn bandwidth(&mut self) {
        for i in 0..MAX_BANDWIDTH {
            let b = self.bandwidth[i];
            if !b.active {
                continue;
            }
            let mut bytes = [0; MAX_LOG_RECORD];
            let Ok(len) = encode_bandwidth(&mut bytes, &b.connection, b.tx, b.rx) else {
                continue;
            };
            if !self.has_room(len) {
                continue;
            }
            if let Some(mut data) = allocate_record(len) {
                data.copy_from_slice(&bytes[..len]);
                self.push_event(data, NO_SLOT, 0);
                self.bandwidth[i].active = false;
            }
        }
    }
    pub fn memory_stats(&mut self) {
        let mut text = Text {
            bytes: [0; 400],
            len: 0,
        };
        let s = self.stats;
        let _ = write!(
            text,
            "HyperVXNdisFilter: fixed_bytes={} event_bytes={}/{} pending={}/{} cached_v4={} cached_v6={} cache_bytes={} cache_alloc_fail={} rx={} allow={} drop={} queued={} cache_hits={} timeout={} overflow={} cancel={} invalidated={} malformed={} non_ip={}",
            core::mem::size_of::<Self>(),
            self.queued_bytes,
            MAX_EVENT_BYTES,
            self.pending_count(),
            MAX_PENDING,
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
    fn default_queue_and_capture_pressure_drop_without_losing_tokens() {
        let mut e = default_engine();
        assert_eq!(
            e.submit(101, packet(), 1, None, 100, None),
            Submission::Finish(Action {
                token: 1,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), 0);
        for token in 1..=MAX_PENDING {
            submit(&mut e, 101, token);
        }
        assert_eq!(
            e.submit(101, packet(), 999, None, 100, record(&packet())),
            Submission::Finish(Action {
                token: 999,
                finish: Finish::Drop
            })
        );
        assert_eq!(e.pending_count(), MAX_PENDING);
        let mut count = 0;
        while let Some(action) = e.take_due(8100) {
            assert_eq!(action.finish, Finish::Drop);
            count += 1;
        }
        assert_eq!(count, MAX_PENDING);
        assert_eq!(e.pending_count(), 0);
        assert_eq!(e.stats().overflow, 2);
        assert_eq!(e.stats().allowed, 0);
        assert_eq!(e.stats().dropped, MAX_PENDING as u64 + 2);
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
        let mut candidates = e.cache_candidates();
        assert_eq!(candidates.count_ones(), 2);
        let mut batches = 0;
        while candidates != 0 {
            let slot = candidates.trailing_zeros() as usize;
            candidates &= candidates - 1;
            let slots = e.cache_cleanup_slots(slot);
            assert!(slots > crate::cache::CLEANUP_SLOTS_PER_BATCH);
            for start in (0..slots).step_by(crate::cache::CLEANUP_SLOTS_PER_BATCH) {
                let mut work = CacheWork::empty();
                let active = e.clean_range_with_work(slot, start, 60101, &mut work);
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
        assert_eq!(e.cache_cleanup_slots(MAX_ADAPTERS), 0);
        assert!(!e.clean_range_with_work(MAX_ADAPTERS, 0, 60101, &mut CacheWork::empty()));
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
        assert_eq!(e.cache_candidates().count_ones(), 2);
        e.invalidate(101, true);
        assert_eq!(e.cache_candidates().count_ones(), 1);
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
        e.verdict_with_work(id, Verdict::PermanentAccept, 101, &mut CacheWork::empty())
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
    fn queue_pressure_fallback_without_lost_owned_token() {
        let mut e = engine();
        let k = 101;
        for i in 0..MAX_PENDING {
            let _ = submit(&mut e, k, i + 1);
        }
        assert!(matches!(
            e.submit(k, packet(), 999, None, 100, record(&packet())),
            Submission::Finish(Action {
                token: 999,
                finish: Finish::Allow
            })
        ));
        let mut count = 0;
        while e.take_due(2100).is_some() {
            count += 1;
        }
        assert_eq!(count, MAX_PENDING);
        assert_eq!(e.pending_count(), 0);
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
            p.ip_len = p.payload_len;
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
            assert_eq!(e.count, 0);
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
        assert_eq!(e.count, 0);
    }
    #[test]
    fn event_byte_budget_falls_back_and_disconnect_frees_all_records() {
        let mut e = engine();
        e.read(&mut [0; MAX_LOG_RECORD]);
        let k = 101;
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        p.cacheable = false;
        let size = connection_header_len(&p.connection) + MAX_PAYLOAD;
        let mut tokens = 0;
        while e.wants_event(k, &p, 100) {
            tokens += 1;
            assert!(matches!(
                e.submit(k, p, tokens, None, 100, record(&p)),
                Submission::Pending(_)
            ));
        }
        assert_eq!(tokens, MAX_EVENT_BYTES / size);
        assert_eq!(e.queued_bytes, tokens * size);
        assert!(e.queued_bytes <= MAX_EVENT_BYTES);
        assert_eq!(
            e.submit(k, p, 999, None, 100, record(&p)),
            Submission::Finish(Action {
                token: 999,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.stats().overflow, 1);
        e.disconnect();
        assert_eq!(e.queued_bytes, 0);
        assert_eq!(e.count, 0);
        let mut released = 0;
        while e.take_due(101).is_some() {
            released += 1;
        }
        assert_eq!(released, tokens);
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
                    u64::from_le_bytes(b[i + 22..i + 30].try_into().unwrap()),
                    100
                );
                assert_eq!(
                    u64::from_le_bytes(b[i + 30..i + 38].try_into().unwrap()),
                    75
                );
                seen += 1;
            }
            i += 5 + len;
        }
        assert_eq!(seen, 1);
    }
    #[test]
    fn bandwidth_counts_admitted_bytes_and_uses_existing_wire() {
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
                assert_eq!(len, 33);
                seen = true;
                assert_eq!(
                    u64::from_le_bytes(b[i + 22..i + 30].try_into().unwrap()),
                    100
                );
            }
            i += 5 + len;
        }
        assert!(seen);
    }

    #[test]
    fn interface_indices_are_unique_nonzero_and_slots_are_reusable() {
        let mut e = Box::new(Engine::new());
        assert!(!e.attach(0));
        assert!(!e.restart(0));
        for index in 1..=MAX_ADAPTERS as u32 {
            assert!(e.attach(index));
            assert!(e.restart(index));
            assert!(!e.attach(index));
        }
        assert!(!e.attach(1000));
        e.detach(1);
        assert!(e.attach(1000));
        assert!(e.restart(1000));
        assert!(!e.restart(1));
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
            e.verdict_with_work(old, Verdict::PermanentAccept, 101, &mut work)
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
