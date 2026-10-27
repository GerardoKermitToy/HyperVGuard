use crate::packet::{Flow, NdisPath, Packet};
use alloc::vec::Vec;
use core::fmt::{self, Write};
use hyperv_protocol::{
    Connection, Direction, MAX_LOG_RECORD, MAX_PAYLOAD, MAX_RECORD, Verdict, connection_header_len,
    encode_bandwidth, encode_connection_header, encode_log,
};

pub const MAX_PENDING: usize = 256;
pub const MAX_EVENTS: usize = 512;
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CACHE: usize = 1024;
pub const MAX_ADAPTERS: usize = 32;
const WAYS: usize = 4;
const MAX_BANDWIDTH: usize = 256;
const NO_SLOT: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub adapter: u64,
    pub epoch: u64,
    pub path: NdisPath,
    pub vlan: u32,
    pub flow: Flow,
}
impl Key {
    pub const EMPTY: Self = Self {
        adapter: 0,
        epoch: 0,
        path: NdisPath::Receive,
        vlan: 0,
        flow: Flow::EMPTY,
    };
    fn hash(&self) -> usize {
        let mut h = 0xcbf29ce484222325u64;
        for b in self
            .adapter
            .to_le_bytes()
            .iter()
            .chain(self.epoch.to_le_bytes().iter())
            .chain([self.path as u8].iter())
            .chain(self.vlan.to_le_bytes().iter())
            .chain(self.flow.l2.iter())
            .chain(self.flow.source.iter())
            .chain(self.flow.destination.iter())
            .chain(self.flow.source_port.to_le_bytes().iter())
            .chain(self.flow.destination_port.to_le_bytes().iter())
            .chain([self.flow.l2_len, self.flow.ipv6 as u8, self.flow.protocol].iter())
        {
            h = (h ^ u64::from(*b)).wrapping_mul(0x100000001b3);
        }
        h as usize
    }
}
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

#[derive(Clone, Copy)]
struct Adapter {
    id: u64,
    interface_index: u32,
    epoch: u64,
    running: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    id: u64,
    token: usize,
    cancel: usize,
    deadline: u64,
    key: Key,
    packet: Packet,
}
impl Pending {
    const EMPTY: Self = Self {
        id: 0,
        token: 0,
        cancel: 0,
        deadline: 0,
        key: Key::EMPTY,
        packet: Packet::EMPTY,
    };
}
#[derive(Clone, Copy)]
struct Cached {
    valid: bool,
    key: Key,
    allow: bool,
    expires: u64,
}
impl Cached {
    const EMPTY: Self = Self {
        valid: false,
        key: Key::EMPTY,
        allow: false,
        expires: 0,
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
        timeouts: 0,
        overflow: 0,
        cancelled: 0,
        invalidated: 0,
        malformed: 0,
        non_ip: 0,
    };
}

// Metadata is fixed-size; queued records own bounded nonpaged allocations.
// Parsing and full packet copies happen OUTSIDE the policy spin lock.
pub struct Engine {
    adapters: [Adapter; MAX_ADAPTERS],
    pending: [Pending; MAX_PENDING],
    cache: [Cached; MAX_CACHE],
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
        Self {
            adapters: [Adapter {
                id: 0,
                interface_index: 0,
                epoch: 0,
                running: false,
            }; MAX_ADAPTERS],
            pending: [Pending::EMPTY; MAX_PENDING],
            cache: [Cached::EMPTY; MAX_CACHE],
            events: [const { Event::EMPTY }; MAX_EVENTS],
            bandwidth: [Bandwidth::EMPTY; MAX_BANDWIDTH],
            head: 0,
            count: 0,
            queued_bytes: 0,
            next_id: 1,
            online: false,
            fail_closed: false,
            timeout: 2000,
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
        self.pending.iter().filter(|p| p.id != 0).count()
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
    pub fn attach(&mut self, id: u64, interface_index: u32) -> bool {
        if id == 0 || self.adapters.iter().any(|s| s.id == id) {
            return false;
        }
        if let Some(s) = self.adapters.iter_mut().find(|s| s.id == 0) {
            *s = Adapter {
                id,
                interface_index,
                epoch: 1,
                running: false,
            };
            true
        } else {
            false
        }
    }
    pub fn restart(&mut self, id: u64) -> bool {
        if let Some(s) = self.adapters.iter_mut().find(|s| s.id == id) {
            if s.epoch == u64::MAX {
                return false;
            }
            s.running = true;
            true
        } else {
            false
        }
    }
    pub fn invalidate(&mut self, id: u64, pause: bool) {
        if let Some(s) = self.adapters.iter_mut().find(|s| s.id == id) {
            s.epoch = s.epoch.saturating_add(1);
            if pause || s.epoch == u64::MAX {
                s.running = false;
            }
        }
        for c in &mut self.cache {
            if c.key.adapter == id {
                c.valid = false;
            }
        }
    }
    pub fn detach(&mut self, id: u64) {
        self.invalidate(id, true);
        if let Some(s) = self.adapters.iter_mut().find(|s| s.id == id) {
            s.id = 0;
        }
    }
    pub fn epoch(&self, id: u64) -> Option<u64> {
        self.adapters
            .iter()
            .find(|s| s.id == id && s.running)
            .map(|s| s.epoch)
    }
    fn live(&self, key: &Key) -> bool {
        self.epoch(key.adapter) == Some(key.epoch)
    }
    pub fn clear_cache(&mut self) {
        for c in &mut self.cache {
            c.valid = false;
        }
    }
    pub fn clean(&mut self, now: u64) {
        for c in &mut self.cache {
            if c.expires <= now {
                c.valid = false;
            }
        }
    }
    fn cache_lookup(&self, key: &Key, now: u64) -> Option<bool> {
        let start = key.hash() % (MAX_CACHE / WAYS) * WAYS;
        self.cache[start..start + WAYS]
            .iter()
            .find(|c| c.valid && c.expires > now && c.key == *key)
            .map(|c| c.allow)
    }
    fn cache_insert(&mut self, key: Key, allow: bool, now: u64) {
        let start = key.hash() % (MAX_CACHE / WAYS) * WAYS;
        let slots = &mut self.cache[start..start + WAYS];
        let index = slots
            .iter()
            .position(|c| !c.valid || c.expires <= now || c.key == key)
            .unwrap_or_else(|| {
                slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, c)| c.expires)
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            });
        slots[index] = Cached {
            valid: true,
            key,
            allow,
            expires: now.saturating_add(self.cache_ttl),
        };
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
    // This is only an allocation/copy optimization, not a reservation. submit()
    // rechecks session, epoch, cache and capacity after the unlocked packet copy.
    pub fn wants_event(&self, key: &Key, packet: &Packet, now: u64) -> bool {
        self.live(key)
            && self.online
            && (!packet.cacheable || self.cache_lookup(key, now).is_none())
            && self
                .has_room(connection_header_len(&packet.connection) + packet.payload_len as usize)
            && self.pending_count() < MAX_PENDING
            && self.next_id != u64::MAX
    }
    pub fn submit(
        &mut self,
        key: Key,
        packet: Packet,
        token: usize,
        cancel: usize,
        now: u64,
        record: Option<Vec<u8>>,
    ) -> Submission {
        self.stats.received = self.stats.received.saturating_add(1);
        let Some(interface_index) = self
            .adapters
            .iter()
            .find(|a| a.id == key.adapter && a.running && a.epoch == key.epoch)
            .map(|a| a.interface_index)
        else {
            self.account(&packet, false);
            return Submission::Finish(Action {
                token,
                finish: Finish::Drop,
            });
        };
        let immediate = if !self.online {
            Some(self.fallback() == Finish::Allow)
        } else if packet.cacheable {
            let c = self.cache_lookup(&key, now);
            if c.is_some() {
                self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
            }
            c
        } else {
            None
        };
        if let Some(allow) = immediate {
            self.account(&packet, allow);
            return Submission::Finish(Action {
                token,
                finish: if allow { Finish::Allow } else { Finish::Drop },
            });
        }
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
            key,
            packet,
        };
        self.stats.queued = self.stats.queued.saturating_add(1);
        Submission::Pending(id)
    }
    fn claim(&mut self, slot: usize, finish: Finish) -> Action {
        let p = self.pending[slot];
        self.pending[slot].id = 0;
        self.account(&p.packet, finish == Finish::Allow);
        Action {
            token: p.token,
            finish,
        }
    }
    pub fn verdict(&mut self, id: u64, verdict: Verdict, now: u64) -> Result<Action, VerdictError> {
        let slot = self
            .pending
            .iter()
            .position(|p| p.id == id && id != 0)
            .ok_or(VerdictError::NotFound)?;
        let p = self.pending[slot];
        if p.deadline <= now || !self.online || !self.live(&p.key) {
            return Err(VerdictError::NotFound);
        }
        if verdict.permanent() && p.packet.cacheable {
            self.cache_insert(p.key, verdict.allows(), now);
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
    // small kernel stack. A concurrent new request can never match an old epoch.
    pub fn take_due(&mut self, now: u64) -> Option<Action> {
        for i in 0..MAX_PENDING {
            let p = self.pending[i];
            if p.id == 0 {
                continue;
            }
            let finish = if !self.live(&p.key) {
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
    pub fn cancel(&mut self, adapter: u64, cancel: usize) -> Option<Action> {
        let slot = self.pending.iter().position(|p| {
            p.id != 0
                && p.key.adapter == adapter
                && p.key.path == NdisPath::Send
                && p.cancel == cancel
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
            "HyperVXNdisFilter: fixed_bytes={} event_bytes={}/{} pending={}/{} cached={} rx={} allow={} drop={} queued={} cache_hits={} timeout={} overflow={} cancel={} invalidated={} malformed={} non_ip={}",
            core::mem::size_of::<Self>(),
            self.queued_bytes,
            MAX_EVENT_BYTES,
            self.pending_count(),
            MAX_PENDING,
            self.cache.iter().filter(|c| c.valid).count(),
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
    use std::{boxed::Box, vec};
    fn engine() -> Box<Engine> {
        let mut e = Box::new(Engine::new());
        assert!(e.attach(1, 101));
        assert!(e.restart(1));
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
    fn key(e: &Engine, vlan: u32) -> Key {
        Key {
            adapter: 1,
            epoch: e.epoch(1).unwrap(),
            vlan,
            ..Key::EMPTY
        }
    }
    fn record(p: &Packet) -> Option<Vec<u8>> {
        allocate_record(connection_header_len(&p.connection) + p.payload_len as usize)
    }
    fn submit(e: &mut Engine, k: Key, t: usize) -> u64 {
        let mut p = packet();
        p.orient(k.path);
        match e.submit(k, p, t, 42, 100, record(&p)) {
            Submission::Pending(id) => id,
            _ => panic!("expected pending"),
        }
    }
    #[test]
    fn connection_indices_follow_each_adapter_across_paths_and_slot_reuse() {
        let mut e = engine();
        e.read(&mut [0; 512]);
        assert!(e.attach(2, 0x12345678));
        assert!(e.restart(2));
        let mut previous_id = 0;
        for (adapter, interface_index) in [
            (1, 101),
            (2, 0x12345678),
            (1, 101),
            (3, 0x87654321),
            (2, 0x12345678),
        ] {
            if adapter == 3 {
                e.detach(1);
                assert!(e.attach(3, interface_index));
                assert!(e.restart(3));
            }
            for ipv6 in [false, true] {
                for path in [NdisPath::Send, NdisPath::Receive] {
                    let mut p = packet();
                    p.connection.ipv6 = ipv6;
                    p.orient(path);
                    let k = Key {
                        adapter,
                        epoch: e.epoch(adapter).unwrap(),
                        path,
                        flow: p.flow,
                        ..Key::EMPTY
                    };
                    let token = adapter as usize;
                    let Submission::Pending(id) = e.submit(k, p, token, 42, 100, record(&p)) else {
                        panic!("each adapter must produce its own event");
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
    fn permanent_scoped_to_adapter_path_vlan_epoch() {
        let mut e = engine();
        let k = key(&e, 1);
        let id = submit(&mut e, k, 11);
        assert_eq!(
            e.verdict(id, Verdict::PermanentAccept, 101).unwrap(),
            Action {
                token: 11,
                finish: Finish::Allow
            }
        );
        assert!(matches!(
            e.submit(k, packet(), 12, 42, 102, record(&packet())),
            Submission::Finish(Action {
                finish: Finish::Allow,
                ..
            })
        ));
        for changed in [
            Key {
                path: NdisPath::Send,
                ..k
            },
            Key { vlan: 2, ..k },
        ] {
            let _ = submit(&mut e, changed, 13);
        }
        assert!(e.attach(2, 101));
        e.restart(2);
        let other = Key {
            adapter: 2,
            epoch: e.epoch(2).unwrap(),
            ..k
        };
        let _ = submit(&mut e, other, 14);
    }
    #[test]
    fn temporary_verdict_never_caches_and_duplicate_rejected() {
        let mut e = engine();
        let k = key(&e, 1);
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
        let k = key(&e, 1);
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
    fn pause_invalidates_and_stale_verdict_cannot_repopulate() {
        let mut e = engine();
        let k = key(&e, 1);
        let id = submit(&mut e, k, 1);
        e.invalidate(1, true);
        assert_eq!(
            e.verdict(id, Verdict::PermanentAccept, 101),
            Err(VerdictError::NotFound)
        );
        assert_eq!(e.take_due(101).unwrap().finish, Finish::Drop);
        e.restart(1);
        let new_key = key(&e, 1);
        assert_ne!(k.epoch, new_key.epoch);
        let _ = submit(&mut e, new_key, 2);
        assert!(matches!(
            e.submit(k, packet(), 3, 42, 102, record(&packet())),
            Submission::Finish(Action {
                finish: Finish::Drop,
                ..
            })
        ));
    }
    #[test]
    fn cancellation_and_event_slot_reuse_do_not_expose_stale_ids() {
        let mut e = engine();
        let k = Key {
            path: NdisPath::Send,
            ..key(&e, 1)
        };
        let old = submit(&mut e, k, 1);
        assert_eq!(e.cancel(1, 42).unwrap().finish, Finish::Cancel);
        let new = submit(&mut e, k, 2);
        assert_ne!(old, new);
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
    fn cancel_send_never_claims_a_receive_with_the_same_cancel_id() {
        let mut e = engine();
        let receive = key(&e, 1);
        let send = Key {
            path: NdisPath::Send,
            ..receive
        };
        let mut p = packet();
        p.orient(NdisPath::Receive);
        assert_eq!(p.connection.direction, Direction::Outbound);
        assert!(matches!(
            e.submit(receive, p, 1, 0, 100, record(&p)),
            Submission::Pending(_)
        ));
        p.orient(NdisPath::Send);
        assert_eq!(p.connection.direction, Direction::Inbound);
        assert!(matches!(
            e.submit(send, p, 2, 0, 100, record(&p)),
            Submission::Pending(_)
        ));
        assert_eq!(e.cancel(1, 0).unwrap().token, 2);
        assert!(e.cancel(1, 0).is_none());
        assert_eq!(e.pending_count(), 1);
        e.disconnect();
        assert_eq!(e.take_due(101).unwrap().token, 1);
    }
    #[test]
    fn partial_reads_remain_a_valid_stream_after_timeout() {
        let mut e = engine();
        let k = key(&e, 1);
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
        let k = key(&e, 1);
        for i in 0..MAX_PENDING {
            let _ = submit(&mut e, k, i + 1);
        }
        assert!(matches!(
            e.submit(k, packet(), 999, 42, 100, record(&packet())),
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
            let k = key(&e, 1);
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
            let Submission::Pending(id) = e.submit(k, p, 7, 0, 100, Some(data)) else {
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
        let k = key(&e, 1);
        let mut p = packet();
        p.payload_len = 70000;
        let _ = e.submit(k, p, 9, 0, 100, record(&p));
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
        let k = key(&e, 1);
        let mut p = packet();
        p.payload_len = MAX_PAYLOAD as u32;
        p.cacheable = false;
        let size = connection_header_len(&p.connection) + MAX_PAYLOAD;
        let mut tokens = 0;
        while e.wants_event(&k, &p, 100) {
            tokens += 1;
            assert!(matches!(
                e.submit(k, p, tokens, 0, 100, record(&p)),
                Submission::Pending(_)
            ));
        }
        assert_eq!(tokens, MAX_EVENT_BYTES / size);
        assert_eq!(e.queued_bytes, tokens * size);
        assert!(e.queued_bytes <= MAX_EVENT_BYTES);
        assert_eq!(
            e.submit(k, p, 999, 0, 100, record(&p)),
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
            let k = key(&e, 1);
            assert_eq!(
                e.submit(k, packet(), 77, 0, 100, None),
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
        let k = key(&e, 1);
        let p = packet();
        let mut data = record(&p).unwrap();
        data.pop();
        assert_eq!(
            e.submit(k, p, 88, 0, 100, Some(data)),
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
        let k = key(&e, 1);
        let p = packet();
        assert!(e.wants_event(&k, &p, 100));
        let data = record(&p);
        e.disconnect();
        assert_eq!(
            e.submit(k, p, 1, 0, 100, data),
            Submission::Finish(Action {
                token: 1,
                finish: Finish::Allow
            })
        );
        assert_eq!(e.queued_bytes, 0);
        e.connect();
        e.read(&mut [0; MAX_LOG_RECORD]);
        assert!(e.wants_event(&k, &p, 100));
        let data = record(&p);
        e.invalidate(1, true);
        assert_eq!(
            e.submit(k, p, 2, 0, 100, data),
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
        let k = key(&e, 1);
        let mut p = packet();
        p.cacheable = false;
        let Submission::Pending(id) = e.submit(k, p, 1, 0, 0, record(&p)) else {
            panic!()
        };
        e.verdict(id, Verdict::PermanentAccept, 1).unwrap();
        assert!(matches!(
            e.submit(k, p, 2, 0, 2, record(&p)),
            Submission::Pending(_)
        ));
    }
    #[test]
    fn ttl_expiry_requires_a_new_decision() {
        let mut e = engine();
        let k = key(&e, 1);
        let id = submit(&mut e, k, 1);
        e.verdict(id, Verdict::PermanentDrop, 101).unwrap();
        assert!(matches!(
            e.submit(k, packet(), 2, 0, 60100, record(&packet())),
            Submission::Finish(Action {
                finish: Finish::Drop,
                ..
            })
        ));
        assert!(matches!(
            e.submit(k, packet(), 3, 0, 60101, record(&packet())),
            Submission::Pending(_)
        ));
    }
    #[test]
    fn bandwidth_combines_guest_normalized_tx_and_rx() {
        let mut e = engine();
        let k = key(&e, 1);
        let tx = packet();
        let mut rx = tx;
        rx.orient(NdisPath::Send);
        rx.ip_len = 75;
        let Submission::Pending(id) = e.submit(k, tx, 1, 0, 100, record(&tx)) else {
            panic!()
        };
        e.verdict(id, Verdict::Accept, 101).unwrap();
        let inbound = Key {
            path: NdisPath::Send,
            ..k
        };
        let Submission::Pending(id) = e.submit(inbound, rx, 2, 0, 102, record(&rx)) else {
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
        let k = key(&e, 1);
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
}
