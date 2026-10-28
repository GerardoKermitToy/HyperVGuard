//! Benchmark-only growing hash index over stable, fallibly allocated pages.
//! Only handles move during bounded migration; counter entries never move.
use super::{Key, Stat, Store, TrafficRecord};
use std::mem;

const PAGE: usize = 128;
const MIGRATE: usize = 32;
const DELETED: u32 = u32::MAX;

#[derive(Clone, Copy, Default)]
struct HandleSlot {
    hash: u64,
    index: u32, // 0 empty; MAX tombstone; other values are stable arena indices.
}

#[derive(Default)]
pub(super) struct IndexedPages {
    pages: Vec<Box<[Stat]>>,
    count: usize,
    current: Vec<HandleSlot>,
    previous: Vec<HandleSlot>,
    cursor: usize,
}
impl IndexedPages {
    fn entry(&self, index: u32) -> &Stat {
        let offset = index as usize - 1;
        &self.pages[offset / PAGE][offset % PAGE]
    }
    fn entry_mut(&mut self, index: u32) -> &mut Stat {
        let offset = index as usize - 1;
        &mut self.pages[offset / PAGE][offset % PAGE]
    }
    fn find(&self, slots: &[HandleSlot], key: Key, hash: u64) -> Option<u32> {
        let mask = slots.len().checked_sub(1)?;
        let mut position = hash as usize & mask;
        for _ in 0..slots.len() {
            let slot = slots[position];
            if slot.index == 0 {
                return None;
            }
            if slot.index != DELETED && slot.hash == hash && self.entry(slot.index).key() == key {
                return Some(slot.index);
            }
            position = (position + 1) & mask;
        }
        None
    }
    fn insert_handle(slots: &mut [HandleSlot], handle: HandleSlot) {
        let mask = slots.len() - 1;
        let mut position = handle.hash as usize & mask;
        for _ in 0..slots.len() {
            if slots[position].index == 0 || slots[position].index == DELETED {
                slots[position] = handle;
                return;
            }
            position = (position + 1) & mask;
        }
        panic!("index capacity invariant");
    }
    fn prepare_index(&mut self) -> bool {
        if !self.current.is_empty() && self.count < self.current.len() / 4 * 3 {
            return true;
        }
        if !self.previous.is_empty() {
            // Doubling and 32 scanned old slots per insertion finish migration
            // before the new 75% threshold. No unbounded emergency rehash.
            return self.count < self.current.len();
        }
        let Some(capacity) = self.current.len().max(64).checked_mul(2) else {
            return false;
        };
        let mut prepared = Vec::new();
        if prepared.try_reserve_exact(capacity).is_err() {
            return false;
        }
        prepared.resize(capacity, HandleSlot::default());
        // A production bridge must allocate/initialize prepared index storage
        // outside PolicyLock, then install these headers under the lock.
        self.previous = mem::replace(&mut self.current, prepared);
        self.cursor = 0;
        true
    }
    fn allocate_entry(&mut self, value: Stat) -> Option<u32> {
        let count = self.count.checked_add(1)?;
        let index = u32::try_from(count)
            .ok()
            .filter(|index| *index != DELETED)?;
        if self.count.is_multiple_of(PAGE) {
            self.pages.try_reserve(1).ok()?;
            let mut page = Vec::new();
            page.try_reserve_exact(PAGE).ok()?;
            // Initialize a bounded page without a page-sized stack array.
            // The page-directory Vec moves pointers, never live Stat values.
            page.resize(PAGE, value);
            self.pages.push(page.into_boxed_slice());
        }
        self.count = count;
        *self.entry_mut(index) = value;
        Some(index)
    }
    fn migrate(&mut self) {
        let end = self.cursor.saturating_add(MIGRATE).min(self.previous.len());
        while self.cursor < end {
            let slot = self.previous[self.cursor];
            if slot.index != 0 && slot.index != DELETED {
                Self::insert_handle(&mut self.current, slot);
                self.previous[self.cursor].index = DELETED;
            }
            self.cursor += 1;
        }
        if self.cursor == self.previous.len() && !self.previous.is_empty() {
            // A production bridge retires this one index allocation unlocked.
            self.previous = Vec::new();
            self.cursor = 0;
        }
    }
}
impl Store for IndexedPages {
    fn add(&mut self, record: &TrafficRecord) -> bool {
        let key = Key::from_record(record);
        let hash = key.hash_value();
        if let Some(index) = self
            .find(&self.current, key, hash)
            .or_else(|| self.find(&self.previous, key, hash))
        {
            self.entry_mut(index).add(record);
            return true;
        }
        if !self.prepare_index() {
            return false;
        }
        let Some(index) = self.allocate_entry(Stat::new(record)) else {
            return false;
        };
        Self::insert_handle(&mut self.current, HandleSlot { hash, index });
        self.migrate();
        true
    }
    fn len(&self) -> usize {
        self.count
    }
    fn visit(&self, visitor: &mut dyn FnMut(Stat)) {
        let mut remaining = self.count;
        for page in &self.pages {
            let used = remaining.min(PAGE);
            for entry in &page[..used] {
                visitor(*entry);
            }
            remaining -= used;
        }
        assert_eq!(remaining, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Direction, connection};

    #[test]
    fn growth_does_not_move_entries_and_hits_do_not_advance_migration() {
        let mut store = IndexedPages::default();
        let mut addresses = Vec::new();
        for id in 0..10_000 {
            let (interface_index, connection) = connection(id, 1);
            let record = TrafficRecord {
                flow_id: id,
                interface_index,
                connection,
                bytes: 9,
            };
            assert!(store.add(&record));
            addresses.push(store.entry((id + 1) as u32) as *const Stat);
        }
        for (id, &address) in addresses.iter().enumerate() {
            assert_eq!(store.entry((id + 1) as u32) as *const Stat, address);
        }
        let cursor = store.cursor;
        let (interface_index, mut connection) = connection(11, 1);
        connection.direction = Direction::Inbound;
        assert!(store.add(&TrafficRecord {
            flow_id: 11,
            interface_index,
            connection,
            bytes: 17
        }));
        assert_eq!(store.cursor, cursor);
        assert_eq!(store.len(), 10_000);
        assert_eq!(store.entry(12).rx, 17);
    }
}
