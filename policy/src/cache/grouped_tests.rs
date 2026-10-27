use super::*;

fn table<const N: usize>(capacity: usize) -> Table<N> {
    let allocation = CachePlan {
        ipv6: N == 16,
        capacity,
        allocator: unsafe { CacheAllocator::new(allocate, free) },
    }
    .allocate()
    .unwrap();
    Table {
        buffer: allocation.buffer,
        capacity,
        ..Table::new()
    }
}
fn check_mirror<const N: usize>(table: &Table<N>) {
    for i in 0..GROUP_WIDTH {
        assert_eq!(table.control(i), unsafe {
            *table.controls().add(table.capacity + i)
        });
    }
}

#[test]
fn control_group_masks_are_exact_for_every_byte_and_lane() {
    for byte in 0..=255u8 {
        for lane in 0..GROUP_WIDTH {
            // Adjacent zero/one differences catch cross-byte subtraction borrows.
            let mut bytes = [byte ^ 1; GROUP_WIDTH];
            bytes[lane] = byte;
            let group = unsafe { Group::load(bytes.as_ptr()) };
            assert_eq!(group.matches(byte), 1 << lane);
            let available = bytes
                .iter()
                .enumerate()
                .fold(0, |mask, (i, b)| mask | (u32::from(b & 0x80 != 0) << i));
            assert_eq!(group.available(), available);
        }
    }
}

#[test]
fn controls_payload_alignment_and_empty_mirror_are_valid() {
    fn check<const N: usize>() {
        let _ = caches();
        for capacity in [GROUP_WIDTH, INITIAL_CAPACITY, 1024] {
            let table = table::<N>(capacity);
            assert_eq!(table.buffer.data as usize % 16, 0);
            assert_eq!(table.entries() as usize % mem::align_of::<Entry<N>>(), 0);
            assert_eq!(table.entries().cast::<u8>(), table.buffer.data);
            assert_eq!(
                table.controls() as usize - table.buffer.data as usize,
                capacity * mem::size_of::<Entry<N>>()
            );
            assert_eq!(
                table.buffer.size,
                capacity + GROUP_WIDTH + capacity * mem::size_of::<Entry<N>>()
            );
            for i in 0..capacity {
                assert_eq!(table.control(i), EMPTY);
                assert!(!table.is_full(i));
            }
            check_mirror(&table);
            assert!(
                table
                    .find(&Tuple::from_connection(&connection(N == 16, 1)), 0)
                    .is_none()
            );
            drop(table);
            BYTES.with(|v| assert_eq!(v.get(), 0));
        }
    }
    check::<4>();
    check::<16>();
}

#[test]
fn colliding_wraparound_groups_cover_full_table_and_reuse_tombstones() {
    fn check<const N: usize>() {
        let _ = caches();
        for capacity in [INITIAL_CAPACITY, 512] {
            for start in 0..GROUP_WIDTH {
                let mut table = table::<N>(capacity);
                let hash = (0x5au64 << 57) | (capacity - GROUP_WIDTH + start) as u64;
                let entry = |n| Entry {
                    tuple: Tuple::from_connection(&connection(N == 16, n)),
                    expires: 60000,
                    allow: n % 2 == 0,
                };
                let calls = ALLOCATIONS.with(Cell::get);
                // Intentionally fill beyond the cache's 75% admission threshold:
                // this exercises every probe group and bounded full-table misses.
                for n in 0..capacity as u32 {
                    assert!(locked(|| table.insert(entry(n), hash)));
                }
                assert_eq!(table.len, capacity);
                assert_eq!(table.used, capacity);
                assert!(!locked(|| table.insert(entry(capacity as u32), hash)));
                assert!(table.find(&entry(capacity as u32).tuple, hash).is_none());
                for n in 0..capacity as u32 {
                    let index = table.find(&entry(n).tuple, hash).unwrap();
                    assert_eq!(*table.entry(index), entry(n));
                }
                check_mirror(&table);
                for n in (0..capacity as u32).step_by(3) {
                    let index = table.find(&entry(n).tuple, hash).unwrap();
                    locked(|| table.remove(index));
                }
                check_mirror(&table);
                for n in 0..capacity as u32 {
                    assert_eq!(table.find(&entry(n).tuple, hash).is_some(), n % 3 != 0);
                }
                for n in (0..capacity as u32).step_by(3) {
                    assert!(locked(|| table.insert(entry(n + capacity as u32), hash)));
                }
                assert_eq!(table.len, capacity);
                assert_eq!(table.used, capacity, "reuse must not increase used load");
                check_mirror(&table);
                for n in 0..capacity as u32 {
                    let id = if n % 3 == 0 { n + capacity as u32 } else { n };
                    let index = table.find(&entry(id).tuple, hash).unwrap();
                    assert_eq!(*table.entry(index), entry(id));
                }
                assert_eq!(ALLOCATIONS.with(Cell::get), calls);
                drop(table);
                BYTES.with(|v| assert_eq!(v.get(), 0));
            }
        }
    }
    check::<4>();
    check::<16>();
}

#[test]
fn invalid_or_overflowed_layouts_fail_before_allocator_call() {
    let _ = caches();
    let calls = ALLOCATIONS.with(Cell::get);
    for capacity in [
        0,
        1,
        GROUP_WIDTH - 1,
        129,
        usize::MAX,
        1 << (usize::BITS - 2),
    ] {
        for ipv6 in [false, true] {
            let work = CacheWork::prepare(Some(CachePlan {
                ipv6,
                capacity,
                allocator: unsafe { CacheAllocator::new(allocate, free) },
            }));
            assert!(work.growth.is_none());
        }
    }
    assert_eq!(ALLOCATIONS.with(Cell::get), calls);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn randomized_cache_churn_matches_standard_map_verdicts_and_ttl() {
    fn check(ipv6: bool) {
        let mut cache = caches();
        let mut expected = std::collections::HashMap::<u32, (bool, u64)>::new();
        let mut random = 0x4859564341434845u64;
        for now in 1..=20000u64 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let id = (random >> 16) as u32 % 1024;
            let c = connection(ipv6, id);
            match random % 7 {
                0..=2 => {
                    let allow = random & 0x100 != 0;
                    let expires = now + 1000;
                    let plan = locked(|| cache.plan(&c));
                    let mut work = CacheWork::prepare(plan);
                    assert!(locked(|| cache.insert(
                        &c,
                        Decision { allow, expires },
                        now,
                        &mut work
                    )));
                    expected.insert(id, (allow, expires));
                }
                3..=4 => {
                    let wanted = expected.get_mut(&id).and_then(|(allow, expires)| {
                        if *expires <= now {
                            return None;
                        }
                        if *allow {
                            *expires = now + 1000;
                        }
                        Some(*allow)
                    });
                    assert_eq!(locked(|| cache.apply(&c, now, 1000)), wanted);
                }
                5 => {
                    let wanted = expected
                        .get(&id)
                        .and_then(|(allow, expires)| (*expires > now).then_some(*allow));
                    assert_eq!(locked(|| cache.get(&c, now)), wanted);
                }
                _ => {
                    maintain(&mut cache, now);
                    expected.retain(|_, (_, expires)| *expires > now);
                }
            }
            if now.is_multiple_of(1999) {
                let retired = locked(|| cache.clear());
                drop(retired);
                expected.clear();
            }
        }
        for id in 0..1024 {
            let wanted = expected
                .get(&id)
                .and_then(|(allow, expires)| (*expires > 20000).then_some(*allow));
            assert_eq!(cache.get(&connection(ipv6, id), 20000), wanted);
        }
        drop(cache);
        BYTES.with(|v| assert_eq!(v.get(), 0));
    }
    check(false);
    check(true);
}
