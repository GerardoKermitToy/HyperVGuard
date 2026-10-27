extern crate std;
use super::*;
use std::cell::Cell;

#[path = "grouped_tests.rs"]
mod grouped;

std::thread_local! {
    static LOCKED: Cell<bool> = const { Cell::new(false) };
    static FAIL: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}
unsafe fn allocate(size: usize) -> *mut u8 {
    LOCKED.with(|v| assert!(!v.get(), "allocation under the policy lock"));
    ALLOCATIONS.with(|v| v.set(v.get() + 1));
    if FAIL.with(Cell::get) {
        return ptr::null_mut();
    }
    let data = unsafe { global_allocate(size) };
    if !data.is_null() {
        BYTES.with(|v| v.set(v.get() + size));
    }
    data
}
unsafe fn free(data: *mut u8, size: usize) {
    LOCKED.with(|v| assert!(!v.get(), "free under the policy lock"));
    BYTES.with(|v| v.set(v.get().checked_sub(size).unwrap()));
    unsafe { global_free(data, size) };
}
fn caches() -> Caches {
    BYTES.with(|v| assert_eq!(v.get(), 0));
    FAIL.with(|v| v.set(false));
    ALLOCATIONS.with(|v| v.set(0));
    Caches::new(unsafe { CacheAllocator::new(allocate, free) })
}
fn locked<R>(f: impl FnOnce() -> R) -> R {
    LOCKED.with(|v| v.set(true));
    let result = f();
    LOCKED.with(|v| v.set(false));
    result
}
fn connection(ipv6: bool, n: u32) -> Connection {
    let mut c = Connection::EMPTY;
    c.ipv6 = ipv6;
    c.protocol = 17;
    c.local_ip[..4].copy_from_slice(&n.to_le_bytes());
    c.remote_ip[..4].copy_from_slice(&[192, 0, 2, 1]);
    c.local_port = 12345;
    c.remote_port = 443;
    c
}
fn insert(caches: &mut Caches, c: &Connection, allow: bool, expires: u64) -> bool {
    let plan = locked(|| caches.plan(c));
    let mut work = CacheWork::prepare(plan);
    locked(|| caches.insert(c, Decision { allow, expires }, 0, &mut work))
}
fn maintain(caches: &mut Caches, now: u64) {
    let mut work = CacheWork::empty();
    locked(|| caches.maintain(now, &mut work));
}

#[test]
fn separate_tables_grow_past_1024_without_evicting_live_entries() {
    let mut caches = caches();
    for n in 0..8192 {
        for ipv6 in [false, true] {
            assert!(insert(&mut caches, &connection(ipv6, n), n % 2 == 0, 60000));
        }
    }
    assert_eq!(caches.counts(), (8192, 8192));
    assert!(caches.ipv4[1].current.capacity >= 16384);
    assert!(caches.ipv6[1].current.capacity >= 16384);
    let calls = ALLOCATIONS.with(Cell::get);
    for n in 0..8192 {
        for ipv6 in [false, true] {
            let c = connection(ipv6, n);
            assert_eq!(locked(|| caches.apply(&c, 1, 1000)), Some(n % 2 == 0));
        }
    }
    assert_eq!(
        ALLOCATIONS.with(Cell::get),
        calls,
        "hits must never allocate"
    );
    assert!(mem::size_of::<Entry<4>>() < mem::size_of::<Entry<16>>());
    drop(caches);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn normalized_tuple_hash_and_full_equality_include_every_requested_field() {
    for ipv6 in [false, true] {
        let c = connection(ipv6, 10);
        fn check<const N: usize>(c: &Connection) {
            let tuple = Tuple::<N>::from_connection(c);
            for changed in [
                Tuple {
                    local_ip: [1; N],
                    ..tuple
                },
                Tuple {
                    remote_ip: [2; N],
                    ..tuple
                },
                Tuple {
                    local_port: 456,
                    ..tuple
                },
                Tuple {
                    remote_port: 789,
                    ..tuple
                },
            ] {
                assert_ne!(tuple, changed);
                assert_ne!(tuple.hash(), changed.hash());
            }
        }
        if ipv6 {
            check::<16>(&c);
        } else {
            check::<4>(&c);
        }
    }
    let c = connection(false, 10);
    let tuple = Tuple::<4>::from_connection(&c);
    let mut tail = c;
    tail.local_ip[15] = 1;
    tail.remote_ip[15] = 2;
    assert_eq!(tuple, Tuple::from_connection(&tail));
    assert_ne!(
        Tuple::<16>::from_connection(&c),
        Tuple::from_connection(&tail)
    );
}

#[test]
fn equal_hashes_never_alias_distinct_ip_port_tuples() {
    let mut caches = caches();
    let c = connection(false, 10);
    assert!(insert(&mut caches, &c, true, 60000));
    let tuple = Tuple::<4>::from_connection(&c);
    let hash = tuple.hash();
    let other = Tuple {
        remote_port: 8443,
        ..tuple
    };
    // Force an exact 64-bit collision, not just a shared bucket index.
    assert!(caches.ipv4[1].current.insert(
        Entry {
            tuple: other,
            allow: false,
            expires: 60000
        },
        hash
    ));
    let a = caches.ipv4[1].current.find(&tuple, hash).unwrap();
    let b = caches.ipv4[1].current.find(&other, hash).unwrap();
    assert_ne!(a, b);
    assert!(caches.ipv4[1].current.entry(a).allow);
    assert!(!caches.ipv4[1].current.entry(b).allow);
}

#[test]
fn tcp_udp_have_independent_decisions_and_expiry_for_the_same_ip_port_tuple() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        let udp = connection(ipv6, 10);
        let mut tcp = udp;
        tcp.protocol = 6;
        assert!(insert(&mut caches, &udp, false, 100));
        assert_eq!(caches.get(&tcp, 1), None);
        assert!(caches.plan(&tcp).is_some());
        assert!(insert(&mut caches, &tcp, true, 100));
        assert_eq!(caches.apply(&tcp, 99, 1000), Some(true));
        assert_eq!(caches.get(&udp, 99), Some(false));
        assert_eq!(caches.get(&udp, 100), None);
        assert_eq!(caches.get(&tcp, 100), Some(true));
    }
    assert_eq!(caches.counts(), (2, 2));
    maintain(&mut caches, 100);
    assert_eq!(caches.counts(), (1, 1));
    maintain(&mut caches, 1099);
    assert_eq!(caches.bytes(), 0);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn failed_initial_allocation_and_growth_preserve_live_verdicts() {
    let mut caches = caches();
    FAIL.with(|v| v.set(true));
    assert!(!insert(&mut caches, &connection(false, 0), true, 60000));
    assert_eq!(caches.bytes(), 0);
    FAIL.with(|v| v.set(false));
    for n in 0..96 {
        assert!(insert(&mut caches, &connection(false, n), true, 60000));
    }
    let bytes = caches.bytes();
    FAIL.with(|v| v.set(true));
    assert!(!insert(&mut caches, &connection(false, 96), true, 60000));
    assert_eq!(caches.counts(), (96, 0));
    assert_eq!(caches.bytes(), bytes);
    for n in 0..96 {
        assert_eq!(caches.get(&connection(false, n), 1), Some(true));
    }
    // An existing entry can still change verdict without any allocation.
    let calls = ALLOCATIONS.with(Cell::get);
    assert!(insert(&mut caches, &connection(false, 0), false, 61000));
    assert_eq!(ALLOCATIONS.with(Cell::get), calls);
    assert_eq!(caches.get(&connection(false, 0), 1), Some(false));
    FAIL.with(|v| v.set(false));
    assert!(insert(&mut caches, &connection(false, 96), true, 60000));
}

#[test]
fn failed_compaction_does_not_fill_probe_chains_with_tombstones() {
    let mut caches = caches();
    for n in 0..96 {
        assert!(insert(
            &mut caches,
            &connection(false, n),
            true,
            if n < 80 { 10 } else { 10000 }
        ));
    }
    for _ in 0..4 {
        maintain(&mut caches, 10);
    }
    assert_eq!(caches.counts(), (16, 0));
    let used = caches.ipv4[1].current.used;
    FAIL.with(|v| v.set(true));
    for n in 100..200 {
        assert!(!insert(&mut caches, &connection(false, n), false, 10000));
    }
    assert_eq!(caches.ipv4[1].current.used, used);
    for n in 80..96 {
        assert_eq!(caches.get(&connection(false, n), 10), Some(true));
    }
    FAIL.with(|v| v.set(false));
    assert!(insert(&mut caches, &connection(false, 200), false, 10000));
}

#[test]
fn only_insertions_advance_migration_and_both_tables_stay_readable() {
    let mut caches = caches();
    for n in 0..97 {
        assert!(insert(&mut caches, &connection(true, n), n % 2 == 0, 60000));
    }
    assert_eq!(caches.ipv6[1].previous.capacity, INITIAL_CAPACITY);
    assert_eq!(caches.ipv6[1].migrate, WORK_PER_PASS);
    let old_count = caches.ipv6[1].previous.len;
    for _ in 0..4 {
        for n in 0..97 {
            assert_eq!(caches.get(&connection(true, n), 1), Some(n % 2 == 0));
        }
        maintain(&mut caches, 1);
        assert_eq!(caches.ipv6[1].migrate, WORK_PER_PASS);
        assert_eq!(caches.ipv6[1].previous.len, old_count);
    }
    for n in 97..101 {
        assert!(insert(&mut caches, &connection(true, n), n % 2 == 0, 60000));
    }
    assert_eq!(caches.ipv6[1].previous.capacity, 0);
    assert_eq!(caches.counts(), (0, 101));
    for n in 0..101 {
        assert_eq!(caches.get(&connection(true, n), 1), Some(n % 2 == 0));
    }
}

#[test]
fn expiry_and_tombstone_reuse_release_tables_without_locked_free() {
    let mut caches = caches();
    for n in 0..96 {
        assert!(insert(
            &mut caches,
            &connection(false, n),
            true,
            if n < 80 { 10 } else { 10000 }
        ));
    }
    for _ in 0..4 {
        maintain(&mut caches, 10);
    }
    assert_eq!(caches.counts(), (16, 0));
    // At high used-slot load but low live load, compact without growing.
    assert!(insert(&mut caches, &connection(false, 100), false, 10000));
    assert_eq!(caches.ipv4[1].current.capacity, INITIAL_CAPACITY);
    for _ in 0..4 {
        maintain(&mut caches, 10);
    }
    for n in 80..96 {
        assert_eq!(caches.get(&connection(false, n), 10), Some(true));
    }
    assert_eq!(caches.get(&connection(false, 100), 10000), None);
    for _ in 0..8 {
        maintain(&mut caches, 10000);
    }
    assert_eq!(caches.bytes(), 0);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn cleanup_expires_both_tables_without_advancing_migration() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        for n in 0..97 {
            assert!(insert(&mut caches, &connection(ipv6, n), true, 10));
        }
    }
    assert!(caches.has_entries());
    assert_eq!(caches.ipv4[1].migrate, WORK_PER_PASS);
    assert_eq!(caches.ipv6[1].migrate, WORK_PER_PASS);
    for _ in 0..8 {
        maintain(&mut caches, 10);
    }
    assert!(!caches.has_entries());
    assert_eq!(caches.counts(), (0, 0));
    assert_eq!(caches.bytes(), 0);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn cleanup_keeps_a_migration_destination_until_old_entries_are_gone() {
    let mut caches = caches();
    for n in 0..97 {
        assert!(insert(&mut caches, &connection(false, n), true, 60000));
    }
    for i in 0..caches.ipv4[1].current.capacity {
        if caches.ipv4[1].current.is_full(i) {
            caches.ipv4[1].current.entry_mut(i).expires = 10;
        }
    }
    let old_count = caches.ipv4[1].previous.len;
    for _ in 0..8 {
        maintain(&mut caches, 10);
    }
    assert_eq!(caches.ipv4[1].current.len, 0);
    assert_eq!(caches.ipv4[1].previous.len, old_count);
    assert_ne!(caches.ipv4[1].current.capacity, 0);
    assert_eq!(caches.ipv4[1].migrate, WORK_PER_PASS);
    assert!(insert(&mut caches, &connection(false, 100), false, 60000));
    assert_eq!(caches.get(&connection(false, 100), 11), Some(false));
}

#[test]
fn ordinary_insertion_does_not_sweep_expired_entries() {
    let mut caches = caches();
    for n in 0..32 {
        assert!(insert(&mut caches, &connection(false, n), true, 10));
    }
    let c = connection(false, 100);
    let mut work = CacheWork::prepare(caches.plan(&c));
    assert!(locked(|| caches.insert(
        &c,
        Decision {
            allow: true,
            expires: 60000
        },
        10,
        &mut work
    )));
    drop(work);
    assert_eq!(caches.counts(), (33, 0));
    assert_eq!(caches.get(&connection(false, 0), 10), None);
    for _ in 0..4 {
        maintain(&mut caches, 10);
    }
    assert_eq!(caches.counts(), (1, 0));
}

#[test]
fn one_expiry_pass_cleans_large_current_and_previous_tables() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        for n in 0..1537 {
            assert!(insert(
                &mut caches,
                &connection(ipv6, n),
                true,
                if n % 3 == 0 { 10 } else { 60000 }
            ));
        }
    }
    assert!(caches.cleanup_slots() > CLEANUP_SLOTS_PER_BATCH);
    assert_ne!(caches.ipv4[1].previous.capacity, 0);
    assert_ne!(caches.ipv6[1].previous.capacity, 0);
    let v4_migrate = caches.ipv4[1].migrate;
    let v6_migrate = caches.ipv6[1].migrate;
    maintain(&mut caches, 10);
    assert_eq!(caches.counts(), (1024, 1024));
    assert_eq!(caches.ipv4[1].migrate, v4_migrate);
    assert_eq!(caches.ipv6[1].migrate, v6_migrate);
    for ipv6 in [false, true] {
        for n in 0..1537 {
            assert_eq!(
                caches.get(&connection(ipv6, n), 10),
                (n % 3 != 0).then_some(true)
            );
        }
    }
    maintain(&mut caches, 60000);
    assert_eq!(caches.counts(), (0, 0));
    assert_eq!(caches.bytes(), 0);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn range_cleanup_survives_growth_between_unlocked_batches() {
    let mut caches = caches();
    for n in 0..768 {
        assert!(insert(
            &mut caches,
            &connection(false, n),
            true,
            if n % 7 == 0 { 60000 } else { 10 }
        ));
    }
    let slots = caches.cleanup_slots();
    assert_eq!(slots, 1024);
    {
        let mut work = CacheWork::empty();
        locked(|| caches.maintain_range(0, 10, &mut work));
    }
    let c = connection(false, 8000);
    {
        let mut work = CacheWork::prepare(locked(|| caches.plan(&c)));
        assert!(locked(|| caches.insert(
            &c,
            Decision {
                allow: false,
                expires: 60000
            },
            11,
            &mut work
        )));
    }
    assert_eq!(caches.ipv4[1].previous.capacity, slots);
    for start in (CLEANUP_SLOTS_PER_BATCH..slots).step_by(CLEANUP_SLOTS_PER_BATCH) {
        let mut work = CacheWork::empty();
        locked(|| caches.maintain_range(start, 10, &mut work));
    }
    assert_eq!(caches.counts(), (111, 0));
    assert_eq!(caches.get(&c, 11), Some(false));
    for n in 0..768 {
        assert_eq!(
            caches.get(&connection(false, n), 11),
            (n % 7 == 0).then_some(true)
        );
    }
}

#[test]
fn stale_growth_plans_and_clear_during_migration_free_outside_lock() {
    let mut caches = caches();
    let c = connection(false, 1);
    let plan = locked(|| caches.plan(&c));
    let stale = CacheWork::prepare(plan);
    assert!(insert(&mut caches, &c, true, 60000));
    // Another writer already created the table; the unused buffer stays in work.
    let mut stale = stale;
    assert!(locked(|| caches.insert(
        &c,
        Decision {
            allow: false,
            expires: 60000
        },
        1,
        &mut stale
    )));
    drop(stale);
    for n in 2..98 {
        assert!(insert(&mut caches, &connection(false, n), true, 60000));
    }
    assert_ne!(caches.ipv4[1].previous.capacity, 0);
    let retired = locked(|| caches.clear());
    assert_eq!(caches.bytes(), 0);
    assert!(retired.bytes() > 0);
    assert!(BYTES.with(Cell::get) > 0);
    drop(retired);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn non_tcp_udp_has_no_cache_even_if_a_caller_requests_permanent_storage() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        let transport = connection(ipv6, 1);
        assert!(insert(&mut caches, &transport, true, 60000));
        let calls = ALLOCATIONS.with(Cell::get);
        for protocol in [0, 1, 2, 47, 50, 58, 255] {
            let mut c = transport;
            c.protocol = protocol;
            assert!(caches.plan(&c).is_none());
            assert!(!caches.insert(
                &c,
                Decision {
                    allow: false,
                    expires: 60000
                },
                0,
                &mut CacheWork::empty()
            ));
            assert_eq!(caches.apply(&c, 1, 1000), None);
            assert_eq!(caches.get(&c, 1), None);
        }
        assert_eq!(ALLOCATIONS.with(Cell::get), calls);
        assert_eq!(caches.get(&transport, 1), Some(true));
    }
    assert_eq!(caches.counts(), (1, 1));
}

#[test]
fn refreshed_accept_and_fixed_drop_survive_rehash_and_expire_exactly() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        for n in 0..97 {
            assert!(insert(&mut caches, &connection(ipv6, n), n % 2 == 0, 1000));
        }
        assert_eq!(caches.apply(&connection(ipv6, 0), 999, 1000), Some(true));
        assert_eq!(caches.apply(&connection(ipv6, 1), 999, 1000), Some(false));
    }
    for _ in 0..20 {
        maintain(&mut caches, 1000);
    }
    assert_eq!(caches.counts(), (1, 1));
    for ipv6 in [false, true] {
        assert_eq!(caches.get(&connection(ipv6, 0), 1998), Some(true));
        assert_eq!(caches.apply(&connection(ipv6, 0), 1999, 1000), None);
    }
    for _ in 0..20 {
        maintain(&mut caches, 1999);
    }
    assert_eq!(caches.bytes(), 0);
}

#[test]
fn all_four_caches_retire_current_and_previous_tables_in_one_cleanup_batch() {
    let mut caches = caches();
    for protocol in [6, 17] {
        for ipv6 in [false, true] {
            for n in 0..97 {
                let mut c = connection(ipv6, n);
                c.protocol = protocol;
                assert!(insert(&mut caches, &c, true, 10));
            }
        }
    }
    for cache in &caches.ipv4 {
        assert_ne!(cache.previous.capacity, 0);
    }
    for cache in &caches.ipv6 {
        assert_ne!(cache.previous.capacity, 0);
    }
    assert_eq!(caches.counts(), (194, 194));
    let mut work = CacheWork::empty();
    locked(|| caches.maintain(10, &mut work));
    assert_eq!(caches.counts(), (0, 0));
    assert_eq!(caches.bytes(), 0);
    assert_eq!(work.retired.iter().filter(|b| !b.data.is_null()).count(), 8);
    BYTES.with(|v| assert!(v.get() > 0));
    drop(work);
    BYTES.with(|v| assert_eq!(v.get(), 0));
}

#[test]
fn growth_and_migration_are_local_to_the_selected_protocol() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        for n in 0..97 {
            assert!(insert(&mut caches, &connection(ipv6, n), true, 60000));
        }
        let old_bytes = caches.bytes();
        for n in 0..10 {
            let mut tcp = connection(ipv6, n);
            tcp.protocol = 6;
            assert_eq!(caches.get(&tcp, 1), None);
            assert!(insert(&mut caches, &tcp, false, 60000));
            assert_eq!(caches.get(&connection(ipv6, n), 1), Some(true));
        }
        assert!(caches.bytes() > old_bytes);
    }
    assert_eq!(caches.ipv4[1].migrate, WORK_PER_PASS);
    assert_eq!(caches.ipv6[1].migrate, WORK_PER_PASS);
    assert_eq!(caches.ipv4[0].previous.capacity, 0);
    assert_eq!(caches.ipv6[0].previous.capacity, 0);
    assert_eq!(caches.counts(), (107, 107));
}

#[test]
fn allocation_failure_in_one_protocol_preserves_the_other_protocol_cache() {
    let mut caches = caches();
    for ipv6 in [false, true] {
        let udp = connection(ipv6, 1);
        assert!(insert(&mut caches, &udp, true, 60000));
        let bytes = caches.bytes();
        let mut tcp = udp;
        tcp.protocol = 6;
        FAIL.with(|v| v.set(true));
        assert!(!insert(&mut caches, &tcp, false, 60000));
        assert_eq!(caches.get(&tcp, 1), None);
        assert_eq!(caches.get(&udp, 1), Some(true));
        assert_eq!(caches.bytes(), bytes);
        FAIL.with(|v| v.set(false));
        assert!(insert(&mut caches, &tcp, false, 60000));
        assert_eq!(caches.get(&tcp, 1), Some(false));
        assert_eq!(caches.get(&udp, 1), Some(true));
    }
    assert_eq!(caches.counts(), (2, 2));
}
