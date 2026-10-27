use super::*;
use std::collections::HashSet;

fn generated<const N: usize>(count: usize, shared: bool) -> (Vec<Connection>, Vec<Connection>) {
    let seed = 0x4859564341434845;
    (
        (0..count)
            .map(|i| connection::<N>(i as u32, shared, seed))
            .collect(),
        (count..count * 2)
            .map(|i| connection::<N>(i as u32, shared, seed))
            .collect(),
    )
}

#[test]
fn generated_tuples_are_unique_and_misses_are_disjoint() {
    fn check<const N: usize>() {
        for shared in [false, true] {
            let (entries, misses) = generated::<N>(10000, shared);
            let keys: HashSet<_> = entries.iter().map(Key::<N>::from_connection).collect();
            assert_eq!(keys.len(), entries.len());
            let missing: HashSet<_> = misses.iter().map(Key::<N>::from_connection).collect();
            assert_eq!(missing.len(), misses.len());
            assert!(keys.is_disjoint(&missing));
        }
    }
    check::<4>();
    check::<16>();
}

#[test]
fn every_container_agrees_on_tuple_expiration_and_refresh_semantics() {
    fn check<const N: usize>() {
        for shared in [false, true] {
            let (entries, misses) = generated::<N>(128, shared);
            for kind in 0..NAMES.len() {
                Store::<N>::build(kind, &entries).check(&entries, &misses);
            }
        }
    }
    check::<4>();
    check::<16>();
}

#[test]
fn mixed_probes_have_ten_percent_misses_and_balanced_hit_decisions() {
    let (entries, misses) = generated::<4>(1000, false);
    let workloads = workloads(&entries, &misses, 1000, 123);
    let mixed = workloads
        .iter()
        .find(|w| w.name == "mixed90_apply")
        .unwrap();
    for (answer, expected) in [(0, 100), (1, 450), (2, 450)] {
        assert_eq!(
            mixed.queries.iter().filter(|q| q.answer == answer).count(),
            expected
        );
    }
    assert_eq!(mixed.checksum, 1350);
    for name in ["hit_read", "hit_apply"] {
        let hits = workloads.iter().find(|w| w.name == name).unwrap();
        let unique: HashSet<_> = hits
            .queries
            .iter()
            .map(|q| Key::<4>::from_connection(&q.connection))
            .collect();
        assert_eq!(unique.len(), entries.len());
    }
}

#[test]
fn production_word_hash_matches_the_selected_standard_map_hasher() {
    fn check<const N: usize>() {
        for shared in [false, true] {
            let (entries, _) = generated::<N>(10000, shared);
            let hasher = BuildHasherDefault::<WordHasher>::default();
            for c in entries {
                let key = Key::<N>::from_connection(&c);
                assert_eq!(driver::hash(&key), hasher.hash_one(key));
            }
        }
    }
    check::<4>();
    check::<16>();
}

#[test]
fn standard_hash_tables_keep_full_identity_even_with_identical_hashes() {
    #[derive(Default)]
    struct CollisionHasher;
    impl Hasher for CollisionHasher {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _: &[u8]) {}
    }
    fn check<const N: usize>() {
        let (entries, misses) = generated::<N>(64, false);
        let mut map: HashMap<Key<N>, driver::Decision, BuildHasherDefault<CollisionHasher>> =
            HashMap::default();
        for (i, c) in entries.iter().enumerate() {
            map.insert(
                Key::from_connection(c),
                driver::Decision {
                    allow: i % 2 == 0,
                    expires: EXPIRES,
                },
            );
        }
        assert_eq!(map.len(), entries.len());
        super::check(&mut map, &entries, &misses);
    }
    check::<4>();
    check::<16>();
}
