//! Property tests for the receipt journal (monotonicity, rejection,
//! per-session isolation, torn-tail tolerance).

use std::fs::OpenOptions;

use proptest::prelude::*;

use crate::session::SessionId;

use super::codec::RECORD_SIZE;
use super::{JournalError, ReceiptJournal};

fn id(b: u8) -> SessionId {
    SessionId::new([b; 32])
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// Property: a strictly-monotonic bump sequence lands at the
    /// highest seq value.
    #[test]
    fn prop_monotonic_sequence_lands_at_max(
        session_byte in any::<u8>(),
        seqs in prop::collection::vec(1u64..1000, 1..50),
    ) {
        let j = ReceiptJournal::in_memory();
        let sess = id(session_byte);
        let mut sorted = seqs;
        sorted.sort_unstable();
        sorted.dedup();
        let max = *sorted.last().unwrap();
        for s in sorted {
            j.bump(&sess, s).unwrap();
        }
        prop_assert_eq!(j.floor(&sess), max);
    }

    /// Property: any bump with `proposed <= floor` rejects.
    #[test]
    fn prop_non_monotonic_bumps_always_reject(
        session_byte in any::<u8>(),
        floor in 1u64..1000,
        proposed in 0u64..1000,
    ) {
        prop_assume!(proposed <= floor);
        let j = ReceiptJournal::in_memory();
        let sess = id(session_byte);
        j.bump(&sess, floor).unwrap();
        let err = j.bump(&sess, proposed).unwrap_err();
        let is_nm = matches!(err, JournalError::SeqNotMonotonic { .. });
        prop_assert!(is_nm);
        prop_assert_eq!(j.floor(&sess), floor);
    }

    /// Property: bumping session A never affects session B.
    #[test]
    fn prop_per_session_isolation(
        a_byte in any::<u8>(),
        b_byte in any::<u8>(),
        a_seq in 1u64..1000,
        b_seq in 1u64..1000,
    ) {
        prop_assume!(a_byte != b_byte);
        let j = ReceiptJournal::in_memory();
        j.bump(&id(a_byte), a_seq).unwrap();
        j.bump(&id(b_byte), b_seq).unwrap();
        prop_assert_eq!(j.floor(&id(a_byte)), a_seq);
        prop_assert_eq!(j.floor(&id(b_byte)), b_seq);
    }

    /// Property: any torn tail (1..RECORD_SIZE-1 bytes) drops
    /// silently on replay.
    #[test]
    fn prop_torn_tail_is_silently_dropped(
        tail_len in 1usize..RECORD_SIZE,
    ) {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn-prop.bin");
        let j = ReceiptJournal::open(&path).unwrap();
        j.bump(&id(0x11), 1).unwrap();
        j.bump(&id(0x22), 2).unwrap();
        drop(j);

        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&vec![0xFFu8; tail_len]).unwrap();
        drop(f);

        let r = ReceiptJournal::open(&path).unwrap();
        prop_assert_eq!(r.floor(&id(0x11)), 1);
        prop_assert_eq!(r.floor(&id(0x22)), 2);
    }
}
