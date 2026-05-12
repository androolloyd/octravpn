//! Property tests for session-state encoding round-trips.

use octravpn_core::session::{SessionId, SessionState};
use proptest::prelude::*;

proptest! {
    #[test]
    fn session_id_hex_round_trip(bytes in any::<[u8; 32]>()) {
        let id = SessionId::new(bytes);
        let s = id.to_hex();
        let parsed = SessionId::from_hex(&s).unwrap();
        prop_assert_eq!(parsed.into_bytes(), bytes);
    }

    #[test]
    fn session_state_u8_round_trip(v in 0u8..=3u8) {
        let s = SessionState::from_u8(v).unwrap();
        match v {
            0 => prop_assert_eq!(s, SessionState::Open),
            1 => prop_assert_eq!(s, SessionState::Settled),
            2 => prop_assert_eq!(s, SessionState::Refunded),
            3 => prop_assert_eq!(s, SessionState::Slashed),
            _ => unreachable!(),
        }
    }
}
