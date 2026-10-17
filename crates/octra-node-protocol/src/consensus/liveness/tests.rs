use super::*;

fn sample(now: f64) -> Sample<'static> {
    Sample {
        height: 7,
        round: 0,
        step: b"propose",
        expected: 7,
        now,
        source: b"periodic",
        stall_sec: 150.0,
        step_timeout_sec: Some(15.0),
        observer: false,
        voting: true,
        catchup_active: false,
        quarantine_active: false,
        state_attested: true,
        pending_finalized: false,
        proposal_active: false,
    }
}

#[test]
fn resets_only_after_stall_and_every_admission_guard() {
    let state = record(&State::new(0.0), &sample(10.0)).state;
    assert!(record(&state, &sample(159.999)).reset.is_none());
    let ready = sample(160.0);
    let reset = record(&state, &ready).reset.unwrap();
    assert_eq!(reset.resets, 1);
    assert_eq!(reset.state_age.to_bits(), 150.0_f64.to_bits());
    for index in 0..8 {
        let mut blocked = ready;
        match index {
            0 => blocked.observer = true,
            1 => blocked.voting = false,
            2 => blocked.catchup_active = true,
            3 => blocked.quarantine_active = true,
            4 => blocked.state_attested = false,
            5 => blocked.pending_finalized = true,
            6 => blocked.proposal_active = true,
            7 => blocked.expected += 1,
            _ => unreachable!(),
        }
        assert!(record(&state, &blocked).reset.is_none(), "guard {index}");
    }
    let reset = record(&state, &ready);
    assert!(record(&reset.state, &sample(309.999)).reset.is_none());
    assert_eq!(record(&reset.state, &sample(310.0)).state.resets, 2);
}

#[test]
fn round_changes_retain_height_age_but_wait_for_protocol_timeout() {
    let mut value = sample(0.0);
    let initial = record(&State::new(0.0), &value).state;
    value.round = 1;
    value.step_timeout_sec = Some(100.0);
    value.now = 100.0;
    let later_round = record(&initial, &value).state;
    value.now = 229.999;
    assert!(record(&later_round, &value).reset.is_none());
    value.now = 230.0;
    let reset = record(&later_round, &value).reset.unwrap();
    assert_eq!(reset.state_age.to_bits(), 130.0_f64.to_bits());
    assert_eq!(reset.height_age.to_bits(), 230.0_f64.to_bits());
    value.round = 0;
    let first_round = record(
        &initial,
        &Sample {
            now: 100.0,
            ..value
        },
    )
    .state;
    assert!(record(&first_round, &value).reset.is_some());
}

#[test]
fn proposal_work_refreshes_state_age_without_erasing_height_age() {
    let state = record(&State::new(0.0), &sample(0.0)).state;
    let active = Sample {
        proposal_active: true,
        now: 140.0,
        ..sample(0.0)
    };
    let state = record(&state, &active).state;
    assert_eq!(state.key_started_at.to_bits(), 140.0_f64.to_bits());
    assert_eq!(state.height_started_at.to_bits(), 0.0_f64.to_bits());
    assert!(record(&state, &sample(200.0)).reset.is_none());
    let changed = Sample {
        round: 1,
        now: 200.0,
        ..sample(0.0)
    };
    let state = record(&state, &changed).state;
    assert!(record(
        &state,
        &Sample {
            now: 244.999,
            ..changed
        }
    )
    .reset
    .is_none());
    assert!(record(
        &state,
        &Sample {
            now: 245.0,
            ..changed
        }
    )
    .reset
    .is_some());
}

#[test]
fn native_float_selection_and_counter_wrap_are_retained() {
    let nan = f64::from_bits(0x7ff8_0000_0000_0042);
    let value = Sample {
        stall_sec: nan,
        step_timeout_sec: Some(-30.0),
        ..sample(0.0)
    };
    assert_eq!(effective_stall_sec(&value).to_bits(), 0.0_f64.to_bits());
    let value = Sample {
        stall_sec: -0.0,
        ..value
    };
    assert_eq!(effective_stall_sec(&value).to_bits(), (-0.0_f64).to_bits());
    let value = Sample {
        step_timeout_sec: Some(nan),
        ..value
    };
    assert!(effective_stall_sec(&value).is_nan());
    let mut state = record(&State::new(0.0), &sample(0.0)).state;
    state.resets = (1_i64 << 62) - 1;
    assert_eq!(record(&state, &sample(150.0)).state.resets, -(1_i64 << 62));
}
