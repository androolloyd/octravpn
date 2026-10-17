use super::*;
use ed25519_dalek::SigningKey;

fn swarm() -> Swarm {
    Swarm::new(
        super::super::Config {
            chain_id: b"diagnostic-lifecycle".to_vec(),
            node_address: b"fixture".to_vec(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: vec![],
            bootstrap: vec![],
            maximum_validators: 16,
            advertised: Endpoint {
                host: b"127.0.0.1".to_vec(),
                port: 19000,
            },
            timeouts: super::super::Timeouts::default(),
            head: Arc::new(|| (0, [0; 32])),
        },
        SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap()
}

fn completion(swarm: &Swarm, generation: u64) -> SessionCompletion {
    SessionCompletion {
        swarm: swarm.clone(),
        generation,
        direction: Direction::Outbound,
        completed: false,
    }
}

#[test]
fn queued_unpolled_cancellation_and_finished_sessions_record_once() {
    let swarm = swarm();
    swarm.state().generation = 1;
    let queued = completion(&swarm, 1);
    let unpolled = async move {
        std::future::pending::<()>().await;
        queued.finish(Ok(()));
    };
    drop(unpolled);
    completion(&swarm, 1).finish(Err(Error::from("connection_closed")));
    let rows = swarm.connection_diagnostics().outcomes;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .find(|row| row.outcome == Outcome::Cancelled)
            .unwrap()
            .count,
        1
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.outcome == Outcome::RemoteClose)
            .unwrap()
            .count,
        1
    );
}

#[test]
fn stale_generation_results_and_cancellation_do_not_populate_a_new_run() {
    let swarm = swarm();
    swarm.state().generation = 1;
    let old = completion(&swarm, 1);
    {
        let mut state = swarm.state();
        state.generation = 2;
        state.connections = diagnostics::Counters::default();
    }
    drop(old);
    for phase in [
        Phase::Transport,
        Phase::Handshake,
        Phase::Admission,
        Phase::Session,
    ] {
        swarm.note(1, Direction::Outbound, phase, Outcome::Other);
    }
    assert!(swarm.connection_diagnostics().outcomes.is_empty());
    completion(&swarm, 2).finish(Ok(()));
    let snapshot = swarm.connection_diagnostics();
    assert_eq!(snapshot.generation, 2);
    assert_eq!(snapshot.outcomes.len(), 1);
    assert_eq!(snapshot.outcomes[0].outcome, Outcome::LocalClose);
}
