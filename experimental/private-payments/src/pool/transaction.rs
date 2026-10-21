//! Local proving and the existing native Circle argument encoding. No witness
//! or spend key is sent to the operator, RPC or verifier.
use super::{call::Call, wire, PoolCircuit, Statement};
use anyhow::{ensure, Result};
use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::rngs::OsRng;
use std::sync::Arc;

#[derive(Clone)]
pub struct Prover(Arc<ProvingKey<Bn254>>);
impl Prover {
    pub fn new(key: Arc<ProvingKey<Bn254>>, accepted_vk: &[u8]) -> Result<Self> {
        ensure!(
            wire::key(&key.vk)? == accepted_vk,
            "pool proving key differs from accepted verification key"
        );
        Ok(Self(key))
    }
    pub fn verification_key(&self) -> Result<Vec<u8>> {
        wire::key(&self.0.vk)
    }
    pub fn prove(&self, circuit: PoolCircuit) -> Result<Vec<u8>> {
        // Arkworks' INFO-level R1CS spans capture witness-bearing Debug fields.
        // Keep host subscribers outside synchronous proving; this also avoids
        // formatting millions of constraint spans in ordinary node logging.
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            let statement = circuit.statement.clone();
            let proof =
                Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &self.0, &mut OsRng)?;
            ensure!(
                Groth16::<Bn254>::verify_proof(
                    &prepare_verifying_key(&self.0.vk),
                    &proof,
                    &statement.fields()
                )?,
                "locally generated pool proof failed verification"
            );
            wire::proof(&proof)
        })
    }
}

pub fn parameters(statement: &Statement, call: &Call, proof: &[u8]) -> Result<serde_json::Value> {
    ensure!(
        proof.len() == 262 && proof.starts_with(b"OG16P1"),
        "invalid native pool proof format"
    );
    ensure!(
        statement.deposit == call.deposit_ou && statement.withdraw == call.withdraw_ou,
        "pool call value flow differs"
    );
    let field = |f| {
        super::encode_field(f)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    Ok(serde_json::json!([
        field(statement.new_notes),
        field(statement.new_spent),
        statement.new_count,
        statement.withdraw,
        std::str::from_utf8(&call.payout)?,
        call.valid_from_ms,
        call.expires_ms,
        call.quote
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        field(statement.authorization),
        field(statement.nullifiers[0]),
        field(statement.nullifiers[1]),
        field(statement.outputs[0]),
        field(statement.outputs[1]),
        call.boxes[0],
        call.boxes[1],
        STANDARD.encode(proof)
    ]))
}

/// Parse public calldata for an index/retry record. This does not authenticate
/// a transition: the canonical node must verify code, execution and finality.
pub fn statement(
    domain: super::Domain,
    old: (ark_bn254::Fr, ark_bn254::Fr, u64),
    context: [u8; 32],
    call: &Call,
    params: &serde_json::Value,
) -> Result<Statement> {
    let p = params
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("pool parameters are not an array"))?;
    ensure!(p.len() == 16, "pool parameter count differs");
    let scalar = |i: usize| -> Result<ark_bn254::Fr> {
        let text = p[i]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("pool field is not a string"))?;
        ensure!(
            text.len() == 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "noncanonical pool field"
        );
        let raw = (0..32)
            .map(|n| u8::from_str_radix(&text[n * 2..n * 2 + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        super::decode_field(
            &raw.try_into()
                .map_err(|_| anyhow::anyhow!("pool field width differs"))?,
        )
    };
    let next = p[2]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("invalid pool count"))?;
    ensure!(
        old.2 <= next && next <= 1_u64 << super::NOTE_DEPTH,
        "pool count outside append tree"
    );
    let result = Statement {
        domain,
        old_notes: old.0,
        old_spent: old.1,
        old_count: old.2,
        new_notes: scalar(0)?,
        new_spent: scalar(1)?,
        new_count: next,
        deposit: call.deposit_ou,
        withdraw: call.withdraw_ou,
        context,
        authorization: scalar(8)?,
        nullifiers: [scalar(9)?, scalar(10)?],
        outputs: [scalar(11)?, scalar(12)?],
    };
    let proof = STANDARD.decode(
        p[15]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid pool proof"))?,
    )?;
    ensure!(
        parameters(&result, call, &proof)? == *params,
        "pool calldata differs from its typed context"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proving_keeps_witness_spans_out_of_the_host_subscriber() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing::{
            span::{Attributes, Id, Record},
            Event, Metadata, Subscriber,
        };
        #[derive(Clone)]
        struct Observer(Arc<AtomicUsize>, Arc<AtomicUsize>);
        impl Subscriber for Observer {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, attrs: &Attributes<'_>) -> Id {
                if attrs.metadata().target() == "r1cs" {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn event(&self, event: &Event<'_>) {
                if event.metadata().target() == "private_proof_boundary_test" {
                    self.1.fetch_add(1, Ordering::Relaxed);
                }
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }
        let domain =
            super::super::Domain::new(&[3; 32], b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP")
                .unwrap();
        let key = super::super::SpendKey::random();
        let note = super::super::Note::new(key.owner(domain), 100_000, &[9; 32]).unwrap();
        let (circuit, _) = super::super::PoolIndex::default()
            .prepare(domain, &[], &[note], 100_000, 0, [9; 32])
            .unwrap();
        let pk = Arc::new(
            Groth16::<Bn254>::generate_random_parameters_with_reduction(
                circuit.clone(),
                &mut OsRng,
            )
            .unwrap(),
        );
        let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
        let observer = Observer(Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let proof = tracing::subscriber::with_default(observer.clone(), || {
            tracing::info!(target:"private_proof_boundary_test", "before proving");
            let proof = prover.prove(circuit).unwrap();
            tracing::info!(target:"private_proof_boundary_test", "after proving");
            proof
        });
        assert_eq!(proof.len(), 262);
        assert_eq!(
            observer.1.load(Ordering::Relaxed),
            2,
            "host diagnostics must remain enabled outside proving"
        );
        assert_eq!(
            observer.0.load(Ordering::Relaxed),
            0,
            "witness-bearing Arkworks spans reached the host subscriber"
        );
    }
    #[test]
    fn public_calldata_roundtrip_is_canonical_and_does_not_claim_proof_validity() {
        let circle = *b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP";
        let domain = super::super::Domain::new(&[3; 32], &circle).unwrap();
        let key = super::super::SpendKey::random();
        let view = crate::native_stealth::view_secret(&[5; 32]);
        let draft = super::super::envelope::Draft::new(
            key.owner(domain),
            10,
            &crate::native_stealth::view_public(&view),
        )
        .unwrap();
        let call = Call {
            quote: [0; 32],
            valid_from_ms: 1,
            expires_ms: 1000,
            payout: circle,
            deposit_ou: 10,
            withdraw_ou: 0,
            boxes: [draft.ciphertext.clone(), String::new()],
        };
        let context = call.context(&[3; 32], &circle, &circle).unwrap();
        let index = super::super::PoolIndex::default();
        let (circuit, _) = index
            .prepare(domain, &[], &[draft.bind(&context)], 10, 0, context)
            .unwrap();
        // Deliberately invalid curve points: parsing encodes public arguments,
        // while actual proof verification belongs to Prover and the native VM.
        let proof = [b"OG16P1".as_slice(), &[0; 256]].concat();
        let p = parameters(&circuit.statement, &call, &proof).unwrap();
        let decoded = statement(domain, index.roots(), context, &call, &p).unwrap();
        assert_eq!(decoded.fields(), circuit.statement.fields());
        for position in [4, 5, 6, 7, 13, 14] {
            let mut changed = p.clone();
            changed[position] = serde_json::json!("different");
            assert!(statement(domain, index.roots(), context, &call, &changed).is_err());
        }
        let mut changed = p.clone();
        changed[0] = serde_json::json!("F".repeat(64));
        assert!(statement(domain, index.roots(), context, &call, &changed).is_err());
        let mut changed = p.clone();
        changed[2] = serde_json::json!((1_u64 << super::super::NOTE_DEPTH) + 1);
        assert!(statement(domain, index.roots(), context, &call, &changed).is_err());
        assert!(parameters(&circuit.statement, &call, &proof[..proof.len() - 1]).is_err());
    }
}
