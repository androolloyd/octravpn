//! Independently authenticate the fixture's stopped client records. This is
//! read-only observation, with no wallet lease, counter reset or admission API.
use super::{array, number, raw32, text};
use octravpn_core::{
    payments::{PlanBinding, PrivateTarget, SignedShieldedStatus, Tariff},
    sealed::{Key, Protection},
    KeyPair, PublicKey,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

// Exact durable transcript, kept separate from any SDK writer constructor.
#[derive(Serialize)]
struct Identity {
    binding: PlanBinding,
    tariff: Tariff,
    original_budget_ou: u64,
    prepaid_bytes: Vec<u64>,
    receipt_key: PublicKey,
    private: Private,
}
#[derive(Serialize)]
struct Private {
    target: PrivateTarget,
    operator_generation: u64,
}

pub(super) fn collect(rows: &[(u8, Value)], key: &Key, meta: &Value, root: &Path) -> Value {
    let mut results = Vec::new();
    for (_, phase) in rows.iter().filter(|(kind, _)| *kind == 13) {
        assert_eq!(number(&phase["version"]), 1);
        let transport = &phase["transport"];
        let hop = usize::try_from(number(&transport["hop"]["position"])).unwrap();
        assert!(hop < 2 && number(&transport["hop"]["count"]) == 2);
        let path = root.join(format!("private-hop-{hop}"));
        assert_eq!(Path::new(text(&transport["journal"])), path);
        let plan: octravpn_client::AcceptedPrivatePlan =
            serde_json::from_value(transport["plan"].clone()).unwrap();
        let seed = key
            .derive_bytes(
                b"private purchase receipt v1",
                &[
                    raw32(&meta["wallet"]).as_slice(),
                    &raw32(&phase["purchase"]),
                ]
                .concat(),
            )
            .unwrap();
        let receipt = KeyPair::from_secret_bytes(&seed);
        let identity = Identity {
            binding: plan.binding,
            tariff: plan.tariff,
            original_budget_ou: plan.quote_ceiling_ou,
            prepaid_bytes: plan.prepaid_bytes,
            receipt_key: receipt.public,
            private: Private {
                target: plan.target,
                operator_generation: plan.operator_generation,
            },
        };
        let mut hash = Sha256::new();
        hash.update(b"Octranet private client journal v1\0");
        hash.update(serde_json::to_vec(&identity).unwrap());
        let scope: [u8; 32] = hash.finalize().into();
        let protection = Protection::new(
            Key::from_bytes(*receipt.secret_bytes())
                .derive(b"private client journal", &scope)
                .unwrap(),
            scope,
        );
        let encrypted =
            crate::bootstrap::read_limited(&path.join("state.json"), 2 * 1024 * 1024).unwrap();
        let plaintext = protection.open(&encrypted).unwrap();
        let envelope: Value = serde_json::from_slice(&plaintext).unwrap();
        let prefix = b"{\"payload\":";
        assert!(plaintext.starts_with(prefix));
        let marker = b",\"checksum\":\"";
        let end = plaintext
            .windows(marker.len())
            .rposition(|part| part == marker)
            .unwrap();
        let mut checksum = Sha256::new();
        checksum.update(b"Octranet client prepaid state v2\0");
        checksum.update(&plaintext[prefix.len()..end]);
        assert_eq!(
            text(&envelope["checksum"]),
            hex::encode(checksum.finalize())
        );
        let payload = &envelope["payload"];
        assert_eq!(
            payload["identity"],
            serde_json::to_value(&identity).unwrap()
        );
        let local = array(&payload["local_bytes"]);
        let uncertain = array(&payload["uncertain_bytes"]);
        let purchased = identity.prepaid_bytes;
        assert!(local.len() == purchased.len() && uncertain.len() == local.len());
        let mut used = local
            .iter()
            .zip(&uncertain)
            .map(|(a, b)| a.checked_add(*b).unwrap())
            .collect::<Vec<_>>();
        let mut pending = vec![0; local.len()];
        if !payload["pending"].is_null() {
            let saved = &payload["pending"];
            assert!(
                number(&saved["sequence"]) > 0
                    && number(&saved["sequence"]) == number(&payload["handoff_sequence"])
            );
            let class = usize::try_from(number(&saved["traffic_class"])).unwrap();
            pending[class] = number(&saved["bytes"]);
            assert!(pending[class] > 0);
            used[class] = used[class].checked_add(pending[class]).unwrap();
        }
        assert!(used.iter().zip(&purchased).all(|(used, paid)| used <= paid));
        let signed: SignedShieldedStatus =
            serde_json::from_value(payload["private_status"].clone()).unwrap();
        signed.verify().unwrap();
        assert!(
            signed.status.connection.binding == identity.binding
                && signed.operator_key == identity.private.target.operator
                && signed.status.connection.sequence == number(&payload["connection_sequence"])
        );
        results.push(json!({"hop":hop,"local":local,"uncertain":uncertain,"pending":pending,"used":used,"purchased":purchased,
            "connection_sequence":number(&payload["connection_sequence"])}));
    }
    results.sort_by_key(|value| number(&value["hop"]));
    assert!(
        results.len() == 2 && number(&results[0]["hop"]) == 0 && number(&results[1]["hop"]) == 1
    );
    json!(results)
}
