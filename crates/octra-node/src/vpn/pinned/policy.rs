//! Price comes from the immutable policy captured atomically by session open.
use super::{
    ensure, Address, AnnounceSessionRequest, Application, Committed, Digest, Engine, Pinned,
    Result, Sha256, Snapshot, STANDARD,
};
use octravpn_core::{
    v3_policy::OperatorPolicy,
    v3_state_root::{snapshot_path, StateRoot},
};

const MAX_BYTES: i64 = 65_536;
fn asset(state: &Snapshot, circle: &[u8], path: &str) -> Result<Vec<u8>> {
    let value =
        octra_node_runtime::circle_assets::public_asset(state, circle, path.as_bytes(), MAX_BYTES)?;
    ensure!(
        value.resource_mode == b"public_resources"
            && value.meta.body_mode == octra_node_protocol::circles::ResourceMode::Public,
        "VPN price policy must be a public resource"
    );
    ensure!(
        value.body_b64.len() <= (MAX_BYTES as usize).div_ceil(3) * 4,
        "VPN policy encoding exceeds bound"
    );
    let raw = STANDARD.decode(value.body_b64)?;
    ensure!(
        raw.len() as i64 == value.meta.size_bytes
            && hex::encode(Sha256::digest(&raw)).as_bytes() == value.meta.blob_hash,
        "VPN policy resource hash or size differs"
    );
    Ok(raw)
}
fn snapshot(state: &Snapshot, circle: &[u8], hash: &str, logical: &str) -> Result<Vec<u8>> {
    let path = snapshot_path(hash, logical)?;
    let key = octra_node_protocol::circles::path_key(path.as_bytes());
    let exists = [b"meta".as_slice(), b"body_b64"].iter().any(|name| {
        state
            .get(&[
                b"circles",
                circle,
                b"assets",
                b"by_hash",
                key.as_bytes(),
                name,
            ])
            .is_some()
    });
    asset(state, circle, if exists { &path } else { logical })
}
impl Pinned {
    pub(crate) async fn quote(
        &self,
        view: &Committed,
        request: &AnnounceSessionRequest,
        bytes: u64,
    ) -> Result<u64> {
        self.check(view, &self.domain)?;
        let (key, _) = self.session_identity(view, &request.session_id)?;
        let deposit = self.uint(view.state(), b"session_deposit", Some(&key))?;
        let opener = Address::try_from_display(std::str::from_utf8(&self.required(
            view.state(),
            b"session_opener",
            Some(&key),
        )?)?)?;
        ensure!(
            opener == Address::from_pubkey(&request.opener_pubkey.0),
            "VPN session tariff opener differs"
        );
        self.opening(view, request, &key, &opener, deposit).await?;
        let anchor = self.required(view.state(), b"session_policy_root", Some(&key))?;
        let anchor = std::str::from_utf8(&anchor)?;
        let circle = self.config.operator_circle.as_bytes();
        let metadata = StateRoot::decode_lenient(&snapshot(
            view.state(),
            circle,
            anchor,
            "/state-root.json",
        )?)?;
        ensure!(
            metadata.circle_id == self.config.operator_circle && metadata.anchor_hex()? == anchor,
            "VPN session policy anchor differs"
        );
        let policy = OperatorPolicy::decode_lenient(&snapshot(
            view.state(),
            circle,
            &metadata.policy_hash,
            "/policy.json",
        )?)?;
        policy.validate()?;
        ensure!(
            policy.hash_hex()? == metadata.policy_hash,
            "VPN session tariff hash differs"
        );
        ensure!(
            policy
                .unknown
                .get("receipt_pubkey_b64")
                .and_then(serde_json::Value::as_str)
                == Some(std::str::from_utf8(&self.receipt_key)?),
            "VPN session tariff receipt identity differs"
        );
        let application = match self.config.application {
            Application::Program => "program",
            Application::Circle => "circle",
        };
        ensure!(
            policy
                .unknown
                .get("application")
                .and_then(serde_json::Value::as_str)
                == Some(application)
                && policy
                    .unknown
                    .get("receipt_chain_id")
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(self.domain.chain_id)),
            "VPN session tariff application domain differs"
        );
        ensure!(
            policy.effective_epoch <= self.uint(view.state(), b"session_opened_at", Some(&key))?,
            "VPN session tariff is not effective at opening"
        );
        let net = u128::from(bytes / 1_048_576) * u128::from(policy.price_per_mb_shared);
        Ok(net.min(u128::from(deposit)) as u64)
    }
}
