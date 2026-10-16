//! Native private/PVAC reads from one captured canonical tree and public blobs.
use super::{account_store, rpc, Arc, Context, Document, Fault, StateBatch, Value};
use octra_node_protocol::{
    light_rpc::json::{self, boolean, number, object, string},
    private_account_rpc as wire,
};
use octra_node_runtime::private_account_rpc as projection;

fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
pub(super) async fn read(
    host: &Arc<Context>,
    method: &[u8],
    doc: Arc<Document>,
    params: Value,
) -> std::result::Result<Vec<u8>, Fault> {
    if matches!(
        method,
        b"octra_stealthOutputs" | b"octra_stealthOutputsPage" | b"octra_stealthOutputsById"
    ) {
        let ids = if method == b"octra_stealthOutputsById" {
            Some(wire::ids(&doc, &params)?)
        } else {
            None
        };
        let page = if ids.is_none() {
            Some(wire::page(
                &doc,
                &params,
                method == b"octra_stealthOutputs",
            )?)
        } else {
            None
        };
        let view = host.node.snapshot().map_err(unavailable)?;
        return host
            .executor
            .read(move || match ids {
                Some(ids) => projection::outputs_by_id(view.state(), &ids),
                None => projection::outputs_page(view.state(), page.expect("stealth page")),
            })
            .await;
    }
    if method == b"octra_pvacMigrationStatus" {
        let view = host.node.snapshot().map_err(unavailable)?;
        let rules = host.executor.private_account_rules(&view).await?;
        let address = rpc::require_address(&doc, &params, 0, "address")?.to_vec();
        let captured = view.clone();
        let account_address = address.clone();
        let cipher = host
            .executor
            .read(move || {
                let account = account_store::load(
                    &StateBatch::from_snapshot(captured.state().clone()),
                    &account_address,
                )
                .map_err(unavailable)?
                .ok_or_else(|| Fault::new(100, b"sender not found"))?;
                Ok(account.encrypted_balance.unwrap_or_else(|| b"0".to_vec()))
            })
            .await?;
        let cipher: Arc<[u8]> = cipher.into();
        let classified = host
            .executor
            .classify_migration(view, address.clone(), cipher.clone())
            .await?;
        let admission = host.executor.migration_admission();
        return projection::migration_status(
            &address,
            &cipher,
            classified,
            rules,
            admission.as_deref(),
        );
    }
    let address = rpc::require_address(&doc, &params, 0, "address")?.to_vec();
    if method == b"octra_encryptedBalance" {
        wire::encrypted_auth(&doc, &params, &address)?;
    }
    let view = host.node.snapshot().map_err(unavailable)?;
    let native = host.executor.clone();
    let method = method.to_vec();
    let node = host.node.clone();
    host.executor
        .read(move || match method.as_slice() {
            b"octra_pvacPubkey" | b"octra_pvacStatus" => {
                let public = native.public_pvac(&view, &address).map_err(unavailable)?;
                if method == b"octra_pvacPubkey" {
                    let mut fields = vec![
                        ("address", string(&address)),
                        (
                            "pvac_pubkey",
                            match &public {
                                None => json::null(),
                                Some(raw) => {
                                    if raw.len().div_ceil(3) * 4 > rpc::MAX_SINGLE {
                                        return Err(Fault::response_limit());
                                    }
                                    string(json::base64(raw))
                                }
                            },
                        ),
                    ];
                    if let Some(raw) = public {
                        fields.push(("pubkey_size", number(raw.len())));
                    }
                    Ok(object(&fields))
                } else {
                    let bound = view
                        .state()
                        .get(&[b"pvac_hashes", &address])
                        .is_some_and(|raw| raw != b"none");
                    let format = public.as_ref().map(|raw| {
                        if raw.first() == Some(&0xec) {
                            b"compressed".as_slice()
                        } else {
                            b"raw".as_slice()
                        }
                    });
                    Ok(object(&[
                        ("address", string(&address)),
                        ("has_pvac_pubkey", boolean(public.is_some())),
                        (
                            "pubkey_size",
                            public
                                .as_ref()
                                .map_or_else(json::null, |raw| number(raw.len())),
                        ),
                        ("deserializable", json::null()),
                        ("canonical_binding", boolean(public.is_some() && bound)),
                        ("pubkey_format", json::optional(format)),
                    ]))
                }
            }
            b"octra_encryptedCipher" | b"octra_encryptedBalance" | b"octra_viewPubkey" => {
                let account = node
                    .account_for_read(
                        &address,
                        account_store::load(
                            &StateBatch::from_snapshot(view.state().clone()),
                            &address,
                        )
                        .map_err(unavailable)?,
                    )
                    .map_err(unavailable)?;
                if method == b"octra_viewPubkey" {
                    return wire::view_pubkey(
                        &address,
                        account
                            .as_ref()
                            .and_then(|account| account.public_key.as_deref()),
                    );
                }
                if method == b"octra_encryptedCipher" {
                    let account = account.ok_or_else(|| Fault::new(100, b"sender not found"))?;
                    return projection::encrypted_cipher(
                        &address,
                        account.encrypted_balance.as_deref().unwrap_or(b"0"),
                    );
                }
                let public = native.public_pvac(&view, &address).map_err(unavailable)?;
                let cipher = account
                    .as_ref()
                    .and_then(|account| account.encrypted_balance.as_deref())
                    .unwrap_or(b"0");
                if cipher.len() > rpc::MAX_SINGLE {
                    return Err(Fault::response_limit());
                }
                Ok(object(&[
                    ("address", string(&address)),
                    ("cipher", string(cipher)),
                    ("has_pvac_pubkey", boolean(public.is_some())),
                ]))
            }
            _ => Err(Fault::missing(&method)),
        })
        .await
}
