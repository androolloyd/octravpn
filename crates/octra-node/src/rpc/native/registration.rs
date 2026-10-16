//! Native BFT registration checks and authenticated local staging removal.
use super::{Arc, Context, Document, Fault, Value};
use octra_node_protocol::registration_rpc as wire;

fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
pub(super) async fn write(
    host: &Arc<Context>,
    method: &[u8],
    doc: Arc<Document>,
    params: Value,
) -> std::result::Result<Vec<u8>, Fault> {
    match method {
        b"octra_registerPublicKey" => host.register_public_key(doc, params).await,
        b"octra_registerPvacPubkey" => {
            let request = host
                .executor
                .read(move || {
                    wire::Pvac::parse(
                        &doc,
                        &params,
                        hex::encode(octra_hfhe::seeded_rng::aes_kat()).as_bytes(),
                    )
                })
                .await?;
            let committed = host.node.snapshot().map_err(unavailable)?;
            let native = host.executor.clone();
            host.executor
                .read(move || {
                    let existing = native
                        .registration_existing(&committed, &request)
                        .map_err(unavailable)?;
                    request.response(existing)
                })
                .await
        }
        b"staging_remove" => {
            let request = wire::Removal::parse(&doc, &params)?;
            host.remove(request).await
        }
        _ => Err(Fault::missing(method)),
    }
}
