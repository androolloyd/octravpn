// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::private::{boolean, field, string};
use crate::{circle_store, state_batch::Snapshot};
use octra_node_protocol::{circle_records::Kind, circles, rpc::Fault};

pub(super) fn read(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    kind: Kind,
    subject: &[u8],
) -> Result<(), Fault> {
    let unavailable = |_| Fault::new(110, b"service unavailable");
    let record = circle_store::record(state, circle, kind, subject).map_err(unavailable)?;
    string(out, kind.subject_field().as_bytes(), subject);
    field(out, b"materialized", boolean(record.materialized()));
    if matches!(kind, Kind::BalanceBinding | Kind::RegisterBinding) {
        let current = record.get(b"current_state_ref");
        out.extend_from_slice(b",\"current_state_ref\":");
        super::optional(out, current);
        let descriptor = match current.and_then(|raw| circles::state_locator(raw).ok()) {
            Some(locator) => circle_store::descriptor(state, circle, locator.path_key.as_bytes())
                .map_err(unavailable)?,
            None => None,
        };
        field(
            out,
            b"descriptor_materialized",
            boolean(descriptor.is_some()),
        );
        field(out, b"descriptor", &descriptor.unwrap_or_default().encode());
    }
    field(out, kind.prefix(), &record.encode());
    Ok(())
}
