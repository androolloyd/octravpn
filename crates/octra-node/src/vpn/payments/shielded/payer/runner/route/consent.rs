use super::{Consent, Hop, Purchase, StoredHop};
use anyhow::{ensure, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[expect(
    clippy::suspicious_operation_groupings,
    reason = "Journal paths must exclude ancestry in both directions, including equality"
)]
pub(super) fn validate(id: [u8; 32], hops: Vec<Hop>) -> Result<(Consent, Vec<Purchase>)> {
    ensure!(
        id != [0; 32] && (2..=octravpn_core::onion::MAX_HOPS).contains(&hops.len()),
        "private route requires an identity and two or three hops"
    );
    let origin = hops[0].terms.target.chain_origin;
    let node = hops[0].payer.1.directory.shared.clone();
    let mut stored = Vec::<StoredHop>::new();
    let mut purchases = Vec::new();
    let mut names = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeMap::new();
    for hop in hops {
        let purchase = Purchase {
            payer: hop.payer,
            id: hop.purchase_id,
            terms: hop.terms,
        };
        purchase.validate()?;
        let terms = &purchase.terms;
        ensure!(
            terms.target.chain_origin == origin
                && Arc::ptr_eq(&node, &purchase.payer.1.directory.shared),
            "private route price, chain or node differs"
        );
        terms.prepaid(&hop.tariff)?;
        hop.endpoint.control(terms.target.clone())?;
        for ip in [
            hop.endpoint.pins.control.ip(),
            hop.endpoint.pins.wireguard.ip(),
        ] {
            ensure!(
                addresses
                    .insert(*ip, stored.len())
                    .is_none_or(|owner| owner == stored.len()),
                "private route endpoint IP belongs to more than one hop"
            );
        }
        let name = hop.interface_name;
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && name != "tailscale0"
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && names.insert(name.clone()),
            "invalid or duplicate private route interface"
        );
        let receipt_key = purchase.receipt_identity()?.public.0;
        ensure!(
            keys.insert(receipt_key),
            "private route repeats a receipt key"
        );
        let journal = super::super::client::canonical_parent(&hop.journal)?;
        let book = purchase.payer.0.disk.path().to_path_buf();
        for prior in &stored {
            ensure!(
                (prior.book != book || prior.purchase != purchase.id)
                    && (prior.wallet != purchase.payer.0.wallet || prior.book == book),
                "private route repeats a job or a cloned custody book"
            );
            if prior.book == book {
                ensure!(
                    prior.terms.relayer_public == terms.relayer_public
                        && prior.terms.fees == terms.fees,
                    "shared route custody changes relayer or fee consent"
                );
            } else {
                ensure!(
                    prior.terms.relayer_public != terms.relayer_public,
                    "separate route books require distinct relayer authorities"
                );
            }
        }
        stored.push(StoredHop {
            book,
            wallet: purchase.payer.0.wallet,
            receipt_key,
            purchase: purchase.id,
            terms: terms.clone(),
            tariff: hop.tariff,
            endpoint: hop.endpoint,
            journal,
            interface_name: name,
        });
        purchases.push(purchase);
    }
    for (i, hop) in stored.iter().enumerate() {
        for (j, other) in stored.iter().enumerate() {
            let book = other.book.parent().context("route book parent missing")?;
            ensure!(
                !hop.journal.starts_with(book)
                    && !book.starts_with(&hop.journal)
                    && (i == j
                        || (!hop.journal.starts_with(&other.journal)
                            && !other.journal.starts_with(&hop.journal))),
                "private route journal paths overlap"
            );
        }
    }
    Ok((
        Consent {
            version: 1,
            id,
            hops: stored,
        },
        purchases,
    ))
}
