//! Native PVAC proof-channel routing. Actor FHE work retains its independent
//! queue; only classified PVAC proofs enter Compute_pool's bounded channel.
use super::Request as Private;
use crate::crypto_worker::Request;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Fhe,
    Required,
    Speculative,
}
pub(crate) fn kind(request: &Request) -> Kind {
    match request {
        Request::Private(
            Private::Amount { .. }
            | Private::Claim { .. }
            | Private::RangeBound { .. }
            | Private::Range { .. }
            | Private::Cell { .. },
        ) => Kind::Required,
        Request::CircleVerify(_) => Kind::Speculative,
        Request::Verify {
            asynchronous: false,
            ..
        } => Kind::Speculative,
        #[cfg(feature = "test-helpers")]
        Request::ProofFault { required, .. } => {
            if *required {
                Kind::Required
            } else {
                Kind::Speculative
            }
        }
        _ => Kind::Fhe,
    }
}
