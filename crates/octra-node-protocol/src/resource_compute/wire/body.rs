use super::{Accelerator, Capability, Commitment, Offer, Reader, Reveal, Vote, Wire, Writer};
use crate::oce1;
type Decoded<T> = std::result::Result<T, oce1::Error>;
// One explicit ordered schema per native record. Numeric decoders retain the
// signed u32 interpretation used by Oce1.get_u32_int; memory is separate.
macro_rules! schema {
    ($type:ty {$($field:ident:$kind:ident),* $(,)?}) => {
        impl Wire for $type {
            fn put(&self,out: &mut Writer) -> Decoded<()> { $(put::$kind(out,&self.$field)?;)* Ok(()) }
            fn get(input: &mut Reader<'_>) -> Decoded<Self> { Ok(Self {$($field:get::$kind(input)?),*}) }
        }
    };
}
// The schema macro passes every field by reference through the same encoder API.
#[allow(clippy::trivially_copy_pass_by_ref)]
mod put {
    use super::{Accelerator, Decoded, Writer};
    pub(super) fn text(out: &mut Writer, value: &[u8]) -> Decoded<()> {
        out.put_bytes(value)
    }
    pub(super) fn hash(out: &mut Writer, value: &[u8]) -> Decoded<()> {
        out.put_hash32(value)
    }
    pub(super) fn signature(out: &mut Writer, value: &[u8]) -> Decoded<()> {
        out.put_sig64(value)
    }
    pub(super) fn int64(out: &mut Writer, value: &i64) -> Decoded<()> {
        out.put_u64(*value as u64)
    }
    pub(super) fn int32(out: &mut Writer, value: &i64) -> Decoded<()> {
        out.put_u32(*value as u32)
    }
    pub(super) fn lanes(out: &mut Writer, value: &i64) -> Decoded<()> {
        out.put_u16(*value as u16)
    }
    pub(super) fn accelerator(out: &mut Writer, value: &Accelerator) -> Decoded<()> {
        out.put_u8(value.code())
    }
}
mod get {
    use super::{oce1, Accelerator, Decoded, Reader};
    pub(super) fn text(input: &mut Reader<'_>) -> Decoded<Vec<u8>> {
        Ok(input.get_bytes_bounded(128)?.to_vec())
    }
    pub(super) fn hash(input: &mut Reader<'_>) -> Decoded<Vec<u8>> {
        Ok(input.get_hash32()?.to_vec())
    }
    pub(super) fn signature(input: &mut Reader<'_>) -> Decoded<Vec<u8>> {
        Ok(input.get_sig64()?.to_vec())
    }
    pub(super) fn int64(input: &mut Reader<'_>) -> Decoded<i64> {
        Ok(input.get_u64()? as i64)
    }
    pub(super) fn int32(input: &mut Reader<'_>) -> Decoded<i64> {
        Ok(i64::from(input.get_u32()? as i32))
    }
    pub(super) fn lanes(input: &mut Reader<'_>) -> Decoded<i64> {
        Ok(i64::from(input.get_u16()?))
    }
    pub(super) fn accelerator(input: &mut Reader<'_>) -> Decoded<Accelerator> {
        Accelerator::from_code(input.get_u8()?).map_err(|e| oce1::Error::new(e.as_bytes().to_vec()))
    }
}
schema!(Offer {
    chain_id: text,
    offered_epoch: int64,
    expires_epoch: int64,
    coordinator: text,
    validator_set_root: hash,
    circle_id: text,
    model_epoch: int64,
    model_state_root: hash,
    graph_root: hash,
    model_root: hash,
    program_root: hash,
    executor_root: hash,
    min_memory_bytes: int64,
    request_bytes: int32,
    response_bytes: int32,
    signature: signature,
});
schema!(Capability {
    chain_id: text,
    observed_epoch: int64,
    valid_until: int64,
    validator_set_root: hash,
    node_id: text,
    circle_id: text,
    model_epoch: int64,
    model_state_root: hash,
    graph_root: hash,
    model_root: hash,
    program_root: hash,
    executor_root: hash,
    evidence_root: hash,
    accelerator: accelerator,
    lanes: lanes,
    memory_bytes: int64,
    max_request_bytes: int32,
    max_response_bytes: int32,
    signature: signature,
});
schema!(Commitment {
    chain_id: text,
    offer_id: hash,
    commit_epoch: int64,
    node_id: text,
    graph_root: hash,
    model_root: hash,
    program_root: hash,
    executor_root: hash,
    nonce_hash: hash,
    signature: signature,
});
schema!(Reveal {
    chain_id: text,
    offer_id: hash,
    commit_epoch: int64,
    reveal_epoch: int64,
    node_id: text,
    graph_root: hash,
    model_root: hash,
    program_root: hash,
    executor_root: hash,
    nonce: text,
    evidence_root: hash,
    signature: signature,
});
schema!(Vote {
    request_id: hash,
    node_id: text,
    output_hash: hash,
    trace_root: hash,
    output_bytes: int32,
    steps: int64,
    operations: int64,
    signature: signature,
});
