use super::{bill, refused, unavailable, Call, Measured, Receipt, Result};
use octra_node_protocol::{
    circle_wasm::codec::Scalar, resource_compute::bill::Outcome, transaction::json_string,
};

fn output(value: &Scalar) -> Vec<u8> {
    match value {
        Scalar::Null => b"null".to_vec(),
        Scalar::Bool(true) => b"true".to_vec(),
        Scalar::Bool(false) => b"false".to_vec(),
        Scalar::Integer(raw) => raw.clone(),
        Scalar::String(raw) => {
            let mut out = Vec::new();
            json_string(&mut out, raw);
            out
        }
    }
}
pub(super) fn observe(
    receipt: &Receipt,
) -> Result<(crate::compute_provider::Observation, Outcome)> {
    let trace = receipt
        .compute_trace
        .as_ref()
        .ok_or_else(|| refused(b"compute measurement has no payable outcome"))?;
    let (output, outcome) = match receipt.compute_exit {
        Some(-1)
            if receipt.compute_fault.as_deref() == Some(b"fuel")
                && !receipt.success
                && trace.steps == receipt.effort_used =>
        {
            (b"{\"compute_stop\":\"fuel\"}".to_vec(), Outcome::Exhausted)
        }
        Some(code)
            if code >= 0
                && receipt.success == (code == 0)
                && trace.steps == receipt.effort_used =>
        {
            if code == 0 {
                let value = receipt
                    .response
                    .as_ref()
                    .ok_or_else(|| refused(b"compute measurement output missing"))?;
                (output(value), Outcome::Complete)
            } else {
                (
                    format!("{{\"compute_stop\":{code}}}").into_bytes(),
                    Outcome::Stopped(i64::from(code)),
                )
            }
        }
        _ => return Err(refused(b"compute measurement has no payable outcome")),
    };
    Ok((
        crate::compute_provider::Observation {
            output_json: output,
            trace_root: trace.root.clone(),
            steps: trace.steps,
            operations: trace.operations,
            effort_used: receipt.effort_used,
        },
        outcome,
    ))
}
pub(super) fn measure(call: &Call, receipt: &Receipt) -> Result<Measured> {
    let (observed, outcome) = observe(receipt)?;
    let root = hex::decode(&observed.trace_root).map_err(unavailable)?;
    bill::measure(
        &call.request,
        &observed.output_json,
        &root,
        observed.steps,
        observed.operations,
        outcome,
    )
}
