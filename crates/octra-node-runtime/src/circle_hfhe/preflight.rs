//! Preserve native Circle argument validation before its callback lane and
//! proof/cipher decoding before the speculative PVAC channel is attempted.
use super::{
    boolean, bytes32, crypto, exception, json, native_base64, private_crypto, proof_result, public,
    rejected, size, string, verifier_cipher, zero, BoundProfile, Engine, Error, Result, ScalarRule,
    Value, ZeroProof, STANDARD, VERIFIER,
};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(crate) enum Step<T> {
    Final(Value),
    Ready(T),
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Parameters {
    action: String,
    #[serde(with = "crate::crypto_worker::tasks::bytes")]
    public: Vec<u8>,
    cipher: String,
    proof: String,
    commitment: Option<String>,
    strict: bool,
    cap: bool,
    math: bool,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Prepared(Parameters);
fn envelope(result: Result<Value>) -> Value {
    match result {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(Error::Rejected(reason)) => json!({"ok":false,"class":"rejected","error":reason}),
        Err(Error::Unavailable(reason)) => json!({"ok":false,"class":"unavailable","error":reason}),
    }
}
pub(crate) fn parameters(input: &Value) -> Step<Parameters> {
    let run = || -> Result<Parameters> {
        let raw = zeroize::Zeroizing::new(serde_json::to_vec(input).map_err(exception)?);
        if raw.is_empty() || raw.len() > 16 * 1024 * 1024 {
            return Err(rejected("hfhe request exceeds resource policy"));
        }
        if !input.is_object() {
            return Err(rejected("invalid payload"));
        }
        let cap = boolean(input, "cap", None)?;
        let math = boolean(input, "math", Some(false))?;
        let _pairs = boolean(input, "hfhe_pairs", Some(false))?;
        let action = string(input, "action")?;
        if !matches!(action, "verify_zero" | "verify_range" | "verify_bound") {
            return Err(rejected(format!("unsupported action: {action}")));
        }
        let public = public(input)?;
        let cipher = string(input, "ciphertext")?.to_owned();
        let proof = string(input, "proof")?.to_owned();
        let commitment = if action == "verify_zero" {
            None
        } else {
            Some(string(input, "amount_commitment")?.to_owned())
        };
        let strict = if commitment.is_some() {
            boolean(input, "strict", Some(false))?
        } else {
            false
        };
        Ok(Parameters {
            action: action.to_owned(),
            public: public.to_bytes().map_err(exception)?,
            cipher,
            proof,
            commitment,
            strict,
            cap,
            math,
        })
    };
    match run() {
        Ok(parameters) => Step::Ready(parameters),
        Err(error) => Step::Final(envelope(Err(error))),
    }
}
pub(crate) fn prepare(mut parameters: Parameters) -> Step<Prepared> {
    let run = || -> Result<Parameters> {
        let cipher = verifier_cipher(&parameters.cipher, parameters.cap)?;
        size(parameters.proof.as_bytes(), 64 * 1024, "proof")?;
        if parameters.action == "verify_range" {
            // Native decode_range_proof_cap checks the prefix/base64 here;
            // proof structure/validity is checked only by the admitted worker.
            let raw = parameters
                .proof
                .strip_prefix("rp_v1|")
                .filter(|raw| !raw.is_empty())
                .ok_or_else(|| rejected("invalid range proof"))?;
            let raw = native_base64::decode(raw.as_bytes())
                .map_err(|_| rejected("invalid range proof"))?;
            parameters.proof = format!("rp_v1|{}", STANDARD.encode(raw));
        } else {
            private_crypto::decode_zero_proof(parameters.proof.as_bytes()).map_err(crypto)?;
        }
        if let Some(commitment) = parameters.commitment.as_mut() {
            *commitment = STANDARD.encode(bytes32(
                &json!({"amount_commitment":commitment}),
                "amount_commitment",
            )?);
        }
        parameters.cipher =
            String::from_utf8(private_crypto::encode_cipher(&cipher).map_err(crypto)?)
                .map_err(exception)?;
        Ok(parameters)
    };
    match run() {
        Ok(parameters) => Step::Ready(Prepared(parameters)),
        Err(Error::Rejected(_)) => Step::Final(envelope(Ok(Value::Bool(false)))),
        Err(error) => Step::Final(envelope(Err(error))),
    }
}
pub(crate) fn verify(prepared: Prepared) -> Value {
    let parameters = prepared.0;
    let run = || -> Result<bool> {
        // These are already validated/canonical private helper images. Do not
        // reapply the incoming Circle five-megabyte registration envelope to a
        // canonical serialization, which native passes straight to its worker.
        let public = private_crypto::load_pubkey(&parameters.public).map_err(crypto)?;
        if !public.supports_alias_rejection() {
            return Ok(false);
        }
        let bound = parameters.action != "verify_zero";
        let cipher = private_crypto::decode_cipher(
            parameters.cipher.as_bytes(),
            parameters.strict,
            if bound { parameters.strict } else { true },
        )
        .map_err(crypto)?;
        let proof = if parameters.action == "verify_range" {
            let raw = parameters
                .proof
                .strip_prefix("rp_v1|")
                .ok_or_else(|| rejected("invalid range proof"))?;
            let raw = native_base64::decode(raw.as_bytes())
                .map_err(|_| rejected("invalid range proof"))?;
            ZeroProof::from_bound_range_bytes(&raw).map_err(|error| {
                if error.is_operational() {
                    exception(error)
                } else {
                    rejected("invalid range proof")
                }
            })?
        } else {
            private_crypto::decode_zero_proof(parameters.proof.as_bytes()).map_err(crypto)?
        };
        let rule = if parameters.math {
            ScalarRule::Wide
        } else {
            ScalarRule::Prior
        };
        if let Some(commitment) = &parameters.commitment {
            let commitment = bytes32(
                &json!({"amount_commitment":commitment}),
                "amount_commitment",
            )?;
            proof_result(zero::verify_bound(
                &public,
                &cipher,
                &proof,
                &commitment,
                if parameters.action == "verify_range" {
                    BoundProfile::Range
                } else {
                    BoundProfile::Standard
                },
                parameters.strict,
                rule,
            ))
        } else {
            proof_result(zero::verify_zero(&public, &cipher, &proof, rule))
        }
    };
    let result = match run() {
        Ok(valid) => Ok(Value::Bool(valid)),
        Err(Error::Rejected(_)) => Ok(Value::Bool(false)),
        Err(error) => Err(error),
    };
    envelope(result)
}
/// This is the same native callback lane used by the in-process compatibility
/// backend. Parameters have already been validated before it is attempted.
pub(crate) fn lane() -> std::sync::TryLockResult<std::sync::MutexGuard<'static, ()>> {
    VERIFIER.try_lock()
}
