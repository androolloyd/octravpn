//! Cheatcode side-types — the queue / id types `ForgeCtx` uses.

use serde_json::Value;
use thiserror::Error;

/// Index returned by `ForgeCtx::snapshot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotId(pub usize);

/// Pending expectation queued before the next `submit`.
#[derive(Clone, Debug)]
pub enum Expectation {
    Emit { name: String },
    EmitFields {
        name: String,
        fields: Vec<(String, Value)>,
    },
    Revert { substring: String },
    RevertExact { expected: String },
    NoEmit { name: String },
    Call { method: String },
}

#[derive(Clone, Debug)]
pub struct SubmitResult {
    pub hash: String,
    pub events: Vec<Value>,
}

impl SubmitResult {
    pub fn find_event(&self, name: &str) -> Option<&Value> {
        self.events.iter().find(|e| e["name"].as_str() == Some(name))
    }

    pub fn find_all_events<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.events
            .iter()
            .filter(move |e| e["name"].as_str() == Some(name))
    }

    pub fn event_str(&self, name: &str, key: &str) -> Option<String> {
        self.find_event(name)
            .and_then(|e| e.get(key))
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    pub fn event_u64(&self, name: &str, key: &str) -> Option<u64> {
        self.find_event(name)
            .and_then(|e| e.get(key))
            .and_then(serde_json::Value::as_u64)
    }

    pub fn event_value(&self, name: &str, key: &str) -> Option<Value> {
        self.find_event(name).and_then(|e| e.get(key)).cloned()
    }
}

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("reverted: {0}")]
    Reverted(String),

    #[error("expect_emit({name}) not satisfied")]
    MissingEmit { name: String },

    #[error("expect_emit({name}) field `{field}` mismatch: expected {expected}, got {actual}")]
    EmitFieldMismatch {
        name: String,
        field: String,
        expected: String,
        actual: String,
    },

    #[error("expect_no_emit({name}) violated — event was emitted")]
    UnexpectedEmit { name: String },

    #[error("expect_call({method}) not invoked")]
    MissingCall { method: String },

    #[error("expected revert containing `{substring}`, but call succeeded")]
    ExpectedRevert { substring: String },

    #[error("expected revert containing `{substring}`, got: {actual}")]
    WrongRevert { substring: String, actual: String },

    #[error("expected exact revert `{expected}`, got: {actual}")]
    WrongRevertExact { expected: String, actual: String },
}

pub(crate) fn check_success(
    events: &[Value],
    tx_method: Option<&str>,
    expectations: &[Expectation],
) -> Result<(), SubmitError> {
    for ex in expectations {
        match ex {
            Expectation::Emit { name } => {
                let hit = events
                    .iter()
                    .any(|e| e["name"].as_str() == Some(name.as_str()));
                if !hit {
                    return Err(SubmitError::MissingEmit { name: name.clone() });
                }
            }
            Expectation::EmitFields { name, fields } => {
                let Some(event) = events
                    .iter()
                    .find(|e| e["name"].as_str() == Some(name.as_str()))
                else {
                    return Err(SubmitError::MissingEmit { name: name.clone() });
                };
                for (k, expected) in fields {
                    let actual = event.get(k).cloned().unwrap_or(Value::Null);
                    if &actual != expected {
                        return Err(SubmitError::EmitFieldMismatch {
                            name: name.clone(),
                            field: k.clone(),
                            expected: expected.to_string(),
                            actual: actual.to_string(),
                        });
                    }
                }
            }
            Expectation::NoEmit { name } => {
                let hit = events
                    .iter()
                    .any(|e| e["name"].as_str() == Some(name.as_str()));
                if hit {
                    return Err(SubmitError::UnexpectedEmit { name: name.clone() });
                }
            }
            Expectation::Call { method } => {
                if tx_method != Some(method.as_str()) {
                    return Err(SubmitError::MissingCall {
                        method: method.clone(),
                    });
                }
            }
            Expectation::Revert { substring } => {
                return Err(SubmitError::ExpectedRevert {
                    substring: substring.clone(),
                });
            }
            Expectation::RevertExact { expected } => {
                return Err(SubmitError::ExpectedRevert {
                    substring: expected.clone(),
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn check_failure(actual: &str, expectations: &[Expectation]) -> Result<(), SubmitError> {
    for ex in expectations {
        if let Expectation::RevertExact { expected } = ex {
            if actual == expected {
                return Ok(());
            }
            return Err(SubmitError::WrongRevertExact {
                expected: expected.clone(),
                actual: actual.to_string(),
            });
        }
    }
    for ex in expectations {
        if let Expectation::Revert { substring } = ex {
            if actual.contains(substring) {
                return Ok(());
            }
            return Err(SubmitError::WrongRevert {
                substring: substring.clone(),
                actual: actual.to_string(),
            });
        }
    }
    Err(SubmitError::Reverted(actual.to_string()))
}
