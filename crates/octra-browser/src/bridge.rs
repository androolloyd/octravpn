//! Sessions and one-use reviews held by the trusted browser shell.
use super::{ApplicationHost, Call, Context, Intent, ReadMethod, ReadRequest, ReviewedAction};
use crate::Error;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

const SESSION_TTL: Duration = Duration::from_secs(600);
const REVIEW_TTL: Duration = Duration::from_secs(90);
const MAX_SESSIONS: usize = 64;
pub(crate) const MAX_REQUEST: usize = 32 * 1024;
const MAX_REPLY: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    method: String,
    #[serde(default = "empty")]
    params: Value,
}
fn empty() -> Value {
    json!({})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Review {
    id: String,
    approve: bool,
}

struct Pending {
    id: String,
    intent: Intent,
    expires: Instant,
}
struct Session {
    context: Context,
    origin: String,
    expires: Instant,
    pending: Option<Pending>,
    window: Instant,
    requests: u16,
}

pub(crate) struct Bridge {
    host: Arc<dyn ApplicationHost>,
    sessions: Mutex<HashMap<String, Session>>,
    reads: Semaphore,
    submissions: Semaphore,
}
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}
fn random_id() -> Result<String, Error> {
    let mut bytes = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Unavailable("session entropy unavailable".into()))?;
    Ok(hex::encode(bytes))
}
impl Bridge {
    pub(crate) fn new(host: Arc<dyn ApplicationHost>) -> Self {
        Self {
            host,
            sessions: Mutex::default(),
            reads: Semaphore::new(16),
            submissions: Semaphore::new(4),
        }
    }
    fn sessions(&self) -> Result<MutexGuard<'_, HashMap<String, Session>>, Error> {
        self.sessions
            .lock()
            .map_err(|_| Error::Unavailable("browser session state unavailable".into()))
    }
    pub(crate) fn open(&self, context: Context, origin: String) -> Result<String, Error> {
        let now = Instant::now();
        let mut sessions = self.sessions()?;
        sessions.retain(|_, s| s.expires > now);
        if sessions.len() >= MAX_SESSIONS {
            return Err(Error::Unavailable("too many open Circle sessions".into()));
        }
        let id = random_id()?;
        sessions.insert(
            id.clone(),
            Session {
                context,
                origin,
                expires: now + SESSION_TTL,
                pending: None,
                window: now,
                requests: 0,
            },
        );
        Ok(id)
    }
    fn session<'a>(
        sessions: &'a mut HashMap<String, Session>,
        token: &str,
        origin: &str,
    ) -> Result<&'a mut Session, Error> {
        let session = sessions
            .get_mut(token)
            .ok_or_else(|| invalid("Circle session unavailable"))?;
        if session.expires <= Instant::now() || session.origin != origin {
            return Err(invalid("Circle session expired or origin changed"));
        }
        Ok(session)
    }
    pub(crate) fn close(&self, token: &str, origin: &str) -> Result<Value, Error> {
        let mut sessions = self.sessions()?;
        Self::session(&mut sessions, token, origin)?;
        sessions.remove(token);
        Ok(json!({"closed": true}))
    }
    pub(crate) async fn request(
        &self,
        token: &str,
        origin: &str,
        request: Request,
    ) -> Result<Value, Error> {
        let context = {
            let mut sessions = self.sessions()?;
            let session = Self::session(&mut sessions, token, origin)?;
            let now = Instant::now();
            if now.duration_since(session.window) >= Duration::from_secs(60) {
                session.window = now;
                session.requests = 0;
            }
            if session.requests >= 120 {
                return Err(invalid("Circle request rate exceeded"));
            }
            session.requests += 1;
            session.context.clone()
        };
        if request.method == "program.call" {
            let call: Call = serde_json::from_value(request.params)
                .map_err(|_| invalid("invalid Circle call"))?;
            call.validate()?;
            let intent = Intent { context, call };
            let id = random_id()?;
            let reply = json!({"review": {"id": id, "intent": intent}});
            let mut sessions = self.sessions()?;
            let session = Self::session(&mut sessions, token, origin)?;
            if session
                .pending
                .as_ref()
                .is_some_and(|p| p.expires > Instant::now())
            {
                return Err(invalid("a Circle call is already awaiting review"));
            }
            session.pending = Some(Pending {
                id,
                intent,
                expires: Instant::now() + REVIEW_TTL,
            });
            return Ok(reply);
        }
        let method = read_method(&request)?;
        let _permit = self
            .reads
            .try_acquire()
            .map_err(|_| Error::Unavailable("Circle reads busy".into()))?;
        let reply = tokio::time::timeout(
            Duration::from_secs(15),
            self.host.read(ReadRequest {
                context,
                method,
                params: request.params,
            }),
        )
        .await
        .map_err(|_| Error::Unavailable("Circle read timed out".into()))??;
        // A revoked session must not receive a late private wallet response.
        Self::session(&mut *self.sessions()?, token, origin)?;
        bounded(json!({"result": reply}))
    }
    pub(crate) async fn review(
        &self,
        token: &str,
        origin: &str,
        review: Review,
    ) -> Result<Value, Error> {
        let pending = {
            let mut sessions = self.sessions()?;
            let session = Self::session(&mut sessions, token, origin)?;
            if session.pending.as_ref().is_none_or(|p| p.id != review.id) {
                return Err(invalid("Circle review unavailable"));
            }
            // Consume before awaiting the host, including cancellation/failure.
            session.pending.take().expect("review checked")
        };
        if pending.expires <= Instant::now() {
            return Err(invalid("Circle review expired"));
        }
        if !review.approve {
            return Ok(json!({"error": "Circle call declined"}));
        }
        let _permit = self
            .submissions
            .try_acquire()
            .map_err(|_| Error::Unavailable("Circle submissions busy; review again".into()))?;
        let reply = tokio::time::timeout(
            Duration::from_secs(60),
            self.host.submit(ReviewedAction {
                intent: pending.intent,
            }),
        )
        .await
        .map_err(|_| {
            Error::Unavailable(
                "submission outcome unknown; check transaction status before retrying".into(),
            )
        })??;
        bounded(json!({"result": reply}))
    }
}

fn bounded(value: Value) -> Result<Value, Error> {
    if serde_json::to_vec(&value)
        .map_err(|_| invalid("invalid host reply"))?
        .len()
        > MAX_REPLY
    {
        return Err(Error::TooLarge);
    }
    Ok(value)
}
fn read_method(request: &Request) -> Result<ReadMethod, Error> {
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct View {
        method: String,
        #[serde(default)]
        params: Vec<Value>,
    }
    match request.method.as_str() {
        "wallet.info" | "wallet.balance" | "program.info" if request.params == empty() => {
            Ok(match request.method.as_str() {
                "wallet.info" => ReadMethod::WalletInfo,
                "wallet.balance" => ReadMethod::WalletBalance,
                _ => ReadMethod::ProgramInfo,
            })
        }
        "program.view" => {
            let view: View = serde_json::from_value(request.params.clone())
                .map_err(|_| invalid("invalid program view"))?;
            Call {
                method: view.method,
                params: view.params,
                amount: "0".into(),
                ou: "0".into(),
            }
            .validate()?;
            Ok(ReadMethod::ProgramView)
        }
        "tx.wait" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Status {
                hash: String,
            }
            let status: Status = serde_json::from_value(request.params.clone())
                .map_err(|_| invalid("invalid transaction status request"))?;
            if status.hash.len() != 64
                || !status
                    .hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("invalid transaction hash"));
            }
            Ok(ReadMethod::TransactionWait)
        }
        _ => Err(invalid("unsupported Circle request")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application::UnavailableHost, Provenance};

    #[tokio::test]
    async fn expired_sessions_and_reviews_cannot_reach_host_and_capacity_is_bounded() {
        let bridge = Bridge::new(Arc::new(UnavailableHost));
        let context = Context {
            circle_id: "one".into(),
            provenance: Provenance::UnpinnedRpc,
        };
        let token = bridge.open(context.clone(), "origin".into()).unwrap();
        let call = Request {
            method: "program.call".into(),
            params: json!({"method":"inc","params":[],"amount":"0","ou":"1"}),
        };
        let reply = bridge.request(&token, "origin", call).await.unwrap();
        bridge
            .sessions()
            .unwrap()
            .get_mut(&token)
            .unwrap()
            .pending
            .as_mut()
            .unwrap()
            .expires = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let id = reply["review"]["id"].as_str().unwrap().to_owned();
        assert!(bridge
            .review(&token, "origin", Review { id, approve: true })
            .await
            .unwrap_err()
            .to_string()
            .contains("review expired"));
        assert!(bridge.sessions().unwrap()[&token].pending.is_none());
        bridge.sessions().unwrap().get_mut(&token).unwrap().expires =
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(bridge
            .request(
                &token,
                "origin",
                Request {
                    method: "wallet.info".into(),
                    params: empty()
                }
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("session expired"));
        for _ in 0..MAX_SESSIONS {
            bridge.open(context.clone(), "origin".into()).unwrap();
        }
        assert!(bridge
            .open(context, "origin".into())
            .unwrap_err()
            .to_string()
            .contains("too many open"));
    }
}
