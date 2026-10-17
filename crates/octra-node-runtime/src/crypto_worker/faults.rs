//! Explicit qualification-only worker faults. These variants are absent from
//! production builds and cannot be selected by network/VM callback inputs.
use super::{Error, Response};
use serde::{Deserialize, Serialize};
use std::{io::Write, time::Duration};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Fault {
    SessionId,
    Delay(u64),
    StartedDelay { millis: u64, ready: String },
    Exit,
    Malformed,
    Oversize,
    Memory,
}
pub(super) fn execute(fault: Fault) -> Result<Response, Error> {
    match fault {
        Fault::SessionId => (),
        Fault::Delay(millis) if millis <= 30_000 => {
            std::thread::sleep(Duration::from_millis(millis));
        }
        Fault::Delay(_) => return Err(Error::Invalid),
        Fault::StartedDelay { millis, ready } => {
            if millis > 30_000 || ready.len() > 4096 {
                return Err(Error::Invalid);
            }
            let mut marker = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(ready)
                .map_err(|_| Error::Unavailable("fault readiness marker refused".into()))?;
            marker
                .write_all(std::process::id().to_string().as_bytes())
                .map_err(|_| Error::Unavailable("fault readiness marker failed".into()))?;
            std::thread::sleep(Duration::from_millis(millis));
        }
        Fault::Exit => std::process::exit(71),
        Fault::Malformed | Fault::Oversize => {
            let mut output = std::io::stdout().lock();
            if matches!(fault, Fault::Oversize) {
                output.write_all(&u64::MAX.to_be_bytes())
            } else {
                output
                    .write_all(&3_u64.to_be_bytes())
                    .and_then(|()| output.write_all(b"bad"))
            }
            .and_then(|()| output.flush())
            .map_err(|_| Error::Unavailable("fault pipe closed".into()))?;
            std::thread::sleep(Duration::from_secs(30));
        }
        Fault::Memory => {
            let mut pages = vec![0_u8; 128 * 1024 * 1024];
            for page in pages.chunks_mut(4096) {
                page[0] = 7;
            }
            std::hint::black_box(&pages);
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    Ok(Response::Fault(std::process::id()))
}
