//! Foundry's `console.log` / `console2.log` equivalent.
//!
//! In Foundry, `console.log` is a bytecode-level cheat the test runner
//! intercepts. For us, just write to stderr (so cargo test's `--nocapture`
//! flag works) and to the `tracing` subscriber if one is configured.

/// Plain log.
#[macro_export]
macro_rules! forge_log {
    ($($arg:tt)*) => {{
        let line = format!($($arg)*);
        eprintln!("[forge] {line}");
        tracing::info!(target: "forge::console", "{line}");
    }};
}

/// `log_named_uint("balance", n)` → `balance: 1000`
#[macro_export]
macro_rules! forge_log_named {
    ($name:expr, $val:expr) => {{
        let n = $name;
        let v = $val;
        eprintln!("[forge] {n}: {v:?}");
        tracing::info!(target: "forge::console", "{n}: {v:?}");
    }};
}

/// Hex-pretty for byte arrays.
#[macro_export]
macro_rules! forge_log_hex {
    ($name:expr, $bytes:expr) => {{
        let n = $name;
        let b = $bytes;
        let h = ::hex::encode(b);
        eprintln!("[forge] {n}: 0x{h}");
    }};
}

pub use forge_log;
pub use forge_log_hex;
pub use forge_log_named;
