//! Packaged, network-free worker entrypoint for embedded node runtimes.
fn main() {
    if run().is_err() {
        // Protocol/crypto inputs can contain private material. The parent owns
        // classified bounded diagnostics; never echo raw helper input/errors.
        std::process::exit(70);
    }
}
fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let command = args
        .next()
        .and_then(|v| v.into_string().ok())
        .ok_or("missing worker command")?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--parent-pid")) {
        return Err("missing parent ownership".into());
    }
    let parent = args
        .next()
        .and_then(|v| v.into_string().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .ok_or("invalid worker parent")?;
    let session = match args.next().as_deref() {
        None => false,
        Some(value) if value == std::ffi::OsStr::new("--session") => true,
        _ => return Err("unexpected worker arguments".into()),
    };
    if args.next().is_some() {
        return Err("unexpected worker arguments".into());
    }
    match command.as_str() {
        "crypto-worker" if session => octra_node_runtime::crypto_worker::helper_session(parent),
        "crypto-worker" => octra_node_runtime::crypto_worker::helper(parent),
        "single-range-worker" if !session => {
            octra_node_runtime::single_private::worker::helper(parent)
        }
        _ => Err("unknown worker command".into()),
    }
}
