//! Embedded `headscale` admin CLI passthrough. Pure client surface — no Hub.
//!
//! The upstream `headscale` binary applies a small binary-level wrapper before
//! delegating to `headscale_cli::dispatch`: when config discovery falls back to
//! defaults and no explicit gRPC address is set, local gRPC setup failures print
//! the default-config warning and use the `connecting to headscale:` envelope.
//! `headscale_cli::dispatch` exposes those controls on `ConnectArgs`, so the
//! embedded surface sets the same flags before dispatch.

use anyhow::Result;
use async_trait::async_trait;
use std::ffi::OsString;

use super::{CliContext, Subcommand};

/// `octravpn-node headscale <subcmd>`
#[derive(clap::Args, Debug)]
#[command(name = "headscale", bin_name = "headscale")]
pub(crate) struct HeadscaleArgs {
    /// Shared connection flags (`--server`, `--token`, `--json`)
    /// — flattened so the same CLI shape as the standalone binary
    /// works. `HEADSCALE_URL` / `HEADSCALE_ADMIN_TOKEN` env-var
    /// fallbacks are preserved.
    #[command(flatten)]
    pub(crate) connect: headscale_cli::ConnectArgs,
    #[command(subcommand)]
    pub(crate) cmd: headscale_cli::AdminCmd,
}

#[async_trait]
impl Subcommand for HeadscaleArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = headscale_cli::dispatch(standalone_connect_args(self.connect), self.cmd).await;
        std::process::exit(code);
    }
}

fn standalone_connect_args(mut connect: headscale_cli::ConnectArgs) -> headscale_cli::ConnectArgs {
    if connect
        .address
        .as_deref()
        .is_none_or(|address| address.trim().is_empty())
    {
        connect.warn_no_config_default = true;
        connect.wrap_grpc_connect_error = true;
        connect.timeout_secs.get_or_insert(5);
    }
    connect
}

pub(crate) fn handle_preparse<I>(args: I) -> Option<i32>
where
    I: IntoIterator<Item = OsString>,
{
    // These upstream Cobra-compatibility shims live in headscale-cli's
    // private binary main, so the embedded clap parser would otherwise
    // reject them before reaching the shared dispatch function.
    let raw = args
        .into_iter()
        .skip(1)
        .map(|arg| arg.into_string().ok())
        .collect::<Option<Vec<_>>>()?;
    let tail = embedded_headscale_tail(&raw)?;
    let command = headscale_command_parts(tail);

    if matches!(command.first().map(String::as_str), Some("tailnet")) {
        eprint!(
            "error: unrecognized subcommand 'tailnet'\n\n\
             Usage: headscale [OPTIONS] <COMMAND>\n\n\
             For more information, try '--help'.\n"
        );
        return Some(2);
    }

    if users_create_missing_name(command) {
        let fmt = output_format_from_args(tail);
        eprint!(
            "{}",
            headscale_cli::admin::output::format_error(fmt, "missing parameters")
        );
        return Some(1);
    }

    None
}

fn embedded_headscale_tail(args: &[String]) -> Option<&[String]> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "headscale" => return Some(&args[i + 1..]),
            "--config" if i + 1 < args.len() => i += 2,
            value if value.starts_with("--config=") => i += 1,
            _ => return None,
        }
    }
    None
}

fn headscale_command_parts(args: &[String]) -> &[String] {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => return &args[i + 1..],
            "-o" | "--output" | "--server" | "--token" | "--address" | "--api-key"
            | "--unix-socket"
                if i + 1 < args.len() =>
            {
                i += 2
            }
            "--force" | "--insecure" => i += 1,
            value
                if value.starts_with("--output=")
                    || value.starts_with("--server=")
                    || value.starts_with("--token=")
                    || value.starts_with("--address=")
                    || value.starts_with("--api-key=")
                    || value.starts_with("--unix-socket=")
                    || value.starts_with("--force=") =>
            {
                i += 1;
            }
            value if value.starts_with("-o") && value.len() > 2 => i += 1,
            _ => return &args[i..],
        }
    }
    &args[args.len()..]
}

fn users_create_missing_name(args: &[String]) -> bool {
    let [group, action, tail @ ..] = args else {
        return false;
    };
    if !matches!(group.as_str(), "users" | "user")
        || !matches!(action.as_str(), "create" | "c" | "new")
    {
        return false;
    }

    let mut i = 0;
    while i < tail.len() {
        match tail[i].as_str() {
            "--" => return i + 1 >= tail.len(),
            "-d" | "--display-name" | "-e" | "--email" | "-p" | "--picture-url" | "-o"
            | "--output"
                if i + 1 < tail.len() =>
            {
                i += 2
            }
            "-h" | "--help" | "-d" | "--display-name" | "-e" | "--email" | "-p"
            | "--picture-url" => return false,
            "--force" | "--insecure" => i += 1,
            value
                if value.starts_with("--display-name=")
                    || value.starts_with("--email=")
                    || value.starts_with("--picture-url=")
                    || value.starts_with("--output=")
                    || value.starts_with("--force=")
                    || value.starts_with("-d") && value.len() > 2
                    || value.starts_with("-e") && value.len() > 2
                    || value.starts_with("-p") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            value if value.starts_with('-') => return false,
            _ => return false,
        }
    }
    true
}

fn output_format_from_args(args: &[String]) -> headscale_cli::OutputFormat {
    let mut fmt = headscale_cli::OutputFormat::Table;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => break,
            "-o" | "--output" if i + 1 < args.len() => {
                fmt = raw_output_format(&args[i + 1]);
                i += 2;
            }
            value if value.starts_with("--output=") => {
                fmt = raw_output_format(value.strip_prefix("--output=").unwrap_or_default());
                i += 1;
            }
            value if value.starts_with("-o") && value.len() > 2 => {
                fmt = raw_output_format(&value[2..]);
                i += 1;
            }
            _ => i += 1,
        }
    }
    fmt
}

fn raw_output_format(value: &str) -> headscale_cli::OutputFormat {
    match value {
        "json" => headscale_cli::OutputFormat::Json,
        "json-line" => headscale_cli::OutputFormat::JsonLine,
        "yaml" => headscale_cli::OutputFormat::Yaml,
        _ => headscale_cli::OutputFormat::Table,
    }
}
