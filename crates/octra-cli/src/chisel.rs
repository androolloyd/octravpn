//! `octra chisel` — interactive REPL.
//!
//! The session keeps a fresh `ChainState` in memory and dispatches a
//! handful of meta-commands plus a `call <method> [...args]` shorthand
//! routed through `contract_call`. A real expression compiler would
//! require an AML interpreter; we stay pragmatic and only target the
//! "fast iteration on contract calls" use case Foundry's `chisel` is
//! primarily used for.

use std::io::{self, BufRead, Write};

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::rpc_client::{self, Endpoint};

#[derive(Args, Debug)]
pub struct ChiselArgs {
    /// RPC URL; defaults to an in-process mock so the REPL works offline.
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: Option<String>,
    /// Program address used when no `to` is supplied on a call.
    #[arg(long, default_value = "octPROGRAMaddress0000000000000000000000")]
    pub program_addr: String,
}

pub fn run(args: &ChiselArgs) -> Result<()> {
    let endpoint = match &args.rpc_url {
        Some(u) => rpc_client::endpoint_from_url(u),
        None => rpc_client::in_process(&args.program_addr),
    };
    let mut session = Session {
        endpoint,
        program_addr: args.program_addr.clone(),
        from: "octCHISEL000000000000000000000000000000001".to_string(),
    };
    repl(&mut session)
}

struct Session {
    endpoint: Endpoint,
    program_addr: String,
    from: String,
}

fn repl(s: &mut Session) -> Result<()> {
    println!("octra chisel — type `:help` for commands, `:quit` to exit");
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut buf = String::new();
    let mut lock = stdin.lock();
    loop {
        write!(out, "> ")?;
        out.flush()?;
        buf.clear();
        let n = lock.read_line(&mut buf)?;
        if n == 0 {
            // EOF
            break;
        }
        let line = buf.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, ":quit" | ":q" | "exit" | "quit") {
            break;
        }
        match dispatch(s, line) {
            Ok(v) => {
                let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
                writeln!(out, "{pretty}")?;
            }
            Err(e) => writeln!(out, "error: {e:#}")?,
        }
    }
    Ok(())
}

fn dispatch(s: &mut Session, line: &str) -> Result<Value> {
    if let Some(rest) = line.strip_prefix(':') {
        return meta(s, rest);
    }
    // shorthand: `<method> arg1 arg2 ...` is a read call.
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow::anyhow!("empty"))?;
    let args: Vec<Value> = parts
        .map(|t| serde_json::from_str(t).unwrap_or_else(|_| Value::String(t.to_string())))
        .collect();
    let params = json!([s.program_addr.clone(), method, args]);
    rpc_client::call(&s.endpoint, "contract_call", params)
}

fn meta(s: &mut Session, rest: &str) -> Result<Value> {
    let mut parts = rest.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "help" => Ok(Value::String(
            "commands:\n\
             :addr <oct...>    set program address used for calls\n\
             :from <oct...>    set the caller address\n\
             :rpc <method> <json-params>   raw json-rpc call\n\
             <method> <args>   contract_call shorthand\n"
                .into(),
        )),
        "addr" => {
            let v = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: :addr <oct...>"))?;
            s.program_addr = v.to_string();
            Ok(Value::String(format!("addr = {}", s.program_addr)))
        }
        "from" => {
            let v = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: :from <oct...>"))?;
            s.from = v.to_string();
            Ok(Value::String(format!("from = {}", s.from)))
        }
        "rpc" => {
            let method = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: :rpc <method> [json]"))?;
            let json_args = rest
                .trim_start_matches("rpc")
                .trim_start()
                .trim_start_matches(method)
                .trim();
            let params: Value = if json_args.is_empty() {
                Value::Array(vec![])
            } else {
                serde_json::from_str(json_args).unwrap_or(Value::Array(vec![]))
            };
            rpc_client::call(&s.endpoint, method, params)
        }
        other => Err(anyhow::anyhow!("unknown :{other}; try :help")),
    }
}
