//! Filesystem / env / FFI cheatcodes — Foundry's `vm.readFile`,
//! `vm.writeFile`, `vm.envString`, `vm.ffi`.
//!
//! Each is a thin convenience wrapper that maps the std error to the
//! plain `String` panic format Foundry tests expect.

use std::process::Command;

/// `vm.readFile(path)`.
pub fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

/// `vm.writeFile(path, contents)`.
pub fn write_file(path: &str, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("write {path}: {e}"))
}

/// `vm.removeFile(path)`.
pub fn remove_file(path: &str) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|e| format!("remove {path}: {e}"))
}

/// `vm.exists(path)`.
pub fn exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// `vm.envString(name)` — returns the env var or an error string.
pub fn env_string(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("env {name}: {e}"))
}

/// `vm.envOr(name, default)` — returns the var or a default.
pub fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// `vm.envU64(name)`.
pub fn env_u64(name: &str) -> Result<u64, String> {
    env_string(name)?
        .parse()
        .map_err(|e: std::num::ParseIntError| format!("env {name} parse u64: {e}"))
}

/// `vm.setEnv(name, value)`.
#[allow(unsafe_code)]
pub fn set_env(name: &str, value: &str) {
    // env mutation is process-global; tests in the same process may
    // interact. Foundry has the same caveat. Rust 1.85+ marks env::set_var
    // unsafe; we accept that since test code is single-threaded for env.
    unsafe { std::env::set_var(name, value) };
}

/// `vm.ffi(["cmd", "arg", ...])`. Executes the command, returns stdout.
pub fn ffi(argv: &[&str]) -> Result<String, String> {
    if argv.is_empty() {
        return Err("ffi: empty argv".into());
    }
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..]);
    let out = cmd.output().map_err(|e| format!("ffi spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ffi {} exited {}: {}",
            argv.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `tryFfi(...)` — like `ffi` but also surfaces exit code + stderr.
#[derive(Debug)]
pub struct FfiResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn try_ffi(argv: &[&str]) -> Result<FfiResult, String> {
    if argv.is_empty() {
        return Err("ffi: empty argv".into());
    }
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..]);
    let out = cmd.output().map_err(|e| format!("ffi spawn: {e}"))?;
    Ok(FfiResult {
        exit_code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// `vm.projectRoot()` — returns the cargo workspace root (the dir
/// containing `Cargo.lock`).
pub fn project_root() -> Result<String, String> {
    let mut cur = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    loop {
        if cur.join("Cargo.lock").exists() {
            return Ok(cur.to_string_lossy().into_owned());
        }
        if !cur.pop() {
            return Err("no Cargo.lock found upward from cwd".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_write_round_trip() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.txt");
        let p_str = p.to_string_lossy();
        write_file(&p_str, "hello").unwrap();
        assert!(exists(&p_str));
        assert_eq!(read_file(&p_str).unwrap(), "hello");
        remove_file(&p_str).unwrap();
        assert!(!exists(&p_str));
    }

    #[test]
    fn env_set_get() {
        set_env("FORGE_TEST_VAR", "yes");
        assert_eq!(env_string("FORGE_TEST_VAR").unwrap(), "yes");
        assert_eq!(env_or("FORGE_TEST_NOPE", "default"), "default");
    }

    #[test]
    fn ffi_echo() {
        // `echo` is universally available on POSIX. Windows test runner
        // uses cmd.exe's `echo`, which prints with a trailing newline.
        #[cfg(not(target_os = "windows"))]
        {
            let out = ffi(&["echo", "octraforge"]).unwrap();
            assert!(out.trim() == "octraforge");
        }
    }
}
