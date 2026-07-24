//! Small process/polling utilities shared by the harness.
//!
//! The harness's hard rule (owner directive): **no fixed-sleep correctness**.
//! Everything that waits, waits on an observed condition with a bounded
//! deadline and fails loudly with the last observed state — never a silent
//! "probably fine by now".

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wall-clock now, Unix milliseconds (report timestamps only — never used for
/// correctness).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Poll `f` every `interval` until it yields `Some(v)` or `timeout` elapses.
///
/// `f` returns `Ok(Some(v))` when the condition holds, `Ok(None)` to keep
/// waiting, or `Err(_)` for a *transient* observation error (kept as context,
/// polling continues — a node mid-boot refuses TCP, which is not a failure
/// yet). On timeout the error names `what` and the last observation, so a
/// failed wait is diagnosable from the report alone.
pub fn poll<T>(
    what: &str,
    timeout: Duration,
    interval: Duration,
    mut f: impl FnMut() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let deadline = Instant::now() + timeout;
    let mut last: String = "no observation yet".to_string();
    loop {
        match f() {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => {}
            Err(e) => last = e,
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out after {}s waiting for {what} (last: {last})",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(interval);
    }
}

/// The captured outcome of a finished child process.
pub struct CmdOutput {
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `program args…` to completion with a hard deadline, capturing output.
///
/// On deadline the child is killed and an error is returned — a wedged wallet
/// or build can never hang the harness (which must always reach teardown).
pub fn run_cmd_timeout(
    program: &Path,
    args: &[&str],
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<CmdOutput, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn {} failed: {e}", program.display()))?;

    // Drain pipes on threads so a chatty child can never dead-lock on a full pipe.
    let mut out_pipe = child.stdout.take().expect("stdout was piped");
    let mut err_pipe = child.stderr.take().expect("stderr was piped");
    let out_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out_pipe.read_to_string(&mut s);
        s
    });
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err_pipe.read_to_string(&mut s);
        s
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{} timed out after {}s and was killed",
                        program.display(),
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("wait on {} failed: {e}", program.display())),
        }
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok(CmdOutput {
        status_ok: status.success(),
        stdout,
        stderr,
    })
}

/// First line of `text` whose label (the part before `:`) trims to `label`;
/// returns the trimmed value after the colon. Parses the `sov-wallet` key/value
/// output format (`public_key : hybrid65:0x…`) without guessing at columns.
pub fn labeled_value(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((l, v)) = line.split_once(':') {
            if l.trim() == label {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Extract the 64-hex transaction id from a `sov-wallet` success line of the
/// form `… (tx <64 hex>)`.
pub fn parse_tx_id(text: &str) -> Option<String> {
    let idx = text.rfind("(tx ")?;
    let rest = &text[idx + 4..];
    let end = rest.find(')')?;
    let id = rest[..end].trim();
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(id.to_string())
    } else {
        None
    }
}
