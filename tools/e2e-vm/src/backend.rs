//! Node-placement backends: WHERE a `sov-rpcd` process runs is swappable; the
//! matrix driver only ever talks to node RPC endpoints.
//!
//! * [`LocalBackend`] — DEFAULT, zero-dependency: each node is a separate real
//!   `sov-rpcd` process on loopback with its own data dir and ports. Real
//!   binaries, real TCP P2P, real PoW — a genuine live multi-node blockchain.
//! * [`SshBackend`] — the same interface over `ssh`/`scp` against a list of
//!   VM hosts from a JSON config (see `ssh-hosts.example.json`). Drop-in: the
//!   matrix never knows which backend placed the node.
//! * [`container_backend_stub`] — documented stub: this development machine has
//!   no docker/podman/multipass/qemu, so a container backend cannot be built
//!   honestly here. The interface it must implement is exactly this trait.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use crate::util::{poll, run_cmd_timeout};

/// Everything needed to place one node: its bundle directory (config, spec,
/// keystore, data dir, logs) plus the addresses the harness dials.
#[derive(Clone)]
pub struct NodePlan {
    /// Node name, e.g. `node-1` (also the bundle subdirectory name).
    pub name: String,
    /// Local bundle directory holding `node-config.json`, `keystore.json`,
    /// the shared `chain-spec.json` path, `data/`, and logs.
    pub dir: PathBuf,
    /// Path of the shared chain-spec file.
    pub spec_path: PathBuf,
    /// JSON-RPC `host:port` the harness (and wallet CLI) dials.
    pub rpc: String,
    /// P2P `host:port`.
    pub p2p: String,
    /// Whether this node mines.
    pub mine: bool,
}

impl NodePlan {
    pub fn config_path(&self) -> PathBuf {
        self.dir.join("node-config.json")
    }
    pub fn keystore_path(&self) -> PathBuf {
        self.dir.join("keystore.json")
    }
    pub fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }
}

/// A node-placement backend. Start/stop are by node name; file surgery (the
/// restart-replay step deletes a snapshot) goes through the backend too, so the
/// matrix is backend-agnostic end to end.
pub trait Backend {
    /// Start (or restart) the node `plan` with the given `sov-rpcd` binary.
    fn start(&mut self, plan: &NodePlan, rpcd: &Path) -> Result<(), String>;
    /// Stop the named node (kill + reap). Idempotent for a node not running.
    fn stop(&mut self, name: &str) -> Result<(), String>;
    /// Delete a file under the node's data dir; `Ok(existed)`.
    fn remove_data_file(&mut self, plan: &NodePlan, file: &str) -> Result<bool, String>;
    /// Whether a file exists under the node's data dir (replay-step probe).
    fn data_file_exists(&mut self, plan: &NodePlan, file: &str) -> Result<bool, String>;
    /// Stop every node this backend started. Returns the names stopped.
    fn stop_all(&mut self) -> Vec<String>;
    /// Verify every planned node is actually DOWN (its RPC endpoint refuses),
    /// so teardown is proven, not assumed.
    fn verify_down(&mut self, plans: &[NodePlan]) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// local backend
// ---------------------------------------------------------------------------

/// Local-process backend. Holds every spawned [`Child`]; `Drop` is a backstop
/// killer so even a panicking harness leaves no orphan `sov-rpcd`.
#[derive(Default)]
pub struct LocalBackend {
    children: HashMap<String, Child>,
}

impl LocalBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for LocalBackend {
    fn start(&mut self, plan: &NodePlan, rpcd: &Path) -> Result<(), String> {
        if self.children.contains_key(&plan.name) {
            return Err(format!("{} is already running", plan.name));
        }
        fs::create_dir_all(plan.data_dir())
            .map_err(|e| format!("create {}: {e}", plan.data_dir().display()))?;
        // Append logs so a restarted node's second boot lands in the same file
        // (the restart-replay step reads like one continuous story).
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(plan.dir.join("node.log"))
            .map_err(|e| format!("open node.log for {}: {e}", plan.name))?;
        let errlog = OpenOptions::new()
            .create(true)
            .append(true)
            .open(plan.dir.join("node.err.log"))
            .map_err(|e| format!("open node.err.log for {}: {e}", plan.name))?;
        let child = Command::new(rpcd)
            .arg(plan.config_path())
            .arg(&plan.spec_path)
            .arg(plan.keystore_path())
            .current_dir(&plan.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errlog))
            .spawn()
            .map_err(|e| format!("spawn sov-rpcd for {}: {e}", plan.name))?;
        self.children.insert(plan.name.clone(), child);
        Ok(())
    }

    fn stop(&mut self, name: &str) -> Result<(), String> {
        if let Some(mut child) = self.children.remove(name) {
            child.kill().map_err(|e| format!("kill {name}: {e}"))?;
            child.wait().map_err(|e| format!("reap {name}: {e}"))?;
        }
        Ok(())
    }

    fn remove_data_file(&mut self, plan: &NodePlan, file: &str) -> Result<bool, String> {
        let path = plan.data_dir().join(file);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("remove {}: {e}", path.display())),
        }
    }

    fn data_file_exists(&mut self, plan: &NodePlan, file: &str) -> Result<bool, String> {
        Ok(plan.data_dir().join(file).is_file())
    }

    fn stop_all(&mut self) -> Vec<String> {
        let names: Vec<String> = self.children.keys().cloned().collect();
        for name in &names {
            let _ = self.stop(name);
        }
        names
    }

    fn verify_down(&mut self, plans: &[NodePlan]) -> Result<(), String> {
        if !self.children.is_empty() {
            return Err(format!(
                "backend still tracks running children: {:?}",
                self.children.keys().collect::<Vec<_>>()
            ));
        }
        // Every RPC endpoint must now REFUSE — an accepted connection means an
        // orphan process survived teardown. Ports linger briefly in TIME_WAIT
        // (which does not accept), so a live accept is unambiguous.
        for plan in plans {
            let addr: std::net::SocketAddr = plan
                .rpc
                .parse()
                .map_err(|e| format!("{}: bad rpc addr {}: {e}", plan.name, plan.rpc))?;
            poll(
                &format!("{} RPC port to close after teardown", plan.name),
                Duration::from_secs(10),
                Duration::from_millis(200),
                || match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                    Ok(_) => Ok(None), // still accepting — keep waiting, then fail
                    Err(_) => Ok(Some(())),
                },
            )?;
        }
        Ok(())
    }
}

impl Drop for LocalBackend {
    fn drop(&mut self) {
        // Backstop only: normal flow already stopped everything explicitly.
        for (_, mut child) in self.children.drain() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// ssh backend (real VMs) — same interface, placement over ssh/scp
// ---------------------------------------------------------------------------

/// One VM host from the ssh config file.
#[derive(Clone)]
pub struct SshHost {
    pub host: String,
    pub user: String,
    /// Path of the ssh private key (passed as `-i`).
    pub key: String,
    /// Remote working directory for node bundles (created if missing).
    pub workdir: String,
}

/// SSH/VM backend: nodes are placed on real hosts, one per entry of the config
/// file, in order (`node-1` → first host, …). The remote layout mirrors the
/// local one (`<workdir>/<node>/…`); the binary is copied once per host.
///
/// This backend is implemented and interface-complete but is NOT exercised by
/// the in-repo proof run: the development machine has no VMs. First use on real
/// VMs should start with `--backend ssh` against 2 disposable hosts.
pub struct SshBackend {
    hosts: Vec<SshHost>,
    /// Hosts that already received the binary this run.
    seeded: Vec<String>,
    /// name → host index, for stop/cleanup.
    running: HashMap<String, usize>,
    /// Local path of the `sov-rpcd` binary to ship.
    timeout: Duration,
}

impl SshBackend {
    /// Parse `ssh-hosts.json`: `{"hosts": [{"host": …, "user": …, "key": …, "workdir": …}]}`.
    pub fn from_config(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
        let hosts = v
            .get("hosts")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{}: missing `hosts` array", path.display()))?
            .iter()
            .map(|h| {
                let field = |k: &str| {
                    h.get(k)
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| format!("{}: host entry missing `{k}`", path.display()))
                };
                Ok(SshHost {
                    host: field("host")?,
                    user: field("user")?,
                    key: field("key")?,
                    workdir: field("workdir")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if hosts.is_empty() {
            return Err(format!("{}: `hosts` is empty", path.display()));
        }
        Ok(SshBackend {
            hosts,
            seeded: Vec::new(),
            running: HashMap::new(),
            timeout: Duration::from_secs(60),
        })
    }

    /// Index of the host a node name maps to (`node-K` → host `K-1`, wrapping
    /// is refused: more nodes than hosts is a config error, stated plainly).
    fn host_for(&self, name: &str) -> Result<usize, String> {
        let k: usize = name
            .strip_prefix("node-")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("unexpected node name `{name}`"))?;
        if k == 0 || k > self.hosts.len() {
            return Err(format!(
                "{name} needs host #{k} but the ssh config lists only {} host(s)",
                self.hosts.len()
            ));
        }
        Ok(k - 1)
    }

    fn ssh(&self, host: &SshHost, script: &str) -> Result<String, String> {
        let target = format!("{}@{}", host.user, host.host);
        let out = run_cmd_timeout(
            Path::new("ssh"),
            &[
                "-i",
                &host.key,
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                &target,
                script,
            ],
            None,
            self.timeout,
        )?;
        if !out.status_ok {
            return Err(format!("ssh {target} `{script}` failed: {}", out.stderr));
        }
        Ok(out.stdout)
    }

    fn scp(&self, host: &SshHost, local: &Path, remote: &str) -> Result<(), String> {
        let target = format!("{}@{}:{remote}", host.user, host.host);
        let local_s = local.to_string_lossy().to_string();
        let out = run_cmd_timeout(
            Path::new("scp"),
            &["-i", &host.key, "-o", "BatchMode=yes", &local_s, &target],
            None,
            self.timeout,
        )?;
        if !out.status_ok {
            return Err(format!(
                "scp {} → {target} failed: {}",
                local.display(),
                out.stderr
            ));
        }
        Ok(())
    }
}

impl Backend for SshBackend {
    fn start(&mut self, plan: &NodePlan, rpcd: &Path) -> Result<(), String> {
        let idx = self.host_for(&plan.name)?;
        let host = self.hosts[idx].clone();
        let node_dir = format!("{}/{}", host.workdir, plan.name);
        self.ssh(&host, &format!("mkdir -p '{node_dir}/data'"))?;
        if !self.seeded.contains(&host.host) {
            self.scp(&host, rpcd, &format!("{}/sov-rpcd", host.workdir))?;
            self.ssh(&host, &format!("chmod +x '{}/sov-rpcd'", host.workdir))?;
            self.seeded.push(host.host.clone());
        }
        // Ship the bundle. NOTE: the node-config written for this backend must
        // carry addresses/data_dir valid ON THE HOST (net.rs handles that when
        // the ssh backend is selected).
        self.scp(
            &host,
            &plan.config_path(),
            &format!("{node_dir}/node-config.json"),
        )?;
        self.scp(
            &host,
            &plan.spec_path,
            &format!("{node_dir}/chain-spec.json"),
        )?;
        self.scp(
            &host,
            &plan.keystore_path(),
            &format!("{node_dir}/keystore.json"),
        )?;
        self.ssh(
            &host,
            &format!(
                "cd '{node_dir}' && nohup '{}/sov-rpcd' node-config.json chain-spec.json \
                 keystore.json > node.log 2>&1 & echo $! > sov-rpcd.pid",
                host.workdir
            ),
        )?;
        self.running.insert(plan.name.clone(), idx);
        Ok(())
    }

    fn stop(&mut self, name: &str) -> Result<(), String> {
        if let Some(idx) = self.running.remove(name) {
            let host = self.hosts[idx].clone();
            let node_dir = format!("{}/{}", host.workdir, name);
            self.ssh(
                &host,
                &format!(
                    "if [ -f '{node_dir}/sov-rpcd.pid' ]; then \
                       kill \"$(cat '{node_dir}/sov-rpcd.pid')\" 2>/dev/null || true; \
                       rm -f '{node_dir}/sov-rpcd.pid'; fi"
                ),
            )?;
        }
        Ok(())
    }

    fn remove_data_file(&mut self, plan: &NodePlan, file: &str) -> Result<bool, String> {
        let idx = self.host_for(&plan.name)?;
        let host = self.hosts[idx].clone();
        let path = format!("{}/{}/data/{file}", host.workdir, plan.name);
        let out = self.ssh(
            &host,
            &format!("if [ -f '{path}' ]; then rm '{path}' && echo existed; else echo missing; fi"),
        )?;
        Ok(out.trim() == "existed")
    }

    fn data_file_exists(&mut self, plan: &NodePlan, file: &str) -> Result<bool, String> {
        let idx = self.host_for(&plan.name)?;
        let host = self.hosts[idx].clone();
        let path = format!("{}/{}/data/{file}", host.workdir, plan.name);
        let out = self.ssh(
            &host,
            &format!("if [ -f '{path}' ]; then echo yes; else echo no; fi"),
        )?;
        Ok(out.trim() == "yes")
    }

    fn stop_all(&mut self) -> Vec<String> {
        let names: Vec<String> = self.running.keys().cloned().collect();
        for name in &names {
            let _ = self.stop(name);
        }
        names
    }

    fn verify_down(&mut self, plans: &[NodePlan]) -> Result<(), String> {
        for plan in plans {
            let addr: std::net::SocketAddr = plan
                .rpc
                .parse()
                .map_err(|e| format!("{}: bad rpc addr {}: {e}", plan.name, plan.rpc))?;
            poll(
                &format!("{} RPC port to close after teardown", plan.name),
                Duration::from_secs(20),
                Duration::from_millis(500),
                || match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                    Ok(_) => Ok(None),
                    Err(_) => Ok(Some(())),
                },
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// container backend — documented stub
// ---------------------------------------------------------------------------

/// The container backend cannot exist honestly on this machine (no docker /
/// podman / multipass / qemu are installed), so instead of a fake it is a
/// documented stub that states exactly what a real one implements:
///
/// * `start`  → `docker run -d --name sov-e2e-<node> -v <bundle>:/bundle`
///   `-p <rpc>:<rpc> -p <p2p>:<p2p> <image> /bundle/node-config.json …`
/// * `stop`   → `docker rm -f sov-e2e-<node>`
/// * `remove_data_file` → `docker exec sov-e2e-<node> rm /bundle/data/<file>`
/// * `verify_down` → the same RPC-refuses probe the other backends use.
///
/// The matrix driver requires nothing else — it only talks to RPC endpoints.
pub fn container_backend_stub() -> Result<Box<dyn Backend>, String> {
    Err(
        "the `container` backend is a documented stub on this machine (no \
         docker/podman/multipass/qemu available) — use `--backend local` (default) \
         or `--backend ssh --ssh-config <hosts.json>`; see tools/e2e-vm/README.md"
            .to_string(),
    )
}

/// Touch-probe used before start: every port the plan needs must be bindable
/// NOW, so a clash fails with a clear message instead of a confusing node boot
/// error minutes later. (Local backend only — remote ports belong to the VMs.)
pub fn preflight_ports(plans: &[NodePlan]) -> Result<(), String> {
    for plan in plans {
        for addr in [&plan.rpc, &plan.p2p] {
            std::net::TcpListener::bind(addr).map_err(|e| {
                format!(
                    "port preflight: {} needs {addr} but it is unavailable ({e}) — \
                     pass --base-rpc/--base-p2p to relocate the run",
                    plan.name
                )
            })?;
            // Listener dropped immediately; the node binds it for real at start.
        }
    }
    Ok(())
}
