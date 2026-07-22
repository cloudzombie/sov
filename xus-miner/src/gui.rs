use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Sense, Stroke,
    Vec2,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const WINDOW_TITLE: &str = "XUS Miner";
const DEFAULT_POOL: &str = "127.0.0.1:3333";
const DEFAULT_USER: &str = "xus-miner";
const MAX_LOG_LINES: usize = 500;
const MAX_METER_SAMPLES: usize = 180;

const BG: Color32 = Color32::from_rgb(9, 11, 18);
const PANEL: Color32 = Color32::from_rgb(15, 18, 29);
const CARD: Color32 = Color32::from_rgb(21, 25, 39);
const CARD_HOVER: Color32 = Color32::from_rgb(25, 30, 47);
const BORDER: Color32 = Color32::from_rgb(43, 50, 71);
const TEXT: Color32 = Color32::from_rgb(235, 239, 248);
const MUTED: Color32 = Color32::from_rgb(142, 151, 174);
const PURPLE: Color32 = Color32::from_rgb(139, 104, 246);
const CYAN: Color32 = Color32::from_rgb(62, 211, 209);
const GREEN: Color32 = Color32::from_rgb(74, 222, 128);
const AMBER: Color32 = Color32::from_rgb(251, 191, 36);
const RED: Color32 = Color32::from_rgb(248, 113, 113);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Starting,
    Connecting,
    Authenticating,
    Mining,
    Reconnecting,
    Stopping,
    Error,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Starting => "STARTING",
            Self::Connecting => "CONNECTING",
            Self::Authenticating => "AUTHENTICATING",
            Self::Mining => "MINING",
            Self::Reconnecting => "RECONNECTING",
            Self::Stopping => "STOPPING",
            Self::Error => "ATTENTION",
        }
    }

    fn color(self) -> Color32 {
        match self {
            Self::Mining => GREEN,
            Self::Starting | Self::Connecting | Self::Authenticating | Self::Reconnecting => AMBER,
            Self::Error => RED,
            Self::Idle | Self::Stopping => MUTED,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RewardRoute {
    #[default]
    OwnedBridge,
    ExternalPool,
}

impl RewardRoute {
    fn persisted(self) -> &'static str {
        match self {
            Self::OwnedBridge => "owned_bridge",
            Self::ExternalPool => "external_pool",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            Self::OwnedBridge => "Bridge coinbase (operator asserted)",
            Self::ExternalPool => "No automatic payout verified",
        }
    }
}

#[derive(Clone)]
struct Settings {
    reward_route: RewardRoute,
    pool: String,
    user: String,
    password: String,
    workers: u64,
    reconnect_secs: u64,
    report_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            reward_route: RewardRoute::OwnedBridge,
            pool: DEFAULT_POOL.into(),
            user: DEFAULT_USER.into(),
            password: "x".into(),
            workers: 1,
            reconnect_secs: 5,
            report_secs: 2,
        }
    }
}

impl Settings {
    fn from_json(value: &Value) -> Self {
        let mut settings = Self::default();
        if value.get("reward_route").and_then(Value::as_str) == Some("external_pool") {
            settings.reward_route = RewardRoute::ExternalPool;
        }
        if let Some(pool) = value.get("pool").and_then(Value::as_str) {
            settings.pool = pool.to_owned();
        }
        if let Some(user) = value.get("user").and_then(Value::as_str) {
            settings.user = user.to_owned();
        }
        if let Some(workers) = value.get("workers").and_then(Value::as_u64) {
            settings.workers = workers.clamp(1, 64);
        }
        if let Some(seconds) = value.get("reconnect_secs").and_then(Value::as_u64) {
            settings.reconnect_secs = seconds.clamp(1, 3_600);
        }
        if let Some(seconds) = value.get("report_secs").and_then(Value::as_u64) {
            settings.report_secs = seconds.clamp(1, 3_600);
        }
        settings
    }

    fn persisted_json(&self) -> Value {
        json!({
            "reward_route": self.reward_route.persisted(),
            "pool": self.pool.trim(),
            "user": self.user.trim(),
            "workers": self.workers,
            "reconnect_secs": self.reconnect_secs,
            "report_secs": self.report_secs,
        })
    }

    fn validate(&self) -> Result<(), String> {
        validate_pool(&self.pool)?;
        if self.user.trim().is_empty() {
            return Err("Worker label cannot be empty.".into());
        }
        if self.user.len() > 256 {
            return Err("Worker label must be 256 characters or fewer.".into());
        }
        if self.password.contains(['\n', '\r']) {
            return Err("Stratum password cannot contain a line break.".into());
        }
        if self.password.len() > 4_096 {
            return Err("Stratum password is unexpectedly large.".into());
        }
        if !(1..=64).contains(&self.workers) {
            return Err("Worker count must be between 1 and 64.".into());
        }
        Ok(())
    }
}

fn validate_pool(raw: &str) -> Result<(), String> {
    let address = raw
        .trim()
        .strip_prefix("stratum+tcp://")
        .or_else(|| raw.trim().strip_prefix("tcp://"))
        .or_else(|| raw.trim().strip_prefix("rpc://"))
        .or_else(|| raw.trim().strip_prefix("http://"))
        .unwrap_or(raw.trim());
    if address.is_empty() || address.chars().any(char::is_whitespace) {
        return Err("Endpoint must be a host and port, such as 192.168.0.244:8645.".into());
    }
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| "Pool is missing its TCP port.".to_string())?;
    if host.is_empty() {
        return Err("Pool host cannot be empty.".into());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "Pool port must be a number from 1 to 65535.".to_string())?;
    if port == 0 {
        return Err("Pool port cannot be zero.".into());
    }
    Ok(())
}

fn is_direct_node_endpoint(raw: &str) -> bool {
    let raw = raw.trim();
    raw.starts_with("rpc://")
        || raw.starts_with("http://")
        || raw.starts_with("https://")
        || raw
            .trim_end_matches('/')
            .rsplit_once(':')
            .is_some_and(|(_, port)| port == "8645")
}

fn settings_path() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .map(|home| home.join(".xus-miner").join("gui-settings.json"))
}

fn load_settings() -> Settings {
    let Some(path) = settings_path() else {
        return Settings::default();
    };
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .as_ref()
        .map(Settings::from_json)
        .unwrap_or_default()
}

fn save_settings(settings: &Settings) -> Result<(), String> {
    let Some(path) = settings_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create settings directory: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(&settings.persisted_json())
        .map_err(|error| format!("cannot encode settings: {error}"))?;
    fs::write(path, bytes).map_err(|error| format!("cannot save settings: {error}"))
}

enum ProcessMessage {
    Telemetry(Value),
    Log(String),
}

struct LogLine {
    at: Instant,
    text: String,
    error: bool,
}

#[derive(Clone, Copy, Debug)]
struct MeterSample {
    hashrate: f64,
    smoothed_hashrate: f64,
    mempool: Option<u64>,
    height: Option<u64>,
    round_probability: Option<f64>,
}

struct MinerApp {
    settings: Settings,
    phase: Phase,
    child: Option<Child>,
    receiver: Option<Receiver<ProcessMessage>>,
    requested_stop: bool,
    started_at: Option<Instant>,
    hashrate: f64,
    smoothed_hashrate: f64,
    total_hashes: u64,
    submitted: u64,
    accepted: u64,
    rejected: u64,
    height: Option<u64>,
    algorithm: String,
    job_id: String,
    coinbase: Option<String>,
    expected_hashes: Option<f64>,
    round_hashes: u64,
    round_probability: Option<f64>,
    height_started_at: Option<Instant>,
    network_hashrate: Option<f64>,
    target_block_ms: Option<u64>,
    network_difficulty: Option<String>,
    last_error: String,
    logs: VecDeque<LogLine>,
    mempool_size: Option<u64>,
    meter_history: VecDeque<MeterSample>,
    last_metrics_at: Option<Instant>,
    ready_workers: u64,
    reveal_password: bool,
    memory_acknowledged: bool,
}

impl Default for MinerApp {
    fn default() -> Self {
        Self {
            settings: load_settings(),
            phase: Phase::Idle,
            child: None,
            receiver: None,
            requested_stop: false,
            started_at: None,
            hashrate: 0.0,
            smoothed_hashrate: 0.0,
            total_hashes: 0,
            submitted: 0,
            accepted: 0,
            rejected: 0,
            height: None,
            algorithm: "—".into(),
            job_id: "Waiting for work".into(),
            coinbase: None,
            expected_hashes: None,
            round_hashes: 0,
            round_probability: None,
            height_started_at: None,
            network_hashrate: None,
            target_block_ms: None,
            network_difficulty: None,
            last_error: String::new(),
            logs: VecDeque::new(),
            mempool_size: None,
            meter_history: VecDeque::new(),
            last_metrics_at: None,
            ready_workers: 0,
            reveal_password: false,
            memory_acknowledged: false,
        }
    }
}

impl MinerApp {
    fn is_running(&self) -> bool {
        self.child.is_some()
    }

    fn reset_telemetry(&mut self) {
        self.hashrate = 0.0;
        self.smoothed_hashrate = 0.0;
        self.total_hashes = 0;
        self.submitted = 0;
        self.accepted = 0;
        self.rejected = 0;
        self.height = None;
        self.algorithm = "—".into();
        self.job_id = "Waiting for work".into();
        self.coinbase = None;
        self.expected_hashes = None;
        self.round_hashes = 0;
        self.round_probability = None;
        self.height_started_at = None;
        self.network_hashrate = None;
        self.target_block_ms = None;
        self.network_difficulty = None;
        self.last_error.clear();
        self.mempool_size = None;
        self.meter_history.clear();
        self.last_metrics_at = None;
        self.ready_workers = 0;
    }

    fn push_log(&mut self, text: impl Into<String>, error: bool) {
        let text = text.into();
        if text.trim().is_empty() {
            return;
        }
        self.logs.push_back(LogLine {
            at: Instant::now(),
            text,
            error,
        });
        while self.logs.len() > MAX_LOG_LINES {
            self.logs.pop_front();
        }
    }

    fn start(&mut self) {
        if self.is_running() {
            return;
        }
        if let Err(error) = self.settings.validate() {
            self.last_error.clone_from(&error);
            self.phase = Phase::Error;
            self.push_log(error, true);
            return;
        }
        if self.settings.workers > 1 && !self.memory_acknowledged {
            let required = self.settings.workers as f64 * 2.3;
            let error = format!(
                "Confirm that at least {required:.1} GiB of memory is available before starting {} RandomX workers.",
                self.settings.workers
            );
            self.last_error.clone_from(&error);
            self.phase = Phase::Error;
            self.push_log(error, true);
            return;
        }
        if let Err(error) = save_settings(&self.settings) {
            self.push_log(error, true);
        }

        self.reset_telemetry();
        self.phase = Phase::Starting;
        self.requested_stop = false;
        self.started_at = Some(Instant::now());
        self.logs.clear();
        self.push_log("Starting isolated mining engine…", false);

        let executable = match env::current_exe() {
            Ok(path) => path,
            Err(error) => {
                self.phase = Phase::Error;
                self.last_error = format!("Cannot locate miner executable: {error}");
                self.push_log(self.last_error.clone(), true);
                return;
            }
        };
        let mut command = Command::new(executable);
        command
            .arg("--headless")
            .arg("--json-events")
            .arg("--password-stdin")
            .arg("--pool")
            .arg(self.settings.pool.trim())
            .arg("--user")
            .arg(self.settings.user.trim())
            .arg("--workers")
            .arg(self.settings.workers.to_string())
            .arg("--reconnect-secs")
            .arg(self.settings.reconnect_secs.to_string())
            .arg("--report-secs")
            .arg(self.settings.report_secs.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.phase = Phase::Error;
                self.last_error = format!("Cannot start mining engine: {error}");
                self.push_log(self.last_error.clone(), true);
                return;
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(error) = stdin.write_all(self.settings.password.as_bytes()) {
                let _ = child.kill();
                let _ = child.wait();
                self.phase = Phase::Error;
                self.last_error = format!("Cannot pass credentials to mining engine: {error}");
                self.push_log(self.last_error.clone(), true);
                return;
            }
        }

        let (sender, receiver) = mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            let tx = sender.clone();
            thread::Builder::new()
                .name("xus-gui-telemetry".into())
                .spawn(move || {
                    for line in BufReader::new(stdout).lines() {
                        match line {
                            Ok(line) => match serde_json::from_str::<Value>(&line) {
                                Ok(value) => {
                                    if tx.send(ProcessMessage::Telemetry(value)).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    if tx.send(ProcessMessage::Log(line)).is_err() {
                                        break;
                                    }
                                }
                            },
                            Err(error) => {
                                let _ = tx.send(ProcessMessage::Log(format!(
                                    "Telemetry channel failed: {error}"
                                )));
                                break;
                            }
                        }
                    }
                })
                .ok();
        }
        if let Some(stderr) = child.stderr.take() {
            thread::Builder::new()
                .name("xus-gui-engine-log".into())
                .spawn(move || {
                    for line in BufReader::new(stderr).lines() {
                        match line {
                            Ok(line) => {
                                if sender.send(ProcessMessage::Log(line)).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                })
                .ok();
        }

        self.receiver = Some(receiver);
        self.child = Some(child);
    }

    fn stop(&mut self) {
        if self.child.is_none() {
            return;
        }
        self.requested_stop = true;
        self.phase = Phase::Stopping;
        self.push_log("Stopping mining engine and releasing worker memory…", false);
        if let Err(error) = self.child.as_mut().expect("child checked above").kill() {
            self.last_error = format!("Could not stop mining engine: {error}");
            self.phase = Phase::Error;
            self.push_log(self.last_error.clone(), true);
        }
    }

    fn poll_process(&mut self, ctx: &egui::Context) {
        let mut messages = Vec::new();
        if let Some(receiver) = &self.receiver {
            while let Ok(message) = receiver.try_recv() {
                messages.push(message);
            }
        }
        for message in messages {
            match message {
                ProcessMessage::Telemetry(value) => self.apply_telemetry(&value),
                ProcessMessage::Log(line) => {
                    // Structured `metrics` telemetry already drives the dashboard.
                    // Do not duplicate its two-second stderr summary into the event log.
                    if line.starts_with("height ") && line.contains(" | total ") {
                        continue;
                    }
                    let lower = line.to_ascii_lowercase();
                    let error = lower.contains("error:")
                        || lower.contains("failed")
                        || lower.contains("submission rejected")
                        || lower.contains("share rejected #")
                        || lower.contains("session ended");
                    self.push_log(line, error);
                }
            }
        }

        let exit = self
            .child
            .as_mut()
            .and_then(|child| match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    self.last_error = format!("Cannot observe mining engine: {error}");
                    self.phase = Phase::Error;
                    None
                }
            });
        if let Some(status) = exit {
            self.child = None;
            self.receiver = None;
            self.hashrate = 0.0;
            self.smoothed_hashrate = 0.0;
            self.last_metrics_at = None;
            if self.requested_stop {
                self.phase = Phase::Idle;
                self.push_log("Mining stopped.", false);
            } else {
                self.phase = Phase::Error;
                self.last_error = format!("Mining engine exited unexpectedly ({status}).");
                self.push_log(self.last_error.clone(), true);
            }
        }

        if self.is_running() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    fn apply_telemetry(&mut self, value: &Value) {
        match value.get("event").and_then(Value::as_str) {
            Some("startup") => {
                self.phase = Phase::Connecting;
                self.push_log("Mining engine online.", false);
            }
            Some("connecting") => {
                self.phase = Phase::Connecting;
            }
            Some("pool_connected") => {
                self.phase = Phase::Authenticating;
                self.push_log("TCP connection established; authenticating…", false);
            }
            Some("node_connected") => {
                self.phase = Phase::Mining;
                self.push_log(
                    "Connected directly to SOV node RPC; requesting work…",
                    false,
                );
            }
            Some("worker_initializing") => {
                if let Some(worker) = value.get("worker").and_then(Value::as_u64) {
                    self.push_log(
                        format!(
                            "Worker {} is initializing its RandomX dataset (~2.3 GiB)…",
                            worker + 1
                        ),
                        false,
                    );
                }
            }
            Some("worker_ready") => {
                if let Some(worker) = value.get("worker").and_then(Value::as_u64) {
                    self.ready_workers = self
                        .ready_workers
                        .saturating_add(1)
                        .min(self.settings.workers);
                    self.push_log(format!("Worker {} ready; hashing.", worker + 1), false);
                }
            }
            Some("job") => {
                self.phase = Phase::Mining;
                let next_height = value.get("height").and_then(Value::as_u64);
                if next_height.is_some() && next_height != self.height {
                    self.round_hashes = 0;
                    self.round_probability = Some(0.0);
                    self.height_started_at = Some(Instant::now());
                }
                self.height = next_height;
                self.algorithm = value
                    .get("algorithm")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                self.job_id = value
                    .get("job_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                self.coinbase = value
                    .get("coinbase")
                    .and_then(Value::as_str)
                    .filter(|account| !account.is_empty())
                    .map(str::to_owned);
                self.expected_hashes = value
                    .get("expected_hashes")
                    .and_then(Value::as_f64)
                    .filter(|expected| expected.is_finite() && *expected > 0.0);
                if self.expected_hashes.is_none() {
                    self.round_probability = None;
                }
            }
            Some("network") => {
                self.network_hashrate = value
                    .get("hashrate")
                    .and_then(Value::as_f64)
                    .filter(|rate| rate.is_finite() && *rate >= 0.0);
                self.target_block_ms = value.get("target_block_ms").and_then(Value::as_u64);
                self.network_difficulty = value
                    .get("difficulty")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            Some("metrics") => {
                let now = Instant::now();
                let elapsed = self
                    .last_metrics_at
                    .map_or(self.settings.report_secs as f64, |last| {
                        now.saturating_duration_since(last).as_secs_f64()
                    });
                self.last_metrics_at = Some(now);
                self.hashrate = value.get("hashrate").and_then(Value::as_f64).unwrap_or(0.0);
                let alpha = 1.0 - (-elapsed / 8.0).exp();
                self.smoothed_hashrate = if self.smoothed_hashrate <= 0.0 && self.hashrate > 0.0 {
                    self.hashrate
                } else {
                    self.smoothed_hashrate + alpha * (self.hashrate - self.smoothed_hashrate)
                }
                .max(0.0);
                self.total_hashes = value
                    .get("total_hashes")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.total_hashes);
                self.submitted = value
                    .get("submitted")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.submitted);
                self.accepted = value
                    .get("accepted")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.accepted);
                self.rejected = value
                    .get("rejected")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.rejected);
                let metrics_height = value.get("height").and_then(Value::as_u64);
                if self.height.is_none() {
                    self.height = metrics_height;
                }
                let round_height = value.get("round_height").and_then(Value::as_u64);
                if round_height == metrics_height && metrics_height == self.height {
                    self.round_hashes = value
                        .get("round_hashes")
                        .and_then(Value::as_u64)
                        .unwrap_or(self.round_hashes);
                    self.round_probability = self.expected_hashes.and_then(|_| {
                        value
                            .get("round_probability")
                            .and_then(Value::as_f64)
                            .filter(|probability| probability.is_finite())
                            .map(|probability| probability.clamp(0.0, 1.0))
                    });
                }
                if let Some(size) = value.get("mempool_size").and_then(Value::as_u64) {
                    self.mempool_size = Some(size);
                }
                self.meter_history.push_back(MeterSample {
                    hashrate: self.hashrate,
                    smoothed_hashrate: self.smoothed_hashrate,
                    mempool: self.mempool_size,
                    height: self.height,
                    round_probability: self.round_probability,
                });
                while self.meter_history.len() > MAX_METER_SAMPLES {
                    self.meter_history.pop_front();
                }
            }
            Some("share") => {
                self.submitted = value
                    .get("submitted")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.submitted);
                self.accepted = value
                    .get("accepted")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.accepted);
                self.rejected = value
                    .get("rejected")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.rejected);
            }
            Some("session_error") => {
                self.phase = Phase::Reconnecting;
                self.hashrate = 0.0;
                self.smoothed_hashrate = 0.0;
                self.last_metrics_at = None;
                self.last_error = value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Pool session ended.")
                    .to_owned();
            }
            _ => {}
        }
    }

    fn solo_block_eta_seconds(&self) -> Option<f64> {
        if !self.telemetry_is_fresh() || !matches!(self.phase, Phase::Mining) {
            return None;
        }
        let expected = self.expected_hashes?;
        (self.smoothed_hashrate > 0.0).then_some(expected / self.smoothed_hashrate)
    }

    fn current_round_probability(&self) -> Option<f64> {
        self.expected_hashes?;
        (self.telemetry_is_fresh() && matches!(self.phase, Phase::Mining))
            .then_some(self.round_probability)
            .flatten()
    }

    fn current_round_elapsed(&self) -> Option<Duration> {
        (self.telemetry_is_fresh() && matches!(self.phase, Phase::Mining))
            .then(|| self.height_started_at.map(|started| started.elapsed()))
            .flatten()
    }

    fn telemetry_is_fresh(&self) -> bool {
        self.last_metrics_at.is_some_and(|at| {
            at.elapsed() < Duration::from_secs(self.settings.report_secs.saturating_mul(3).max(8))
        })
    }

    fn uptime(&self) -> String {
        if !self.is_running() {
            return "00:00:00".into();
        }
        let Some(started) = self.started_at else {
            return "00:00:00".into();
        };
        let seconds = started.elapsed().as_secs();
        format!(
            "{:02}:{:02}:{:02}",
            seconds / 3_600,
            seconds / 60 % 60,
            seconds % 60
        )
    }

    fn formatted_logs(&self) -> String {
        let origin = self.started_at;
        self.logs
            .iter()
            .map(|line| {
                let seconds = origin
                    .map(|start| line.at.saturating_duration_since(start).as_secs())
                    .unwrap_or(0);
                format!("[{:02}:{:02}] {}", seconds / 60, seconds % 60, line.text)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn diagnostics_text(&self) -> String {
        let mempool = self
            .mempool_size
            .map_or_else(|| "unavailable".into(), |size| size.to_string());
        let height = self
            .height
            .map_or_else(|| "unavailable".into(), |height| height.to_string());
        let last_error = if self.last_error.is_empty() {
            "none"
        } else {
            &self.last_error
        };
        let block_eta = self
            .solo_block_eta_seconds()
            .map(format_eta)
            .unwrap_or_else(|| "unavailable".into());
        let round_chance = self
            .current_round_probability()
            .map(format_probability)
            .unwrap_or_else(|| "unavailable".into());
        format!(
            "XUS MINER DIAGNOSTICS\n\
             phase: {}\n\
             endpoint: {}\n\
             algorithm: {}\n\
             height: {}\n\
             job: {}\n\
             coinbase (template confirmed): {}\n\
             hashrate: {}\n\
             smoothed hashrate: {}\n\
             expected solo block time: {}\n\
             current round probability: {}\n\
             expected hashes per block: {}\n\
             network hashrate: {}\n\
             target block cadence: {}\n\
             network difficulty: {}\n\
             total hashes: {}\n\
             workers ready/configured: {}/{}\n\
             mempool pending: {}\n\
             submitted/accepted/rejected: {}/{}/{}\n\
             uptime: {}\n\
             last error: {}\n\
             \nEVENT LOG\n{}",
            self.phase.label(),
            self.settings.pool.trim(),
            self.algorithm,
            height,
            self.job_id,
            self.coinbase.as_deref().unwrap_or("not disclosed"),
            format_hashrate(self.hashrate),
            format_hashrate(self.smoothed_hashrate),
            block_eta,
            round_chance,
            self.expected_hashes
                .map(format_count_f64)
                .unwrap_or_else(|| "unavailable".into()),
            self.network_hashrate
                .map(format_hashrate)
                .unwrap_or_else(|| "unavailable".into()),
            self.target_block_ms
                .map(|ms| format_eta(ms as f64 / 1_000.0))
                .unwrap_or_else(|| "unavailable".into()),
            self.network_difficulty.as_deref().unwrap_or("unavailable"),
            self.total_hashes,
            self.ready_workers,
            self.settings.workers,
            mempool,
            self.submitted,
            self.accepted,
            self.rejected,
            self.uptime(),
            last_error,
            self.formatted_logs(),
        )
    }

    fn engine_log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("ENGINE LOG").size(11.0).strong().color(MUTED));
            ui.label(
                RichText::new("drag the top edge to resize • select text normally")
                    .size(9.0)
                    .color(MUTED),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Clear").clicked() {
                    self.logs.clear();
                }
                if ui.small_button("Copy diagnostics").clicked() {
                    ui.ctx().copy_text(self.diagnostics_text());
                }
            });
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .id_salt("engine-log-scroll-v2")
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.logs.is_empty() {
                    ui.add(
                        egui::Label::new(
                            RichText::new("Engine events will appear here.")
                                .monospace()
                                .size(11.0)
                                .color(MUTED),
                        )
                        .selectable(true),
                    );
                    return;
                }

                let origin = self.started_at;
                let mut job = egui::text::LayoutJob::default();
                for (index, line) in self.logs.iter().enumerate() {
                    let seconds = origin
                        .map(|start| line.at.saturating_duration_since(start).as_secs())
                        .unwrap_or(0);
                    if index > 0 {
                        job.append("\n", 0.0, egui::TextFormat::default());
                    }
                    job.append(
                        &format!("[{:02}:{:02}] {}", seconds / 60, seconds % 60, line.text),
                        0.0,
                        egui::TextFormat {
                            font_id: FontId::monospace(11.0),
                            color: if line.error {
                                RED
                            } else if line.text.contains("COINBASE CONFIRMED") {
                                GREEN
                            } else {
                                MUTED
                            },
                            ..Default::default()
                        },
                    );
                }
                ui.add(egui::Label::new(job).selectable(true).wrap());
            });
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(
            RichText::new("REWARD ROUTE")
                .size(11.0)
                .color(MUTED)
                .strong(),
        );
        ui.add_space(6.0);
        ui.add_enabled_ui(!self.is_running(), |ui| {
            ui.selectable_value(
                &mut self.settings.reward_route,
                RewardRoute::OwnedBridge,
                "My bridge / my coinbase",
            );
            ui.selectable_value(
                &mut self.settings.reward_route,
                RewardRoute::ExternalPool,
                "External pool / contributor",
            );
        });
        ui.add_space(7.0);
        let direct_node = is_direct_node_endpoint(&self.settings.pool);
        let (callout, callout_color) = if direct_node {
            (
                "Direct node mode: the miner reads the coinbase from each block template and refuses any requested-account mismatch. No wallet password or private key is used.",
                GREEN,
            )
        } else {
            match self.settings.reward_route {
            RewardRoute::OwnedBridge => (
                "The bridge—not this miner—sets the public coinbase account. Keep its spending keys in SOV Station.",
                GREEN,
            ),
            RewardRoute::ExternalPool => (
                "Current SOV Stratum has no automatic payout layer. A worker label does not earn XUS by itself.",
                AMBER,
            ),
            }
        };
        Frame::new()
            .fill(callout_color.gamma_multiply(0.08))
            .stroke(Stroke::new(1.0_f32, callout_color.gamma_multiply(0.35)))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(9))
            .show(ui, |ui| {
                ui.label(RichText::new(callout).size(10.0).color(callout_color));
            });

        ui.add_space(16.0);
        ui.label(RichText::new("CONNECTION").size(11.0).color(MUTED).strong());
        ui.add_space(8.0);
        let running = self.is_running();
        ui.add_enabled(
            !running,
            egui::TextEdit::singleline(&mut self.settings.pool)
                .hint_text(DEFAULT_POOL)
                .desired_width(240.0),
        )
        .on_hover_text("SOV node RPC (normally :8645) or Stratum pool/bridge address");
        ui.add_space(8.0);
        ui.add_enabled(
            !running,
            egui::TextEdit::singleline(&mut self.settings.user)
                .hint_text(DEFAULT_USER)
                .desired_width(240.0),
        )
        .on_hover_text(
            "Direct node: public coinbase account, or xus-miner to use the node-configured account. Stratum: worker label.",
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let mut edit = egui::TextEdit::singleline(&mut self.settings.password)
                .hint_text("Stratum password")
                .desired_width(ui.available_width() - 42.0);
            if !self.reveal_password {
                edit = edit.password(true);
            }
            ui.add_enabled(!running, edit);
            if ui
                .add_enabled(
                    !running,
                    egui::Button::new(if self.reveal_password { "Hide" } else { "Show" }),
                )
                .clicked()
            {
                self.reveal_password = !self.reveal_password;
            }
        });
        ui.label(
            RichText::new(if direct_node {
                "Unused in direct node mode; no wallet credential is sent."
            } else {
                "Password is passed over stdin and never saved."
            })
            .size(10.0)
            .color(MUTED),
        );

        ui.add_space(14.0);
        ui.label(RichText::new("COMPUTE").size(11.0).color(MUTED).strong());
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("CPU workers");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let response = ui.add_enabled(
                    !running,
                    egui::DragValue::new(&mut self.settings.workers)
                        .range(1..=64)
                        .speed(0.1),
                );
                if response.changed() {
                    self.memory_acknowledged = false;
                }
            });
        });
        ui.add(
            egui::ProgressBar::new(self.settings.workers as f32 / 64.0)
                .fill(PURPLE)
                .desired_width(240.0)
                .show_percentage(),
        );
        ui.label(
            RichText::new(format!(
                "RandomX memory ceiling ≈ {:.1} GiB",
                self.settings.workers as f64 * 2.3
            ))
            .size(10.0)
            .color(if self.settings.workers > 1 {
                AMBER
            } else {
                MUTED
            }),
        );
        if self.settings.workers > 1 {
            ui.add_enabled(
                !running,
                egui::Checkbox::new(
                    &mut self.memory_acknowledged,
                    format!(
                        "I have ≥ {:.1} GiB free",
                        self.settings.workers as f64 * 2.3
                    ),
                ),
            );
            ui.label(
                RichText::new("This confirmation is never saved.")
                    .size(10.0)
                    .color(MUTED),
            );
        }

        ui.add_space(14.0);
        egui::CollapsingHeader::new("Advanced")
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Reconnect delay");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_enabled(
                            !running,
                            egui::DragValue::new(&mut self.settings.reconnect_secs)
                                .range(1..=3_600)
                                .suffix(" s"),
                        );
                    });
                });
                ui.horizontal(|ui| {
                    ui.label("Telemetry interval");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_enabled(
                            !running,
                            egui::DragValue::new(&mut self.settings.report_secs)
                                .range(1..=3_600)
                                .suffix(" s"),
                        );
                    });
                });
            });

        ui.add_space(14.0);
        let action = match self.settings.reward_route {
            RewardRoute::OwnedBridge => "▶  START MINING",
            RewardRoute::ExternalPool => "▶  START CONTRIBUTING",
        };
        let button = if running {
            egui::Button::new(RichText::new("■  STOP MINING").strong().color(TEXT))
                .fill(Color32::from_rgb(102, 42, 55))
        } else {
            egui::Button::new(RichText::new(action).strong().color(TEXT))
                .fill(Color32::from_rgb(20, 126, 133))
        };
        if ui.add_sized([ui.available_width(), 44.0], button).clicked() {
            if running {
                self.stop();
            } else {
                self.start();
            }
        }
    }

    fn header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 20.0, PURPLE);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "X",
                FontId::proportional(23.0),
                TEXT,
            );
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("XUS MINER").size(21.0).strong().color(TEXT));
                ui.label(
                    RichText::new("SOV external proof-of-work console")
                        .size(11.0)
                        .color(MUTED),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                Frame::new()
                    .fill(self.phase.color().gamma_multiply(0.13))
                    .stroke(Stroke::new(
                        1.0_f32,
                        self.phase.color().gamma_multiply(0.55),
                    ))
                    .corner_radius(CornerRadius::same(20))
                    .inner_margin(Margin::symmetric(14, 7))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(self.phase.label())
                                .size(11.0)
                                .strong()
                                .color(self.phase.color()),
                        );
                    });
            });
        });
    }

    fn status_rail(&self, ui: &mut egui::Ui) {
        let metrics_fresh = self.telemetry_is_fresh();
        let connected = matches!(self.phase, Phase::Mining) && self.height.is_some();
        let hashing = connected && metrics_fresh && self.hashrate > 0.0;
        let has_job = connected && self.job_id != "Waiting for work";
        let pulse_time = ui.input(|input| input.time);

        ui.columns(4, |columns| {
            heartbeat_card(
                &mut columns[0],
                "NODE LINK",
                if connected {
                    "CONNECTED"
                } else {
                    self.phase.label()
                },
                if connected {
                    "RPC telemetry live"
                } else {
                    "Waiting for node"
                },
                if connected { GREEN } else { self.phase.color() },
                connected,
                pulse_time,
            );
            heartbeat_card(
                &mut columns[1],
                "PROOF OF WORK",
                if hashing {
                    "HASHING"
                } else if connected {
                    "WARMING"
                } else {
                    "OFFLINE"
                },
                if hashing {
                    format!(
                        "{} • {} workers",
                        format_hashrate(self.hashrate),
                        self.ready_workers
                    )
                } else if connected {
                    "Preparing workers".into()
                } else {
                    "No active engine".into()
                },
                if hashing {
                    CYAN
                } else if connected {
                    AMBER
                } else {
                    RED
                },
                hashing,
                pulse_time + 0.17,
            );
            heartbeat_card(
                &mut columns[2],
                "JOB FEED",
                if has_job { "ACTIVE" } else { "WAITING" },
                self.height.map_or_else(
                    || "No current template".into(),
                    |height| {
                        format!(
                            "Block #{height} • {}",
                            self.solo_block_eta_seconds()
                                .map(format_eta)
                                .unwrap_or_else(|| {
                                    if self.expected_hashes.is_none() {
                                        "ETA unavailable".into()
                                    } else {
                                        "ETA locking".into()
                                    }
                                })
                        )
                    },
                ),
                if has_job { PURPLE } else { AMBER },
                has_job,
                pulse_time + 0.34,
            );
            let pending = self.mempool_size.unwrap_or(0);
            heartbeat_card(
                &mut columns[3],
                "TX QUEUE",
                if pending > 0 { "TRANSACTIONS" } else { "CLEAR" },
                self.mempool_size
                    .map(|size| format!("{size} pending for mining"))
                    .unwrap_or_else(|| "Awaiting node data".into()),
                if pending > 0 { GREEN } else { MUTED },
                connected && self.mempool_size.is_some(),
                pulse_time + 0.51,
            );
        });
    }

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        self.header(ui);
        ui.add_space(14.0);
        self.status_rail(ui);
        ui.add_space(12.0);
        ui.columns(4, |columns| {
            metric_card(
                &mut columns[0],
                "HASHRATE",
                &format_hashrate(self.hashrate),
                CYAN,
            );
            metric_card(
                &mut columns[1],
                "CHAIN HEIGHT",
                &self
                    .height
                    .map(|height| format!("#{height}"))
                    .unwrap_or_else(|| "—".into()),
                PURPLE,
            );
            metric_card(
                &mut columns[2],
                "SOLO BLOCK ETA",
                &self
                    .solo_block_eta_seconds()
                    .map(format_eta)
                    .unwrap_or_else(|| {
                        if self.height.is_some() && self.expected_hashes.is_none() {
                            "N/A (POOL)".into()
                        } else {
                            "LOCKING…".into()
                        }
                    }),
                GREEN,
            );
            metric_card(&mut columns[3], "UPTIME", &self.uptime(), AMBER);
        });

        ui.add_space(12.0);
        Frame::new()
            .fill(CARD)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("LIVE MINING METERS")
                            .size(11.0)
                            .strong()
                            .color(MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} total hashes",
                                format_count(self.total_hashes)
                            ))
                            .size(11.0)
                            .color(MUTED),
                        );
                    });
                });
                ui.add_space(8.0);
                let eta = self.solo_block_eta_seconds();
                let probability = self.current_round_probability();
                ui.columns(4, |columns| {
                    meter_readout(
                        &mut columns[0],
                        "SMOOTHED HASHRATE",
                        &format_hashrate(self.smoothed_hashrate),
                        "8-second signal lock",
                        CYAN,
                    );
                    meter_readout(
                        &mut columns[1],
                        "EXPECTED SOLO FIND",
                        &eta.map(format_eta).unwrap_or_else(|| "—".into()),
                        "probabilistic mean",
                        GREEN,
                    );
                    meter_readout(
                        &mut columns[2],
                        "50% SOLO WINDOW",
                        &eta.map(|seconds| format_eta(seconds * std::f64::consts::LN_2))
                            .unwrap_or_else(|| "—".into()),
                        "median at current rate",
                        PURPLE,
                    );
                    meter_readout(
                        &mut columns[3],
                        "CURRENT ROUND CHANCE",
                        &probability
                            .map(format_probability)
                            .unwrap_or_else(|| "—".into()),
                        &self
                            .current_round_elapsed()
                            .map(|elapsed| format!("{} on block", format_elapsed(elapsed)))
                            .unwrap_or_else(|| "waiting for work".into()),
                        AMBER,
                    );
                });
                ui.add_space(9.0);
                let width = ui.available_width();
                egui::Resize::default()
                    .id_salt("live-mining-meter-height-v3")
                    .default_size([width, 205.0])
                    .min_size([width, 175.0])
                    .max_size([width, 430.0])
                    .resizable([false, true])
                    .with_stroke(false)
                    .show(ui, |ui| {
                        let meter_height = ui.available_height().max(170.0);
                        mining_meter(
                            ui,
                            &self.meter_history,
                            self.settings.report_secs,
                            meter_height,
                        );
                    });
                ui.add_space(7.0);
                ui.horizontal_wrapped(|ui| {
                    Frame::new()
                        .fill(PURPLE.gamma_multiply(0.18))
                        .stroke(Stroke::new(1.0, PURPLE.gamma_multiply(0.72)))
                        .corner_radius(CornerRadius::same(7))
                        .inner_margin(Margin::symmetric(9, 5))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("●").size(8.0).color(PURPLE));
                                ui.label(
                                    RichText::new("NETWORK HASHRATE")
                                        .size(9.0)
                                        .strong()
                                        .color(TEXT),
                                );
                                ui.label(
                                    RichText::new(
                                        self.network_hashrate
                                            .map(format_hashrate)
                                            .unwrap_or_else(|| "—".into()),
                                    )
                                    .size(11.0)
                                    .strong()
                                    .monospace()
                                    .color(PURPLE),
                                );
                            });
                        })
                        .response
                        .on_hover_text("Estimated by the connected SOV node; separate from this miner's local hashrate.");
                    ui.label(
                        RichText::new(format!(
                            "TARGET CADENCE {}",
                            self.target_block_ms
                                .map(|ms| format_eta(ms as f64 / 1_000.0))
                                .unwrap_or_else(|| "—".into())
                        ))
                        .size(9.0)
                        .monospace()
                        .color(MUTED),
                    );
                    ui.label(RichText::new("•").size(9.0).color(BORDER));
                    ui.label(
                        RichText::new(format!(
                            "WORK / BLOCK {}",
                            self.expected_hashes
                                .map(format_count_f64)
                                .unwrap_or_else(|| "—".into())
                        ))
                        .size(9.0)
                        .monospace()
                        .color(MUTED),
                    );
                    ui.label(RichText::new("•").size(9.0).color(BORDER));
                    ui.label(
                        RichText::new("ETA is statistical, never a guaranteed countdown")
                            .size(9.0)
                            .color(MUTED),
                    );
                });
            });

        ui.add_space(12.0);
        let width = ui.available_width();
        egui::Resize::default()
            .id_salt("work-health-height-v2")
            .default_size([width, 205.0])
            .min_size([width, 155.0])
            .max_size([width, 360.0])
            .resizable([false, true])
            .with_stroke(false)
            .show(ui, |ui| {
                let card_height = ui.available_height().max(150.0);
                ui.columns(2, |columns| {
                    Frame::new()
                        .fill(CARD)
                        .stroke(Stroke::new(1.0_f32, BORDER))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::same(16))
                        .show(&mut columns[0], |ui| {
                            ui.set_min_height(card_height - 32.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("ACTIVE WORK")
                                        .size(11.0)
                                        .strong()
                                        .color(MUTED),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(
                                        RichText::new("↘ resize section")
                                            .size(9.0)
                                            .color(MUTED),
                                    );
                                });
                            });
                            ui.add_space(10.0);
                            ui.columns(2, |chips| {
                                work_chip(&mut chips[0], "ALGORITHM", &self.algorithm, CYAN);
                                work_chip(
                                    &mut chips[1],
                                    "HEIGHT",
                                    &self
                                        .height
                                        .map(|height| format!("#{height}"))
                                        .unwrap_or_else(|| "—".into()),
                                    PURPLE,
                                );
                            });
                            ui.add_space(10.0);
                            copyable_detail_row(ui, "Job ID", &self.job_id);
                            copyable_detail_row(ui, "Endpoint", self.settings.pool.trim());
                            copyable_detail_row(
                                ui,
                                "Coinbase",
                                self.coinbase.as_deref().unwrap_or("awaiting template confirmation"),
                            );
                            copyable_detail_row(
                                ui,
                                "Mempool",
                                &self
                                    .mempool_size
                                    .map(|size| format!("{size} pending transaction(s)"))
                                    .unwrap_or_else(|| "unavailable".into()),
                            );
                            copyable_detail_row(
                                ui,
                                "Route",
                                if is_direct_node_endpoint(&self.settings.pool) {
                                    "Direct SOV node (template verified)"
                                } else {
                                    self.settings.reward_route.summary()
                                },
                            );
                        });
                    Frame::new()
                        .fill(CARD)
                        .stroke(Stroke::new(1.0_f32, BORDER))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::same(16))
                        .show(&mut columns[1], |ui| {
                            ui.set_min_height(card_height - 32.0);
                            ui.label(
                                RichText::new("SUBMISSION HEALTH")
                                    .size(11.0)
                                    .strong()
                                    .color(MUTED),
                            );
                            ui.add_space(10.0);
                            detail_row(ui, "Submitted", &self.submitted.to_string());
                            detail_row(ui, "Accepted", &self.accepted.to_string());
                            detail_row(ui, "Rejected", &self.rejected.to_string());
                            let ratio = if self.accepted + self.rejected == 0 {
                                "—".into()
                            } else {
                                format!(
                                    "{:.2}%",
                                    self.accepted as f64 * 100.0
                                        / (self.accepted + self.rejected) as f64
                                )
                            };
                            detail_row(ui, "Acceptance", &ratio);
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new(
                                    "Direct-node counters advance only when a network-difficulty block is submitted.",
                                )
                                .size(10.0)
                                .color(MUTED),
                            );
                        });
                });
            });

        if !self.last_error.is_empty() && matches!(self.phase, Phase::Error | Phase::Reconnecting) {
            ui.add_space(12.0);
            Frame::new()
                .fill(RED.gamma_multiply(0.09))
                .stroke(Stroke::new(1.0_f32, RED.gamma_multiply(0.45)))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::same(12))
                .show(ui, |ui| {
                    ui.label(RichText::new(&self.last_error).color(RED));
                });
        }
    }
}

impl Drop for MinerApp {
    fn drop(&mut self) {
        let _ = save_settings(&self.settings);
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl eframe::App for MinerApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_process(ctx);
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::left("miner-controls")
            .default_size(285.0)
            .min_size(250.0)
            .max_size(460.0)
            .resizable(true)
            .frame(
                Frame::new()
                    .fill(PANEL)
                    .inner_margin(Margin::same(18))
                    .stroke(Stroke::new(1.0_f32, BORDER)),
            )
            .show(ui, |ui| {
                ui.label(
                    RichText::new("OPERATOR CONTROLS")
                        .size(13.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label(
                    RichText::new("Hash here. Keep keys elsewhere.")
                        .size(11.0)
                        .color(MUTED),
                );
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.controls(ui);
                    ui.add_space(22.0);
                    ui.label(
                        RichText::new("No wallet seed or private key is used.")
                            .size(10.0)
                            .color(GREEN),
                    );
                    ui.label(
                        RichText::new(format!("xus-miner v{}", env!("CARGO_PKG_VERSION")))
                            .size(10.0)
                            .color(MUTED),
                    );
                });
            });
        egui::Panel::bottom("engine-log-panel-v2")
            .default_size(220.0)
            .min_size(100.0)
            .max_size(560.0)
            .resizable(true)
            .frame(
                Frame::new()
                    .fill(CARD)
                    .inner_margin(Margin::same(14))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| self.engine_log_panel(ui));
        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG).inner_margin(Margin::same(22)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.dashboard(ui));
            });
    }
}

fn install_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.global_style_mut(|style| {
        style.visuals = egui::Visuals::dark();
        style.visuals.panel_fill = BG;
        style.visuals.window_fill = PANEL;
        style.visuals.extreme_bg_color = Color32::from_rgb(11, 14, 23);
        style.visuals.faint_bg_color = CARD;
        style.visuals.widgets.inactive.bg_fill = CARD;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
        style.visuals.widgets.hovered.bg_fill = CARD_HOVER;
        style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, PURPLE);
        style.visuals.widgets.active.bg_fill = PURPLE.gamma_multiply(0.35);
        style.visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, PURPLE);
        style.visuals.selection.bg_fill = PURPLE.gamma_multiply(0.55);
        style.visuals.hyperlink_color = CYAN;
        style.spacing.item_spacing = Vec2::new(8.0, 7.0);
    });
}

fn metric_card(ui: &mut egui::Ui, label: &str, value: &str, accent: Color32) {
    Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
            ui.add_space(5.0);
            ui.label(RichText::new(value).size(21.0).strong().color(accent));
        });
}

fn heartbeat_card(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    detail: impl Into<String>,
    color: Color32,
    live: bool,
    time: f64,
) {
    let detail = detail.into();
    Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(
            1.0,
            if live {
                color.gamma_multiply(0.48)
            } else {
                BORDER
            },
        ))
        .corner_radius(CornerRadius::same(11))
        .inner_margin(Margin::same(11))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (pulse_rect, _) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::hover());
                let painter = ui.painter_at(pulse_rect);
                let center = pulse_rect.center();
                if live {
                    for offset in [0.0, 0.5] {
                        let cycle = ((time * 1.15 + offset) % 1.0) as f32;
                        painter.circle_stroke(
                            center,
                            5.0 + cycle * 10.0,
                            Stroke::new(1.3, color.gamma_multiply((1.0 - cycle) * 0.55)),
                        );
                    }
                }
                painter.circle_filled(center, if live { 5.0 } else { 4.0 }, color);
                painter.circle_filled(center, 1.8, TEXT);

                ui.vertical(|ui| {
                    ui.label(RichText::new(label).size(9.0).strong().color(MUTED));
                    ui.label(RichText::new(value).size(12.0).strong().color(color));
                    ui.label(RichText::new(detail).size(9.0).color(MUTED));
                });
            });
        });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(11.0).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).size(11.0).color(TEXT).monospace());
        });
    });
}

fn work_chip(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.08))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(8.0).strong().color(MUTED));
            ui.label(
                RichText::new(value)
                    .size(13.0)
                    .strong()
                    .monospace()
                    .color(color),
            );
        });
}

fn copyable_detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(10.0).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(value.to_owned());
            }
            ui.add(
                egui::Label::new(RichText::new(value).size(10.0).monospace().color(TEXT))
                    .truncate()
                    .selectable(true),
            )
            .on_hover_text(value);
        });
    });
}

fn meter_readout(ui: &mut egui::Ui, label: &str, value: &str, detail: &str, color: Color32) {
    ui.label(RichText::new(label).size(8.0).strong().color(MUTED));
    ui.label(
        RichText::new(value)
            .size(15.0)
            .strong()
            .monospace()
            .color(color),
    );
    ui.label(RichText::new(detail).size(8.0).color(MUTED));
}

fn chart_grid(painter: &egui::Painter, rect: egui::Rect) {
    painter.rect_filled(rect, CornerRadius::same(8), BG);
    for step in 1..4 {
        let y = egui::lerp(rect.top()..=rect.bottom(), step as f32 / 4.0);
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(1.0_f32, BORDER.gamma_multiply(0.48)),
        );
    }
    for step in 1..6 {
        let x = egui::lerp(rect.left()..=rect.right(), step as f32 / 6.0);
        painter.line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            Stroke::new(1.0_f32, BORDER.gamma_multiply(0.22)),
        );
    }
}

fn mining_meter(ui: &mut egui::Ui, history: &VecDeque<MeterSample>, report_secs: u64, height: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(8), BG);
    if history.len() < 2 {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Live meter locks after the second telemetry sample",
            FontId::proportional(11.0),
            MUTED,
        );
        return;
    }

    let outer = rect.shrink2(Vec2::new(8.0, 7.0));
    let graph_top = outer.top() + 23.0;
    let cells_height = 14.0;
    let graph_bottom = outer.bottom() - cells_height - 17.0;
    let graph_height = (graph_bottom - graph_top).max(80.0);
    let rate_bottom = graph_top + graph_height * 0.67;
    let rate_rect = egui::Rect::from_min_max(
        egui::pos2(outer.left(), graph_top),
        egui::pos2(outer.right(), rate_bottom - 4.0),
    );
    let probability_rect = egui::Rect::from_min_max(
        egui::pos2(outer.left(), rate_bottom + 5.0),
        egui::pos2(outer.right(), graph_bottom),
    );
    chart_grid(&painter, rate_rect);
    painter.rect_filled(probability_rect, CornerRadius::same(4), BG);
    for step in 1..6 {
        let x = egui::lerp(outer.left()..=outer.right(), step as f32 / 6.0);
        painter.line_segment(
            [
                egui::pos2(x, rate_rect.top()),
                egui::pos2(x, probability_rect.bottom()),
            ],
            Stroke::new(1.0, BORDER.gamma_multiply(0.22)),
        );
    }
    painter.line_segment(
        [probability_rect.left_top(), probability_rect.right_top()],
        Stroke::new(1.0, BORDER.gamma_multiply(0.55)),
    );

    let max_rate = history
        .iter()
        .map(|sample| sample.hashrate.max(sample.smoothed_hashrate))
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let average_rate = history
        .iter()
        .map(|sample| sample.smoothed_hashrate)
        .sum::<f64>()
        / history.len() as f64;
    let denominator = (history.len() - 1) as f32;
    let x_for = |index: usize| egui::lerp(outer.left()..=outer.right(), index as f32 / denominator);
    let raw_points: Vec<_> = history
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let y = egui::lerp(
                rate_rect.bottom()..=rate_rect.top(),
                (sample.hashrate / max_rate).clamp(0.0, 1.0) as f32,
            );
            egui::pos2(x_for(index), y)
        })
        .collect();
    let locked_points: Vec<_> = history
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let y = egui::lerp(
                rate_rect.bottom()..=rate_rect.top(),
                (sample.smoothed_hashrate / max_rate).clamp(0.0, 1.0) as f32,
            );
            egui::pos2(x_for(index), y)
        })
        .collect();
    for pair in locked_points.windows(2) {
        painter.add(egui::Shape::convex_polygon(
            vec![
                egui::pos2(pair[0].x, rate_rect.bottom()),
                egui::pos2(pair[1].x, rate_rect.bottom()),
                pair[1],
                pair[0],
            ],
            CYAN.gamma_multiply(0.13),
            Stroke::NONE,
        ));
    }
    painter.add(egui::Shape::line(
        locked_points.clone(),
        Stroke::new(8.0, CYAN.gamma_multiply(0.07)),
    ));
    painter.add(egui::Shape::line(
        raw_points,
        Stroke::new(1.0, CYAN.gamma_multiply(0.38)),
    ));
    painter.add(egui::Shape::line(
        locked_points.clone(),
        Stroke::new(2.0, CYAN),
    ));

    let probability_scale = history
        .iter()
        .filter_map(|sample| sample.round_probability)
        .fold(0.0_f64, f64::max)
        .clamp(0.01, 1.0);
    let probability_points: Vec<_> = history
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            sample.round_probability.map(|probability| {
                egui::pos2(
                    x_for(index),
                    egui::lerp(
                        probability_rect.bottom()..=probability_rect.top(),
                        (probability / probability_scale).clamp(0.0, 1.0) as f32,
                    ),
                )
            })
        })
        .collect();
    for pair in probability_points.windows(2) {
        if let [Some(left), Some(right)] = pair {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(left.x, probability_rect.bottom()),
                    egui::pos2(right.x, probability_rect.bottom()),
                    *right,
                    *left,
                ],
                PURPLE.gamma_multiply(0.16),
                Stroke::NONE,
            ));
            painter.line_segment([*left, *right], Stroke::new(1.7, PURPLE));
        }
    }

    let markers: Vec<_> = history
        .iter()
        .zip(history.iter().skip(1))
        .enumerate()
        .filter_map(|(index, (previous, current))| {
            (current.height.is_some() && current.height != previous.height)
                .then_some((index + 1, current.height.expect("height checked")))
        })
        .collect();
    let marker_skip = markers.len().saturating_sub(6);
    for (ordinal, (index, block_height)) in markers.iter().skip(marker_skip).enumerate() {
        let x = x_for(*index);
        painter.line_segment(
            [
                egui::pos2(x, rate_rect.top()),
                egui::pos2(x, probability_rect.bottom()),
            ],
            Stroke::new(1.4, AMBER.gamma_multiply(0.78)),
        );
        painter.text(
            egui::pos2(
                x + 4.0,
                rate_rect.top() + if ordinal % 2 == 0 { 3.0 } else { 14.0 },
            ),
            egui::Align2::LEFT_TOP,
            format!("B{block_height}"),
            FontId::monospace(8.5),
            AMBER,
        );
    }

    if let Some(latest) = locked_points.last() {
        let pulse = ((ui.input(|input| input.time) * 1.35) % 1.0) as f32;
        painter.circle_filled(*latest, 3.4, TEXT);
        painter.circle_stroke(
            *latest,
            5.0 + pulse * 6.0,
            Stroke::new(1.2, CYAN.gamma_multiply((1.0 - pulse) * 0.7)),
        );
    }

    if let Some(block_height) = history.back().and_then(|sample| sample.height) {
        painter.line_segment(
            [
                rate_rect.right_top(),
                egui::pos2(rate_rect.right(), probability_rect.bottom()),
            ],
            Stroke::new(1.5, PURPLE.gamma_multiply(0.9)),
        );
        painter.text(
            rate_rect.right_top() + Vec2::new(-5.0, 3.0),
            egui::Align2::RIGHT_TOP,
            format!("B{block_height} LIVE"),
            FontId::monospace(9.0),
            PURPLE,
        );
    }

    let cells = history.len().min(48);
    let cell_top = outer.bottom() - cells_height;
    let cell_width = outer.width() / cells as f32;
    for cell in 0..cells {
        let index = if cells == 1 {
            history.len() - 1
        } else {
            cell * (history.len() - 1) / (cells - 1)
        };
        let sample = history.get(index).expect("meter sample index");
        let activity = (sample.smoothed_hashrate / max_rate).clamp(0.0, 1.0) as f32;
        let color = if sample.mempool.unwrap_or(0) > 0 {
            GREEN
        } else {
            CYAN
        };
        let cell_rect = egui::Rect::from_min_max(
            egui::pos2(outer.left() + cell as f32 * cell_width + 1.0, cell_top),
            egui::pos2(
                outer.left() + (cell + 1) as f32 * cell_width - 1.0,
                outer.bottom(),
            ),
        );
        painter.rect_filled(
            cell_rect,
            CornerRadius::same(2),
            color.gamma_multiply(0.12 + activity * 0.76),
        );
    }

    let span = Duration::from_secs(report_secs.saturating_mul((history.len() - 1) as u64));
    painter.text(
        outer.left_top(),
        egui::Align2::LEFT_TOP,
        format!("POW FLIGHT RECORDER  •  LAST {}", format_elapsed(span)),
        FontId::monospace(9.5),
        MUTED,
    );
    painter.text(
        outer.right_top(),
        egui::Align2::RIGHT_TOP,
        format!(
            "AVG {}  •  PEAK {}",
            format_hashrate(average_rate),
            format_hashrate(max_rate)
        ),
        FontId::monospace(9.5),
        CYAN,
    );
    painter.text(
        probability_rect.left_top() + Vec2::new(5.0, 3.0),
        egui::Align2::LEFT_TOP,
        format!(
            "BLOCK HUNT {}  •  SCALE 0–{}",
            history
                .back()
                .and_then(|sample| sample.round_probability)
                .map(format_probability)
                .unwrap_or_else(|| "—".into()),
            format_probability(probability_scale)
        ),
        FontId::monospace(9.0),
        PURPLE,
    );
    painter.text(
        egui::pos2(outer.left(), cell_top - 3.0),
        egui::Align2::LEFT_BOTTOM,
        format!(
            "MEMPOOL {}  •  HASH CELLS {}",
            history
                .back()
                .and_then(|sample| sample.mempool)
                .map_or_else(|| "—".into(), |pending| pending.to_string()),
            cells
        ),
        FontId::monospace(8.5),
        if history
            .back()
            .and_then(|sample| sample.mempool)
            .unwrap_or(0)
            > 0
        {
            GREEN
        } else {
            MUTED
        },
    );
}

fn format_eta(seconds: f64) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return "—".into();
    }
    if seconds < 60.0 {
        return format!("≈{:.0}s", seconds.max(1.0));
    }
    if seconds < 3_600.0 {
        let total = seconds.round() as u64;
        return format!("≈{}m {:02}s", total / 60, total % 60);
    }
    if seconds < 86_400.0 {
        let total = seconds.round() as u64;
        return format!("≈{}h {:02}m", total / 3_600, total / 60 % 60);
    }
    if seconds < 31_536_000.0 {
        let total = seconds.round() as u64;
        return format!("≈{}d {:02}h", total / 86_400, total / 3_600 % 24);
    }
    format!("≈{:.1}y", seconds / 31_536_000.0)
}

fn format_elapsed(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3_600, seconds / 60 % 60)
    }
}

fn format_probability(probability: f64) -> String {
    let percent = probability.clamp(0.0, 1.0) * 100.0;
    if percent > 0.0 && percent < 0.01 {
        format!("{percent:.4}%")
    } else if percent < 1.0 {
        format!("{percent:.2}%")
    } else {
        format!("{percent:.1}%")
    }
}

fn format_count_f64(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        "unavailable".into()
    } else if value >= 1_000_000_000_000_000.0 {
        format!("{value:.3e}")
    } else if value >= 1_000_000_000_000.0 {
        format!("{:.2}T", value / 1_000_000_000_000.0)
    } else if value >= 1_000_000_000.0 {
        format!("{:.2}B", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.2}K", value / 1_000.0)
    } else {
        format!("{value:.0}")
    }
}

fn format_hashrate(rate: f64) -> String {
    if rate >= 1_000_000_000.0 {
        format!("{:.2} GH/s", rate / 1_000_000_000.0)
    } else if rate >= 1_000_000.0 {
        format!("{:.2} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.2} kH/s", rate / 1_000.0)
    } else {
        format!("{rate:.2} H/s")
    }
}

fn format_count(value: u64) -> String {
    if value >= 1_000_000_000 {
        format!("{:.2}B", value as f64 / 1_000_000_000.0)
    } else if value >= 1_000_000 {
        format!("{:.2}M", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.2}K", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

pub fn run() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1_120.0, 760.0])
            .with_min_inner_size([900.0, 620.0])
            .with_title(WINDOW_TITLE),
        ..Default::default()
    };
    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(|creation| {
            install_theme(&creation.egui_ctx);
            Ok(Box::<MinerApp>::default())
        }),
    )
    .map_err(|error| format!("GUI failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_pool_forms() {
        assert!(validate_pool("127.0.0.1:3333").is_ok());
        assert!(validate_pool("192.168.0.244:8645").is_ok());
        assert!(validate_pool("rpc://192.168.0.244:8645").is_ok());
        assert!(validate_pool("http://127.0.0.1:8645").is_ok());
        assert!(validate_pool("tcp://pool.example:4444").is_ok());
        assert!(validate_pool("stratum+tcp://[::1]:3333").is_ok());
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_pool_values() {
        assert!(validate_pool("").is_err());
        assert!(validate_pool("pool.example").is_err());
        assert!(validate_pool("pool.example:0").is_err());
        assert!(validate_pool("pool.example:99999").is_err());
        assert!(validate_pool("pool example:3333").is_err());
    }

    #[test]
    fn persisted_settings_never_include_password() {
        let settings = Settings {
            password: "super-secret".into(),
            ..Settings::default()
        };
        let encoded = settings.persisted_json().to_string();
        assert!(!encoded.contains("super-secret"));
        assert!(encoded.contains(DEFAULT_POOL));
    }

    #[test]
    fn copied_diagnostics_include_connection_state_but_never_password() {
        let mut app = MinerApp::default();
        app.settings.pool = "192.168.0.244:8645".into();
        app.settings.password = "wallet-secret-must-not-copy".into();
        app.algorithm = "RandomX".into();
        app.height = Some(10_126);
        app.coinbase = Some("confirmed-reward-account".into());
        let copied = app.diagnostics_text();
        assert!(copied.contains("192.168.0.244:8645"));
        assert!(copied.contains("RandomX"));
        assert!(copied.contains("10126"));
        assert!(copied.contains("confirmed-reward-account"));
        assert!(!copied.contains("wallet-secret-must-not-copy"));
    }

    #[test]
    fn block_eta_and_round_probability_follow_verified_target_work() {
        let mut app = MinerApp::default();
        app.apply_telemetry(&json!({
            "event": "job",
            "height": 42,
            "algorithm": "RandomX",
            "job_id": "job-42-a",
            "expected_hashes": 1_000.0,
        }));
        app.apply_telemetry(&json!({
            "event": "metrics",
            "height": 42,
            "hashrate": 100.0,
            "total_hashes": 100,
            "round_height": 42,
            "round_hashes": 100,
            "round_probability": 1.0 - (-0.1_f64).exp(),
            "mempool_size": 3,
        }));

        assert_eq!(app.smoothed_hashrate, 100.0);
        assert_eq!(app.solo_block_eta_seconds(), Some(10.0));
        let probability = app.current_round_probability().unwrap();
        assert!((probability - (1.0 - (-0.1_f64).exp())).abs() < 1e-12);
        assert_eq!(app.meter_history.len(), 1);
        assert_eq!(app.meter_history.back().unwrap().mempool, Some(3));

        // A refreshed template at the same height keeps the probabilistic round;
        // a new height starts a new round at the current total-hash counter.
        app.apply_telemetry(&json!({
            "event": "job",
            "height": 42,
            "algorithm": "RandomX",
            "job_id": "job-42-b",
            "expected_hashes": 1_000.0,
        }));
        assert_eq!(app.round_hashes, 100);
        app.apply_telemetry(&json!({
            "event": "job",
            "height": 43,
            "algorithm": "RandomX",
            "job_id": "job-43",
            "expected_hashes": 2_000.0,
        }));
        assert_eq!(app.round_hashes, 0);
        assert_eq!(app.current_round_probability(), Some(0.0));

        // A reporter sample assembled across a height transition must not
        // restore the previous round's counters after the new job event.
        app.apply_telemetry(&json!({
            "event": "metrics",
            "height": 43,
            "hashrate": 100.0,
            "total_hashes": 200,
            "round_height": 42,
            "round_hashes": 200,
            "round_probability": 0.2,
        }));
        assert_eq!(app.round_hashes, 0);
        assert_eq!(app.current_round_probability(), Some(0.0));

        app.apply_telemetry(&json!({"event": "session_error", "message": "offline"}));
        assert_eq!(app.solo_block_eta_seconds(), None);
        assert_eq!(app.current_round_probability(), None);
    }

    #[test]
    fn network_meter_telemetry_and_eta_labels_are_explicit() {
        let mut app = MinerApp::default();
        app.apply_telemetry(&json!({
            "event": "network",
            "hashrate": 1_361.5,
            "target_block_ms": 150_000,
            "difficulty": "228382",
        }));
        assert_eq!(app.network_hashrate, Some(1_361.5));
        assert_eq!(app.target_block_ms, Some(150_000));
        assert_eq!(app.network_difficulty.as_deref(), Some("228382"));
        assert_eq!(format_eta(462.0), "≈7m 42s");
        assert_eq!(format_probability(0.1234), "12.3%");
    }

    #[test]
    fn live_meter_paints_hashrate_round_resets_and_mempool_cells() {
        let history = VecDeque::from([
            MeterSample {
                hashrate: 1_800.0,
                smoothed_hashrate: 1_750.0,
                mempool: Some(3),
                height: Some(10_194),
                round_probability: Some(0.04),
            },
            MeterSample {
                hashrate: 2_050.0,
                smoothed_hashrate: 1_820.0,
                mempool: Some(1),
                height: Some(10_194),
                round_probability: Some(0.08),
            },
            MeterSample {
                hashrate: 1_920.0,
                smoothed_hashrate: 1_850.0,
                mempool: Some(0),
                height: Some(10_195),
                round_probability: Some(0.01),
            },
        ]);
        let context = egui::Context::default();
        let output = context.run_ui(egui::RawInput::default(), |ui| {
            mining_meter(ui, &history, 2, 220.0);
        });
        assert!(output.shapes.len() > 20);
    }

    #[test]
    fn saved_numeric_settings_are_clamped() {
        let settings = Settings::from_json(&json!({
            "workers": 999,
            "reconnect_secs": 0,
            "report_secs": 99_999,
        }));
        assert_eq!(settings.workers, 64);
        assert_eq!(settings.reconnect_secs, 1);
        assert_eq!(settings.report_secs, 3_600);
    }
}
