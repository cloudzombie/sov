//! The native `sov-station` desktop window — a real cross-platform GUI (macOS,
//! Windows, Linux) over the SAME read-only RPC the CLI uses. A background thread
//! polls a node every second and writes a [`Snapshot`]; the UI renders it live.
//! The station can also **launch and supervise a local testnet-1 node** (Start /
//! Stop), so it is a self-contained "run a node and watch it" application.
//!
//! Everything shown is real data read from a running node over JSON-RPC — the
//! GUI invents nothing; like the CLI, it only re-presents.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::collections::HashMap;

use eframe::egui;
use serde_json::{json, Value};
use sov_crypto::{Keypair, PublicKey};
use sov_primitives::{AccountId, Balance, Hash};
use sov_rpc::{
    ChainSpec, Daemon, DaemonHandle, Keystore, KeystoreEntry, NodeConfig, P2p, P2pConfig,
    P2pHandle, RpcClient, SyncShared,
};
use sov_shielded::{
    encode_shielded, shielded_transfer_with_change, unshield_amount, AnyAddress, NoteStore,
    Receiver, ShieldedBundle, ShieldedKey, ShieldedParams, UnifiedAddress,
};
use sov_types::{Action, SignedTransaction, Transaction};
use sov_wallet::{generate_mnemonic, HdWallet};
use zeroize::Zeroize;

use crate::vault;

/// Accounts the wallet panel watches by default: the station's own miner and the
/// two perpetual mining-tax recipients (consensus constants).
// Genesis-bound accounts worth watching by default. (A wallet's own implicit
// account is added to the watch list when it is created/imported.)
/// Named accounts the dashboard tracks balances for out of the box. Empty: the
/// coinbase pays the miner directly (no tax accounts), and a user adds any named
/// accounts they care about themselves.
const DEFAULT_ACCOUNTS: [&str; 0] = [];

/// The local block explorer (started with `node src/server.js` in `explorer/`).
/// Block heights in the Blocks tab deep-link into it.
const EXPLORER_URL: &str = "http://127.0.0.1:8730";

/// One miner-registry row.
#[derive(Clone, Default)]
struct MinerRow {
    account: String,
    blocks: u64,
    first: u64,
    last: u64,
}

/// One watched account's live state.
#[derive(Clone, Default)]
struct AccountRow {
    account: String,
    balance: String,
    nonce: String,
    key_state: String,
    /// The bound controlling key (`hybrid65:0x…`), if any — lets a wallet
    /// recognize a named account its key controls and operate as it.
    key: String,
}

/// One recent block's coinbase (issuance, paid entirely to the miner), in grains.
#[derive(Clone, Default)]
struct BlockRow {
    height: u64,
    /// The block header's wall-clock timestamp (Unix ms), surfaced in the Blocks tab.
    timestamp_ms: u64,
    /// The proof-of-work nonce that sealed this block — the literal "work"
    /// surfaced in the Mining tab's recent-proofs list.
    nonce: u64,
    miner: String,
    reward: String,
    miner_amount: String,
    /// Header identity + seal, for the in-app block-detail view (click a block in the
    /// Blocks tab). All from `sov_getBlockDigest`.
    hash: String,
    prev_hash: String,
    state_root: String,
    /// The compact PoW target (`nBits`) the nonce satisfied.
    bits: u32,
    /// Number of transactions in the block (a coinbase-only block has 0).
    tx_count: usize,
}

/// The live state the poller writes and the UI reads.
#[derive(Clone, Default)]
struct Snapshot {
    online: bool,
    chain_id: String,
    height: Option<u64>,
    head_hash: String,
    state_root: String,
    supply_mined: String,
    supply_total: String,
    difficulty: String,
    /// Proof-of-work seal in force ("Sha256d" / "RandomX"), the consensus target
    /// block interval, and the head block's winning nonce + compact target — the
    /// raw "how work is proven" facts surfaced in the Mining tab.
    pow_algo: String,
    target_block_ms: u64,
    head_nonce: Option<u64>,
    head_bits: Option<u32>,
    mempool: Option<usize>,
    reward: String,
    miners: Vec<MinerRow>,
    accounts: Vec<AccountRow>,
    blocks: Vec<BlockRow>,
    /// Shielded pool value (grains) and the live de-shield drain-limiter budget,
    /// so the wallet can show how much can be de-shielded right now and when the
    /// window resets — making the circuit breaker visible instead of a silent
    /// transaction failure. `None` while offline or on a node without the RPC.
    shielded_pool: String,
    deshieldable_now: Option<u128>,
    deshield_resets_at: Option<u64>,
    /// The de-shield drain-limiter's full per-window cap (grains), so the wallet can
    /// show "X of LIMIT this window". `None`/0 when the limiter is disabled.
    deshield_limit: Option<u128>,
    error: Option<String>,
    updated_ms: u64,
    /// LIVE peer/sync telemetry, read in-process from the embedded node every frame
    /// (not over RPC), so the Node tab shows a rolling, never-stale picture even while
    /// the loopback RPC poller is momentarily unreachable.
    ///
    /// `peers` is the count of DISTINCT authenticated remote nodes (a redundant link is
    /// never double-counted). `best_peer_height` is the tallest peer chain we have heard
    /// of. `syncing` means we are still catching up to a heavier peer chain — while true
    /// the node is downloading, not mining (it joins the existing chain before extending
    /// it). `None`/false when there is no embedded node or no P2P.
    peers: Option<usize>,
    best_peer_height: Option<u64>,
    syncing: bool,
    /// This node's measured proof-of-work rate (H/s); 0 when not actively mining.
    local_hashrate: u64,
    /// The exact network fee (grains) a wallet send would pay right now, per route,
    /// straight from `sov_estimateFee` (0 on a fee-free testnet, the real cost on
    /// mainnet). Shown in the send-review modal so the spender sees the full cost.
    fee_transfer_grains: u128,
    fee_shielded_grains: u128,
}

/// UI-editable polling config, shared with the poller thread.
#[derive(Clone)]
struct Config {
    rpc: String,
    accounts: Vec<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock `HH:MM:SS` for log line timestamps.
fn clock_hms() -> String {
    let secs = (now_ms() / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Append a timestamped line to the shared node log, capping the buffer so it
/// cannot grow without bound. Real operational logs (startup, replay timing, RPC
/// up, block production, errors), surfaced in the Node tab.
fn push_log(logs: &Arc<Mutex<Vec<String>>>, msg: impl Into<String>) {
    if let Ok(mut v) = logs.lock() {
        v.push(format!("{}  {}", clock_hms(), msg.into()));
        let n = v.len();
        // Keep a deep ring buffer so an operator can scroll back through a whole
        // session's history (peering churn, sync, restarts) when diagnosing.
        if n > 5_000 {
            v.drain(0..n - 5_000);
        }
    }
}

/// Lowercase hex of `bytes` (for writing a seed into the node keystore).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Abbreviate a long (implicit) account id for display: `abcd1234…wxyz`.
fn short_id(id: &str) -> String {
    if id.len() <= 16 {
        id.to_string()
    } else {
        format!("{}…{}", &id[..8], &id[id.len() - 4..])
    }
}

/// Abbreviate a hybrid65 public key for display, keeping the scheme prefix:
/// `hybrid65:0x15b0fbad…37ffe7656` (the full value is on the copy button).
fn short_pubkey(pk: &str) -> String {
    match pk.split_once("0x") {
        Some((prefix, hex)) if hex.len() > 16 => {
            format!("{prefix}0x{}…{}", &hex[..8], &hex[hex.len() - 6..])
        }
        _ => pk.to_string(),
    }
}

/// Whether `account` is a human-readable NAMED account (e.g. `name.reserve.sov`)
/// rather than an implicit, key-derived hash id. This is the "named vs not yet"
/// distinction surfaced in the wallet UI.
fn is_named_account(account: &str) -> bool {
    AccountId::new(account)
        .map(|id| !id.is_implicit())
        .unwrap_or(false)
}

/// SOV Station palette — one cohesive, bank-grade theme in two MODES (a GitHub dark
/// family and a clean "retail bank" light family): a slate/white base, restrained
/// hairline borders, a confident SOV-green accent, and unambiguous success / error /
/// warning signal colors. All UI color flows from here through mode-aware accessors,
/// so flipping [`set_dark`] re-skins every panel, card, banner, pill and badge at once
/// (not just egui's base visuals) — no dark islands on a light background.
mod palette {
    use eframe::egui::Color32;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The active mode (dark by default). A process-wide atomic so every free-function
    /// panel can read it without threading state through; flipped by the ☀/🌙 toggle.
    static DARK: AtomicBool = AtomicBool::new(true);
    pub fn set_dark(dark: bool) {
        DARK.store(dark, Ordering::Relaxed);
    }
    pub fn is_dark() -> bool {
        DARK.load(Ordering::Relaxed)
    }
    /// Pick the dark or light value for the current mode.
    fn pick(dark: Color32, light: Color32) -> Color32 {
        if is_dark() {
            dark
        } else {
            light
        }
    }

    const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
        Color32::from_rgb(r, g, b)
    }

    // Each accessor returns the dark value / the calibrated light value.
    pub fn bg() -> Color32 {
        pick(rgb(13, 17, 23), rgb(246, 248, 250))
    } // app background
    pub fn panel() -> Color32 {
        pick(rgb(22, 27, 34), rgb(255, 255, 255))
    } // cards / windows
    pub fn surface() -> Color32 {
        pick(rgb(33, 38, 45), rgb(240, 242, 245))
    } // buttons / inputs at rest
    pub fn surface_hi() -> Color32 {
        pick(rgb(48, 54, 61), rgb(225, 228, 232))
    } // hovered
    pub fn field() -> Color32 {
        pick(rgb(9, 12, 17), rgb(255, 255, 255))
    } // recessed input wells
    pub fn border() -> Color32 {
        pick(rgb(48, 54, 61), rgb(208, 215, 222))
    } // hairline borders
    pub fn text() -> Color32 {
        pick(rgb(230, 237, 243), rgb(31, 35, 40))
    } // primary text
    pub fn text_dim() -> Color32 {
        pick(rgb(139, 148, 158), rgb(101, 109, 118))
    } // secondary text
    pub fn accent() -> Color32 {
        pick(rgb(46, 160, 67), rgb(31, 136, 61))
    } // SOV green — primary action
    pub fn accent_hi() -> Color32 {
        pick(rgb(63, 185, 80), rgb(46, 160, 67))
    }
    pub fn success() -> Color32 {
        pick(rgb(63, 185, 80), rgb(26, 127, 55))
    } // a transaction landed
    pub fn error() -> Color32 {
        pick(rgb(248, 81, 73), rgb(207, 34, 46))
    } // a transaction failed
    pub fn warning() -> Color32 {
        pick(rgb(210, 153, 34), rgb(154, 103, 0))
    }
    pub fn link() -> Color32 {
        pick(rgb(88, 166, 255), rgb(9, 105, 218))
    }
    /// A faint translucent tint of `c` (for status-banner fills/strokes).
    pub fn tint(c: Color32, alpha: u8) -> Color32 {
        Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
    }
}

/// Install the cohesive theme in the requested mode (dark or light). Sets the active
/// `palette` mode FIRST (so every accessor returns the right family), then the whole
/// widget palette (rest / hover / press), recessed input wells, accent selection, link
/// color, and a little more breathing room — so every panel inherits one consistent
/// look. Called at startup and again whenever the ☀/🌙 toggle flips the mode.
fn install_theme(ctx: &egui::Context, dark: bool) {
    use egui::{Rounding, Stroke};
    palette::set_dark(dark);
    let mut style = (*ctx.style()).clone();
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let r = Rounding::same(6.0);

    v.widgets.noninteractive.bg_fill = palette::panel();
    v.widgets.noninteractive.weak_bg_fill = palette::panel();
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette::border());
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.noninteractive.rounding = r;

    v.widgets.inactive.bg_fill = palette::surface();
    v.widgets.inactive.weak_bg_fill = palette::surface();
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, palette::border());
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.inactive.rounding = r;

    v.widgets.hovered.bg_fill = palette::surface_hi();
    v.widgets.hovered.weak_bg_fill = palette::surface_hi();
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, palette::accent());
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.hovered.rounding = r;

    v.widgets.active.bg_fill = palette::accent();
    v.widgets.active.weak_bg_fill = palette::accent();
    v.widgets.active.bg_stroke = Stroke::new(1.0, palette::accent_hi());
    v.widgets.active.fg_stroke = Stroke::new(1.0, egui::Color32::WHITE);
    v.widgets.active.rounding = r;

    v.widgets.open = v.widgets.inactive;

    v.selection.bg_fill = palette::tint(palette::accent(), 90);
    v.selection.stroke = Stroke::new(1.0, palette::accent_hi());
    v.hyperlink_color = palette::link();
    v.warn_fg_color = palette::warning();
    v.error_fg_color = palette::error();
    v.window_fill = palette::panel();
    v.window_stroke = Stroke::new(1.0, palette::border());
    v.window_rounding = Rounding::same(10.0);
    v.panel_fill = palette::bg();
    v.extreme_bg_color = palette::field(); // text-edit / code wells
                                           // Striped rows + code wells, mode-aware (a faint stripe on whichever base).
    v.faint_bg_color = if dark {
        egui::Color32::from_rgb(26, 31, 38)
    } else {
        egui::Color32::from_rgb(244, 246, 249)
    };
    v.code_bg_color = if dark {
        egui::Color32::from_rgb(28, 33, 40)
    } else {
        egui::Color32::from_rgb(235, 238, 242)
    };

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 24.0;
    style.spacing.indent = 18.0;
    ctx.set_style(style);
}

/// The outcome of an action/transaction, for at-a-glance green/red coloring.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TxStatus {
    Ok,
    Err,
    Info,
}

/// Classify a result message as success, failure, or neutral. Robust to BOTH
/// conventions in this codebase — a leading `✓` / `✗` marker AND plain
/// "… failed: …" strings — so a failure for ANY reason colors red.
fn tx_status(msg: &str) -> TxStatus {
    if msg.contains('✗') {
        return TxStatus::Err;
    }
    let lower = msg.to_ascii_lowercase();
    const FAIL: &[&str] = &[
        "fail",
        "error",
        "reject",
        "insufficient",
        "invalid",
        "unable",
        "denied",
        "unauthorized",
        "unrecognized",
        "not a ",
        "no such",
        "too ",
        "exceeded",
        "refused",
        "timed out",
        "timeout",
        "cannot",
        "can't",
    ];
    if FAIL.iter().any(|k| lower.contains(k)) {
        return TxStatus::Err;
    }
    if msg.contains('✓') {
        return TxStatus::Ok;
    }
    TxStatus::Info
}

/// The signal color for a status (green / red / neutral).
fn status_color(s: TxStatus) -> egui::Color32 {
    match s {
        TxStatus::Ok => palette::success(),
        TxStatus::Err => palette::error(),
        TxStatus::Info => palette::text_dim(),
    }
}

/// Strip the leading status glyph (✓/✗/•) the action layer prepends, leaving the
/// human message. Shared by the result banner and the status-bar toast.
fn strip_status_glyph(msg: &str) -> &str {
    msg.trim_start_matches('✓')
        .trim_start_matches('✗')
        .trim_start_matches('•')
        .trim_start()
}

/// The text for the single-line status-bar toast: the message with its glyph stripped
/// and capped to `max_chars` (char-safe, ellipsis on overflow) so a long error can
/// never blow out the bottom-bar layout. The full text still shows in the Wallet
/// status banner.
fn toast_chip_text(msg: &str, max_chars: usize) -> String {
    let body = strip_status_glyph(msg);
    if body.chars().count() > max_chars {
        let keep = max_chars.saturating_sub(1);
        let mut s: String = body.chars().take(keep).collect();
        s.push('…');
        s
    } else {
        body.to_string()
    }
}

/// A highlighted result banner — a faint status-tinted card with the message in the
/// success (green) or failure (red) color. This is the at-a-glance "did my
/// transaction land?" signal the wallet shows after every action.
fn status_banner(ui: &mut egui::Ui, msg: &str) {
    if msg.is_empty() {
        return;
    }
    let st = tx_status(msg);
    let col = status_color(st);
    let glyph = match st {
        TxStatus::Ok => "✓",
        TxStatus::Err => "✗",
        TxStatus::Info => "•",
    };
    let body = strip_status_glyph(msg);
    egui::Frame::none()
        .fill(palette::tint(col, 28))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 130)))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(10.0, 7.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(glyph).color(col).strong());
                ui.label(egui::RichText::new(body).color(col));
            });
        });
}

/// Render a one-line result message colored by outcome — green on success, red on
/// failure (for any reason), dim for neutral/progress. The inline counterpart to
/// [`status_banner`], used for the per-panel result lines (tokens, swaps, register…).
fn status_label(ui: &mut egui::Ui, msg: &str) {
    if msg.is_empty() {
        return;
    }
    ui.label(egui::RichText::new(msg).color(status_color(tx_status(msg))));
}

/// A small colored pill identifying the network (e.g. `● TESTNET · SHA-256d`),
/// tinted amber for testnet / green for mainnet — the at-a-glance "where am I".
fn network_badge(ui: &mut egui::Ui, net: Network) {
    let col = net.color();
    egui::Frame::none()
        .fill(palette::tint(col, 30))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 150)))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(9.0, 3.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("● {} · {}", net.label(), net.pow_algo()))
                    .small()
                    .strong()
                    .color(col),
            );
        });
}

/// A small tinted status pill (e.g. `PRIVATE`, `PUBLIC`) in the given signal color.
fn pill(ui: &mut egui::Ui, text: &str, col: egui::Color32) {
    egui::Frame::none()
        .fill(palette::tint(col, 30))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 150)))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(9.0, 3.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).small().strong().color(col));
        });
}

/// Green for a named account, amber for an unnamed (implicit) one — the colors
/// the wallet UI uses everywhere to delineate the two at a glance.
fn named_color(named: bool) -> egui::Color32 {
    if named {
        palette::success()
    } else {
        palette::warning()
    }
}

/// Render `data` as a QR code, drawn directly with the egui painter (no image
/// backend) at roughly `size` pixels square, with a white quiet-zone border.
fn qr_widget(ui: &mut egui::Ui, data: &str, size: f32) {
    let code = match qrcode::QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            ui.label(egui::RichText::new("(QR unavailable for this address)").weak());
            return;
        }
    };
    let w = code.width();
    let colors = code.to_colors();
    let quiet = 2usize; // modules of quiet zone, each side
    let n = w + quiet * 2;
    let (rect, _resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3.0, egui::Color32::WHITE);
    let cell = size / n as f32;
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let min = egui::pos2(
                    rect.min.x + (x + quiet) as f32 * cell,
                    rect.min.y + (y + quiet) as f32 * cell,
                );
                painter.rect_filled(
                    egui::Rect::from_min_size(min, egui::vec2(cell, cell)),
                    0.0,
                    egui::Color32::BLACK,
                );
            }
        }
    }
}

fn field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Grains → a trimmed `XUS` decimal string (1 XUS = 100,000,000 grains).
fn xus(grains: &str) -> String {
    let g: u128 = grains.parse().unwrap_or(0);
    let whole = g / 100_000_000;
    let frac = g % 100_000_000;
    let whole = group_thousands(whole);
    if frac == 0 {
        whole
    } else {
        let s = format!("{frac:08}");
        format!("{whole}.{}", s.trim_end_matches('0'))
    }
}

/// Group an integer with comma thousands separators: `1234567` → `1,234,567`.
fn group_thousands(n: u128) -> String {
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn short(s: &str) -> String {
    if s.len() <= 20 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..12], &s[s.len() - 6..])
    }
}

/// One full poll of the node into a fresh snapshot.
fn poll(client: &RpcClient, cfg: &Config) -> Snapshot {
    let mut s = Snapshot::default();
    match client.chain_id() {
        Ok(id) => {
            s.online = true;
            s.chain_id = id;
        }
        Err(e) => {
            s.error = Some(e.to_string());
            s.updated_ms = now_ms();
            return s;
        }
    }
    s.height = client.height().ok();
    if let Ok(head) = client.head() {
        s.head_hash = head.hash().to_hex();
        // The head block's proof of work: the nonce a miner found and the compact
        // target it had to beat. These are the literal "work" of Nakamoto consensus.
        s.head_nonce = Some(head.header.nonce);
        s.head_bits = Some(head.header.bits);
    }
    if let Ok(v) = client.call("sov_getStateRoot", json!({})) {
        s.state_root = v.as_str().unwrap_or_default().to_string();
    }
    if let Ok(v) = client.call("sov_getSupply", json!({})) {
        s.supply_mined = field(&v, "mined");
        s.supply_total = field(&v, "total");
    }
    if let Ok(v) = client.call("sov_getShieldedInfo", json!({})) {
        s.shielded_pool = field(&v, "poolValue");
        s.deshieldable_now = v
            .get("deshieldableNowGrains")
            .and_then(Value::as_str)
            .and_then(|x| x.parse::<u128>().ok());
        s.deshield_resets_at = v.get("windowResetsAtHeight").and_then(Value::as_u64);
        s.deshield_limit = v
            .get("deshieldLimitGrains")
            .and_then(Value::as_str)
            .and_then(|x| x.parse::<u128>().ok());
    }
    if let Ok(v) = client.call("sov_getDifficulty", json!({})) {
        s.difficulty = field(&v, "sha256d");
        s.pow_algo = field(&v, "algo");
        s.target_block_ms = v.get("targetBlockMs").and_then(Value::as_u64).unwrap_or(0);
    }
    // The live per-route network fee, straight from consensus (0 on a fee-free
    // testnet, the real cost on mainnet) — surfaced in the send-review modal. A node
    // without the method just reports no fee (graceful on older peers).
    let fee_of = |kind: &str| -> u128 {
        client
            .call("sov_estimateFee", json!({ "kind": kind }))
            .ok()
            .and_then(|v| {
                v.get("feeGrains")
                    .and_then(Value::as_str)
                    .and_then(|g| g.parse::<u128>().ok())
            })
            .unwrap_or(0)
    };
    s.fee_transfer_grains = fee_of("transfer");
    s.fee_shielded_grains = fee_of("shielded");
    s.mempool = client.mempool_size().ok();
    if let Ok(r) = client.mint_reward() {
        s.reward = r.grains().to_string();
    }
    if let Ok(Value::Array(rows)) = client.call("sov_getMiners", json!({})) {
        s.miners = rows
            .iter()
            .map(|r| MinerRow {
                account: field(r, "account"),
                blocks: r.get("blocksMined").and_then(Value::as_u64).unwrap_or(0),
                first: r
                    .get("firstSeenHeight")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                last: r.get("lastSeenHeight").and_then(Value::as_u64).unwrap_or(0),
            })
            .collect();
    }
    for acct in &cfg.accounts {
        s.accounts.push(account_row(client, acct));
    }
    if let Some(h) = s.height {
        let from = h.saturating_sub(11);
        for height in (from..=h).rev() {
            if let Ok(d) = client.call("sov_getBlockDigest", json!({ "height": height })) {
                if !d.is_null() {
                    s.blocks.push(block_row(height, &d));
                }
            }
        }
    }
    s.updated_ms = now_ms();
    s
}

fn account_row(client: &RpcClient, account: &str) -> AccountRow {
    let id = match AccountId::new(account) {
        Ok(id) => id,
        Err(_) => {
            return AccountRow {
                account: account.to_string(),
                balance: "invalid id".to_string(),
                ..Default::default()
            }
        }
    };
    let balance = client.balance(&id).map(|b| b.grains().to_string()).ok();
    let nonce = client.nonce(&id).ok();
    let (key_state, key) = match client.account(&id) {
        Ok(Some(a)) => match a.key {
            Some(k) => ("key set", k.to_string()),
            None => ("keyless", String::new()),
        },
        Ok(None) => ("absent", String::new()),
        Err(_) => ("unknown", String::new()),
    };
    AccountRow {
        account: account.to_string(),
        balance: balance.unwrap_or_else(|| "—".to_string()),
        nonce: nonce
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
        key_state: key_state.to_string(),
        key,
    }
}

fn block_row(height: u64, digest: &Value) -> BlockRow {
    let mut row = BlockRow {
        height,
        timestamp_ms: digest
            .get("timestampMs")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        nonce: digest.get("nonce").and_then(Value::as_u64).unwrap_or(0),
        hash: digest
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        prev_hash: digest
            .get("prevHash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        state_root: digest
            .get("stateRoot")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        bits: digest.get("bits").and_then(Value::as_u64).unwrap_or(0) as u32,
        tx_count: digest
            .get("txIds")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0),
        ..Default::default()
    };
    let cb = digest.get("coinbase");
    if let Some(cb) = cb.filter(|c| !c.is_null()) {
        row.reward = field(cb, "reward");
        if let Some(Value::Array(recips)) = cb.get("recipients") {
            for r in recips {
                let amt = field(r, "amount");
                if r.get("role").and_then(Value::as_str) == Some("miner") {
                    row.miner = field(r, "account");
                    row.miner_amount = amt;
                }
            }
        }
    }
    row
}

/// A wallet held for the session. The on-chain `account` is **key-derived**
/// (an implicit id = `hex(blake3(pubkey))`), so it cannot collide with — or be
/// squatted onto — anyone else's account; the user-supplied `label` is a local
/// display name only. The 32-byte `seed` is the secret; the signing keypair is
/// re-derived from it on demand (`Keypair` is deliberately neither `Clone` nor
/// stored), and the shielded + unified addresses follow from the same seed.
struct LoadedWallet {
    label: String,
    account: String,
    public_key: String,
    seed: [u8; 32],
    shielded: String,
    unified: String,
    /// The BIP-39 recovery phrase, when known (generated/imported here, or loaded
    /// from a keystore that stored it). `None` for a wallet restored from a raw
    /// seed only — that wallet still works, but its phrase cannot be re-shown
    /// (BIP-39 → seed is one-way). Held in-session; persisted only in the
    /// encrypted keystore.
    mnemonic: Option<String>,
    /// A NAMED account this wallet's key also controls (e.g. a genesis-bound
    /// `name.reserve.sov`). When set, send/activate/de-shield act AS this account,
    /// signing with the same key. `None` = operate the wallet's own implicit id.
    operate_as: Option<String>,
    /// Watch-only: added from a PUBLIC KEY with no private key on this machine, so
    /// it can monitor balances/names/NFTs but cannot sign. Spending is done via the
    /// air-gapped flow (build unsigned here → sign on the offline machine that
    /// holds the seed → broadcast here). `seed` is unused (zeroed) when true.
    watch_only: bool,
}

impl LoadedWallet {
    fn from_seed(label: String, seed: [u8; 32], mnemonic: Option<String>) -> Result<Self, String> {
        // The on-chain identity IS the key's fingerprint — never a typed name —
        // so a coinbase paid here is claimable only by this wallet's key.
        let pk = Keypair::hybrid_from_seed(seed).public_key();
        let account = pk.implicit_account_id().to_string();
        // The full `hybrid65:0x…` key — what you hand over to bind a NAMED
        // genesis account (e.g. a tax account) to this wallet. Safe to share.
        let public_key = pk.to_string();
        let zkey = ShieldedKey::from_seed(seed).ok_or("shielded key derivation failed")?;
        let shielded = encode_shielded(&zkey.address());
        let unified = AccountId::new(&account)
            .ok()
            .and_then(|id| UnifiedAddress::new(Some(id), Some(zkey.address())).ok())
            .map(|u| u.encode())
            .unwrap_or_default();
        Ok(LoadedWallet {
            label,
            account,
            public_key,
            seed,
            shielded,
            unified,
            mnemonic,
            operate_as: None,
            watch_only: false,
        })
    }

    /// Build a WATCH-ONLY wallet from a public key (the `hybrid65:0x…` form, or a
    /// bare Ed25519 hex). It derives the same implicit account a real wallet would,
    /// so it monitors that account — but holds no private key and cannot sign.
    fn watch_only(label: String, public_key_str: &str) -> Result<Self, String> {
        let pk: PublicKey =
            serde_json::from_value(serde_json::Value::String(public_key_str.trim().to_string()))
                .map_err(|e| format!("not a valid public key: {e}"))?;
        let account = pk.implicit_account_id().to_string();
        Ok(LoadedWallet {
            label,
            account,
            public_key: pk.to_string(),
            seed: [0u8; 32],
            shielded: String::new(), // no viewing key without the seed
            unified: String::new(),
            mnemonic: None,
            operate_as: None,
            watch_only: true,
        })
    }

    /// The account this wallet currently acts as: a linked named account if one
    /// is set, else the wallet's own implicit id. All on-chain actions sign with
    /// this wallet's key but name this account as the transaction signer.
    fn effective_account(&self) -> String {
        self.operate_as
            .clone()
            .unwrap_or_else(|| self.account.clone())
    }
}

/// Memory hygiene: when a wallet is dropped (removed, replaced, or on shutdown)
/// scrub every byte that could reconstruct or spend the key — the seed, the BIP-39
/// phrase, and the shielded viewing key — so they don't survive in freed heap, a
/// swap page, or a core dump. The public id / account / unified address are not
/// secret and are left as-is.
impl Drop for LoadedWallet {
    fn drop(&mut self) {
        self.seed.zeroize();
        if let Some(phrase) = self.mnemonic.as_mut() {
            phrase.zeroize();
        }
        self.shielded.zeroize();
    }
}

/// Status of the most recent wallet action. `generate`/`import` are instant;
/// `send`/`activate` run on a worker thread (a shielded send first builds the
/// Halo2 prover), so the UI shows progress without freezing.
#[derive(Clone, Default)]
struct ActionState {
    busy: bool,
    message: String,
}

/// The selected wallet's scanned shielded-pool view (recomputed on demand by
/// trial-decrypting the chain — the pool is private, so only the holder can).
#[derive(Clone, Default)]
struct ShieldedView {
    scanning: bool,
    account: String,
    balance: u64, // unspent pool balance, in grains
    notes: usize, // unspent note count
    scanned_height: u64,
    message: String,
}

/// Cumulative coinbase your wallets have earned, summed from the chain's per-block
/// coinbase (paid entirely to the miner). Computed on demand (a full scan), cached here.
#[derive(Clone, Default)]
struct EarningsView {
    computing: bool,
    scanned_height: u64,
    total_grains: u128,
    rows: Vec<EarningRow>,
    message: String,
}

/// Cached token view: this wallet's token balances + ONE PAGE of the chain's
/// token registry (paged so the registry never loads unbounded).
#[derive(Clone, Default)]
struct TokensView {
    loading: bool,
    account: String,
    holdings: Vec<(String, String, String)>, // (asset hex, symbol, balance grains)
    registry: Vec<(String, String, String, String)>, // (asset, symbol, issuer, supply grains)
    offset: usize,                           // the registry page's starting offset
    has_more: bool,                          // another registry page exists after this one
    // Owned NFTs: (display, is_sns, collection_hex, token_id_hex) — SNS names too.
    nfts: Vec<(String, bool, String, String)>,
    message: String,
}

/// Cached HTLC lookup for the Swaps tab.
#[derive(Clone, Default)]
struct SwapsView {
    looking: bool,
    id: String,
    found: Option<(String, String, String, String, u64)>, // locker, recipient, amount, hashlock, timeout
    message: String,
}

/// One account's mining earnings: blocks it was paid in and the grains total.
#[derive(Clone)]
struct EarningRow {
    label: String,
    account: String,
    role: String,
    blocks: u64,
    grains: u128,
}

/// Parse a decimal XUS amount ("1.5") into grains (1 XUS = 100,000,000 grains).
fn parse_xus(s: &str) -> Option<u128> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 8 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u128 = whole.parse().ok()?;
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 8 {
        frac_padded.push('0');
    }
    let frac: u128 = frac_padded.parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

/// Format grains as a plain decimal XUS string (no thousands separators) — for
/// putting a computed value back INTO an input field (e.g. the Max button).
fn grains_to_xus_plain(grains: u128) -> String {
    let whole = grains / 100_000_000;
    let frac = grains % 100_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{frac:08}").trim_end_matches('0'))
    }
}

/// The detected destination tier for a "To" string, used to validate and label
/// a send before it is broadcast.
enum SendRoute {
    Empty,
    Invalid,
    Transparent(String), // a named account (public)
    Shielded,            // xus1… (private)
    Unified,             // uxus1… (routes shielded when possible)
}

impl SendRoute {
    fn detect(to: &str) -> Self {
        let to = to.trim();
        if to.is_empty() {
            return SendRoute::Empty;
        }
        match AnyAddress::parse(to) {
            Ok(AnyAddress::Transparent(id)) => SendRoute::Transparent(id.to_string()),
            Ok(AnyAddress::Shielded(_)) => SendRoute::Shielded,
            Ok(AnyAddress::Unified(_)) => SendRoute::Unified,
            Err(_) => SendRoute::Invalid,
        }
    }
    fn is_valid(&self) -> bool {
        !matches!(self, SendRoute::Empty | SendRoute::Invalid)
    }
    /// True when the route keeps the amount/recipient private.
    fn private(&self) -> bool {
        matches!(self, SendRoute::Shielded | SendRoute::Unified)
    }
    /// A short human label + color for inline display.
    fn label(&self) -> (String, egui::Color32) {
        match self {
            SendRoute::Empty => (String::new(), palette::text_dim()),
            SendRoute::Invalid => ("✗ unrecognized address".into(), palette::error()),
            SendRoute::Transparent(a) => {
                (format!("→ transparent · {a} (public)"), palette::warning())
            }
            SendRoute::Shielded => ("→ shielded (private)".into(), palette::success()),
            SendRoute::Unified => (
                "→ unified (routes shielded — private)".into(),
                palette::success(),
            ),
        }
    }
}

/// Which of a wallet's addresses the Receive view shows (shielded is the private
/// default).
#[derive(PartialEq, Eq, Clone, Copy)]
enum ReceiveKind {
    Shielded,
    Unified,
    Account,
}

/// A send awaiting the user's explicit confirmation (the review-before-broadcast
/// step). Captured when "Review" is clicked; cleared on Confirm or Cancel.
#[derive(Clone)]
struct PendingSend {
    from_label: String,
    from_account: String,
    to: String,
    amount_grains: u128,
    /// The spendable balance (grains) of the source the amount is drawn from — the
    /// transparent account for a normal send, the shielded pool for a pool spend —
    /// so the review modal can show the resulting balance after amount + fee.
    from_balance_grains: u128,
    route_label: String,
    self_send: bool,
    /// True when BOTH ends are public (transparent→transparent): the amount and
    /// both parties are visible on-chain — the privacy downgrade to warn about.
    links_public: bool,
    /// True for a fully-private spend FROM the shielded pool (sender, recipient,
    /// and amount all hidden) — dispatched via `shielded_send`, not `send`.
    from_pool: bool,
}

/// The local node, running **in-process** inside sov-station (the Bitcoin Core
/// `bitcoin-qt` model: the wallet *is* the node). Holds the daemon's RPC +
/// block-production threads and optional P2P engine. Shutting it down — explicitly
/// (Stop) or when the window closes (Drop/`on_exit`) — halts the node; there is no
/// separate process, so a node can never be orphaned or outlive its UI.
struct EmbeddedNode {
    daemon: DaemonHandle,
    p2p: Option<P2pHandle>,
    /// The account the node mines its coinbase to (for the status badge).
    account: String,
    /// Live sync telemetry, written by the P2P engine and read by the production loop
    /// (to gate mining) and the UI (for a rolling status). Shared by clone with both.
    sync: Arc<SyncShared>,
}

/// A socket-free, in-process snapshot of the embedded node's CHAIN state — read every
/// frame so the Node tab rolls in real time even when the loopback RPC poller blips.
/// Requires the node lock (so it can be momentarily unavailable mid-commit; the
/// lock-free [`SyncView`] is not).
struct ChainView {
    height: u64,
    chain_id: String,
    head_hash: String,
    state_root: String,
    /// Total mined supply, in grains (every coin is mined; genesis supply is zero).
    supply_grains: String,
    mempool: usize,
}

/// A lock-free view of peering/sync, always available (atomics) so the Node tab's peer
/// and sync status never blank out just because the node is busy committing a block.
struct SyncView {
    /// Distinct authenticated peer nodes (never double-counts a redundant link).
    peers: usize,
    /// Tallest peer chain height we have heard of (0 if none).
    best_peer_height: u64,
    /// Still catching up to a heavier peer chain — downloading, not mining.
    syncing: bool,
    /// This node's measured proof-of-work rate (H/s); 0 when not actively mining.
    local_hashrate: u64,
}

impl EmbeddedNode {
    /// Stop block production, the RPC server, and P2P, joining their threads.
    fn shutdown(self) {
        if let Some(p2p) = self.p2p {
            p2p.shutdown();
        }
        self.daemon.shutdown();
    }

    /// Dial a peer now — non-blocking; the engine keeps retrying so the link forms
    /// once the peer is reachable. Tolerant of the address form (`ip:port`,
    /// `host:port`, or a bare ip / hostname → default P2P port appended). Returns the
    /// concrete target(s) queued (so the UI can show exactly what it is dialing), or
    /// an error for an unresolvable address / a node that is not running — never a
    /// silent no-op.
    fn dial(&self, addr: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        match &self.p2p {
            Some(p2p) => p2p.tcp().request_reconnect(addr),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "P2P is not running on this node",
            )),
        }
    }

    /// Number of currently-connected peers (live, read straight from the in-process
    /// transport — no RPC needed since the node runs inside this app).
    fn peer_count(&self) -> usize {
        self.p2p.as_ref().map(|p| p.tcp().peer_count()).unwrap_or(0)
    }

    /// A SOCKET-FREE read of the embedded node's CHAIN state, straight from the
    /// in-process chain. Uses `try_lock`, so a momentarily-busy node (mid-commit /
    /// mid-reorg) returns `None` rather than blocking the UI — the node is still up,
    /// just busy this instant. This is why the desktop app never needs to "connect" to
    /// its own node over a loopback RPC socket (the source of the spurious "Transport:
    /// … did not properly respond" on Windows).
    fn chain_view(&self) -> Option<ChainView> {
        let node = self.daemon.node();
        let guard = node.try_lock().ok()?;
        let chain = guard.chain();
        Some(ChainView {
            height: chain.height(),
            chain_id: chain.chain_id().to_string(),
            head_hash: chain.head().hash().to_hex(),
            state_root: chain.ledger().state_root().to_hex(),
            supply_grains: chain
                .ledger()
                .total_supply()
                .map(|b| b.grains().to_string())
                .unwrap_or_default(),
            mempool: guard.mempool_len(),
        })
    }

    /// A LOCK-FREE read of peering/sync telemetry (atomics, written by the P2P engine),
    /// so the peer count and sync status never blank just because the node is busy
    /// committing. The peer count is DISTINCT authenticated nodes — a redundant link is
    /// never shown as a ghost.
    fn sync_view(&self) -> SyncView {
        SyncView {
            peers: self.sync.authed_peers(),
            best_peer_height: self.sync.best_peer_height(),
            // "Syncing" = a real initial download (many blocks behind), not a 1-block
            // race — so a node racing at the tip reads as "Synced", not perpetually
            // "Syncing". Matches the mining gate exactly.
            syncing: self.sync.should_gate_mining(),
            local_hashrate: self.sync.local_hashrate(),
        }
    }
}

/// Lifecycle state of the embedded node, shared between the UI thread and the
/// background start worker (which builds the daemon and replays the block log off
/// the UI thread, so the window never freezes during startup).
// The `Running` variant owns the live node handles (intentionally the large one); it
// is held in a single long-lived slot, not stored in bulk, so boxing it would only add
// indirection on every status read.
#[allow(clippy::large_enum_variant)]
#[derive(Default)]
enum NodeRun {
    /// No node running.
    #[default]
    Stopped,
    /// A start is in flight: building the daemon and replaying the block log.
    Starting,
    /// The node is up, serving RPC and producing blocks.
    Running(EmbeddedNode),
    /// The last start attempt failed; the message explains why.
    Failed(String),
}

/// The application window.
pub struct Station {
    snapshot: Arc<Mutex<Snapshot>>,
    config: Arc<Mutex<Config>>,
    tab: Tab,
    rpc_field: String,
    // The node runs IN-PROCESS (embedded), not as a subprocess: its lifetime is the
    // app's, so it can never orphan or desync from the GUI. Shared with the start
    // worker thread (which builds + replays off the UI thread).
    node_run: Arc<Mutex<NodeRun>>,
    node_status: String,
    // Real, timestamped node logs (startup, replay timing, RPC up, block production,
    // errors), shared with the start worker + poller and shown in the Node tab.
    node_logs: Arc<Mutex<Vec<String>>>,
    // Last-logged node observables, so a CHANGE — peer count, RPC online/offline,
    // height progress — is appended to the node log as it happens (live visibility
    // into peering churn and sync, the things the operator is watching for).
    log_prev_peers: Option<usize>,
    log_prev_online: Option<bool>,
    log_prev_height: Option<u64>,
    // Sync-pipeline observables, so the operator SEES the join progress stage by stage
    // (authenticated peers, catch-up starting/finishing, the peer chain height we are
    // pulling toward) instead of a silent "connected but nothing happening".
    log_prev_authed: Option<usize>,
    log_prev_syncing: Option<bool>,
    log_prev_best: Option<u64>,
    // A peer to bootstrap the local node to (`host:port`), so two machines join the
    // SAME testnet (same genesis + a P2P link). Persisted in the node config.
    peer_addr: String,
    // UI theme mode (dark by default). Persisted across launches; flipped by the ☀/🌙
    // toggle, which re-installs the theme live.
    dark_mode: bool,
    // This machine's LAN address to hand to the OTHER machine (cached at launch).
    lan_addr: Option<String>,
    network: Network,
    // Wallet state (held in-session; secrets never leave this process).
    wallets: Vec<LoadedWallet>,
    selected: usize,
    mining_account: Option<String>, // the wallet account the local node mines to (badge)
    rename_field: String,           // editable label for the active wallet
    forget_armed: bool,             // remove-wallet confirmation modal is open
    forget_confirm: String,         // typed text that must match the label to remove
    reveal_phrase: bool,            // show the active wallet's recovery phrase (export)
    receive_kind: ReceiveKind,      // which address the Receive view shows
    pending_send: Option<PendingSend>, // a send awaiting confirmation (review modal)
    block_detail: Option<u64>,      // height of the block open in the detail view
    vault_ui: VaultUi,              // all state for the Vault (multisig) tab; isolated
    wallets_dirty: bool,            // wallets exist that aren't saved to the keystore
    confirm_quit: bool,             // quit requested with unsaved wallets — show guard
    gen_name: String,
    import_name: String,
    import_mnemonic: String,
    watch_label: String,  // label for a new watch-only wallet
    watch_pubkey: String, // public key to watch (hybrid65:0x…)
    // Air-gapped (offline) signing: build an unsigned tx here (online), sign it on
    // the machine that holds the seed, broadcast the signed result here.
    ofl_to: String,           // unsigned transfer recipient
    ofl_amount: String,       // unsigned transfer amount (XUS)
    ofl_unsigned: String,     // built unsigned-tx JSON (export → offline machine)
    ofl_sign_in: String,      // pasted unsigned-tx JSON to sign (offline machine)
    ofl_signed: String,       // signed-tx JSON output (→ back to an online node)
    ofl_broadcast_in: String, // pasted signed-tx JSON to broadcast
    ofl_msg: String,          // offline-tools status line
    send_to: String,
    send_amount: String,
    private_to: String, // recipient for a fully-private (shielded→shielded) send
    private_amount: String, // amount (XUS) for the private send
    deshield_amount: String, // amount (XUS) to de-shield (pool → transparent), variable
    // Tokens tab form fields + cached view.
    tok_symbol: String,
    tok_issue_amount: String,
    tok_issue_to: String,
    tok_xfer_asset: String,
    tok_xfer_to: String,
    tok_xfer_amount: String,
    nft_send_to: String, // recipient for an NFT (or SNS name) transfer
    tok_offset: usize,   // current registry page offset
    tokens_view: Arc<Mutex<TokensView>>,
    // Swaps (HTLC) tab form fields + cached lookup.
    htlc_recipient: String,
    htlc_amount: String,
    htlc_preimage: String,
    htlc_timeout: String,
    htlc_lookup_id: String,
    swaps_view: Arc<Mutex<SwapsView>>,
    backup_mnemonic: Option<(String, String)>, // (account, mnemonic) shown once
    operate_as_field: String,                  // named account to link to the selected wallet
    operate_msg: String,                       // result of the last control check
    name_field: String,                        // SNS name to register (e.g. alice.sov)
    name_check: Arc<Mutex<NameCheck>>,         // live availability/format check for name_field
    // SNS is foundational: every loaded wallet's on-chain names are cached here,
    // keyed by the account they resolve to, so a wallet's name is shown uniformly
    // everywhere (header, switch list, your-names) — not just for the active one.
    names_by_account: Arc<Mutex<HashMap<String, Vec<String>>>>,
    names_refreshed_at: Option<Instant>, // last SNS-cache refresh (for periodic re-poll)
    shielded_scan_for: String,           // account auto-scanned for the shielded pool (debounce)
    action: Arc<Mutex<ActionState>>,
    params: Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    shielded: Arc<Mutex<ShieldedView>>,
    earnings: Arc<Mutex<EarningsView>>,
    /// The MASTER session passphrase that encrypts the wallet store. Set ONLY via a
    /// confirmed first-run setup or a VERIFIED unlock/keystore-load — never typed
    /// once and used directly (see `passphrase_set`).
    passphrase: String,
    keystore_msg: String,
    /// True when an encrypted wallet store exists on disk that hasn't been unlocked
    /// this session — the UI shows the unlock screen and nothing else until the
    /// passphrase is entered. The decryption key is never stored, so this is the
    /// gate on every launch.
    locked: bool,
    unlock_error: String,
    /// First-run passphrase SETUP, shown before the master passphrase is ever used
    /// to encrypt. Two inputs that must MATCH (and meet a length floor) — so a typo
    /// can't silently become the key and lock you out.
    show_setup: bool,
    setup_pw: String,
    setup_pw2: String,
    /// True once the master passphrase has been established by a CONFIRMED setup or a
    /// VERIFIED unlock / keystore-load — the only paths allowed to encrypt the store.
    /// Typing into the portable-keystore field never sets this.
    passphrase_set: bool,
    /// Passphrase for the PORTABLE keystore file (Save/Load backup), kept separate
    /// from the master so opening a backup can't silently re-key the live store.
    keystore_pass: String,
    copied_at: Option<u64>, // ms timestamp of the last copy, for the toast
    activity: Arc<Mutex<Vec<String>>>, // recent action log (newest first), with txids
    pending_network: Option<Network>, // a mainnet switch awaiting confirmation
    /// The most recent action result surfaced as a transient toast (`message`,
    /// `shown_at_ms`), visible from ANY tab, and the message already toasted (so each
    /// result toasts once). Green on success, red on failure (`tx_status`).
    toast: Option<(String, u64)>,
    toast_seen: String,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Node,
    Mining,
    Wallet,
    Tokens,
    Swaps,
    Vault,
    Blocks,
    Activity,
}

/// All transient UI state for the Vault (treasury multisig) tab — grouped in ONE
/// struct so the whole feature is a single Station field. None of this is persisted
/// in the wallet/keystore; saved vault definitions live in their own public file (see
/// [`vault`]). Remove this field + the `Tab::Vault` arm to delete the feature cleanly.
#[derive(Default)]
struct VaultUi {
    vaults: Vec<vault::Vault>,
    loaded: bool,
    // Create-a-vault form
    new_name: String,
    new_account: String,
    new_member_name: String,
    new_member_key: String,
    new_members: Vec<vault::Member>,
    new_threshold: u16,
    create_msg: String,
    // Send-from-a-vault form (becomes a proposal)
    send_vault: usize,
    send_to: String,
    send_amount: String,
    send_msg: String,
    // The approval inbox, filled by a background fetch off `sov_getMultisigProposals`.
    inbox: Arc<Mutex<Inbox>>,
    last_fetch: Option<Instant>,
}

/// The pending-proposals inbox, shared with the fetch worker.
#[derive(Default)]
struct Inbox {
    proposals: Vec<ProposalView>,
    fetching: bool,
    error: String,
}

/// One pending vault spend, decoded for display. The chain is the source of truth;
/// this is just what `sov_getMultisigProposals` returned, plus whether the selected
/// wallet still needs to approve it.
#[derive(Clone, Default)]
struct ProposalView {
    vault_name: String,
    account: String,
    id_hex: String,
    to: String,
    amount_grains: u128,
    approved: usize,
    threshold: u16,
    /// The selected wallet is a member of this vault who has NOT yet approved.
    can_approve: bool,
    /// The selected wallet is a member (so it may at least cancel).
    is_member: bool,
}

/// The network the app is pointed at. Wallets are key material and work on ANY
/// network unchanged, so switching never touches them — only the chain view (RPC,
/// balances, blocks) follows. Testnet is a local sandbox (mine + reset); Mainnet
/// is the real chain (no destructive reset; connect to a real node).
#[derive(PartialEq, Eq, Clone, Copy)]
enum Network {
    Testnet,
    Mainnet,
}

impl Network {
    /// Short display name (also the top-bar chip text).
    fn label(self) -> &'static str {
        match self {
            Network::Testnet => "TESTNET",
            Network::Mainnet => "MAINNET",
        }
    }

    /// The chain-id a node on this network must report — used as a safety guard
    /// against acting on the wrong chain.
    fn chain_id(self) -> &'static str {
        match self {
            Network::Testnet => "sov-testnet-1",
            Network::Mainnet => "sov-mainnet",
        }
    }

    /// The default RPC endpoint to point at when this network is selected.
    fn default_rpc(self) -> &'static str {
        // Both default to the local node today; mainnet seeds are configured by
        // the operator (or hardcoded) at launch.
        "127.0.0.1:8645"
    }

    /// The frozen chain-spec file (under `chain/specs/`) a local node of this
    /// network is built from. Mainnet's spec does not exist until launch.
    fn spec_filename(self) -> &'static str {
        match self {
            Network::Testnet => "testnet-1.json",
            Network::Mainnet => "mainnet.json",
        }
    }

    /// Whether this network is a local sandbox: self-mining and a destructive
    /// "reset chain" are offered ONLY here. A real chain (mainnet) is never
    /// wipeable from the wallet, so those controls are hidden.
    fn is_sandbox(self) -> bool {
        matches!(self, Network::Testnet)
    }

    /// The chip color: amber for testnet (caution: not real value), green for
    /// mainnet (live).
    fn color(self) -> egui::Color32 {
        match self {
            Network::Testnet => palette::warning(),
            Network::Mainnet => palette::success(),
        }
    }

    /// The proof-of-work algorithm a node on this network mines with — shown next to
    /// the network selector. Fixed per network by the chain-spec's `pow` (not an
    /// independent choice): testnet runs **SHA-256d** (fast, single-box friendly);
    /// mainnet runs **RandomX** (Monero's memory-hard, ASIC-resistant CPU PoW).
    fn pow_algo(self) -> &'static str {
        match self {
            Network::Testnet => "SHA-256d",
            Network::Mainnet => "RandomX",
        }
    }
}

impl Station {
    fn new(snapshot: Arc<Mutex<Snapshot>>, config: Arc<Mutex<Config>>) -> Self {
        let rpc_field = config.lock().map(|c| c.rpc.clone()).unwrap_or_default();
        let mut station = Station {
            snapshot,
            config,
            tab: Tab::Node,
            rpc_field,
            node_run: Arc::new(Mutex::new(NodeRun::Stopped)),
            node_status: String::new(),
            node_logs: Arc::new(Mutex::new(Vec::new())),
            log_prev_peers: None,
            log_prev_online: None,
            log_prev_height: None,
            log_prev_authed: None,
            log_prev_syncing: None,
            log_prev_best: None,
            peer_addr: read_saved_peer(),
            dark_mode: read_saved_theme(),
            lan_addr: lan_ipv4(),
            network: Network::Testnet,
            wallets: Vec::new(),
            selected: 0,
            mining_account: None,
            rename_field: String::new(),
            forget_armed: false,
            forget_confirm: String::new(),
            reveal_phrase: false,
            receive_kind: ReceiveKind::Shielded,
            pending_send: None,
            block_detail: None,
            vault_ui: VaultUi::default(),
            wallets_dirty: false,
            confirm_quit: false,
            gen_name: "my-wallet".to_string(),
            import_name: "imported".to_string(),
            import_mnemonic: String::new(),
            watch_label: String::new(),
            watch_pubkey: String::new(),
            ofl_to: String::new(),
            ofl_amount: String::new(),
            ofl_unsigned: String::new(),
            ofl_sign_in: String::new(),
            ofl_signed: String::new(),
            ofl_broadcast_in: String::new(),
            ofl_msg: String::new(),
            send_to: String::new(),
            send_amount: String::new(),
            private_to: String::new(),
            private_amount: String::new(),
            deshield_amount: String::new(),
            tok_symbol: String::new(),
            tok_issue_amount: String::new(),
            tok_issue_to: String::new(),
            tok_xfer_asset: String::new(),
            tok_xfer_to: String::new(),
            nft_send_to: String::new(),
            tok_xfer_amount: String::new(),
            tok_offset: 0,
            tokens_view: Arc::new(Mutex::new(TokensView::default())),
            htlc_recipient: String::new(),
            htlc_amount: String::new(),
            htlc_preimage: String::new(),
            htlc_timeout: String::new(),
            htlc_lookup_id: String::new(),
            swaps_view: Arc::new(Mutex::new(SwapsView::default())),
            backup_mnemonic: None,
            operate_as_field: String::new(),
            operate_msg: String::new(),
            name_field: String::new(),
            name_check: Arc::new(Mutex::new(NameCheck::default())),
            names_by_account: Arc::new(Mutex::new(HashMap::new())),
            names_refreshed_at: None,
            shielded_scan_for: String::new(),
            action: Arc::new(Mutex::new(ActionState::default())),
            params: Arc::new(Mutex::new(None)),
            shielded: Arc::new(Mutex::new(ShieldedView::default())),
            earnings: Arc::new(Mutex::new(EarningsView::default())),
            copied_at: None,
            activity: Arc::new(Mutex::new(Vec::new())),
            pending_network: None,
            toast: None,
            toast_seen: String::new(),
            passphrase: String::new(),
            keystore_msg: String::new(),
            locked: false,
            unlock_error: String::new(),
            show_setup: false,
            setup_pw: String::new(),
            setup_pw2: String::new(),
            passphrase_set: false,
            keystore_pass: String::new(),
        };
        // If an encrypted wallet store exists, start LOCKED — the wallets load only
        // once the passphrase is entered (its key is never stored on disk). With no
        // store yet, stay unlocked; the passphrase is set when the first wallet is
        // created. The legacy device-key store also triggers the lock screen and is
        // migrated to passphrase encryption on first unlock.
        station.locked = autosave_path().map(|p| p.exists()).unwrap_or(false);
        // Migration / safety: this version runs the node IN-PROCESS, so there should
        // be no external node. Kill any legacy `sov-rpcd` subprocess left over from
        // an older build (tracked by its pidfile) so it can't hold the RPC/P2P ports
        // or keep mining headless. From here on, the node's lifetime is the app's.
        stop_tracked_node();
        let _ = std::fs::remove_file(node_pid_path());
        // First-run guidance: a node mines to a wallet, so with no wallet yet, open
        // on the Wallet tab (where you create/import one) rather than the Node tab
        // with a silently-greyed "Start". With a wallet present, the app IS the node:
        // bring the embedded node up automatically (closing the app stops it). Safe —
        // `build_and_run_node` refuses to touch a chain mined to a different wallet.
        if station.wallets.is_empty() {
            station.tab = Tab::Wallet;
        } else if station.network.is_sandbox() {
            station.start_local_node();
        }
        station
    }

    /// Track this account's balance in the poller, and watch the wallet list.
    fn register_wallet(&mut self, wallet: LoadedWallet) {
        if let Ok(mut c) = self.config.lock() {
            if !c.accounts.contains(&wallet.account) {
                c.accounts.push(wallet.account.clone());
            }
        }
        self.wallets.push(wallet);
        self.selected = self.wallets.len() - 1;
        self.wallets_dirty = true;
    }

    /// A passphrase must be set before the first wallet is created, so the encrypted
    /// store always has a key. Returns true when one is set; otherwise flashes a
    /// pointer to the passphrase field and returns false.
    fn require_passphrase(&mut self) -> bool {
        if self.passphrase_set && !self.passphrase.is_empty() {
            true
        } else {
            // No confirmed master passphrase yet → open the create-with-confirm
            // screen rather than encrypting under an unverified string.
            self.show_setup = true;
            false
        }
    }

    /// Generate a brand-new wallet (fresh mnemonic + hybrid PQ key). Instant and
    /// offline; the mnemonic is shown once for backup and never leaves the process.
    fn generate_wallet(&mut self) {
        if !self.require_passphrase() {
            return;
        }
        // The typed text is a display LABEL only — the on-chain account id is
        // derived from the new key, so it can never collide with another
        // account or inherit its funds.
        let label = self.gen_name.trim();
        let label = if label.is_empty() { "wallet" } else { label }.to_string();
        let mnemonic = match generate_mnemonic(24) {
            Ok(m) => m,
            Err(e) => return self.set_action(&format!("generate failed: {e}")),
        };
        let mut seed = match HdWallet::from_mnemonic(&mnemonic, "") {
            Ok(w) => w.derive_seed(0, 0),
            Err(e) => return self.set_action(&format!("derive failed: {e}")),
        };
        let result = LoadedWallet::from_seed(label.clone(), seed, Some(mnemonic.clone()));
        seed.zeroize(); // wipe the stack copy; the wallet owns its own (also zeroized)
        match result {
            Ok(w) => {
                let account = w.account.clone();
                self.register_wallet(w);
                self.backup_mnemonic = Some((account, mnemonic));
                self.set_action("wallet generated — BACK UP THE MNEMONIC");
                self.auto_save();
            }
            Err(e) => self.set_action(&format!("derive failed: {e}")),
        }
    }

    /// Import a wallet from an existing BIP-39 mnemonic.
    fn import_wallet(&mut self) {
        if !self.require_passphrase() {
            return;
        }
        // The typed text is a display LABEL only; the on-chain id is re-derived
        // deterministically from the mnemonic's key.
        let label = self.import_name.trim();
        let label = if label.is_empty() { "wallet" } else { label }.to_string();
        let mnemonic = self.import_mnemonic.trim().to_string();
        let mut seed = match HdWallet::from_mnemonic(&mnemonic, "") {
            Ok(w) => w.derive_seed(0, 0),
            Err(e) => return self.set_action(&format!("invalid mnemonic: {e}")),
        };
        let result = LoadedWallet::from_seed(label, seed, Some(mnemonic));
        seed.zeroize(); // wipe the stack copy; the wallet owns its own (also zeroized)
        match result {
            Ok(w) => {
                self.register_wallet(w);
                // `.clear()` only resets the length — scrub the bytes first so the
                // typed phrase doesn't linger in the field's freed capacity.
                self.import_mnemonic.zeroize();
                self.import_mnemonic.clear();
                self.set_action("wallet imported");
                self.auto_save();
            }
            Err(e) => self.set_action(&format!("import failed: {e}")),
        }
    }

    /// Add a WATCH-ONLY wallet from a public key: monitor an account with no
    /// private key on this machine (it cannot sign). Persisted like any wallet.
    fn add_watch_only(&mut self) {
        if !self.require_passphrase() {
            return;
        }
        let label = self.watch_label.trim();
        let label = if label.is_empty() { "Watch" } else { label }.to_string();
        let pk = self.watch_pubkey.trim().to_string();
        if pk.is_empty() {
            return self.set_action("enter a public key to watch");
        }
        match LoadedWallet::watch_only(label, &pk) {
            Ok(w) => {
                if self.wallets.iter().any(|x| x.account == w.account) {
                    return self.set_action("that account is already loaded");
                }
                self.watch_pubkey.clear();
                self.watch_label.clear();
                self.register_wallet(w);
                self.set_action("👁 watch-only wallet added");
                self.auto_save();
            }
            Err(e) => self.set_action(&format!("watch-only: {e}")),
        }
    }

    /// Whether the active wallet can sign. A watch-only wallet cannot — it sets a
    /// status message pointing to the offline-signing tools and returns false.
    fn require_signing(&self) -> bool {
        let watch = self
            .wallets
            .get(self.selected)
            .map(|w| w.watch_only)
            .unwrap_or(false);
        if watch {
            self.set_action(
                "👁 watch-only wallet — cannot sign here. Build an unsigned tx below, sign it on \
                 the machine that holds the seed, then broadcast.",
            );
        }
        !watch
    }

    /// Build an UNSIGNED transfer for the active wallet's account and put its JSON
    /// in `ofl_unsigned` to carry to an air-gapped machine. Uses the account's
    /// current on-chain nonce (from the live poll) — no key needed, so it works
    /// from a watch-only wallet.
    fn build_unsigned(&mut self) {
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let signer = w.effective_account();
        let pk_str = w.public_key.clone();
        let to = self.ofl_to.trim().to_string();
        let Some(grains) = parse_xus(&self.ofl_amount) else {
            self.ofl_msg = "amount must be a number (e.g. 1.5)".into();
            return;
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let build = (|| -> Result<(String, u64), String> {
            let signer_id = AccountId::new(&signer).map_err(|e| e.to_string())?;
            let to_id = AccountId::new(&to).map_err(|e| e.to_string())?;
            let public_key: PublicKey = serde_json::from_value(serde_json::Value::String(pk_str))
                .map_err(|e| e.to_string())?;
            // The signer's current on-chain nonce (so the offline-signed tx is
            // immediately includable when broadcast).
            let nonce = RpcClient::new(rpc)
                .with_timeout(Duration::from_secs(8))
                .nonce(&signer_id)
                .map_err(|e| e.to_string())?;
            let tx = Transaction {
                signer: signer_id,
                public_key,
                nonce,
                action: Action::Transfer {
                    to: to_id,
                    amount: Balance::from_grains(grains),
                },
            };
            Ok((
                serde_json::to_string_pretty(&tx).map_err(|e| e.to_string())?,
                nonce,
            ))
        })();
        match build {
            Ok((json, nonce)) => {
                self.ofl_unsigned = json;
                self.ofl_msg = format!(
                    "✓ unsigned tx built (nonce {nonce}) — copy it to your offline machine to sign"
                );
            }
            Err(e) => self.ofl_msg = format!("build failed: {e}"),
        }
    }

    /// Sign a pasted unsigned-tx JSON with the active wallet's key (offline; no
    /// network). The wallet's key must match the transaction's `public_key`.
    fn sign_offline(&mut self) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let input = self.ofl_sign_in.trim().to_string();
        let signed = (|| -> Result<String, String> {
            let tx: Transaction = serde_json::from_str(&input).map_err(|e| e.to_string())?;
            let kp = Keypair::hybrid_from_seed(seed);
            // SignedTransaction::sign refuses if the keypair's key isn't the one the
            // transaction names — exactly the cross-wallet guard we want.
            let stx = SignedTransaction::sign(tx, &kp).map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&stx).map_err(|e| e.to_string())
        })();
        match signed {
            Ok(json) => {
                self.ofl_signed = json;
                self.ofl_msg = "✓ signed — copy this to an online node and broadcast".into();
            }
            Err(e) => self.ofl_msg = format!("sign failed: {e}"),
        }
    }

    /// Broadcast a pasted signed-tx JSON to the connected node.
    fn broadcast_signed(&mut self, ctx: &egui::Context) {
        let input = self.ofl_broadcast_in.trim().to_string();
        if input.is_empty() {
            self.ofl_msg = "paste a signed transaction to broadcast".into();
            return;
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "broadcasting signed tx…");
        std::thread::spawn(move || {
            let msg = (|| -> Result<String, String> {
                let stx: SignedTransaction =
                    serde_json::from_str(&input).map_err(|e| format!("not a signed tx: {e}"))?;
                let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(15));
                let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
                Ok(format!("✓ broadcast — tx {}", &txid.to_hex()[..14]))
            })()
            .unwrap_or_else(|e| format!("✗ broadcast failed: {e}"));
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    fn set_action(&self, message: &str) {
        if let Ok(mut a) = self.action.lock() {
            a.busy = false;
            a.message = message.to_string();
        }
    }

    /// Link a named account to the selected wallet so send/activate act AS it.
    /// Checks on-chain (real key comparison) whether this wallet controls it, but
    /// links it regardless — the account may be about to be genesis-bound to this
    /// key. The named account is added to the poller's watch list for its balance.
    fn set_operate_as(&mut self) {
        let name = self.operate_as_field.trim().to_string();
        if let Err(e) = AccountId::new(&name) {
            self.operate_msg = format!("invalid account id: {e}");
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        self.operate_msg = check_control(&rpc, seed, &name);
        if let Some(w) = self.wallets.get_mut(self.selected) {
            w.operate_as = Some(name.clone());
        }
        if let Ok(mut c) = self.config.lock() {
            if !c.accounts.contains(&name) {
                c.accounts.push(name);
            }
        }
    }

    /// Stop operating a linked named account; revert to the wallet's own id.
    fn clear_operate_as(&mut self) {
        if let Some(w) = self.wallets.get_mut(self.selected) {
            w.operate_as = None;
        }
        self.operate_msg.clear();
    }

    /// Rename the active wallet's display label (local only — the on-chain id is
    /// the key's fingerprint and never changes).
    fn rename_selected(&mut self) {
        let label = self.rename_field.trim().to_string();
        if label.is_empty() {
            return;
        }
        if let Some(w) = self.wallets.get_mut(self.selected) {
            w.label = label;
        }
        self.rename_field.clear();
        self.auto_save();
    }

    /// Forget the active wallet (remove it from the session). Irreversible
    /// without its recovery phrase or a saved keystore — guarded by a two-click
    /// confirm in the UI. Never touches on-chain state.
    fn forget_selected(&mut self) {
        if self.selected < self.wallets.len() {
            let gone = self.wallets.remove(self.selected);
            // Drop it from the poller's watch list (unless another wallet shares
            // the account, which cannot happen for distinct keys).
            if let Ok(mut c) = self.config.lock() {
                c.accounts.retain(|a| a != &gone.account);
            }
            if self.mining_account.as_deref() == Some(gone.account.as_str()) {
                self.mining_account = None;
            }
        }
        self.selected = self.selected.min(self.wallets.len().saturating_sub(1));
        self.forget_armed = false;
        self.rename_field.clear();
        self.auto_save();
    }

    /// Register a NEW human-readable `*.sov` name on-chain (ENS/SNS-style),
    /// binding it as an **alias that resolves to this wallet's account**. The
    /// wallet keeps its own identity and funds — the name just points at it, so
    /// others can pay `alice.sov` instead of the key fingerprint. First-come;
    /// pays a one-time registration fee (earned by miners) from this wallet's
    /// balance. Submitted on a worker; the registry updates once the tx is mined.
    fn register_named(&mut self, ctx: &egui::Context) {
        let name = self.name_field.trim().to_string();
        if let Err(e) = validate_name_format(&name) {
            self.operate_msg = format!("✗ {e}");
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let signer = w.effective_account();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();

        let action = self.action.clone();
        let activity = self.activity.clone();
        let cache = self.names_by_account.clone();
        let ctx = ctx.clone();
        begin(&action, &format!("registering {name} on-chain…"));
        std::thread::spawn(move || {
            let msg = match register_name_onchain(&rpc, seed, &signer, &name) {
                Ok(tx) => format!(
                    "✓ {name} registered — it will resolve to your account once mined (tx {})",
                    &tx[..tx.len().min(14)]
                ),
                Err(e) => format!("✗ register failed: {e}"),
            };
            // Best-effort cache refresh for this account (the new name shows once
            // the tx is mined; the periodic refresh picks it up regardless).
            if let Ok(names) = fetch_names_of(&rpc, &signer) {
                if let Ok(mut m) = cache.lock() {
                    m.insert(signer.clone(), names);
                }
            }
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    /// Send `amount` to `to` (a named account, a `xus1…` shielded address, or a
    /// `uxus1…` unified address). Routing + Halo2 proving happen on a worker.
    fn send(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // Spend from whichever account this wallet operates (own implicit id, or
        // a linked named account such as a tax account), signing with its key.
        let from = w.effective_account();
        let to = self.send_to.trim().to_string();
        let Some(grains) = parse_xus(&self.send_amount) else {
            return self.set_action("amount must be a number of XUS (e.g. 1.5)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "sending…");
        std::thread::spawn(move || {
            let msg = send_payment(&rpc, seed, &from, &to, grains, &params, &action)
                .map(|id| {
                    format!(
                        "✓ submitted {} XUS → {to} — in the mempool, confirms next block (tx {})",
                        xus(&grains.to_string()),
                        &id[..id.len().min(14)]
                    )
                })
                .unwrap_or_else(|e| format!("✗ send failed: {e}"));
            finish(&action, &msg);
            record(&activity, &msg);
            ctx.request_repaint();
        });
    }

    /// Scan the chain for the selected wallet's shielded notes and total its
    /// unspent pool balance. The pool is private, so this trial-decrypts every
    /// shielded bundle with the wallet's key — only the holder can.
    fn scan_shielded(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return; // watch-only has no shielded viewing key (no seed)
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let account = w.account.clone();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.shielded.clone();
        let ctx = ctx.clone();
        if let Ok(mut v) = view.lock() {
            v.scanning = true;
            v.account = account.clone();
            v.message = "scanning the shielded pool…".to_string();
        }
        std::thread::spawn(move || {
            let result = scan_store(&rpc, seed);
            if let Ok(mut v) = view.lock() {
                v.scanning = false;
                match result {
                    Ok(store) => {
                        v.account = account;
                        v.balance = store.balance();
                        v.notes = store.unspent_count();
                        v.scanned_height = store.scanned_height();
                        v.message = format!("scanned to height {}", store.scanned_height());
                    }
                    Err(e) => v.message = format!("scan failed: {e}"),
                }
            }
            ctx.request_repaint();
        });
    }

    /// De-shield the largest unspent note back to this wallet's transparent
    /// account (a real Halo2 spend). Re-scans to rebuild the witness tree.
    fn deshield(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        // Sign with the account this wallet OPERATES (the key-bound named account
        // when attached), not its keyless implicit id — that account both pays the
        // fee and receives the de-shielded funds. Using the implicit id would be
        // rejected ("unauthorized") because it has no key bound on-chain.
        let account = w.effective_account();
        // The variable amount to de-shield (XUS → grains). Must be a positive
        // amount; the UI only enables the button when it is within budget.
        let Some(grains) = parse_xus(&self.deshield_amount).filter(|g| *g > 0) else {
            finish(&self.action, "enter an amount to de-shield");
            return;
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let shielded = self.shielded.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "de-shielding (rebuilding witness + proving)…");
        std::thread::spawn(move || {
            match deshield_amount(&rpc, seed, &account, grains, &params, &action) {
                Ok(id) => {
                    let line = format!("de-shielded to {account} (tx {})", &id[..id.len().min(14)]);
                    finish(&action, &format!("{line} — updating balance…"));
                    record(&activity, &line);
                    ctx.request_repaint();
                    refresh_shielded_view(&rpc, seed, &account, &shielded, &ctx);
                    finish(&action, "de-shield confirmed — shielded balance updated");
                }
                Err(e) => {
                    let msg = format!("de-shield failed: {e}");
                    finish(&action, &msg);
                    record(&activity, &msg);
                }
            }
            ctx.request_repaint();
        });
    }

    /// Fully-private send (shielded → shielded): spend this wallet's scanned
    /// notes to pay `private_to`, with private change back. Sender, recipient, and
    /// amount are all hidden. Re-scans for a fresh witness, then proves on a worker.
    fn send_private(&self, ctx: &egui::Context) {
        if !self.require_signing() {
            return;
        }
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let seed = w.seed;
        let signer = w.effective_account();
        let to = self.private_to.trim().to_string();
        let Some(grains) = parse_xus(&self.private_amount) else {
            return self.set_action("amount must be a number of XUS (e.g. 1.5)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let account = self
            .wallets
            .get(self.selected)
            .map(|w| w.account.clone())
            .unwrap_or_default();
        let action = self.action.clone();
        let params = self.params.clone();
        let shielded = self.shielded.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        begin(&action, "private send (rebuilding witness + proving)…");
        std::thread::spawn(move || {
            match shielded_send(&rpc, seed, &signer, &to, grains, &params, &action) {
                Ok(id) => {
                    let line = format!(
                        "sent {} XUS privately (tx {})",
                        xus(&grains.to_string()),
                        &id[..id.len().min(14)]
                    );
                    finish(&action, &format!("{line} — updating balance…"));
                    record(&activity, &line);
                    ctx.request_repaint();
                    // The spend's nullifier lands when the tx is mined; re-scan so
                    // the shielded view drops the spent note (no stale balance).
                    refresh_shielded_view(&rpc, seed, &account, &shielded, &ctx);
                    finish(&action, "private send confirmed — shielded balance updated");
                }
                Err(e) => {
                    let msg = format!("private send failed: {e}");
                    finish(&action, &msg);
                    record(&activity, &msg);
                }
            }
            ctx.request_repaint();
        });
    }

    /// Serialize the in-session wallets into a keystore (label + seed + phrase).
    /// The on-chain id re-derives from the seed on load (it is the key's
    /// fingerprint); the phrase is stored so it can be exported after a restart.
    fn wallets_to_keystore(&self) -> Keystore {
        Keystore {
            miners: self
                .wallets
                .iter()
                .map(|w| KeystoreEntry {
                    account: w.label.clone(),
                    // Watch-only entries carry no seed — just the watched key.
                    seed_hex: if w.watch_only {
                        String::new()
                    } else {
                        hex_lower(&w.seed)
                    },
                    scheme: Some("hybrid65".to_string()),
                    mnemonic: w.mnemonic.clone(),
                    public_key: if w.watch_only {
                        Some(w.public_key.clone())
                    } else {
                        None
                    },
                })
                .collect(),
        }
    }

    /// Persist wallets to the auto-file, encrypted under the session PASSPHRASE
    /// (Argon2id) — the decryption key is derived from what you type and is never
    /// written to disk. Called on every change so "once unlocked, it stays".
    /// Requires the wallet to be unlocked (a passphrase set); a no-op otherwise so
    /// it can never overwrite the encrypted store with something weaker.
    fn auto_save(&mut self) {
        let Ok(path) = autosave_path() else { return };
        if self.wallets.is_empty() {
            // No wallets → remove the file so the empty state also persists.
            let _ = std::fs::remove_file(&path);
            self.wallets_dirty = false;
            return;
        }
        if self.passphrase.is_empty() {
            // Should not happen (creation is gated on a passphrase), but never fall
            // back to a weaker, keyless save.
            self.keystore_msg = "set a passphrase to save your wallet".to_string();
            return;
        }
        match self
            .wallets_to_keystore()
            .to_encrypted_json(&self.passphrase)
        {
            Ok(json) => {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if std::fs::write(&path, json).is_ok() {
                    restrict_to_owner(&path);
                    self.wallets_dirty = false;
                } else {
                    self.keystore_msg = "auto-save failed to write".to_string();
                }
            }
            Err(e) => self.keystore_msg = format!("auto-save failed: {e}"),
        }
    }

    /// Build wallets from a decrypted keystore into the live set (dedup by derived
    /// account). Shared by unlock and the portable-keystore import.
    fn load_keystore_entries(&mut self, ks: &Keystore) -> usize {
        let mut loaded = 0;
        for entry in &ks.miners {
            // A watch-only entry carries a public key and no seed; a normal entry
            // carries a seed.
            let built = if let Some(pk) = &entry.public_key {
                LoadedWallet::watch_only(entry.account.clone(), pk)
            } else {
                match hex_decode32(&entry.seed_hex) {
                    Ok(bytes) => LoadedWallet::from_seed(
                        entry.account.clone(),
                        bytes,
                        entry.mnemonic.clone(),
                    ),
                    Err(_) => continue,
                }
            };
            let Ok(w) = built else {
                continue;
            };
            if self.wallets.iter().any(|x| x.account == w.account) {
                continue;
            }
            self.register_wallet(w);
            loaded += 1;
        }
        loaded
    }

    /// Unlock the wallet store with the typed passphrase. On success the wallets
    /// load and the app unlocks. A LEGACY store (encrypted under the old on-disk
    /// device key) is transparently MIGRATED on first unlock: decrypt with the
    /// device key, re-encrypt under this passphrase, and delete the device key — so
    /// no decryption key is ever left on disk again. Existing wallets are never
    /// orphaned: as long as the device key is present, any passphrase migrates them.
    fn try_unlock(&mut self) {
        if self.passphrase.is_empty() {
            self.unlock_error = "enter your passphrase".to_string();
            return;
        }
        let Ok(path) = autosave_path() else {
            self.locked = false;
            return;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            // Nothing saved → nothing to unlock; treat the typed passphrase as the
            // new one for the wallets you're about to create.
            self.locked = false;
            self.unlock_error.clear();
            return;
        };
        // 1) Current format: passphrase-encrypted.
        if let Ok(ks) = Keystore::from_encrypted_or_plain(&text, Some(&self.passphrase)) {
            self.load_keystore_entries(&ks);
            self.locked = false;
            self.passphrase_set = true; // verified against the store
            self.unlock_error.clear();
            self.wallets_dirty = false;
            return;
        }
        // 2) Legacy format: encrypted under the on-disk device key → migrate.
        if let Ok(dkey) = legacy_device_key_hex() {
            if let Ok(ks) = Keystore::from_encrypted_or_plain(&text, Some(&dkey)) {
                self.load_keystore_entries(&ks);
                self.locked = false;
                self.passphrase_set = true; // verified via migration
                self.unlock_error.clear();
                // Re-encrypt under the passphrase, then remove the device key.
                self.auto_save();
                remove_legacy_device_key();
                self.set_action("wallet migrated to passphrase encryption");
                return;
            }
        }
        self.unlock_error = "wrong passphrase".to_string();
    }

    /// The full-window unlock screen shown while [`locked`](Self#structfield.locked).
    /// Nothing else renders until the passphrase decrypts the store.
    fn show_unlock_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(60.0);
            ui.vertical_centered(|ui| {
                ui.heading("🔒  Wallet locked");
                ui.add_space(8.0);
                ui.label(
                    "Enter your passphrase to decrypt this device's wallets. The key is \
                     derived from your passphrase and is never stored — so it's required \
                     every launch.",
                );
                ui.add_space(16.0);
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.passphrase)
                        .password(true)
                        .hint_text("passphrase")
                        .desired_width(280.0),
                );
                ui.add_space(10.0);
                let submit = ui.button("Unlock").clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if submit {
                    self.try_unlock();
                }
                if !self.unlock_error.is_empty() {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::from_rgb(220, 80, 80), &self.unlock_error);
                }
                ui.add_space(20.0);
                ui.label(
                    egui::RichText::new(
                        "Forgot it? Re-import each wallet from its 24-word recovery phrase. \
                         An older wallet from a previous version is upgraded automatically on \
                         first unlock.",
                    )
                    .small()
                    .weak(),
                );
            });
        });
    }

    /// The first-run passphrase CREATION screen — two inputs that must match before
    /// the master passphrase is set, so a typo can't become the encryption key and
    /// lock you out. Shown when a wallet action needs a passphrase and none is set.
    fn show_setup_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(50.0);
            let action = ui
                .vertical_centered(|ui| {
                    render_passphrase_setup(ui, &mut self.setup_pw, &mut self.setup_pw2).0
                })
                .inner;
            match action {
                SetupAction::Set => {
                    // Committed only because the two inputs matched (button was enabled).
                    self.passphrase.zeroize();
                    self.passphrase = self.setup_pw.clone();
                    self.passphrase_set = true;
                    self.setup_pw.zeroize();
                    self.setup_pw.clear();
                    self.setup_pw2.zeroize();
                    self.setup_pw2.clear();
                    self.show_setup = false;
                    self.set_action("passphrase set — now create or import a wallet");
                }
                SetupAction::Cancel => {
                    self.setup_pw.zeroize();
                    self.setup_pw.clear();
                    self.setup_pw2.zeroize();
                    self.setup_pw2.clear();
                    self.show_setup = false;
                }
                SetupAction::None => {}
            }
        });
    }

    /// The Vault tab — easy-mode treasury multisig (M-of-N). Drives the already-shipped
    /// On-chain coordination: an approval inbox (polled from `sov_getMultisigProposals`)
    /// shows each pending spend with a one-tap Approve; proposing is the Send form. No
    /// codes. Actions are normal member transactions via the isolated [`vault`] module.
    fn vault_panel(&mut self, ui: &mut egui::Ui) {
        if !self.vault_ui.loaded {
            self.vault_ui.vaults = vault::load_vaults();
            self.vault_ui.loaded = true;
            if self.vault_ui.new_threshold == 0 {
                self.vault_ui.new_threshold = 2;
            }
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        // Pre-extract the selected wallet's identity so closures never borrow self.wallets.
        let sel = self.wallets.get(self.selected);
        let my_account = sel.map(|w| w.effective_account()).unwrap_or_default();
        let my_key = sel.map(|w| w.public_key.clone()).unwrap_or_default();
        let my_seed = sel.filter(|w| !w.watch_only).map(|w| w.seed);

        // Auto-refresh the approval inbox from the chain while the tab is open.
        let stale = self
            .vault_ui
            .last_fetch
            .map(|t| t.elapsed() >= Duration::from_secs(4))
            .unwrap_or(true);
        if stale && !self.vault_ui.vaults.is_empty() {
            self.vault_ui.last_fetch = Some(Instant::now());
            self.fetch_proposals(&rpc, my_key.clone(), ui.ctx().clone());
        }

        ui.heading("🛡 Shared Vault");
        ui.label(
            egui::RichText::new(
                "A vault is an account several members must approve before it spends. \
                 Send from it like any account — co-signers just tap Approve below. The \
                 chain coordinates everything; there are no codes to copy.",
            )
            .weak(),
        );
        ui.separator();

        // Intents collected inside closures, executed afterwards (so closures never
        // need to borrow `self` to call a method).
        let mut do_create = false;
        let mut do_send = false;
        let mut refresh = false;
        let mut approve: Option<(String, String)> = None; // (vault account, proposal id hex)
        let mut cancel: Option<(String, String)> = None;

        // ── Needs your approval (the inbox, filled from the chain) ──
        egui::CollapsingHeader::new(egui::RichText::new("Needs your approval").strong())
            .default_open(true)
            .show(ui, |ui| {
                let (proposals, fetching, error) = self
                    .vault_ui
                    .inbox
                    .lock()
                    .map(|i| (i.proposals.clone(), i.fetching, i.error.clone()))
                    .unwrap_or_default();
                if ui.small_button("⟳ Refresh").clicked() {
                    refresh = true;
                }
                if fetching {
                    ui.label(egui::RichText::new("checking the chain…").small().weak());
                }
                if !error.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(220, 160, 60), &error);
                }
                let mine: Vec<&ProposalView> = proposals.iter().filter(|p| p.is_member).collect();
                if mine.is_empty() && !fetching {
                    ui.label(egui::RichText::new("nothing waiting on you").weak());
                }
                for p in mine {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "Send {} XUS → {}",
                                grains_to_xus_plain(p.amount_grains),
                                p.to
                            ))
                            .strong(),
                        );
                        ui.label(
                            egui::RichText::new(format!("from “{}” ({})", p.vault_name, p.account))
                                .small()
                                .weak(),
                        );
                        ui.horizontal(|ui| {
                            let dots: String = (0..p.threshold as usize)
                                .map(|i| if i < p.approved { '✓' } else { '○' })
                                .collect();
                            ui.label(format!("{} of {}  {dots}", p.approved, p.threshold));
                            if p.can_approve {
                                if ui
                                    .add_enabled(my_seed.is_some(), egui::Button::new("Approve"))
                                    .clicked()
                                {
                                    approve = Some((p.account.clone(), p.id_hex.clone()));
                                }
                            } else {
                                ui.label(egui::RichText::new("✓ you approved").small().weak());
                            }
                            if ui.small_button("Cancel").clicked() {
                                cancel = Some((p.account.clone(), p.id_hex.clone()));
                            }
                        });
                    });
                }
            });

        // ── Your vaults ──
        egui::CollapsingHeader::new(egui::RichText::new("Your vaults").strong())
            .default_open(true)
            .show(ui, |ui| {
                if self.vault_ui.vaults.is_empty() {
                    ui.label(egui::RichText::new("none yet — create one below").weak());
                }
                let mut forget: Option<usize> = None;
                for (i, v) in self.vault_ui.vaults.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "“{}” — {}  ({} of {})",
                            v.name,
                            v.account,
                            v.threshold,
                            v.members.len()
                        ));
                        if ui.small_button("Forget").clicked() {
                            forget = Some(i);
                        }
                    });
                }
                if let Some(i) = forget {
                    self.vault_ui.vaults.remove(i);
                    let _ = vault::save_vaults(&self.vault_ui.vaults);
                }
            });

        // ── Create a vault ──
        egui::CollapsingHeader::new(egui::RichText::new("Create a vault").strong()).show(
            ui,
            |ui| {
                ui.horizontal(|ui| {
                    ui.label("Vault name");
                    ui.text_edit_singleline(&mut self.vault_ui.new_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Account to secure");
                    ui.text_edit_singleline(&mut self.vault_ui.new_account);
                    if !my_account.is_empty() && ui.button("Use selected wallet").clicked() {
                        self.vault_ui.new_account = my_account.clone();
                    }
                });
                ui.add_space(4.0);
                ui.label("Members — each holder's name + public key:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_ui.new_member_name)
                            .hint_text("name")
                            .desired_width(110.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_ui.new_member_key)
                            .hint_text("hybrid65:0x…")
                            .desired_width(260.0),
                    );
                    if ui.button("Add").clicked() {
                        match vault::parse_pubkey(&self.vault_ui.new_member_key) {
                            Ok(_) => {
                                let name = if self.vault_ui.new_member_name.trim().is_empty() {
                                    format!("member {}", self.vault_ui.new_members.len() + 1)
                                } else {
                                    self.vault_ui.new_member_name.trim().to_string()
                                };
                                self.vault_ui.new_members.push(vault::Member {
                                    name,
                                    pubkey: self.vault_ui.new_member_key.trim().to_string(),
                                });
                                self.vault_ui.new_member_name.clear();
                                self.vault_ui.new_member_key.clear();
                                self.vault_ui.create_msg.clear();
                            }
                            Err(e) => self.vault_ui.create_msg = e,
                        }
                    }
                    if !my_key.is_empty()
                        && ui.button("Add me").clicked()
                        && !self.vault_ui.new_members.iter().any(|m| m.pubkey == my_key)
                    {
                        self.vault_ui.new_members.push(vault::Member {
                            name: "Me".to_string(),
                            pubkey: my_key.clone(),
                        });
                    }
                });
                let mut drop_member: Option<usize> = None;
                for (i, m) in self.vault_ui.new_members.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!("• {} — {}", m.name, short_pubkey(&m.pubkey)));
                        if ui.small_button("✕").clicked() {
                            drop_member = Some(i);
                        }
                    });
                }
                if let Some(i) = drop_member {
                    self.vault_ui.new_members.remove(i);
                }
                let n = self.vault_ui.new_members.len().max(1) as u16;
                ui.horizontal(|ui| {
                    ui.label("Approvals required");
                    ui.add(egui::DragValue::new(&mut self.vault_ui.new_threshold).range(1..=n));
                    ui.label(format!("of {}", self.vault_ui.new_members.len()));
                });
                if ui
                    .add_enabled(
                        my_seed.is_some(),
                        egui::Button::new("Create vault on-chain"),
                    )
                    .clicked()
                {
                    do_create = true;
                }
                if my_seed.is_none() {
                    ui.label(
                        egui::RichText::new("select a signing wallet (not watch-only) first")
                            .small()
                            .weak(),
                    );
                }
                if !self.vault_ui.create_msg.is_empty() {
                    ui.label(egui::RichText::new(&self.vault_ui.create_msg).weak());
                }
            },
        );

        // ── Send from a vault (this PROPOSES the spend; co-signers approve above) ──
        egui::CollapsingHeader::new(egui::RichText::new("Send from a vault").strong()).show(
            ui,
            |ui| {
                if self.vault_ui.vaults.is_empty() {
                    ui.label(egui::RichText::new("create a vault first").weak());
                    return;
                }
                let names: Vec<String> = self
                    .vault_ui
                    .vaults
                    .iter()
                    .map(|v| format!("{} ({})", v.name, v.account))
                    .collect();
                if self.vault_ui.send_vault >= names.len() {
                    self.vault_ui.send_vault = 0;
                }
                egui::ComboBox::from_label("vault")
                    .selected_text(names[self.vault_ui.send_vault].clone())
                    .show_ui(ui, |ui| {
                        for (i, n) in names.iter().enumerate() {
                            ui.selectable_value(&mut self.vault_ui.send_vault, i, n);
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("Send to");
                    ui.text_edit_singleline(&mut self.vault_ui.send_to);
                });
                ui.horizontal(|ui| {
                    ui.label("Amount (XUS)");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_ui.send_amount)
                            .desired_width(120.0),
                    );
                });
                if ui
                    .add_enabled(my_seed.is_some(), egui::Button::new("Propose spend"))
                    .clicked()
                {
                    do_send = true;
                }
                if my_seed.is_none() {
                    ui.label(
                        egui::RichText::new("select a signing wallet that is a vault member first")
                            .small()
                            .weak(),
                    );
                }
                if !self.vault_ui.send_msg.is_empty() {
                    ui.label(egui::RichText::new(&self.vault_ui.send_msg).weak());
                }
            },
        );

        // ── Execute collected intents (clean &mut self here) ──
        if refresh {
            self.vault_ui.last_fetch = None; // force a fetch on the next frame
        }
        if do_create {
            self.vault_create(&rpc, my_seed);
        }
        if do_send {
            self.vault_propose(&rpc, my_seed);
        }
        if let Some((account, id)) = approve {
            self.vault_decide(&rpc, my_seed, &account, &id, true);
        }
        if let Some((account, id)) = cancel {
            self.vault_decide(&rpc, my_seed, &account, &id, false);
        }
    }

    /// Build a vault from the create-form fields, save it locally, and submit the
    /// `SetMultisig` that opts the account into M-of-N (signed by the selected wallet).
    fn vault_create(&mut self, rpc: &str, my_seed: Option<[u8; 32]>) {
        let Some(seed) = my_seed else {
            self.vault_ui.create_msg = "select a signing wallet first".to_string();
            return;
        };
        let v = vault::Vault {
            name: if self.vault_ui.new_name.trim().is_empty() {
                "Vault".to_string()
            } else {
                self.vault_ui.new_name.trim().to_string()
            },
            account: self.vault_ui.new_account.trim().to_string(),
            members: self.vault_ui.new_members.clone(),
            threshold: self.vault_ui.new_threshold,
        };
        let action = match v.set_multisig_action() {
            Ok(a) => a,
            Err(e) => {
                self.vault_ui.create_msg = e;
                return;
            }
        };
        // Save the definition locally so it's usable immediately (public data only).
        if !self.vault_ui.vaults.iter().any(|x| x.account == v.account) {
            self.vault_ui.vaults.push(v.clone());
            let _ = vault::save_vaults(&self.vault_ui.vaults);
        }
        // Reset the form.
        self.vault_ui.new_name.clear();
        self.vault_ui.new_account.clear();
        self.vault_ui.new_members.clear();
        self.vault_ui.new_threshold = 2;
        self.vault_ui.create_msg = "saved — submitting SetMultisig…".to_string();
        // Dispatch the on-chain opt-in (signed by the account's current controller).
        let rpc = rpc.to_string();
        let signer = v.account.clone();
        let action_state = self.action.clone();
        let activity = self.activity.clone();
        begin(&action_state, "securing the account as a vault…");
        std::thread::spawn(move || {
            let msg = match submit_action(&rpc, seed, &signer, action) {
                Ok(tx) => format!(
                    "✓ vault secured (SetMultisig tx {})",
                    &tx[..tx.len().min(14)]
                ),
                Err(e) => format!("✗ could not secure vault: {e}"),
            };
            finish(&action_state, &msg);
            record(&activity, &msg);
        });
    }

    /// PROPOSE a spend from the selected vault. Submitted as the member's OWN
    /// transaction (their key/nonce/fee); their signature is their first approval.
    fn vault_propose(&mut self, rpc: &str, my_seed: Option<[u8; 32]>) {
        let Some(seed) = my_seed else {
            self.vault_ui.send_msg = "select a signing wallet first".to_string();
            return;
        };
        let Some(member) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        else {
            return;
        };
        let Some(v) = self.vault_ui.vaults.get(self.vault_ui.send_vault).cloned() else {
            self.vault_ui.send_msg = "pick a vault".to_string();
            return;
        };
        let to = self.vault_ui.send_to.trim().to_string();
        if to.is_empty() {
            self.vault_ui.send_msg = "enter a recipient".to_string();
            return;
        }
        let Some(grains) = parse_xus(&self.vault_ui.send_amount) else {
            self.vault_ui.send_msg = "amount must be a number of XUS".to_string();
            return;
        };
        let account = match AccountId::new(&v.account) {
            Ok(a) => a,
            Err(e) => {
                self.vault_ui.send_msg = format!("bad vault account: {e}");
                return;
            }
        };
        let to_id = match AccountId::new(&to) {
            Ok(a) => a,
            Err(e) => {
                self.vault_ui.send_msg = format!("bad recipient: {e}");
                return;
            }
        };
        let action = Action::ProposeMultisig {
            account,
            action: Box::new(Action::Transfer {
                to: to_id,
                amount: Balance::from_grains(grains),
            }),
        };
        self.vault_ui.send_to.clear();
        self.vault_ui.send_amount.clear();
        self.vault_ui.send_msg = "proposing…".to_string();
        self.vault_ui.last_fetch = None; // refresh the inbox right after
        let rpc = rpc.to_string();
        let action_state = self.action.clone();
        let activity = self.activity.clone();
        begin(&action_state, "proposing the vault spend…");
        std::thread::spawn(move || {
            let msg = match submit_action(&rpc, seed, &member, action) {
                Ok(tx) => format!(
                    "✓ proposed — co-signers can now approve it (tx {})",
                    &tx[..tx.len().min(14)]
                ),
                Err(e) => format!("✗ propose failed: {e}"),
            };
            finish(&action_state, &msg);
            record(&activity, &msg);
        });
    }

    /// APPROVE (or CANCEL) a pending proposal — the member's own one-tap transaction.
    fn vault_decide(
        &mut self,
        rpc: &str,
        my_seed: Option<[u8; 32]>,
        account: &str,
        id_hex: &str,
        approve: bool,
    ) {
        let Some(seed) = my_seed else {
            self.set_action("select a signing wallet first");
            return;
        };
        let Some(member) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        else {
            return;
        };
        let acct = match AccountId::new(account) {
            Ok(a) => a,
            Err(e) => return self.set_action(&format!("bad vault account: {e}")),
        };
        let pid = match Hash::from_hex(id_hex) {
            Ok(h) => h,
            Err(e) => return self.set_action(&format!("bad proposal id: {e}")),
        };
        let action = if approve {
            Action::ApproveMultisig {
                account: acct,
                proposal: pid,
            }
        } else {
            Action::CancelMultisig {
                account: acct,
                proposal: pid,
            }
        };
        self.vault_ui.last_fetch = None; // refresh the inbox right after
        let verb = if approve { "approving" } else { "cancelling" };
        let rpc = rpc.to_string();
        let action_state = self.action.clone();
        let activity = self.activity.clone();
        begin(&action_state, &format!("{verb} the vault spend…"));
        std::thread::spawn(move || {
            let msg = match submit_action(&rpc, seed, &member, action) {
                Ok(tx) => format!("✓ {verb} submitted (tx {})", &tx[..tx.len().min(14)]),
                Err(e) => format!("✗ {verb} failed: {e}"),
            };
            finish(&action_state, &msg);
            record(&activity, &msg);
        });
    }

    /// Refresh the approval inbox: query `sov_getMultisigProposals` for every saved
    /// vault on a worker, decode each pending spend, and flag the ones the selected
    /// wallet still needs to approve. Runs off the UI thread; repaints when done.
    fn fetch_proposals(&self, rpc: &str, my_key: String, ctx: egui::Context) {
        if let Ok(mut i) = self.vault_ui.inbox.lock() {
            i.fetching = true;
        }
        let vaults = self.vault_ui.vaults.clone();
        let inbox = self.vault_ui.inbox.clone();
        let rpc = rpc.to_string();
        std::thread::spawn(move || {
            let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(6));
            let mut out: Vec<ProposalView> = Vec::new();
            let mut error = String::new();
            for v in &vaults {
                match client.call("sov_getMultisigProposals", json!({ "account": v.account })) {
                    Ok(Value::Array(arr)) => {
                        for p in &arr {
                            let action = p.get("action");
                            let to = action
                                .and_then(|a| a.get("to"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let amount_grains = action
                                .and_then(|a| a.get("amount"))
                                .and_then(Value::as_str)
                                .and_then(|s| s.parse::<u128>().ok())
                                .unwrap_or(0);
                            let approved =
                                p.get("approved").and_then(Value::as_u64).unwrap_or(0) as usize;
                            let threshold =
                                p.get("threshold").and_then(Value::as_u64).unwrap_or(0) as u16;
                            let approvers: Vec<u16> = p
                                .get("approvers")
                                .and_then(Value::as_array)
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_u64().map(|n| n as u16))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let my_idx = v.member_index(&my_key);
                            out.push(ProposalView {
                                vault_name: v.name.clone(),
                                account: v.account.clone(),
                                id_hex: field(p, "id"),
                                to,
                                amount_grains,
                                approved,
                                threshold,
                                can_approve: my_idx
                                    .map(|i| !approvers.contains(&i))
                                    .unwrap_or(false),
                                is_member: my_idx.is_some(),
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(e) => error = format!("could not read proposals: {e}"),
                }
            }
            if let Ok(mut i) = inbox.lock() {
                i.proposals = out;
                i.fetching = false;
                i.error = error;
            }
            ctx.request_repaint();
        });
    }

    /// Export all wallets to the passphrase-encrypted PORTABLE keystore (a backup
    /// you can move between machines). Day-to-day persistence is automatic via
    /// [`auto_save`](Self::auto_save); this is the hardened/portable copy.
    fn save_wallets(&mut self) {
        if self.keystore_pass.is_empty() {
            self.keystore_msg = "enter a passphrase for the backup file first".to_string();
            return;
        }
        if self.wallets.is_empty() {
            self.keystore_msg = "no wallets to save".to_string();
            return;
        }
        self.keystore_msg = match self
            .wallets_to_keystore()
            .to_encrypted_json(&self.keystore_pass)
        {
            Ok(json) => match write_keystore(&json) {
                Ok(path) => format!("exported {} wallet(s) → {path}", self.wallets.len()),
                Err(e) => format!("save failed: {e}"),
            },
            Err(e) => format!("encrypt failed: {e}"),
        };
    }

    /// Load + decrypt wallets from the portable backup file under its passphrase.
    fn load_wallets(&mut self) {
        if self.keystore_pass.is_empty() {
            self.keystore_msg = "enter the backup file's passphrase first".to_string();
            return;
        }
        let text = match read_keystore() {
            Ok(t) => t,
            Err(e) => {
                self.keystore_msg = format!("load failed: {e}");
                return;
            }
        };
        let ks = match Keystore::from_encrypted_or_plain(&text, Some(&self.keystore_pass)) {
            Ok(k) => k,
            Err(e) => {
                self.keystore_msg = format!("decrypt failed: {e}");
                return;
            }
        };
        let mut loaded = 0;
        for entry in &ks.miners {
            let Ok(bytes) = hex_decode32(&entry.seed_hex) else {
                continue;
            };
            // `entry.account` is the saved display label; the on-chain id is
            // re-derived from the seed. Dedup by that derived id. The phrase is
            // restored when the keystore carried it (so it can be re-exported).
            let Ok(w) =
                LoadedWallet::from_seed(entry.account.clone(), bytes, entry.mnemonic.clone())
            else {
                continue;
            };
            if self.wallets.iter().any(|x| x.account == w.account) {
                continue;
            }
            self.register_wallet(w);
            loaded += 1;
        }
        // If there's no master passphrase yet, adopt the backup's so the loaded
        // wallets persist on this device; otherwise keep the existing master.
        if !self.passphrase_set {
            self.passphrase = self.keystore_pass.clone();
            self.passphrase_set = true;
        }
        // Persist the imported backup to this device too, so it auto-loads next time.
        self.auto_save();
        self.keystore_msg = format!("loaded {loaded} wallet(s)");
    }

    /// Launch a local testnet-1 node the station supervises, and point the poller
    /// at it. If a wallet is selected, the node mines to it — so the wallet
    /// self-funds from coinbase. Reuses the proven `sov-testnet join` + `sov-rpcd`.
    fn start_local_node(&mut self) {
        // A node must mine to a wallet the user controls — refuse otherwise, so
        // coinbase can never accrue to an account nobody holds the key for.
        let Some(w) = self.wallets.get(self.selected) else {
            self.node_status =
                "create or open a wallet first — a node mines to a wallet you control".to_string();
            return;
        };
        // Idempotent: never start a second node on top of a running/starting one.
        if self.local_node_running() {
            return;
        }
        let label = w.label.clone();
        let account = w.account.clone();
        let seed = w.seed;
        let spec = self.network.spec_filename().to_string();

        *self.node_run.lock().unwrap() = NodeRun::Starting;
        self.mining_account = Some(account.clone());
        self.node_status = format!("starting node (replaying chain) — mining to {label}…");
        if let Ok(mut c) = self.config.lock() {
            c.rpc = "127.0.0.1:8645".to_string();
            self.rpc_field = c.rpc.clone();
        }
        push_log(
            &self.node_logs,
            format!("start requested — mining to {label}"),
        );

        // Build + replay the node OFF the UI thread (replaying thousands of blocks
        // would otherwise freeze the window), then publish the running handle.
        let run = Arc::clone(&self.node_run);
        let logs = Arc::clone(&self.node_logs);
        let peer = self.peer_addr.clone();
        std::thread::spawn(move || {
            let result = build_and_run_node(&spec, &account, seed, &peer, &logs);
            let mut slot = run.lock().unwrap();
            match result {
                Ok(node) => {
                    // If the user pressed Stop while we were building, don't run —
                    // shut the just-built node down so it can't become a ghost.
                    if matches!(*slot, NodeRun::Starting) {
                        *slot = NodeRun::Running(node);
                    } else {
                        drop(slot);
                        node.shutdown();
                        push_log(&logs, "start cancelled — node shut down");
                    }
                }
                Err(e) => {
                    push_log(&logs, format!("start FAILED: {e}"));
                    if matches!(*slot, NodeRun::Starting) {
                        *slot = NodeRun::Failed(e);
                    }
                }
            }
        });
    }

    /// For the in-process embedded node, trust the DIRECT read over any loopback-RPC
    /// poll: a Running local node is ONLINE (it lives in this process), its height and
    /// chain id come straight from the chain, and a transient poll error is cleared —
    /// the node is never reached over a socket, so a socket timeout is meaningless and
    /// must not surface as "offline" / a transport error (the Windows symptom). On a
    /// momentary `try_lock` miss (node mid-commit) we keep the last height; it's still
    /// online.
    fn apply_local_status(&self, snap: &mut Snapshot) {
        if let NodeRun::Running(node) = &*self.node_run.lock().unwrap() {
            snap.online = true;
            snap.error = None;
            // Lock-free peer/sync telemetry — always available, so these never blank
            // out while the node is mid-commit.
            let sv = node.sync_view();
            snap.peers = Some(sv.peers);
            snap.best_peer_height = Some(sv.best_peer_height);
            snap.syncing = sv.syncing;
            snap.local_hashrate = sv.local_hashrate;
            // Live chain state, read in-process every frame so height + supply + head
            // ROLL in real time (no dependency on the loopback RPC poller, which blips
            // on Windows). Skipped silently if the node is busy this instant.
            if let Some(cv) = node.chain_view() {
                snap.height = Some(cv.height);
                if !cv.chain_id.is_empty() {
                    snap.chain_id = cv.chain_id;
                }
                snap.head_hash = cv.head_hash;
                snap.state_root = cv.state_root;
                snap.supply_mined = cv.supply_grains;
                snap.mempool = Some(cv.mempool);
            }
        }
    }

    /// Render the current transaction toast (if any) INLINE in the status bar — a
    /// colored, auto-dismissing chip (green on success, red on failure) drawn at the
    /// left of the bottom bar so a result is never missed from any tab, and never
    /// floats over the top-bar node-status line. Returns `true` while a toast is live
    /// (the caller then suppresses the staleness indicator for its brief lifetime).
    fn show_bottom_toast(&mut self, ui: &mut egui::Ui) -> bool {
        const TOAST_MS: u64 = 5_000;
        let Some((msg, at)) = self.toast.clone() else {
            return false;
        };
        if now_ms().saturating_sub(at) >= TOAST_MS {
            self.toast = None;
            return false;
        }
        let st = tx_status(&msg);
        let col = status_color(st);
        let glyph = match st {
            TxStatus::Ok => "✓",
            TxStatus::Err => "✗",
            TxStatus::Info => "•",
        };
        // The status bar is a single line shared with the version label — cap the
        // message so a long error can never blow out the layout.
        let shown = toast_chip_text(&msg, 96);
        ui.label(
            egui::RichText::new(format!("{glyph}  {shown}"))
                .color(col)
                .strong(),
        );
        // Keep repainting so the toast dismisses on time even if nothing else changes.
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(200));
        true
    }

    /// One tab in the top toolbar: a leading glyph + label, a clear active state
    /// (accent-filled pill via the selectable's selection styling), and built-in hover
    /// feedback. Replaces the plain text `selectable_value` row.
    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, glyph: &str, label: &str) {
        let selected = self.tab == tab;
        let text = egui::RichText::new(format!("{glyph}  {label}"));
        let text = if selected {
            text.strong().color(palette::text())
        } else {
            text.color(palette::text_dim())
        };
        if ui.selectable_label(selected, text).clicked() {
            self.tab = tab;
        }
    }

    /// Append a node-log line whenever a watched observable changes — the live peer
    /// count (in-process), RPC online/offline, and head height — so the Node log shows
    /// peering churn and sync progress as they happen instead of a frozen number. Only
    /// transitions are logged (most frames change nothing), so the log stays readable.
    fn log_node_changes(&mut self, snap: &Snapshot) {
        let peers = match &*self.node_run.lock().unwrap() {
            NodeRun::Running(node) => Some(node.peer_count()),
            _ => None,
        };
        match (self.log_prev_peers, peers) {
            (Some(prev), Some(now)) if prev != now => {
                // RAW TCP links (an inbound + an outbound to one node briefly count as
                // two before dedup collapses them) — distinct from "authenticated peers"
                // below, which is the real remote-node count. Labeling them apart stops a
                // transient link reading as a ghost peer.
                push_log(&self.node_logs, format!("TCP links {prev} → {now}"));
                self.log_prev_peers = Some(now);
            }
            (None, Some(now)) => self.log_prev_peers = Some(now),
            (Some(_), None) => self.log_prev_peers = None, // node stopped
            _ => {}
        }
        // RPC reachability transitions (this is the "offline up top" the user sees).
        if self.log_prev_online != Some(snap.online) {
            if let Some(prev) = self.log_prev_online {
                if prev != snap.online {
                    push_log(
                        &self.node_logs,
                        if snap.online {
                            "RPC online — node responding".to_string()
                        } else {
                            "RPC OFFLINE — node not responding".to_string()
                        },
                    );
                }
            }
            self.log_prev_online = Some(snap.online);
        }
        // Head-height progress (mining and/or sync catching up).
        if let Some(h) = snap.height {
            match self.log_prev_height {
                Some(prev) if prev != h => {
                    push_log(&self.node_logs, format!("height {prev} → {h}"));
                    self.log_prev_height = Some(h);
                }
                None => self.log_prev_height = Some(h),
                _ => {}
            }
        }
        // Authenticated-peer transitions — the stage AFTER raw TCP connect: a peer is
        // only counted here once it has proven same chain + genesis + key over the
        // encrypted channel. If raw peers climb but this stays 0, the operator can see
        // the handshake is the thing failing (wrong network / version), not the sync.
        if let Some(now) = snap.peers {
            match self.log_prev_authed {
                Some(prev) if prev != now => {
                    push_log(
                        &self.node_logs,
                        format!("authenticated peers {prev} → {now}"),
                    );
                    self.log_prev_authed = Some(now);
                }
                None => self.log_prev_authed = Some(now),
                _ => {}
            }
        }
        // The height of the peer chain we are pulling toward — so a catch-up shows a
        // concrete target ("syncing to 8400"), not an opaque spinner.
        if let Some(best) = snap.best_peer_height.filter(|b| *b > 0) {
            match self.log_prev_best {
                Some(prev) if prev != best => {
                    push_log(&self.node_logs, format!("peer chain height: {best}"));
                    self.log_prev_best = Some(best);
                }
                None => self.log_prev_best = Some(best),
                _ => {}
            }
        }
        // Catch-up start/finish: the explicit "downloading vs mining" state the user
        // asked to see — the node downloads the existing chain first, then mines.
        if self.log_prev_syncing != Some(snap.syncing) {
            if self.log_prev_syncing.is_some() {
                push_log(
                    &self.node_logs,
                    if snap.syncing {
                        "syncing — downloading the existing chain from a peer (mining paused)"
                            .to_string()
                    } else {
                        "✓ synced — caught up to the network tip, mining enabled".to_string()
                    },
                );
            }
            self.log_prev_syncing = Some(snap.syncing);
        }
    }

    /// Whether the embedded node is up or coming up. In-process, so this is the true
    /// state — there is no external process to fall out of sync with.
    fn local_node_running(&self) -> bool {
        matches!(
            *self.node_run.lock().unwrap(),
            NodeRun::Running(_) | NodeRun::Starting
        )
    }

    fn stop_local_node(&mut self) {
        // Take the running node out and shut it down SYNCHRONOUSLY: shutdown joins the
        // production + RPC + P2P threads and releases the listen ports BEFORE we
        // return, so a subsequent Start/Reset can never race the old listeners (the
        // "address already in use" / ghost-miner class of bug). It is fast (flags +
        // short joins), so the brief UI pause is acceptable for an explicit Stop.
        let prev = std::mem::replace(&mut *self.node_run.lock().unwrap(), NodeRun::Stopped);
        if let NodeRun::Running(node) = prev {
            node.shutdown();
        }
        self.mining_account = None;
        self.node_status = "local node stopped".to_string();
        push_log(
            &self.node_logs,
            "node stopped — RPC + P2P halted, ports released",
        );
    }

    /// Node-tab peering controls (Bitcoin/Zcash style): designate a seed peer once;
    /// it is persisted and **auto-dialed on every start**, and gossip discovers the
    /// rest of the network from there. Also shows the live peer count and this
    /// machine's own dial-able address so the other node can seed back to it.
    fn node_peering_ui(&mut self, ui: &mut egui::Ui) {
        if !self.network.is_sandbox() {
            return;
        }
        ui.add_space(12.0);
        ui.separator();
        ui.heading("Peering");
        ui.label(
            egui::RichText::new(
                "Join other machines to this testnet. Enter one peer's address — it is saved \
                 and auto-dialed every start, then the rest of the network is discovered \
                 automatically (gossip). Solo mining works with zero peers.",
            )
            .weak(),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Seed peer");
            ui.add(
                egui::TextEdit::singleline(&mut self.peer_addr)
                    .hint_text("other machine's IP — port optional (e.g. 192.168.0.244)")
                    .desired_width(320.0),
            );
            if ui
                .button("Connect")
                .on_hover_text("save + dial now, and auto-dial on every start")
                .clicked()
            {
                let p = self.peer_addr.trim().to_string();
                self.peer_addr = p.clone();
                save_peer(&p);
                if p.is_empty() {
                    self.node_status = "seed peer cleared".into();
                    push_log(&self.node_logs, "seed peer cleared".to_string());
                } else {
                    // Dial NOW if the node is up; report the REAL outcome — the resolved
                    // target (with any appended/looked-up port) or the actual error — so
                    // the box never "appears to dial but does nothing".
                    let outcome = match &*self.node_run.lock().unwrap() {
                        NodeRun::Running(node) => Some(node.dial(&p)),
                        _ => None,
                    };
                    match outcome {
                        Some(Ok(addrs)) => {
                            let list = addrs
                                .iter()
                                .map(|a| a.to_string())
                                .collect::<Vec<_>>()
                                .join(", ");
                            self.node_status = format!("dialing {list} (auto-dial on)");
                            push_log(&self.node_logs, format!("seed peer {p} → dialing {list}"));
                        }
                        Some(Err(e)) => {
                            self.node_status = format!("seed peer '{p}' rejected: {e}");
                            push_log(&self.node_logs, format!("seed peer '{p}' rejected: {e}"));
                        }
                        None => {
                            // Node not started yet: saved, and auto-dialed on next start.
                            self.node_status =
                                format!("seed peer saved ({p}) — start the node to dial");
                            push_log(
                                &self.node_logs,
                                format!("seed peer saved: {p} (auto-dials when the node starts)"),
                            );
                        }
                    }
                }
            }
            // Windows only: a one-click firewall fix (re-request the inbound allow),
            // for the case where the first-run UAC prompt was dismissed.
            if cfg!(windows)
                && ui
                    .button("Allow through Windows Firewall")
                    .on_hover_text("re-add the inbound allow rule (one UAC prompt)")
                    .clicked()
            {
                add_firewall_rule();
                self.node_status =
                    "requested Windows Firewall allow — accept the UAC prompt".into();
                push_log(
                    &self.node_logs,
                    "re-requested Windows Firewall inbound allow",
                );
            }
        });
        // Live peer count, read straight from the in-process transport.
        let peers = match &*self.node_run.lock().unwrap() {
            NodeRun::Running(node) => Some(node.peer_count()),
            _ => None,
        };
        match peers {
            Some(n) if n > 0 => {
                ui.colored_label(
                    palette::success(),
                    format!("● {n} peer(s) connected — on the same testnet"),
                );
            }
            Some(_) => {
                ui.colored_label(
                    palette::error(),
                    "● 0 peers — NOT connected. Set the other machine's address above + Connect.",
                );
            }
            None => {
                ui.label(egui::RichText::new("node stopped").weak());
            }
        }
        if let Some(ip) = &self.lan_addr {
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!(
                    "This machine's address (enter THIS in the other node's Seed peer): {ip}:9645",
                ))
                .monospace()
                .size(12.0),
            );
            ui.label(
                egui::RichText::new(format!(
                    "RPC for tools/explorer (e.g. the conformance sweep): {ip}:8645",
                ))
                .monospace()
                .size(12.0)
                .color(palette::text_dim()),
            );
        }
    }

    /// Wipe the local node's chain entirely — back to genesis (height 0). Stops
    /// the node first. The next "Start local node" rebuilds a fresh chain from
    /// the current spec, mining to the active wallet. Use after a genesis change
    /// (e.g. binding tax keys) or to clear coins mined to an old account.
    fn reset_local_chain(&mut self) {
        self.stop_local_node();
        let dir = local_node_dir();
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                self.node_status =
                    "local chain wiped — Start local node to mine a fresh chain from genesis"
                        .to_string()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.node_status = "no local chain to wipe — already clean".to_string()
            }
            Err(e) => self.node_status = format!("could not wipe local chain: {e}"),
        }
    }

    /// Switch the app between networks. Wallets are untouched (keys work on any
    /// network); only the chain view changes. Any supervised local node is
    /// stopped first (never leave a testnet node running under a mainnet view),
    /// and the RPC endpoint resets to the new network's default.
    fn switch_network(&mut self, to: Network) {
        if to == self.network {
            return;
        }
        self.stop_local_node();
        self.network = to;
        let rpc = to.default_rpc().to_string();
        if let Ok(mut c) = self.config.lock() {
            c.rpc = rpc.clone();
        }
        self.rpc_field = rpc;
        self.node_status = format!("switched to {} — wallets unchanged", to.label());
    }
}

impl Station {
    /// Halt the embedded node, joining its threads. Called on window close (Drop and
    /// eframe's `on_exit`) so the node's lifetime is exactly the app's — it can never
    /// linger as an orphan daemon with no UI to control it.
    fn shutdown_node(&mut self) {
        let prev = std::mem::replace(&mut *self.node_run.lock().unwrap(), NodeRun::Stopped);
        if let NodeRun::Running(node) = prev {
            node.shutdown();
        }
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        self.shutdown_node();
        // Scrub typed secrets that aren't owned by a LoadedWallet: the unlock/keystore
        // passphrase, the recovery phrase being typed into the Import field, and the
        // one-time phrase shown right after generating a wallet. (Each LoadedWallet
        // wipes its own seed/phrase/viewing-key via its Drop impl.)
        self.passphrase.zeroize();
        self.keystore_pass.zeroize();
        self.setup_pw.zeroize();
        self.setup_pw2.zeroize();
        self.import_mnemonic.zeroize();
        if let Some((_, phrase)) = self.backup_mnemonic.as_mut() {
            phrase.zeroize();
        }
    }
}

impl eframe::App for Station {
    /// eframe may signal exit without dropping the app; halt the node here too so
    /// closing the window always stops it.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_node();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Locked: an encrypted wallet store exists but hasn't been unlocked this
        // session. Show ONLY the unlock screen — no wallets, no node — until the
        // passphrase decrypts the store.
        if self.locked {
            self.show_unlock_screen(ctx);
            return;
        }
        // First-run: create a passphrase (with confirmation) before anything can be
        // encrypted under it.
        if self.show_setup {
            self.show_setup_screen(ctx);
            return;
        }
        let mut snap = self.snapshot.lock().map(|s| s.clone()).unwrap_or_default();

        // The desktop app's node runs IN-PROCESS — read its status DIRECTLY rather than
        // trusting a loopback-RPC poll that can spuriously time out ("Transport: … did
        // not properly respond") and falsely read offline. A running local node is
        // online, period; its height/chain come straight from the chain.
        self.apply_local_status(&mut snap);

        // Live change-logging: append peer-count / online-offline / height changes to
        // the node log the moment they happen, so the operator sees peering churn and
        // sync progress as it occurs (not just a frozen number).
        self.log_node_changes(&snap);

        // Surface each new action RESULT as a transient toast — visible from ANY tab,
        // not just Wallet — so you always see the moment a send lands (green) or fails
        // (red). Detected once per distinct result message; rendered in the bottom bar
        // (see `show_bottom_toast`) so it never floats over the top-bar node status.
        {
            let (busy, msg) = self
                .action
                .lock()
                .map(|a| (a.busy, a.message.clone()))
                .unwrap_or((false, String::new()));
            if !busy && !msg.is_empty() && msg != self.toast_seen {
                self.toast = Some((msg.clone(), now_ms()));
                self.toast_seen = msg;
            }
        }

        // Keep the window title in sync with the selected network.
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
            "SOV Station — {}",
            self.network.label()
        )));

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("SOV Station");
                ui.separator();
                // Network selector — one colored chip that IS the switcher (no more
                // redundant "TESTNET TESTNET"); you ALWAYS know which network you're on,
                // and switching keeps every wallet (keys are network-agnostic).
                let mut chosen = self.network;
                egui::ComboBox::from_id_salt("network")
                    .selected_text(
                        egui::RichText::new(format!("● {}", self.network.label()))
                            .strong()
                            .color(self.network.color()),
                    )
                    .width(120.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut chosen, Network::Testnet, "Testnet");
                        ui.selectable_value(&mut chosen, Network::Mainnet, "Mainnet");
                    });
                if chosen != self.network {
                    // Switching TO mainnet is consequential (real value) — confirm
                    // first. Switching back to testnet is harmless, so do it now.
                    match chosen {
                        Network::Mainnet => self.pending_network = Some(Network::Mainnet),
                        Network::Testnet => self.switch_network(Network::Testnet),
                    }
                }
                // PoW algorithm for the selected network (fixed by its chain-spec, not a
                // separate choice): SHA-256d on testnet, RandomX on mainnet. Shown so the
                // operator always knows exactly what their CPU is mining.
                ui.label(
                    egui::RichText::new(format!("⛏ {}", self.network.pow_algo()))
                        .strong()
                        .color(palette::link()),
                )
                .on_hover_text(
                    "Proof-of-work algorithm for this network. Testnet: SHA-256d (fast). \
                     Mainnet: RandomX (Monero's memory-hard, ASIC-resistant CPU PoW). \
                     Reward rate is proportional to your hashpower.",
                );
                ui.separator();
                let (dot, label) = if snap.online {
                    (palette::success(), "online")
                } else {
                    (palette::error(), "offline")
                };
                ui.colored_label(dot, "●");
                ui.label(label);
                if !snap.chain_id.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new(&snap.chain_id).monospace());
                    // SAFETY GUARD: the connected node must be on the selected
                    // network. A mismatch (e.g. a testnet node while "Mainnet" is
                    // chosen) is flagged loudly so no action lands on the wrong chain.
                    if snap.online && snap.chain_id != self.network.chain_id() {
                        ui.colored_label(
                            palette::error(),
                            format!(
                                "⚠ not {} — expected {}",
                                self.network.label(),
                                self.network.chain_id()
                            ),
                        );
                    }
                }
                // Theme toggle (right-aligned): flip dark/light live + persist the choice.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (glyph, hint) = if self.dark_mode {
                        ("☀", "Switch to light mode")
                    } else {
                        ("🌙", "Switch to dark mode")
                    };
                    if ui.button(glyph).on_hover_text(hint).clicked() {
                        self.dark_mode = !self.dark_mode;
                        install_theme(ui.ctx(), self.dark_mode);
                        save_theme(self.dark_mode);
                    }
                });
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("RPC");
                ui.add(egui::TextEdit::singleline(&mut self.rpc_field).desired_width(220.0));
                if ui.button("Connect").clicked() {
                    if let Ok(mut c) = self.config.lock() {
                        c.rpc = self.rpc_field.trim().to_string();
                    }
                }
                ui.separator();
                // Sandbox controls (self-mine + destructive reset) exist ONLY on a
                // sandbox network. On mainnet there is no "reset" — a real chain is
                // never wipeable from the wallet — so these are simply absent.
                if self.network.is_sandbox() {
                    if self.local_node_running() {
                        if ui.button("Stop local node").clicked() {
                            self.stop_local_node();
                        }
                    } else {
                        // Mining is bound to a wallet: disable until one is active,
                        // and name the target so it's unmistakable which earns.
                        let target = self.wallets.get(self.selected).map(|w| w.label.clone());
                        let enabled = target.is_some();
                        let btn = ui.add_enabled(enabled, egui::Button::new("Start local node"));
                        let btn = match &target {
                            Some(l) => {
                                btn.on_hover_text(format!("mines to “{l}” (the active wallet)"))
                            }
                            None => btn.on_hover_text("create or open a wallet first"),
                        };
                        if btn.clicked() {
                            self.start_local_node();
                        }
                        if ui
                            .button("Reset local chain")
                            .on_hover_text(
                                "Sandbox only. Wipe the local chain back to genesis (height 0). \
                                 Use after a genesis change or to clear coins mined to an old \
                                 account.",
                            )
                            .clicked()
                        {
                            self.reset_local_chain();
                        }
                        // VISIBLE guidance (not just a hover) for the most common
                        // first-run confusion: a greyed "Start" because there is no
                        // wallet yet. A node must mine to a wallet you control.
                        if !enabled {
                            ui.label(
                                egui::RichText::new(
                                    "← create or import a wallet in the Wallet tab first \
                                     (a node mines to a wallet you control)",
                                )
                                .color(palette::warning()),
                            );
                        }
                    }
                } else {
                    ui.label(
                        egui::RichText::new("connect to a mainnet node via the RPC field").weak(),
                    );
                }
                // Live status derived from the ACTUAL in-process run state, so it
                // always reflects reality — "starting (replaying)" instead of a bare
                // connection error, the mining account when up, the reason on failure.
                let live = match &*self.node_run.lock().unwrap() {
                    NodeRun::Stopped => None,
                    NodeRun::Starting => {
                        Some("● starting node — replaying chain, RPC up shortly…".to_string())
                    }
                    NodeRun::Running(n) => Some(format!(
                        "● node running in-process — mining to {} on 127.0.0.1:8645",
                        short_id(&n.account)
                    )),
                    NodeRun::Failed(e) => Some(format!("✗ node failed to start: {e}")),
                };
                match live {
                    Some(s) => {
                        ui.label(egui::RichText::new(s).weak());
                    }
                    None if !self.node_status.is_empty() => {
                        ui.label(egui::RichText::new(&self.node_status).weak());
                    }
                    None => {}
                }
            });
            ui.add_space(6.0);
            // A real toolbar: a glyph per tab, a clear active state, and a hairline
            // separating it from the content below.
            ui.horizontal(|ui| {
                self.tab_button(ui, Tab::Node, "◧", "Node");
                self.tab_button(ui, Tab::Mining, "⛏", "Mining");
                self.tab_button(ui, Tab::Wallet, "👛", "Wallet");
                self.tab_button(ui, Tab::Tokens, "⬡", "Tokens");
                self.tab_button(ui, Tab::Swaps, "⇄", "Swaps");
                self.tab_button(ui, Tab::Vault, "🛡", "Vault");
                self.tab_button(ui, Tab::Blocks, "▦", "Blocks");
                self.tab_button(ui, Tab::Activity, "◷", "Activity");
            });
            ui.add_space(4.0);
            ui.separator();
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                // A live transaction toast owns the left of the status bar for its brief
                // lifetime (green/red) — more important in that moment than staleness or a
                // node error, and it can never collide with the top-bar node status here.
                if !self.show_bottom_toast(ui) {
                    if let Some(err) = &snap.error {
                        ui.colored_label(palette::error(), format!("⚠ {err}"));
                    } else if snap.updated_ms > 0 {
                        let age = now_ms().saturating_sub(snap.updated_ms);
                        ui.label(egui::RichText::new(format!("updated {age} ms ago")).weak());
                    }
                }
                // Right-aligned: the app version (always visible) + a "copied ✓" toast.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "SOV Station v{} · {} (testnet)",
                            env!("CARGO_PKG_VERSION"),
                            self.network.label()
                        ))
                        .weak()
                        .monospace(),
                    );
                    // A copy from an explicit button (`self.copied_at`) OR from any
                    // `copy_glyph` affordance (egui memory) shows the same confirmation.
                    let last_copy = self.copied_at.into_iter().chain(copied_recent(ctx)).max();
                    if let Some(t) = last_copy {
                        if now_ms().saturating_sub(t) < 1500 {
                            ui.separator();
                            ui.colored_label(palette::success(), "copied ✓");
                            ctx.request_repaint(); // keep ticking so it fades on time
                        } else {
                            self.copied_at = None;
                        }
                    }
                });
            });
            ui.add_space(3.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Every tab scrolls — the wallet in particular has many sections and
            // must never clip below the window. (Blocks scrolls its own table.)
            match self.tab {
                Tab::Node => {
                    let logs = self.node_logs.lock().map(|v| v.clone()).unwrap_or_default();
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_node")
                        .show(ui, |ui| {
                            node_panel(ui, &snap);
                            self.node_peering_ui(ui);
                            node_log_panel(ui, &logs);
                        });
                }
                Tab::Mining => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_mining")
                        .show(ui, |ui| {
                            self.mining_earnings_section(ui);
                            mining_panel(ui, &snap);
                        });
                }
                Tab::Wallet => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_wallet")
                        .show(ui, |ui| self.wallet_panel(ui, &snap));
                }
                Tab::Tokens => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_tokens")
                        .show(ui, |ui| self.tokens_panel(ui));
                }
                Tab::Swaps => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_swaps")
                        .show(ui, |ui| self.swaps_panel(ui));
                }
                Tab::Vault => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_vault")
                        .show(ui, |ui| self.vault_panel(ui));
                }
                Tab::Blocks => blocks_panel(ui, &snap, &mut self.block_detail),
                Tab::Activity => {
                    egui::ScrollArea::vertical()
                        .id_salt("scroll_activity")
                        .show(ui, |ui| self.activity_panel(ui));
                }
            }
        });

        // ── Warn on quit if wallets aren't saved ──
        if ctx.input(|i| i.viewport().close_requested())
            && self.wallets_dirty
            && !self.wallets.is_empty()
        {
            self.confirm_quit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        if self.confirm_quit {
            egui::Window::new("Unsaved wallets")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(
                        "You have wallets that aren't saved to disk. Quitting now loses any wallet \
                         you haven't backed up (recovery phrase) or saved to the keystore.",
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(egui::RichText::new("Quit anyway").color(palette::error()))
                            .clicked()
                        {
                            self.wallets_dirty = false; // accept the loss
                            self.confirm_quit = false;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if ui.button("Stay (let me save)").clicked() {
                            self.confirm_quit = false;
                        }
                    });
                });
        }

        // ── Confirm switching to MAINNET (real value, not a sandbox) ──
        if self.pending_network == Some(Network::Mainnet) {
            egui::Window::new("Switch to MAINNET?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.colored_label(
                        Network::Mainnet.color(),
                        "MAINNET is the live network — real value. Your wallets are unchanged; the \
                         view switches to the mainnet chain. Sandbox mining/reset are not offered \
                         there.",
                    );
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(
                                egui::RichText::new("Switch to MAINNET")
                                    .strong()
                                    .color(Network::Mainnet.color()),
                            )
                            .clicked()
                        {
                            self.pending_network = None;
                            self.switch_network(Network::Mainnet);
                        }
                        if ui.button("Stay on Testnet").clicked() {
                            self.pending_network = None;
                        }
                    });
                });
        }

        // Keep the live view ticking even without input events.
        // Repaint frequently so the connection/sync status, peer count, height, and
        // logs update LIVE (not stale) — the operator sees peers connect in real time.
        ctx.request_repaint_after(Duration::from_millis(300));
    }
}

fn kv(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.label(egui::RichText::new(k).weak());
    ui.label(egui::RichText::new(if v.is_empty() { "—" } else { v }).monospace());
    ui.end_row();
}

/// Stable egui-memory key for "something was just copied", set by [`copy_glyph`] from
/// any panel (free functions can't touch `self.copied_at`) and read by the bottom bar,
/// so a copy from anywhere shows the same "copied ✓" confirmation.
fn copied_memory_id() -> egui::Id {
    egui::Id::new("sov_copied_at")
}

/// The most recent copy timestamp recorded in egui memory by [`copy_glyph`], if any.
fn copied_recent(ctx: &egui::Context) -> Option<u64> {
    ctx.data(|d| d.get_temp::<u64>(copied_memory_id()))
}

/// A compact copy-to-clipboard affordance — a small 📋 button that copies `value`.
/// A free function (no `&self`) so it works from every panel; confirmation is the
/// shared bottom-bar "copied ✓" (signalled through egui memory), so there is no
/// per-row layout shift. No-op for an empty / placeholder value.
fn copy_glyph(ui: &mut egui::Ui, value: &str) {
    if value.is_empty() || value == "—" {
        return;
    }
    let resp = ui
        .add(
            egui::Button::new(
                egui::RichText::new("📋")
                    .size(11.0)
                    .color(palette::text_dim()),
            )
            .frame(false),
        )
        .on_hover_text("Copy");
    if resp.clicked() {
        ui.output_mut(|o| o.copied_text = value.to_owned());
        let now = now_ms();
        ui.ctx()
            .data_mut(|d| d.insert_temp(copied_memory_id(), now));
    }
}

/// A key/value grid row whose value is a hash or address: a shortened, monospace
/// display with a copy affordance that puts the FULL value on the clipboard.
fn kv_copy(ui: &mut egui::Ui, k: &str, full: &str) {
    ui.label(egui::RichText::new(k).weak());
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(if full.is_empty() {
                "—".to_string()
            } else {
                short(full)
            })
            .monospace(),
        );
        copy_glyph(ui, full);
    });
    ui.end_row();
}

/// A friendly empty-state block — a large glyph "illustration" + a title and a hint —
/// shown where a list or feed has nothing yet, so a panel never reads as broken or
/// blank but instead tells the user what will appear and how to make it happen.
fn empty_state(ui: &mut egui::Ui, glyph: &str, title: &str, hint: &str) {
    ui.add_space(28.0);
    ui.vertical_centered(|ui| {
        ui.label(
            egui::RichText::new(glyph)
                .size(40.0)
                .color(palette::text_dim()),
        );
        ui.add_space(8.0);
        ui.label(egui::RichText::new(title).strong().size(15.0));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(hint).weak());
    });
    ui.add_space(28.0);
}

/// Real node logs — the embedded node's startup, replay timing, RPC/P2P bring-up,
/// and errors — in a monospace, newest-last view so the user can see exactly what
/// the node is doing (and why a start was slow or failed).
fn node_log_panel(ui: &mut egui::Ui, logs: &[String]) {
    ui.add_space(10.0);
    ui.separator();
    ui.horizontal(|ui| {
        ui.heading("Node log");
        ui.label(
            egui::RichText::new(format!(
                "(embedded node — in-process · {} lines)",
                logs.len()
            ))
            .weak(),
        );
    });
    ui.add_space(4.0);
    if logs.is_empty() {
        ui.label(egui::RichText::new("no node activity yet — Start local node to begin").weak());
        return;
    }
    // A tall, scrollable, monospace view so an operator can watch live activity and
    // scroll back through the whole session — the primary window into what the node
    // is doing (peering, sync, restarts, errors).
    egui::Frame::group(ui.style()).show(ui, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("node_log_scroll")
            .max_height(520.0)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in logs.iter().rev().take(2_000).rev() {
                    ui.label(egui::RichText::new(line).monospace().size(12.5));
                }
            });
    });
}

fn node_panel(ui: &mut egui::Ui, s: &Snapshot) {
    ui.heading("Node");
    ui.add_space(6.0);
    egui::Grid::new("node-kv")
        .num_columns(2)
        .spacing([24.0, 6.0])
        .show(ui, |ui| {
            kv(ui, "Chain", &s.chain_id);
            kv(
                ui,
                "Height",
                &s.height.map(|h| h.to_string()).unwrap_or_default(),
            );
            kv_copy(ui, "Head", &s.head_hash);
            kv_copy(ui, "State root", &s.state_root);
            kv(
                ui,
                "Supply (mined)",
                &format!("{} XUS", xus(&s.supply_mined)),
            );
            kv(
                ui,
                "Supply (total)",
                &format!("{} XUS", xus(&s.supply_total)),
            );
            kv(ui, "Difficulty", &s.difficulty);
            kv(
                ui,
                "Mempool",
                &s.mempool.map(|m| m.to_string()).unwrap_or_default(),
            );
            kv(
                ui,
                "Peers",
                &s.peers.map(|p| p.to_string()).unwrap_or_default(),
            );
        });
    ui.add_space(8.0);
    // Connection/sync status — color-coded and LIVE (the UI repaints continuously),
    // through the mode-aware palette so it reads correctly in light AND dark:
    //   green  = solid peer connection(s), at the tip, mining
    //   amber  = connected but catching up (syncing)
    //   red    = NOT connected (0 peers) or offline/error
    let (green, orange, red) = (palette::success(), palette::warning(), palette::error());
    if s.online {
        let local_h = s.height.unwrap_or(0);
        let best = s.best_peer_height.unwrap_or(0);
        let peers = s.peers.unwrap_or(0);
        if s.syncing {
            let behind = best.saturating_sub(local_h);
            ui.label(
                egui::RichText::new(format!(
                    "⟳ SYNCING — {local_h} / {best}  ({behind} behind) — downloading from {peers} peer(s)"
                ))
                .color(orange)
                .strong(),
            );
        } else if peers > 0 {
            ui.label(
                egui::RichText::new(format!(
                    "● CONNECTED — {peers} peer(s), synced at height {local_h}, mining"
                ))
                .color(green)
                .strong(),
            );
        } else {
            ui.label(
                egui::RichText::new(format!(
                    "● NOT CONNECTED — 0 peers (height {local_h}). Set the OTHER machine's address \
                     in the Seed peer field below and click Connect."
                ))
                .color(red)
                .strong(),
            );
        }
    } else {
        ui.label(
            egui::RichText::new("● OFFLINE — no node running. Start a local node above.")
                .color(red)
                .strong(),
        );
    }
}

/// "1.23 MH/s" — a human hashrate from hashes-per-second.
fn fmt_hashrate(hps: f64) -> String {
    if hps >= 1e9 {
        format!("{:.2} GH/s", hps / 1e9)
    } else if hps >= 1e6 {
        format!("{:.2} MH/s", hps / 1e6)
    } else if hps >= 1e3 {
        format!("{:.2} kH/s", hps / 1e3)
    } else {
        format!("{hps:.0} H/s")
    }
}

/// Friendly name for the raw PoW algo string the node reports.
fn pow_algo_display(raw: &str) -> &str {
    match raw {
        "Sha256d" => "SHA-256d",
        "RandomX" => "RandomX",
        "" => "—",
        other => other,
    }
}

/// Average gap (ms) between recent blocks' timestamps (newest-first) — the observed
/// block time, for the cadence + hashrate estimate. `None` with fewer than two blocks.
fn avg_block_interval_ms(blocks: &[BlockRow]) -> Option<u64> {
    let mut total = 0u64;
    let mut n = 0u64;
    for w in blocks.windows(2) {
        if w[0].timestamp_ms > w[1].timestamp_ms {
            total += w[0].timestamp_ms - w[1].timestamp_ms;
            n += 1;
        }
    }
    (n > 0).then(|| total / n)
}

/// A bordered section card (the cohesive container used across the richer panels).
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::group(ui.style())
        .fill(palette::panel())
        .stroke(egui::Stroke::new(1.0, palette::border()))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, add)
        .inner
}

/// Draw a small bar sparkline of recent block intervals (oldest→newest, left→right),
/// each bar colored by how close it is to the target cadence (green ≤2×, amber ≤4×,
/// red beyond), with a dashed target reference line — block cadence at a glance.
fn interval_sparkline(ui: &mut egui::Ui, blocks: &[BlockRow], target_ms: u64) {
    let mut intervals: Vec<f32> = Vec::new();
    for w in blocks.windows(2) {
        if w[0].timestamp_ms > w[1].timestamp_ms {
            intervals.push((w[0].timestamp_ms - w[1].timestamp_ms) as f32 / 1000.0);
        }
    }
    intervals.reverse(); // oldest first, so the newest block is on the right
    if intervals.is_empty() {
        return;
    }
    let target_s = (target_ms as f32 / 1000.0).max(0.001);
    let max = intervals
        .iter()
        .copied()
        .fold(target_s, f32::max)
        .max(0.001);
    let (w, h) = (240.0_f32, 38.0_f32);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let n = intervals.len() as f32;
    let slot = w / n;
    for (i, &v) in intervals.iter().enumerate() {
        let x = rect.left() + i as f32 * slot;
        let bar_h = (v / max) * h;
        let col = if v <= target_s * 2.0 {
            palette::success()
        } else if v <= target_s * 4.0 {
            palette::warning()
        } else {
            palette::error()
        };
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x, rect.bottom() - bar_h),
                egui::pos2(x + (slot * 0.7).max(1.0), rect.bottom()),
            ),
            egui::Rounding::same(1.0),
            col,
        );
    }
    // The target cadence as a reference line.
    let ty = rect.bottom() - (target_s / max) * h;
    painter.line_segment(
        [egui::pos2(rect.left(), ty), egui::pos2(rect.right(), ty)],
        egui::Stroke::new(1.0, palette::tint(palette::text_dim(), 170)),
    );
}

fn mining_panel(ui: &mut egui::Ui, s: &Snapshot) {
    ui.heading("Mining");
    ui.label(
        egui::RichText::new(
            "Proof of work: a miner hashes the block header with a changing nonce until the seal \
             falls below the target. The winning nonce is the block's proof — one hash to verify, \
             the whole network's effort to find. Block rewards track HASHPOWER, not machine count: \
             a node with N× the hashrate earns ~N× the blocks. Compare \"Your hashrate\" across \
             machines to see the split is fair.",
        )
        .weak()
        .small(),
    );
    ui.add_space(8.0);

    let diff = s.difficulty.parse::<f64>().ok();
    let obs = avg_block_interval_ms(&s.blocks);
    let net_hps = match (diff, obs) {
        (Some(d), Some(ms)) if ms > 0 => Some(d / (ms as f64 / 1000.0)),
        _ => None,
    };

    // ── Hashpower hero — your measured rate vs the estimated network rate, up front ──
    card(ui, |ui| {
        ui.columns(2, |c| {
            c[0].label(
                egui::RichText::new("YOUR HASHPOWER")
                    .small()
                    .color(palette::text_dim()),
            );
            let yours = if s.local_hashrate > 0 {
                fmt_hashrate(s.local_hashrate as f64)
            } else if s.syncing {
                "paused — syncing".to_string()
            } else {
                "—".to_string()
            };
            c[0].label(
                egui::RichText::new(yours)
                    .size(26.0)
                    .strong()
                    .color(palette::accent_hi()),
            );
            c[1].label(
                egui::RichText::new("NETWORK HASHPOWER (est)")
                    .small()
                    .color(palette::text_dim()),
            );
            c[1].label(
                egui::RichText::new(net_hps.map(fmt_hashrate).unwrap_or_else(|| "—".to_string()))
                    .size(26.0)
                    .strong()
                    .color(palette::text()),
            );
        });
    });
    ui.add_space(8.0);

    // ── Block cadence sparkline — recent intervals at a glance ──
    if s.blocks.len() > 2 {
        ui.label(
            egui::RichText::new("Block cadence — recent intervals (newest →)")
                .small()
                .color(palette::text_dim()),
        );
        interval_sparkline(ui, &s.blocks, s.target_block_ms);
        ui.add_space(8.0);
    }

    // ── Proof-of-Work card — the algorithm, difficulty, target, and the live proof ──
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("PROOF OF WORK")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(format!("⛏ {}", pow_algo_display(&s.pow_algo)))
                        .strong()
                        .color(palette::accent_hi()),
                );
            });
        });
        ui.add_space(6.0);
        egui::Grid::new("pow-kv")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                kv(ui, "Difficulty", &s.difficulty);
                if let Some(d) = diff {
                    if d > 1.0 {
                        kv(
                            ui,
                            "≈ work per block",
                            &format!("{:.1} leading zero bits", d.log2()),
                        );
                    }
                }
                if let Some(nb) = s.head_bits {
                    kv(ui, "Target (nBits)", &format!("0x{nb:08x}"));
                }
                if let Some(n) = s.head_nonce {
                    kv(ui, "Head nonce (the proof)", &n.to_string());
                }
                if let Some(ms) = obs {
                    kv(
                        ui,
                        "Observed block time",
                        &format!("{:.1}s", ms as f64 / 1000.0),
                    );
                }
                if s.target_block_ms > 0 {
                    kv(
                        ui,
                        "Target block time",
                        &format!("{:.0}s", s.target_block_ms as f64 / 1000.0),
                    );
                }
                kv(
                    ui,
                    "Height",
                    &s.height.map(|h| h.to_string()).unwrap_or_default(),
                );
                kv(ui, "Block reward", &format!("{} XUS", xus(&s.reward)));
                kv(
                    ui,
                    "Mempool",
                    &s.mempool.map(|m| m.to_string()).unwrap_or_default(),
                );
            });
    });

    // ── Latest block solved ──
    if let Some(b) = s.blocks.first() {
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(
                egui::RichText::new("LATEST BLOCK SOLVED")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.add_space(4.0);
            egui::Grid::new("latest-block-kv")
                .num_columns(2)
                .spacing([24.0, 6.0])
                .show(ui, |ui| {
                    kv(ui, "Height", &b.height.to_string());
                    ui.label(egui::RichText::new("Nonce").weak());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(b.nonce.to_string()).monospace());
                        copy_glyph(ui, &b.nonce.to_string());
                    });
                    ui.end_row();
                    kv(ui, "Solved", &block_time(b.timestamp_ms));
                    kv_copy(ui, "Miner", &b.miner);
                    if !s.head_hash.is_empty() {
                        kv_copy(ui, "Block hash", &s.head_hash);
                    }
                    kv(ui, "Coinbase", &format!("{} XUS", xus(&b.reward)));
                });
        });
    }

    // ── Recent proofs of work — per-block nonces + solve cadence ──
    if s.blocks.len() > 1 {
        ui.add_space(10.0);
        ui.label(egui::RichText::new("Recent proofs of work").strong());
        ui.add_space(4.0);
        egui::ScrollArea::vertical()
            .id_salt("recent-pow")
            .max_height(180.0)
            .show(ui, |ui| {
                egui::Grid::new("recent-pow-grid")
                    .num_columns(4)
                    .striped(true)
                    .spacing([18.0, 4.0])
                    .show(ui, |ui| {
                        for h in ["Height", "Interval", "Nonce", "Miner"] {
                            ui.label(egui::RichText::new(h).weak());
                        }
                        ui.end_row();
                        for (i, b) in s.blocks.iter().enumerate() {
                            ui.monospace(b.height.to_string());
                            let interval = s
                                .blocks
                                .get(i + 1)
                                .and_then(|older| b.timestamp_ms.checked_sub(older.timestamp_ms));
                            ui.monospace(
                                interval
                                    .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
                                    .unwrap_or_else(|| "—".to_string()),
                            );
                            ui.monospace(b.nonce.to_string());
                            ui.monospace(short_id(&b.miner));
                            ui.end_row();
                        }
                    });
            });
    }

    // ── Miner registry ──
    ui.add_space(10.0);
    ui.label(egui::RichText::new("Miner registry").strong());
    ui.add_space(4.0);
    egui::Grid::new("miners")
        .num_columns(4)
        .striped(true)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            for h in ["Account", "Blocks", "First", "Last"] {
                ui.label(egui::RichText::new(h).weak());
            }
            ui.end_row();
            if s.miners.is_empty() {
                ui.label("—");
                ui.end_row();
            }
            for m in &s.miners {
                ui.monospace(short_id(&m.account));
                ui.monospace(m.blocks.to_string());
                ui.monospace(m.first.to_string());
                ui.monospace(m.last.to_string());
                ui.end_row();
            }
        });
}

impl Station {
    // ── Tokens tab: view / issue / transfer native SOV tokens (real on-chain). ──
    fn tokens_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Tokens");
        let Some((signer, seed)) = self
            .wallets
            .get(self.selected)
            .map(|w| (w.effective_account(), w.seed))
        else {
            ui.label(egui::RichText::new("create or open a wallet to use tokens").weak());
            return;
        };
        ui.label(egui::RichText::new(format!("acting as {signer}")).weak());
        let tv = self
            .tokens_view
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        let mut do_refresh = false;
        let mut do_issue = false;
        let mut do_transfer = false;
        let mut do_prev = false;
        let mut do_next = false;

        // Your token balances.
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Your token balances").strong());
            if tv.loading {
                ui.spinner();
            } else if ui.button("Refresh").clicked() {
                do_refresh = true;
            }
        });
        if tv.account == signer && !tv.holdings.is_empty() {
            egui::Grid::new("tok_holdings")
                .num_columns(3)
                .striped(true)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    for h in ["Symbol", "Asset", "Balance"] {
                        ui.label(egui::RichText::new(h).weak());
                    }
                    ui.end_row();
                    for (asset, symbol, bal) in &tv.holdings {
                        ui.monospace(symbol);
                        ui.monospace(short_id(asset));
                        ui.monospace(xus(bal));
                        ui.end_row();
                    }
                });
        } else {
            ui.label(egui::RichText::new("none — Refresh to scan").weak());
        }

        // Your NFTs (non-fungible). SNS names ARE NFTs (reserved collection), so a
        // registered name shows here as a collectible alongside any other NFTs —
        // and can be SENT (transferring an SNS name re-points it to the recipient).
        ui.separator();
        ui.label(egui::RichText::new("Your NFTs & names").strong());
        let mut send_nft: Option<(String, bool, String, String)> = None;
        if tv.account == signer && !tv.nfts.is_empty() {
            ui.horizontal(|ui| {
                ui.label("send to");
                ui.add(
                    egui::TextEdit::singleline(&mut self.nft_send_to)
                        .hint_text("recipient account id or a .sov name")
                        .desired_width(300.0),
                );
            });
            let busy = self.action.lock().map(|a| a.busy).unwrap_or(false);
            let has_to = !self.nft_send_to.trim().is_empty();
            egui::Grid::new("tok_nfts")
                .num_columns(3)
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Item", "Kind", ""] {
                        ui.label(egui::RichText::new(h).weak());
                    }
                    ui.end_row();
                    for (display, is_sns, coll, tid) in &tv.nfts {
                        ui.monospace(display);
                        if *is_sns {
                            ui.colored_label(named_color(true), "SNS name · NFT");
                        } else {
                            ui.label(egui::RichText::new("NFT").weak());
                        }
                        ui.add_enabled_ui(!busy && has_to, |ui| {
                            if ui
                                .button("Send")
                                .on_hover_text("Transfer this NFT to the recipient above")
                                .clicked()
                            {
                                send_nft =
                                    Some((display.clone(), *is_sns, coll.clone(), tid.clone()));
                            }
                        });
                        ui.end_row();
                    }
                });
            ui.label(
                egui::RichText::new(
                    "Sending an SNS name transfers ownership — it then resolves to the recipient.",
                )
                .weak()
                .small(),
            );
        } else {
            ui.label(egui::RichText::new("none — Refresh to scan").weak());
        }
        if let Some((display, is_sns, coll, tid)) = send_nft {
            self.send_nft(ui.ctx(), signer.clone(), seed, display, is_sns, coll, tid);
        }

        // The chain's token registry — paged, never the whole set (scales to any
        // number of assets).
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Token registry (paged)").strong());
            ui.add_enabled_ui(tv.offset > 0, |ui| {
                if ui.button("‹ Prev").clicked() {
                    do_prev = true;
                }
            });
            ui.label(
                egui::RichText::new(format!(
                    "showing {}–{}",
                    if tv.registry.is_empty() {
                        0
                    } else {
                        tv.offset + 1
                    },
                    tv.offset + tv.registry.len()
                ))
                .weak(),
            );
            ui.add_enabled_ui(tv.has_more, |ui| {
                if ui.button("Next ›").clicked() {
                    do_next = true;
                }
            });
        });
        if !tv.registry.is_empty() {
            egui::Grid::new("tok_registry")
                .num_columns(4)
                .striped(true)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    for h in ["Symbol", "Asset", "Issuer", "Supply"] {
                        ui.label(egui::RichText::new(h).weak());
                    }
                    ui.end_row();
                    for (asset, symbol, issuer, supply) in &tv.registry {
                        ui.monospace(symbol);
                        ui.monospace(short_id(asset));
                        ui.monospace(short_id(issuer));
                        ui.monospace(xus(supply));
                        ui.end_row();
                    }
                });
        } else {
            ui.label(egui::RichText::new("none on this page — Refresh to load").weak());
        }

        // Issue a token (creates the asset on first issue; mints more after).
        ui.separator();
        ui.label(egui::RichText::new("Issue a token").strong());
        ui.horizontal(|ui| {
            ui.label("Symbol");
            ui.add(
                egui::TextEdit::singleline(&mut self.tok_symbol)
                    .hint_text("USD1")
                    .desired_width(90.0),
            );
            ui.label("Amount");
            ui.add(egui::TextEdit::singleline(&mut self.tok_issue_amount).desired_width(110.0));
            ui.label("To");
            ui.add(
                egui::TextEdit::singleline(&mut self.tok_issue_to)
                    .hint_text("recipient (default: you)")
                    .desired_width(180.0),
            );
            if ui.button("Issue").clicked() {
                do_issue = true;
            }
        });

        // Transfer an existing token.
        ui.separator();
        ui.label(egui::RichText::new("Transfer a token").strong());
        ui.horizontal(|ui| {
            ui.label("Asset");
            ui.add(
                egui::TextEdit::singleline(&mut self.tok_xfer_asset)
                    .hint_text("asset id (hex)")
                    .desired_width(200.0),
            );
        });
        ui.horizontal(|ui| {
            ui.label("To");
            ui.add(egui::TextEdit::singleline(&mut self.tok_xfer_to).desired_width(200.0));
            ui.label("Amount");
            ui.add(egui::TextEdit::singleline(&mut self.tok_xfer_amount).desired_width(110.0));
            if ui.button("Send token").clicked() {
                do_transfer = true;
            }
        });
        if !tv.message.is_empty() {
            status_label(ui, &tv.message);
        }

        if do_prev {
            self.tok_offset = self.tok_offset.saturating_sub(50);
            self.refresh_tokens(ui.ctx(), signer.clone(), seed);
        }
        if do_next {
            self.tok_offset += 50;
            self.refresh_tokens(ui.ctx(), signer.clone(), seed);
        }
        if do_refresh {
            self.refresh_tokens(ui.ctx(), signer.clone(), seed);
        }
        if do_issue {
            self.issue_token(ui.ctx(), signer.clone(), seed);
        }
        if do_transfer {
            self.transfer_token(ui.ctx(), signer, seed);
        }
    }

    fn refresh_tokens(&self, ctx: &egui::Context, signer: String, _seed: [u8; 32]) {
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let offset = self.tok_offset;
        const PAGE: usize = 50;
        let view = self.tokens_view.clone();
        let ctx = ctx.clone();
        if let Ok(mut v) = view.lock() {
            v.loading = true;
            v.message = "scanning tokens…".to_string();
        }
        ctx.request_repaint();
        std::thread::spawn(move || {
            let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(8));
            // Your holdings are bounded by what you actually hold.
            let holdings = client
                .call("sov_getTokenBalances", json!({ "account": signer }))
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|r| (field(r, "asset"), field(r, "symbol"), field(r, "balance")))
                .collect();
            // The registry is fetched ONE PAGE at a time (bounded response).
            let resp = client
                .call("sov_listTokens", json!({ "offset": offset, "limit": PAGE }))
                .unwrap_or(Value::Null);
            let registry = resp
                .get("tokens")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|r| {
                    (
                        field(r, "asset"),
                        field(r, "symbol"),
                        field(r, "issuer"),
                        field(r, "supply"),
                    )
                })
                .collect();
            let has_more = resp
                .get("hasMore")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // Owned NFTs (non-fungible) — includes SNS names, which ARE NFTs.
            let nfts: Vec<(String, bool, String, String)> = client
                .call("sov_nftsOf", json!({ "account": &signer }))
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|r| {
                    let is_sns = r.get("isSns").and_then(Value::as_bool).unwrap_or(false);
                    let token_id = field(r, "tokenId");
                    let collection = field(r, "collection");
                    let display = r
                        .get("tokenText")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("0x{}…", &token_id[..token_id.len().min(12)]));
                    (display, is_sns, collection, token_id)
                })
                .collect();
            if let Ok(mut v) = view.lock() {
                v.loading = false;
                v.account = signer;
                v.holdings = holdings;
                v.registry = registry;
                v.offset = offset;
                v.has_more = has_more;
                v.nfts = nfts;
                v.message = "tokens refreshed".to_string();
            }
            ctx.request_repaint();
        });
    }

    fn issue_token(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let symbol = self.tok_symbol.trim().to_string();
        let to = {
            let t = self.tok_issue_to.trim();
            if t.is_empty() {
                signer.clone()
            } else {
                t.to_string()
            }
        };
        let Some(grains) = parse_xus(&self.tok_issue_amount) else {
            return self.set_token_msg("amount must be a number (e.g. 100)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.tokens_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let to_id = match AccountId::new(&to) {
                Ok(id) => id,
                Err(e) => {
                    return set_token_view_msg(&view, &ctx, &format!("invalid recipient: {e}"))
                }
            };
            let action = Action::TokenIssue {
                symbol,
                amount: Balance::from_grains(grains),
                to: to_id,
            };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ issued token (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ issue failed: {e}"));
            record(&activity, &msg);
            set_token_view_msg(&view, &ctx, &msg);
        });
    }

    fn transfer_token(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let asset_hex = self.tok_xfer_asset.trim().to_string();
        let to = self.tok_xfer_to.trim().to_string();
        let Some(grains) = parse_xus(&self.tok_xfer_amount) else {
            return self.set_token_msg("amount must be a number (e.g. 1.5)");
        };
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.tokens_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let asset = match Hash::from_hex(&asset_hex) {
                Ok(h) => h,
                Err(_) => return set_token_view_msg(&view, &ctx, "asset id must be 64 hex chars"),
            };
            let to_id = match AccountId::new(&to) {
                Ok(id) => id,
                Err(e) => {
                    return set_token_view_msg(&view, &ctx, &format!("invalid recipient: {e}"))
                }
            };
            let action = Action::TokenTransfer {
                asset,
                to: to_id,
                amount: Balance::from_grains(grains),
            };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ sent token (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ token send failed: {e}"));
            record(&activity, &msg);
            set_token_view_msg(&view, &ctx, &msg);
        });
    }

    fn set_token_msg(&self, msg: &str) {
        if let Ok(mut v) = self.tokens_view.lock() {
            v.message = msg.to_string();
        }
    }

    /// Transfer an NFT to a recipient. An SNS name goes via `TransferName` (it
    /// re-points the name); any other NFT via `NftTransfer`. The recipient may be
    /// an account id or a `.sov` name (resolved first).
    #[allow(clippy::too_many_arguments)]
    fn send_nft(
        &self,
        ctx: &egui::Context,
        signer: String,
        seed: [u8; 32],
        display: String,
        is_sns: bool,
        collection_hex: String,
        token_id_hex: String,
    ) {
        let to_raw = self.nft_send_to.trim().to_string();
        if to_raw.is_empty() {
            return self.set_token_msg("enter a recipient first");
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.tokens_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // Resolve a `.sov`-name recipient to the account it points to.
            let to = resolve_payee(&rpc, &to_raw);
            let result = (|| -> Result<String, String> {
                let to_id = AccountId::new(&to).map_err(|e| e.to_string())?;
                let action = if is_sns {
                    Action::TransferName {
                        name: display.clone(),
                        to: to_id,
                    }
                } else {
                    Action::NftTransfer {
                        collection: Hash::from_hex(&collection_hex).map_err(|e| e.to_string())?,
                        token_id: hex_decode(&token_id_hex)?,
                        to: to_id,
                    }
                };
                let tx = submit_action(&rpc, seed, &signer, action)?;
                Ok(format!(
                    "✓ sent {display} → {} (tx {})",
                    short_id(&to),
                    &tx[..tx.len().min(14)]
                ))
            })()
            .unwrap_or_else(|e| format!("✗ send failed: {e}"));
            record(&activity, &result);
            set_token_view_msg(&view, &ctx, &result);
        });
    }

    // ── Swaps tab: hash-time-locked contracts (the SOV half of an atomic swap). ──
    fn swaps_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Atomic swaps (HTLC)");
        ui.label(
            egui::RichText::new(
                "Lock funds behind a hashlock + timeout. The recipient claims by revealing the \
                 secret (which lets you claim the other chain's leg); after the timeout you refund.",
            )
            .weak(),
        );
        let Some((signer, seed)) = self
            .wallets
            .get(self.selected)
            .map(|w| (w.effective_account(), w.seed))
        else {
            ui.label(egui::RichText::new("create or open a wallet to use swaps").weak());
            return;
        };
        ui.label(egui::RichText::new(format!("acting as {signer}")).weak());
        let sv = self
            .swaps_view
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        let mut do_lock = false;
        let mut do_lookup = false;
        let mut do_claim = false;
        let mut do_refund = false;

        // Lock.
        ui.separator();
        ui.label(egui::RichText::new("Lock (open an HTLC)").strong());
        ui.horizontal(|ui| {
            ui.label("Recipient");
            ui.add(egui::TextEdit::singleline(&mut self.htlc_recipient).desired_width(200.0));
            ui.label("Amount XUS");
            ui.add(egui::TextEdit::singleline(&mut self.htlc_amount).desired_width(110.0));
        });
        ui.horizontal(|ui| {
            ui.label("Secret");
            ui.add(
                egui::TextEdit::singleline(&mut self.htlc_preimage)
                    .hint_text("the preimage (shared secret)")
                    .desired_width(220.0),
            );
            ui.label("Timeout height");
            ui.add(egui::TextEdit::singleline(&mut self.htlc_timeout).desired_width(90.0));
            if ui.button("Lock").clicked() {
                do_lock = true;
            }
        });
        if !self.htlc_preimage.trim().is_empty() {
            ui.label(
                egui::RichText::new(format!(
                    "hashlock = sha256(secret) = {}",
                    sha256_hex(self.htlc_preimage.trim().as_bytes())
                ))
                .small()
                .weak(),
            );
        }

        // Lookup / claim / refund by id.
        ui.separator();
        ui.label(egui::RichText::new("Find / claim / refund").strong());
        ui.horizontal(|ui| {
            ui.label("HTLC id");
            ui.add(
                egui::TextEdit::singleline(&mut self.htlc_lookup_id)
                    .hint_text("the lock tx id (hex)")
                    .desired_width(360.0),
            );
            if ui.button("Look up").clicked() {
                do_lookup = true;
            }
        });
        if sv.id == self.htlc_lookup_id.trim() {
            if let Some((locker, recipient, amount, hashlock, timeout)) = &sv.found {
                egui::Grid::new("htlc_detail")
                    .num_columns(2)
                    .spacing([14.0, 4.0])
                    .show(ui, |ui| {
                        kv(ui, "Locker", locker);
                        kv(ui, "Recipient", recipient);
                        kv(ui, "Amount", &format!("{} XUS", xus(amount)));
                        kv(ui, "Hashlock", hashlock);
                        kv(ui, "Timeout height", &timeout.to_string());
                    });
            } else if !sv.message.is_empty() {
                status_label(ui, &sv.message);
            }
        }
        ui.horizontal(|ui| {
            if ui
                .button("Claim (reveal secret above)")
                .on_hover_text("claims the HTLC with the Secret field, revealing it on-chain")
                .clicked()
            {
                do_claim = true;
            }
            if ui.button("Refund (after timeout)").clicked() {
                do_refund = true;
            }
        });
        if !sv.message.is_empty() {
            ui.label(egui::RichText::new(&sv.message).weak());
        }

        if do_lock {
            self.htlc_lock(ui.ctx(), signer.clone(), seed);
        }
        if do_lookup {
            self.htlc_lookup(ui.ctx());
        }
        if do_claim {
            self.htlc_claim(ui.ctx(), signer.clone(), seed);
        }
        if do_refund {
            self.htlc_refund(ui.ctx(), signer, seed);
        }
    }

    fn htlc_lock(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let recipient = self.htlc_recipient.trim().to_string();
        let secret = self.htlc_preimage.trim().to_string();
        let Some(grains) = parse_xus(&self.htlc_amount) else {
            return self.set_swap_msg("amount must be a number (e.g. 1.5)");
        };
        let Ok(timeout) = self.htlc_timeout.trim().parse::<u64>() else {
            return self.set_swap_msg("timeout height must be a whole number");
        };
        if secret.is_empty() {
            return self.set_swap_msg("enter a secret (preimage)");
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let recipient_id = match AccountId::new(&recipient) {
                Ok(id) => id,
                Err(e) => {
                    return set_swap_view_msg(&view, &ctx, &format!("invalid recipient: {e}"))
                }
            };
            let action = Action::HtlcLock {
                recipient: recipient_id,
                amount: Balance::from_grains(grains),
                hashlock: sha256_bytes(secret.as_bytes()),
                timeout_height: timeout,
            };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ HTLC opened — id = {id}"))
                .unwrap_or_else(|e| format!("✗ lock failed: {e}"));
            record(&activity, &msg);
            set_swap_view_msg(&view, &ctx, &msg);
        });
    }

    fn htlc_lookup(&self, ctx: &egui::Context) {
        let id = self.htlc_lookup_id.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let ctx = ctx.clone();
        if let Ok(mut v) = view.lock() {
            v.looking = true;
            v.id = id.clone();
        }
        std::thread::spawn(move || {
            let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(5));
            let res = client.call("sov_getHtlc", json!({ "hash": id }));
            if let Ok(mut v) = view.lock() {
                v.looking = false;
                v.id = id;
                match res {
                    Ok(val) if !val.is_null() => {
                        v.found = Some((
                            field(&val, "locker"),
                            field(&val, "recipient"),
                            field(&val, "amount"),
                            field(&val, "hashlock"),
                            val.get("timeoutHeight")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        ));
                        v.message = "HTLC found".to_string();
                    }
                    Ok(_) => {
                        v.found = None;
                        v.message =
                            "no such HTLC (never opened, or already claimed/refunded)".to_string();
                    }
                    Err(e) => {
                        v.found = None;
                        v.message = format!("lookup failed: {e}");
                    }
                }
            }
            ctx.request_repaint();
        });
    }

    fn htlc_claim(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let id_hex = self.htlc_lookup_id.trim().to_string();
        let secret = self.htlc_preimage.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let htlc_id = match Hash::from_hex(&id_hex) {
                Ok(h) => h,
                Err(_) => return set_swap_view_msg(&view, &ctx, "HTLC id must be 64 hex chars"),
            };
            let action = Action::HtlcClaim {
                htlc_id,
                preimage: secret.into_bytes(),
            };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ HTLC claimed (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ claim failed: {e}"));
            record(&activity, &msg);
            set_swap_view_msg(&view, &ctx, &msg);
        });
    }

    fn htlc_refund(&self, ctx: &egui::Context, signer: String, seed: [u8; 32]) {
        let id_hex = self.htlc_lookup_id.trim().to_string();
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let view = self.swaps_view.clone();
        let activity = self.activity.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let htlc_id = match Hash::from_hex(&id_hex) {
                Ok(h) => h,
                Err(_) => return set_swap_view_msg(&view, &ctx, "HTLC id must be 64 hex chars"),
            };
            let action = Action::HtlcRefund { htlc_id };
            let msg = submit_action(&rpc, seed, &signer, action)
                .map(|id| format!("✓ HTLC refunded (tx {})", &id[..id.len().min(14)]))
                .unwrap_or_else(|e| format!("✗ refund failed: {e}"));
            record(&activity, &msg);
            set_swap_view_msg(&view, &ctx, &msg);
        });
    }

    fn set_swap_msg(&self, msg: &str) {
        if let Ok(mut v) = self.swaps_view.lock() {
            v.message = msg.to_string();
        }
    }

    /// The Mining tab's "earned by your wallet" panel: cumulative coinbase your
    /// wallets have actually received, summed from the chain on demand.
    fn mining_earnings_section(&self, ui: &mut egui::Ui) {
        ui.heading("Your mining earnings");
        let ev = self.earnings.lock().map(|e| e.clone()).unwrap_or_default();
        if self.wallets.is_empty() {
            ui.label(egui::RichText::new("create or open a wallet to track earnings").weak());
            ui.separator();
            return;
        }
        egui::Frame::group(ui.style())
            .fill(palette::tint(palette::success(), 30))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("TOTAL EARNED").small().weak());
                    ui.label(
                        egui::RichText::new(format!("{} XUS", xus(&ev.total_grains.to_string())))
                            .strong()
                            .size(18.0)
                            .color(palette::success()),
                    );
                    if ev.scanned_height > 0 {
                        ui.label(
                            egui::RichText::new(format!("(to height {})", ev.scanned_height))
                                .weak(),
                        );
                    }
                });
                if !ev.rows.is_empty() {
                    egui::Grid::new("earnings")
                        .num_columns(4)
                        .striped(true)
                        .spacing([18.0, 4.0])
                        .show(ui, |ui| {
                            for h in ["Wallet", "Role", "Blocks", "Earned XUS"] {
                                ui.label(egui::RichText::new(h).weak());
                            }
                            ui.end_row();
                            for r in &ev.rows {
                                ui.label(format!("{}  ({})", r.label, short_id(&r.account)));
                                ui.monospace(&r.role);
                                ui.monospace(r.blocks.to_string());
                                ui.monospace(xus(&r.grains.to_string()));
                                ui.end_row();
                            }
                        });
                }
            });
        ui.horizontal(|ui| {
            if ev.computing {
                ui.spinner();
                ui.label("scanning the chain for your coinbase…");
            } else if ui
                .button("Compute earnings")
                .on_hover_text("scan every block's coinbase for payments to your wallets")
                .clicked()
            {
                self.compute_earnings(ui.ctx());
            }
            if !ev.message.is_empty() {
                ui.label(egui::RichText::new(&ev.message).weak());
            }
        });
        ui.separator();
    }

    /// Scan the chain's per-block coinbase for payments to any account this
    /// wallet controls (its implicit id and any named account it operates), on a
    /// worker thread. Real on-chain data — every grain is a coinbase the chain paid.
    fn compute_earnings(&self, ctx: &egui::Context) {
        // account id -> display label, for every account the user controls.
        let mut accounts: HashMap<String, String> = HashMap::new();
        for w in &self.wallets {
            accounts.insert(w.account.clone(), w.label.clone());
            if let Some(named) = &w.operate_as {
                accounts.insert(named.clone(), w.label.clone());
            }
        }
        let rpc = self
            .config
            .lock()
            .map(|c| c.rpc.clone())
            .unwrap_or_default();
        let earnings = self.earnings.clone();
        let ctx = ctx.clone();
        if let Ok(mut e) = earnings.lock() {
            e.computing = true;
            e.message = "scanning…".to_string();
        }
        ctx.request_repaint();
        std::thread::spawn(move || {
            let result = scan_earnings(&rpc, &accounts);
            if let Ok(mut e) = earnings.lock() {
                e.computing = false;
                match result {
                    Ok((total, tip, rows)) => {
                        e.total_grains = total;
                        e.scanned_height = tip;
                        e.rows = rows;
                        e.message = format!("scanned {tip} blocks");
                    }
                    Err(err) => e.message = format!("scan failed: {err}"),
                }
            }
            ctx.request_repaint();
        });
    }

    /// The hero balance card — the first thing the Wallet tab shows: the selected
    /// wallet's spendable balance in large type, its label + account, the network
    /// badge, and live miner / watch-only / shielded-pool context. The at-a-glance
    /// "how much do I have, and where" that a bank app leads with.
    fn balance_card(&self, ui: &mut egui::Ui, s: &Snapshot) {
        let Some(w) = self.wallets.get(self.selected) else {
            return;
        };
        let label = w.label.clone();
        let effective = w.effective_account();
        let watch_only = w.watch_only;
        let account = w.account.clone();
        let bal = s
            .accounts
            .iter()
            .find(|a| a.account == effective)
            .map(|a| xus(&a.balance))
            .unwrap_or_else(|| "—".to_string());
        let named = is_named_account(&effective);
        let is_miner = self.mining_account.as_deref() == Some(account.as_str());
        // Shielded (private) balance for this wallet, if it has been scanned.
        let shielded = self
            .shielded
            .lock()
            .ok()
            .filter(|v| v.account == effective && v.balance > 0)
            .map(|v| grains_to_xus_plain(u128::from(v.balance)));

        egui::Frame::group(ui.style())
            .fill(palette::panel())
            .stroke(egui::Stroke::new(1.0, palette::border()))
            .rounding(egui::Rounding::same(10.0))
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("ACTIVE WALLET")
                            .small()
                            .color(palette::text_dim()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        network_badge(ui, self.network);
                        if is_miner {
                            ui.label(
                                egui::RichText::new("⛏ mining")
                                    .small()
                                    .color(palette::success()),
                            );
                        }
                        if watch_only {
                            ui.label(
                                egui::RichText::new("👁 watch-only")
                                    .small()
                                    .color(palette::text_dim()),
                            );
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&bal)
                            .size(34.0)
                            .strong()
                            .color(palette::text()),
                    );
                    ui.label(
                        egui::RichText::new("XUS")
                            .size(15.0)
                            .color(palette::text_dim()),
                    );
                    if let Some(sh) = &shielded {
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new(format!("🛡 {sh} private"))
                                .color(palette::accent_hi()),
                        );
                    }
                });
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&label).strong().color(palette::link()));
                    ui.label(egui::RichText::new("·").color(palette::text_dim()));
                    ui.label(
                        egui::RichText::new(short_id(&effective))
                            .monospace()
                            .color(palette::text_dim()),
                    );
                    if named {
                        ui.label(
                            egui::RichText::new("✓ named")
                                .small()
                                .color(palette::success()),
                        );
                    }
                });
                // In-flight transactions: anything in the node's mempool is waiting to be
                // mined into the next block. The big number above is the CONFIRMED on-chain
                // balance, so a just-sent tx shows here as pending until that block lands
                // (the funds aren't "still in your wallet" — they're committed to the
                // pending tx, which confirms in ~one block).
                if let Some(n) = s.mempool.filter(|n| *n > 0) {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "⏳ {n} transaction(s) in the mempool — confirming in the next block"
                        ))
                        .small()
                        .color(palette::warning()),
                    );
                }
            });
        ui.add_space(10.0);
    }

    /// The dedicated Activity tab — the full session history of submitted actions,
    /// newest first, each line timestamped and colored by outcome (green succeeded /
    /// red failed). The same feed the wallet shows, given room to breathe.
    fn activity_panel(&self, ui: &mut egui::Ui) {
        ui.heading("Activity");
        ui.label(
            egui::RichText::new(
                "Every action you've submitted this session — newest first. Green where it \
                 succeeded, red where it failed.",
            )
            .weak()
            .small(),
        );
        ui.add_space(8.0);
        let log = self.activity.lock().map(|l| l.clone()).unwrap_or_default();
        if log.is_empty() {
            empty_state(
                ui,
                "◷",
                "No activity yet",
                "Send, shield, register a name, or open a swap — it shows up here.",
            );
            return;
        }
        if ui.button("Clear").clicked() {
            if let Ok(mut l) = self.activity.lock() {
                l.clear();
            }
        }
        ui.add_space(6.0);
        card(ui, |ui| {
            for line in &log {
                let (time, body) = line.split_once('\t').unwrap_or(("", line.as_str()));
                let col = status_color(tx_status(body));
                ui.horizontal_wrapped(|ui| {
                    if !time.is_empty() {
                        ui.label(
                            egui::RichText::new(time)
                                .monospace()
                                .size(11.0)
                                .color(palette::text_dim()),
                        );
                    }
                    ui.label(egui::RichText::new(body).monospace().size(12.0).color(col));
                });
            }
        });
    }

    /// A compact onboarding checklist — the create-wallet → start-node → mine → send
    /// journey — shown atop the Wallet tab until the user is up and running, so a
    /// first-time user always knows the next step. Auto-hides once fully set up.
    fn first_run_checklist(&self, ui: &mut egui::Ui, s: &Snapshot) {
        let has_wallet = !self.wallets.is_empty();
        let node_running = matches!(&*self.node_run.lock().unwrap(), NodeRun::Running(_));
        let acct = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account());
        let row = acct
            .as_ref()
            .and_then(|a| s.accounts.iter().find(|r| &r.account == a));
        let has_funds = row
            .and_then(|a| a.balance.parse::<u128>().ok())
            .map(|b| b > 0)
            .unwrap_or(false);
        let has_sent = row
            .and_then(|a| a.nonce.parse::<u64>().ok())
            .map(|n| n > 0)
            .unwrap_or(false);
        // Fully set up — the checklist has served its purpose, so get out of the way.
        if has_wallet && node_running && has_funds && has_sent {
            return;
        }
        fn step(ui: &mut egui::Ui, done: bool, current: bool, text: &str) {
            ui.horizontal(|ui| {
                let (glyph, col) = if done {
                    ("✓", palette::success())
                } else if current {
                    ("▸", palette::accent_hi())
                } else {
                    ("○", palette::text_dim())
                };
                ui.label(egui::RichText::new(glyph).color(col).strong());
                let t = egui::RichText::new(text);
                ui.label(if done {
                    t.color(palette::text_dim()).strikethrough()
                } else if current {
                    t.strong()
                } else {
                    t.color(palette::text_dim())
                });
            });
        }
        card(ui, |ui| {
            ui.label(
                egui::RichText::new("GET STARTED")
                    .small()
                    .color(palette::text_dim()),
            );
            ui.add_space(4.0);
            // "current" highlights the first not-yet-done step.
            step(ui, has_wallet, !has_wallet, "Create or restore a wallet");
            step(
                ui,
                node_running,
                has_wallet && !node_running,
                "Start the local node (it mines to your wallet)",
            );
            step(
                ui,
                has_funds,
                node_running && !has_funds,
                "Mine your first block (wait for a coinbase)",
            );
            step(
                ui,
                has_sent,
                has_funds && !has_sent,
                "Send your first transaction",
            );
        });
        ui.add_space(8.0);
    }

    fn wallet_panel(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let ctx = ui.ctx().clone();
        ui.heading("Wallet");
        self.first_run_checklist(ui, s);

        // ── STATE 1 — Onboarding ──
        // Like every real wallet, you must create or restore a recovery phrase
        // before ANY other action. Nothing else in the wallet (and no node mining)
        // is reachable until a wallet exists.
        if self.wallets.is_empty() {
            ui.label(
                egui::RichText::new(
                    "Create or restore a wallet to begin. A recovery phrase is required before any \
                     action — and the local node mines to the wallet you select. Your on-chain \
                     account id is derived from your key (not the label), so it can never collide \
                     with — or inherit the funds of — another account.",
                )
                .weak(),
            );
            ui.add_space(10.0);
            let mut do_generate = false;
            let mut do_import = false;
            let mut do_load = false;
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Create a new wallet").strong());
                ui.horizontal(|ui| {
                    ui.label("Label (display only)");
                    ui.add(egui::TextEdit::singleline(&mut self.gen_name).desired_width(220.0));
                    if ui.button("Generate recovery phrase").clicked() {
                        do_generate = true;
                    }
                });
            });
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Restore from a recovery phrase").strong());
                ui.horizontal(|ui| {
                    ui.label("Label (display only)");
                    ui.add(egui::TextEdit::singleline(&mut self.import_name).desired_width(220.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Mnemonic    ");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.import_mnemonic).desired_width(420.0),
                    );
                    if ui.button("Restore").clicked() {
                        do_import = true;
                    }
                });
            });
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Open an encrypted keystore").strong());
                ui.horizontal(|ui| {
                    ui.label("Passphrase");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.keystore_pass)
                            .password(true)
                            .desired_width(200.0),
                    );
                    if ui.button("Unlock").clicked() {
                        do_load = true;
                    }
                });
            });
            let err = self
                .action
                .lock()
                .map(|a| a.message.clone())
                .unwrap_or_default();
            if !err.is_empty() {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(err).weak());
            }
            if !self.keystore_msg.is_empty() {
                ui.add_space(4.0);
                status_label(ui, &self.keystore_msg);
            }
            if do_generate {
                self.generate_wallet();
            }
            if do_import {
                self.import_wallet();
            }
            if do_load {
                self.load_wallets();
            }
            return;
        }

        // ── STATE 2 — Backup gate ──
        // A freshly generated phrase must be acknowledged (written down) before
        // the wallet can be used.
        if let Some((acct, mnem)) = self.backup_mnemonic.clone() {
            let mut acked = false;
            // The just-generated wallet's public key, for binding a named genesis
            // account (e.g. a tax account) to it. Public — safe to copy/share.
            let pubkey = self
                .wallets
                .iter()
                .find(|w| w.account == acct)
                .map(|w| w.public_key.clone())
                .unwrap_or_default();
            egui::Frame::group(ui.style())
                .fill(palette::tint(palette::warning(), 30))
                .show(ui, |ui| {
                    ui.colored_label(
                        palette::warning(),
                        "⚠ Write this recovery phrase down now — offline, in order. It is the ONLY \
                         way to restore this wallet, is shown once, and must never be shared.",
                    );
                    ui.label(egui::RichText::new(format!("account: {acct}")).monospace());
                    ui.label(egui::RichText::new(&mnem).monospace());
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(
                        egui::RichText::new(
                            "Public key (safe to share — hand this over to bind a named genesis \
                             account such as a tax account):",
                        )
                        .weak(),
                    );
                    ui.label(egui::RichText::new(short_pubkey(&pubkey)).monospace());
                    if ui.button("Copy public key").clicked() {
                        ui.output_mut(|o| o.copied_text = pubkey.clone());
                    }
                    ui.add_space(6.0);
                    if ui.button("I have written it down — continue").clicked() {
                        acked = true;
                    }
                });
            if acked {
                if let Some((_, phrase)) = self.backup_mnemonic.as_mut() {
                    phrase.zeroize(); // scrub before the Option drops the String
                }
                self.backup_mnemonic = None;
            }
            return;
        }

        // ── STATE 3 — Full wallet (a wallet exists and its phrase is backed up) ──
        let mut do_generate = false;
        let mut do_import = false;
        let mut do_add_watch = false;
        let mut select: Option<usize> = None;
        let mut do_rename = false;
        let mut do_forget = false;
        let mut do_save = false;

        // ── Auto-attach: if a wallet's key controls a watched NAMED account (e.g.
        // a genesis-bound tax account), operate as it automatically so its balance
        // shows — no manual "attach" step. Pure key match against polled data; the
        // chain already proved the binding. ──
        for w in self.wallets.iter_mut() {
            if w.operate_as.is_some() || w.public_key.is_empty() {
                continue;
            }
            if let Some(named) = s
                .accounts
                .iter()
                .find(|a| is_named_account(&a.account) && a.key == w.public_key)
            {
                w.operate_as = Some(named.account.clone());
            }
        }

        // The hero balance card — prominent spendable balance + network badge, up top.
        self.balance_card(ui, s);

        // ── Unsaved-wallets banner — nudge to persist before they can be lost ──
        if self.wallets_dirty && !self.wallets.is_empty() {
            egui::Frame::group(ui.style())
                .fill(palette::tint(palette::warning(), 30))
                .stroke(egui::Stroke::new(1.0, palette::warning()))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "⚠ {} wallet(s) not saved to disk — back them up so they survive a \
                                 restart.",
                                self.wallets.len()
                            ))
                            .color(palette::warning()),
                        );
                        if self.keystore_pass.is_empty() {
                            ui.label(
                                egui::RichText::new(
                                    "enter a backup passphrase in “Wallet file” below, then Save",
                                )
                                .small()
                                .weak(),
                            );
                        } else if ui.button("Save now").clicked() {
                            do_save = true;
                        }
                    });
                });
            ui.add_space(4.0);
        }

        // ── Add / import a wallet (at the top — the first thing you reach for) ──
        ui.collapsing("➕ Add or import a wallet", |ui| {
            let enter = |r: &egui::Response, ui: &egui::Ui| {
                r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            };
            ui.horizontal(|ui| {
                ui.label("New wallet label");
                let r = ui.add(egui::TextEdit::singleline(&mut self.gen_name).desired_width(200.0));
                if ui.button("Generate").clicked() || enter(&r, ui) {
                    do_generate = true;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Import label");
                ui.add(egui::TextEdit::singleline(&mut self.import_name).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                ui.label("mnemonic");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.import_mnemonic).desired_width(420.0),
                );
                if ui.button("Import").clicked() || enter(&r, ui) {
                    do_import = true;
                }
            });
            ui.separator();
            ui.label(
                egui::RichText::new(
                    "👁 Watch-only: monitor an account from its public key — no private key here, \
                     so it can't sign. Spend it via the offline-signing tools (build unsigned here \
                     → sign on the machine with the seed → broadcast).",
                )
                .weak()
                .small(),
            );
            ui.horizontal(|ui| {
                ui.label("Watch label");
                ui.add(egui::TextEdit::singleline(&mut self.watch_label).desired_width(150.0));
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.watch_pubkey)
                        .hint_text("public key — hybrid65:0x…")
                        .desired_width(320.0),
                );
                if ui.button("Add watch-only").clicked() || enter(&r, ui) {
                    do_add_watch = true;
                }
            });
        });
        ui.add_space(4.0);
        ui.separator();

        // ── Active-wallet banner: the unmistakable "who am I acting as" strip ──
        let balance_of = |acct: &str| {
            s.accounts
                .iter()
                .find(|a| a.account == acct)
                .map(|a| xus(&a.balance))
                .unwrap_or_else(|| "—".to_string())
        };
        if let Some(w) = self.wallets.get(self.selected) {
            let label = w.label.clone();
            let account = w.account.clone();
            let effective = w.effective_account();
            let is_miner = self.mining_account.as_deref() == Some(account.as_str());
            // Name state, shown CONSISTENTLY for both kinds of name: a wallet
            // operating AS a named account (e.g. name.reserve.sov) and a wallet
            // with an SNS alias resolving to it (e.g. claude.sov) are BOTH "named".
            // SNS names are trusted only when the cache is for THIS account (avoids
            // a one-frame flash of the previous wallet's names after switching).
            let operating_named = is_named_account(&effective);
            let sns_names: Vec<String> = self
                .names_by_account
                .lock()
                .ok()
                .and_then(|m| m.get(&effective).cloned())
                .unwrap_or_default();
            let has_sns = !sns_names.is_empty();
            let named = operating_named || has_sns;
            // A green border for a named wallet (operate-as OR SNS), amber for an
            // unnamed (implicit) one — the name-state is unmistakable at a glance.
            egui::Frame::group(ui.style())
                .fill(palette::tint(palette::link(), 30))
                .stroke(egui::Stroke::new(1.5, named_color(named)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("ACTIVE WALLET").small().weak());
                        ui.label(
                            egui::RichText::new(&label)
                                .strong()
                                .size(16.0)
                                .color(palette::link()),
                        );
                        ui.label(egui::RichText::new(short_id(&account)).monospace().weak());
                        if is_miner {
                            ui.label(
                                egui::RichText::new("⛏ mining")
                                    .small()
                                    .color(palette::success()),
                            );
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(format!("{} XUS", balance_of(&effective)))
                                    .strong(),
                            );
                        });
                    });
                    // Name-state line — consistent for both kinds of name.
                    if w.watch_only {
                        ui.label(
                            egui::RichText::new(
                                "👁 WATCH-ONLY  ·  no private key here — monitor only",
                            )
                            .strong()
                            .color(palette::link()),
                        );
                    } else if operating_named {
                        ui.label(
                            egui::RichText::new(format!("✓ NAMED ACCOUNT  ·  {effective}"))
                                .strong()
                                .color(named_color(true)),
                        );
                    } else if has_sns {
                        ui.label(
                            egui::RichText::new(format!("✓ SNS  ·  {}", sns_names.join(", ")))
                                .strong()
                                .color(named_color(true)),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new(
                                "○ UNNAMED  ·  implicit address only — register an SNS name below \
                                 for a human-readable account",
                            )
                            .color(named_color(false)),
                        );
                    }
                    // Rename + remove the active wallet. Remove opens a deliberate
                    // type-to-confirm modal (handled below) — no one-click delete.
                    ui.horizontal(|ui| {
                        ui.label("Label");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rename_field)
                                .desired_width(180.0)
                                .hint_text(&label),
                        );
                        if ui.button("Rename").clicked() {
                            do_rename = true;
                        }
                        ui.separator();
                        if ui.button("🗑 Remove wallet").clicked() {
                            self.forget_armed = true;
                            self.forget_confirm.clear();
                        }
                    });
                });
        }

        // ── Remove-wallet confirmation modal: type the label to enable removal,
        // so a wallet can never be deleted by an accidental click. ──
        if self.forget_armed {
            let target_label = self
                .wallets
                .get(self.selected)
                .map(|w| w.label.clone())
                .unwrap_or_default();
            let ctx = ui.ctx().clone();
            let matches = self.forget_confirm.trim() == target_label && !target_label.is_empty();
            egui::Window::new("Remove wallet")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.colored_label(
                        palette::warning(),
                        "⚠ This removes the wallet from the app. It can ONLY be restored from its \
                         recovery phrase (or a saved backup). Export the phrase first if you need it.",
                    );
                    ui.add_space(6.0);
                    ui.label(format!("To confirm, type the wallet's label:  {target_label}"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.forget_confirm)
                            .hint_text(&target_label)
                            .desired_width(220.0),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(matches, |ui| {
                            if ui
                                .button(
                                    egui::RichText::new("Remove permanently")
                                        .color(palette::error()),
                                )
                                .clicked()
                            {
                                do_forget = true;
                                self.forget_armed = false;
                                self.forget_confirm.clear();
                            }
                        });
                        if ui.button("Cancel").clicked() {
                            self.forget_armed = false;
                            self.forget_confirm.clear();
                        }
                    });
                    if !matches && !self.forget_confirm.is_empty() {
                        ui.label(
                            egui::RichText::new("label doesn't match")
                                .small()
                                .color(palette::error()),
                        );
                    }
                });
        }

        // ── Wallet switcher: every wallet, one click to make active. Each row is
        // tagged NAMED (green) or unnamed (amber) so the distinction is obvious.
        ui.add_space(6.0);
        ui.label(egui::RichText::new("Switch wallet").strong());
        // Snapshot the per-account SNS name cache once, so each row's badge reflects
        // its registered name (not just an operate-as named account).
        let names_map: HashMap<String, Vec<String>> = self
            .names_by_account
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        for (i, w) in self.wallets.iter().enumerate() {
            let active = i == self.selected;
            let marker = if active { "● " } else { "○ " };
            let is_miner = self.mining_account.as_deref() == Some(w.account.as_str());
            let effective = w.effective_account();
            let operating_named = is_named_account(&effective);
            let sns = names_map.get(&effective).cloned().unwrap_or_default();
            let named = operating_named || !sns.is_empty();
            ui.horizontal(|ui| {
                // Show the balance of the account this wallet OPERATES (its named
                // account when attached, else its own implicit id) — so a tax
                // wallet shows its real balance, not its empty implicit address.
                let text = format!(
                    "{marker}{}   {}   {} XUS",
                    w.label,
                    short_id(&w.account),
                    balance_of(&effective)
                );
                let rich = if active {
                    egui::RichText::new(text).strong()
                } else {
                    egui::RichText::new(text)
                };
                if ui.selectable_label(active, rich).clicked() {
                    select = Some(i);
                }
                // Name-state badge — operate-as named account, else SNS name(s),
                // else unnamed. Hooked to the same SNS cache as the header.
                let badge = if operating_named {
                    egui::RichText::new(format!("named · {effective}")).small()
                } else if !sns.is_empty() {
                    egui::RichText::new(format!("SNS · {}", sns.join(", "))).small()
                } else {
                    egui::RichText::new("unnamed").small()
                };
                ui.label(badge.color(named_color(named)));
                if is_miner {
                    ui.label(egui::RichText::new("⛏").small().color(palette::success()));
                }
            });
        }

        // Selected wallet detail + actions (decoupled from the borrow via a clone).
        let sel = self.wallets.get(self.selected).map(|w| {
            (
                w.label.clone(),
                w.account.clone(),
                w.public_key.clone(),
                w.shielded.clone(),
                w.unified.clone(),
                w.operate_as.clone(),
                w.mnemonic.clone(),
                w.watch_only,
            )
        });
        let mut do_set_operate = false;
        let mut do_clear_operate = false;
        let mut do_register_named = false;
        let mut new_pending: Option<PendingSend> = None;
        let mut did_copy = false;
        let mut do_send = false;
        let mut do_private_send = false;
        let mut do_scan = false;
        let mut do_deshield = false;
        let mut do_build_unsigned = false;
        let mut do_sign_offline = false;
        let mut do_broadcast = false;
        if let Some((
            label,
            account,
            public_key,
            shielded,
            unified,
            operate_as,
            mnemonic,
            w_watch_only,
        )) = sel
        {
            // The account the wallet is acting as: a linked named account, or its
            // own implicit id. Balances/nonce/actions follow this.
            let effective = operate_as.clone().unwrap_or_else(|| account.clone());
            let onchain = s.accounts.iter().find(|a| a.account == effective);
            ui.add_space(6.0);
            egui::Grid::new("wdetail")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    kv(ui, "Label", &label);
                    kv(ui, "Your account", &account);
                    kv(ui, "Public key", &short_pubkey(&public_key));
                    if let Some(named) = &operate_as {
                        kv(ui, "▶ Operating as", named);
                    }
                    kv(
                        ui,
                        "Balance",
                        &format!(
                            "{} XUS",
                            onchain
                                .map(|a| xus(&a.balance))
                                .unwrap_or_else(|| "—".into())
                        ),
                    );
                    kv(
                        ui,
                        "On-chain",
                        onchain
                            .map(|a| a.key_state.as_str())
                            .unwrap_or("not yet on-chain"),
                    );
                    kv(
                        ui,
                        "Nonce",
                        onchain.map(|a| a.nonce.as_str()).unwrap_or("—"),
                    );
                    kv(ui, "Shielded", &shielded);
                    kv(ui, "Unified", &unified);
                });
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("copy:").weak());
                if ui.button("account").clicked() {
                    ui.output_mut(|o| o.copied_text = account.clone());
                    did_copy = true;
                }
                if ui.button("public key").clicked() {
                    ui.output_mut(|o| o.copied_text = public_key.clone());
                    did_copy = true;
                }
                if ui.button("shielded addr").clicked() {
                    ui.output_mut(|o| o.copied_text = shielded.clone());
                    did_copy = true;
                }
                if ui.button("unified addr").clicked() {
                    ui.output_mut(|o| o.copied_text = unified.clone());
                    did_copy = true;
                }
            });
            ui.label(
                egui::RichText::new(
                    "“public key” is the hybrid65:0x… line to hand over for binding a named \
                     genesis account (e.g. a tax account). Safe to share; never share the phrase.",
                )
                .weak(),
            );

            // Export / reveal the recovery phrase — re-displayable any time (not
            // just at generation), so the wallet can be backed up or moved.
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Recovery phrase").strong());
                match &mnemonic {
                    Some(_) if !self.reveal_phrase => {
                        if ui.button("Reveal / export").clicked() {
                            self.reveal_phrase = true;
                        }
                    }
                    Some(phrase) => {
                        if ui.button("Hide").clicked() {
                            self.reveal_phrase = false;
                        }
                        if ui.button("Copy phrase").clicked() {
                            ui.output_mut(|o| o.copied_text = phrase.clone());
                            did_copy = true;
                        }
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                "not available (restored from a raw seed) — save the keystore to \
                                 keep it",
                            )
                            .weak(),
                        );
                    }
                }
            });
            if self.reveal_phrase {
                if let Some(phrase) = &mnemonic {
                    egui::Frame::group(ui.style())
                        .fill(palette::tint(palette::warning(), 30))
                        .show(ui, |ui| {
                            ui.colored_label(
                                palette::warning(),
                                "⚠ Anyone who sees these 24 words owns this wallet. Write them \
                                 down offline; never paste them online.",
                            );
                            ui.label(egui::RichText::new(phrase).monospace());
                        });
                }
            }

            // ── Name (ENS/SNS-style) ──────────────────────────────────────
            // Register a *.sov name that RESOLVES to this wallet's account. The
            // name is a pure alias — funds never leave the account.
            let typed_name = self.name_field.trim().to_string();
            let (name_ok, name_msg, name_busy) = self
                .name_check
                .lock()
                .ok()
                .map(|c| {
                    if c.name == typed_name {
                        (c.ok, c.message.clone(), c.checking)
                    } else {
                        (false, String::new(), !typed_name.is_empty())
                    }
                })
                .unwrap_or((false, String::new(), false));
            let my_names_list: Vec<String> = self
                .names_by_account
                .lock()
                .ok()
                .and_then(|m| m.get(&effective).cloned())
                .unwrap_or_default();
            ui.add_space(8.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.label(egui::RichText::new("Sovereign Name Service (SNS)").strong());
                ui.label(
                    egui::RichText::new(
                        "Your address is a key fingerprint. Register a “.sov” name so people can \
                         pay you by name — it resolves to THIS account and your funds never move. \
                         First-come; a one-time fee (earned by miners) applies.",
                    )
                    .weak(),
                );
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.name_field)
                            .hint_text("alice.sov")
                            .desired_width(220.0),
                    );
                    let busy = self.action.lock().map(|a| a.busy).unwrap_or(false);
                    // The validation gate: enabled only once the name is well-
                    // formed AND confirmed available on-chain (so it WILL resolve).
                    let can = name_ok && !busy && !typed_name.is_empty();
                    if ui
                        .add_enabled(can, egui::Button::new("Register on-chain"))
                        .on_hover_text(
                            "Bind this .sov name as an alias to your account. Enabled only once \
                             the name is valid and available on the network.",
                        )
                        .clicked()
                    {
                        do_register_named = true;
                    }
                });
                // Live status: empty / checking / available / invalid / taken.
                if typed_name.is_empty() {
                    ui.label(egui::RichText::new("enter a name like alice.sov").weak());
                } else if name_busy {
                    ui.label(egui::RichText::new("checking the network…").weak());
                } else if !name_msg.is_empty() {
                    let col = if name_ok {
                        palette::success()
                    } else {
                        palette::error()
                    };
                    ui.colored_label(col, &name_msg);
                }
                if !my_names_list.is_empty() {
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(format!("Your names: {}", my_names_list.join(", ")))
                            .color(named_color(true)),
                    );
                }
                if !self.operate_msg.is_empty() {
                    status_label(ui, &self.operate_msg);
                }
            });

            // ── Operate a named account you control (advanced) ─────────────
            // The genesis/tax-account path: act AS a named account this key
            // already controls. This is NOT name registration.
            ui.add_space(6.0);
            egui::CollapsingHeader::new("Operate a named account (advanced)")
                .default_open(operate_as.is_some())
                .show(ui, |ui| {
                    if let Some(named) = &operate_as {
                        ui.label(
                            egui::RichText::new(format!(
                                "✓ acting AS “{named}” — Send / Receive below use it, signed by \
                                 this wallet's key."
                            ))
                            .color(named_color(true)),
                        );
                        if ui
                            .button("Back to my key's own address")
                            .on_hover_text("Stop acting as the named account; use this wallet's implicit address.")
                            .clicked()
                        {
                            do_clear_operate = true;
                        }
                    } else {
                        ui.label(
                            egui::RichText::new(
                                "Attach a named account this key already controls (e.g. a \
                                 genesis-bound tax/reserve account) and act as it — no transaction. \
                                 For a human-readable alias, use “Name” above instead.",
                            )
                            .weak(),
                        );
                        ui.horizontal(|ui| {
                            ui.label("Account");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.operate_as_field)
                                    .hint_text("name.reserve.sov")
                                    .desired_width(220.0),
                            );
                            if ui.button("Attach").clicked() {
                                do_set_operate = true;
                            }
                        });
                    }
                });

            // ── Receive ──
            ui.separator();
            ui.label(egui::RichText::new("Receive").strong());
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.receive_kind,
                    ReceiveKind::Shielded,
                    "Shielded (private)",
                );
                ui.selectable_value(&mut self.receive_kind, ReceiveKind::Unified, "Unified");
                ui.selectable_value(&mut self.receive_kind, ReceiveKind::Account, "Account");
            });
            let recv_addr = match self.receive_kind {
                ReceiveKind::Shielded => shielded.clone(),
                ReceiveKind::Unified => unified.clone(),
                ReceiveKind::Account => account.clone(),
            };
            ui.horizontal(|ui| {
                qr_widget(ui, &recv_addr, 132.0);
                ui.vertical(|ui| {
                    if self.receive_kind == ReceiveKind::Shielded {
                        ui.label(
                            egui::RichText::new("private — recommended receive address")
                                .small()
                                .color(named_color(true)),
                        );
                    }
                    ui.add(
                        egui::Label::new(egui::RichText::new(&recv_addr).monospace().size(11.0))
                            .wrap(),
                    );
                    if ui.button("Copy address").clicked() {
                        ui.output_mut(|o| o.copied_text = recv_addr.clone());
                        did_copy = true;
                    }
                });
            });

            // ── Send ──
            ui.separator();
            ui.label(egui::RichText::new("Send").strong());
            // Spendable balance of the account we're sending FROM (the effective).
            let spendable: u128 = onchain.map(|a| a.balance.parse().unwrap_or(0)).unwrap_or(0);
            ui.horizontal(|ui| {
                ui.label("To");
                ui.add(egui::TextEdit::singleline(&mut self.send_to).desired_width(420.0));
                if ui.button("Shield to my pool").clicked() {
                    self.send_to = shielded.clone();
                    self.receive_kind = ReceiveKind::Shielded;
                }
            });
            // Live route detection + self-send labelling.
            let route = SendRoute::detect(&self.send_to);
            let to_trim = self.send_to.trim();
            let self_send = !to_trim.is_empty()
                && (to_trim == shielded
                    || to_trim == unified
                    || to_trim == account
                    || to_trim == effective);
            let (route_text, route_color) = route.label();
            if !route_text.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(route_text).small().color(route_color));
                    if self_send {
                        ui.label(
                            egui::RichText::new("· your own address")
                                .small()
                                .color(named_color(true)),
                        );
                    }
                });
            } else {
                ui.label(
                    egui::RichText::new("named account → transparent · xus1…/uxus1… → shielded")
                        .weak(),
                );
            }
            // Amount + Max + live validation. The network fee is RESERVED: a send must
            // leave room for it (amount + fee ≤ balance), or the tx would fail execution
            // ("cannot afford fee") and clog the mempool while blocks come up empty.
            let fee = if route.private() {
                s.fee_shielded_grains
            } else {
                s.fee_transfer_grains
            };
            // The most you can send while still covering the fee.
            let sendable = spendable.saturating_sub(fee);
            let amount_grains = parse_xus(&self.send_amount);
            let amount_resp = ui
                .horizontal(|ui| {
                    ui.label("Amount XUS");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.send_amount).desired_width(160.0),
                    );
                    if ui
                        .button("Max")
                        .on_hover_text("send the most that still leaves room for the network fee")
                        .clicked()
                    {
                        self.send_amount = grains_to_xus_plain(sendable);
                    }
                    let note = if fee > 0 {
                        format!(
                            "balance {} XUS · fee ~{} XUS",
                            xus(&spendable.to_string()),
                            xus(&fee.to_string())
                        )
                    } else {
                        format!("balance {} XUS", xus(&spendable.to_string()))
                    };
                    ui.label(egui::RichText::new(note).weak());
                    r
                })
                .inner;
            let amount_err: Option<String> = match amount_grains {
                None if !self.send_amount.trim().is_empty() => {
                    Some("amount must be a number (e.g. 1.5)".to_string())
                }
                Some(0) => Some("amount must be greater than zero".to_string()),
                Some(g) if g > spendable => Some("amount exceeds your balance".to_string()),
                Some(g) if g > sendable => Some(format!(
                    "amount + network fee (~{} XUS) exceeds your balance — lower it or use Max",
                    xus(&fee.to_string())
                )),
                _ => None,
            };
            if let Some(e) = &amount_err {
                ui.label(
                    egui::RichText::new(format!("✗ {e}"))
                        .small()
                        .color(palette::error()),
                );
            }
            let busy = self.action.lock().map(|a| a.busy).unwrap_or(false);
            let can_send = route.is_valid()
                && matches!(amount_grains, Some(g) if g > 0 && g <= sendable)
                && !busy;
            // Pressing Enter in the amount field reviews the send (same as the button).
            let submit_enter =
                amount_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let mut review_clicked = false;
            ui.add_enabled_ui(can_send, |ui| {
                if ui.button("Review send →").clicked() {
                    review_clicked = true;
                }
            });
            if (review_clicked || submit_enter) && can_send {
                if let Some(g) = amount_grains {
                    new_pending = Some(PendingSend {
                        from_label: label.clone(),
                        from_account: effective.clone(),
                        to: to_trim.to_string(),
                        amount_grains: g,
                        from_balance_grains: spendable,
                        route_label: route.label().0,
                        self_send,
                        // Any transparent route puts sender, recipient, and amount
                        // on-chain in the clear — the privacy downgrade.
                        links_public: !route.private(),
                        from_pool: false,
                    });
                }
            }
            if busy {
                ui.label(egui::RichText::new("working…").weak());
            }

            // Shielded pool: private balance (scanned by trial-decryption) + de-shield.
            ui.separator();
            ui.label(egui::RichText::new("Shielded pool (private)").strong());
            let sv = self.shielded.lock().map(|v| v.clone()).unwrap_or_default();
            let for_this = sv.account == account;
            ui.horizontal(|ui| {
                if sv.scanning {
                    ui.spinner();
                    ui.label("scanning the pool…");
                } else if for_this && sv.scanned_height > 0 {
                    ui.label(format!(
                        "{} XUS  ({} unspent note(s), scanned to height {})",
                        xus(&sv.balance.to_string()),
                        sv.notes,
                        sv.scanned_height
                    ));
                } else {
                    ui.label(egui::RichText::new("not scanned yet").weak());
                }
            });
            // De-shield a VARIABLE amount: move `amount` from the pool to this
            // account's transparent balance; any remainder stays shielded as change.
            // The amount is bounded by the wallet's shielded balance AND the node's
            // live per-window drain budget, both shown so the limit is never a
            // surprise (the de-shield circuit breaker is visible, not silent).
            let snap = self.snapshot.lock().map(|s| s.clone()).unwrap_or_default();
            let budget_now = snap.deshieldable_now;
            // The de-shieldable ceiling: the smaller of the scanned shielded balance
            // and the current window budget (a de-shield over budget would be mined
            // and rejected, so we never offer more than can actually go through now).
            let deshield_cap: u128 = match budget_now {
                Some(b) => (sv.balance as u128).min(b),
                None => sv.balance as u128,
            };
            let ds_grains = parse_xus(&self.deshield_amount);
            ui.horizontal(|ui| {
                if ui.button("Scan pool").clicked() {
                    do_scan = true;
                }
                ui.label("De-shield XUS");
                ui.add(
                    egui::TextEdit::singleline(&mut self.deshield_amount)
                        .hint_text("amount")
                        .desired_width(140.0),
                );
                ui.add_enabled_ui(deshield_cap > 0, |ui| {
                    if ui
                        .button("Max")
                        .on_hover_text("de-shield the most allowed right now (balance, capped by the window budget)")
                        .clicked()
                    {
                        self.deshield_amount = grains_to_xus_plain(deshield_cap);
                    }
                });
                let ds_ok = for_this
                    && sv.notes > 0
                    && !sv.scanning
                    && !busy
                    && matches!(ds_grains, Some(g) if g > 0 && g <= deshield_cap);
                ui.add_enabled_ui(ds_ok, |ui| {
                    if ui.button("De-shield").clicked() {
                        do_deshield = true;
                    }
                });
            });
            // Show the live budget so the per-window drain limit is transparent — and,
            // when the window cap (not the balance) is the binding constraint, say so
            // LOUDLY with when it resets, so a limited/0 Max never reads as a broken
            // wallet (this is the de-shield circuit breaker, working as designed).
            if for_this {
                match budget_now {
                    Some(b) => {
                        // Reset as a time estimate (height delta × block time), not a raw height.
                        let reset_str = match (snap.deshield_resets_at, snap.height) {
                            (Some(r), Some(h)) if r > h && snap.target_block_ms > 0 => {
                                let secs = (r - h) * snap.target_block_ms / 1000;
                                if secs >= 60 {
                                    format!(" — resets in ~{} min (block {r})", secs / 60)
                                } else {
                                    format!(" — resets in ~{secs}s (block {r})")
                                }
                            }
                            (Some(r), _) => format!(" — resets at block {r}"),
                            _ => String::new(),
                        };
                        if b < sv.balance as u128 {
                            // The per-window cap, not the balance, is the limit right now.
                            let of_limit = snap
                                .deshield_limit
                                .filter(|l| *l > 0)
                                .map(|l| format!(" of {} XUS/window", grains_to_xus_plain(l)))
                                .unwrap_or_default();
                            ui.label(
                                egui::RichText::new(format!(
                                    "⏳ De-shield rate-limited — up to {} XUS{} de-shieldable now{}. \
                                     Your {} XUS pool balance exceeds the per-window cap, so de-shield \
                                     in batches. (Private shielded → shielded sends are NOT limited.)",
                                    grains_to_xus_plain(deshield_cap),
                                    of_limit,
                                    reset_str,
                                    xus(&sv.balance.to_string()),
                                ))
                                .small()
                                .color(palette::warning()),
                            );
                        } else {
                            let cap_note = snap
                                .deshield_limit
                                .filter(|l| *l > 0)
                                .map(|l| format!("; per-window cap {} XUS", grains_to_xus_plain(l)))
                                .unwrap_or_default();
                            ui.label(
                                egui::RichText::new(format!(
                                    "de-shieldable now: up to {} XUS (balance {} XUS{})",
                                    grains_to_xus_plain(deshield_cap),
                                    xus(&sv.balance.to_string()),
                                    cap_note,
                                ))
                                .small()
                                .weak(),
                            );
                        }
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                "de-shield moves a variable amount to this account (transparent); change stays shielded",
                            )
                            .small()
                            .weak(),
                        );
                    }
                }
            }

            // ── Send privately (shielded → shielded): sender, recipient, and
            // amount ALL hidden. Spends this wallet's scanned notes; private change
            // returns to the wallet. ──
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Send privately (fully shielded)").strong());
            ui.label(
                egui::RichText::new(
                    "spends your shielded notes to a xus1…/uxus1… address — sender, recipient, and \
                     amount are all hidden on-chain.",
                )
                .weak(),
            );
            ui.horizontal(|ui| {
                ui.label("To");
                ui.add(
                    egui::TextEdit::singleline(&mut self.private_to)
                        .hint_text("xus1… (recipient stays private)")
                        .desired_width(420.0),
                );
            });
            let priv_route = SendRoute::detect(&self.private_to);
            if !self.private_to.trim().is_empty() && !priv_route.private() {
                ui.label(
                    egui::RichText::new(
                        "✗ private send needs a shielded (xus1…) or unified address",
                    )
                    .small()
                    .color(palette::error()),
                );
            }
            let priv_grains = parse_xus(&self.private_amount);
            ui.horizontal(|ui| {
                ui.label("Amount XUS");
                ui.add(egui::TextEdit::singleline(&mut self.private_amount).desired_width(160.0));
                if ui
                    .button("Max")
                    .on_hover_text("send your full scanned shielded balance")
                    .clicked()
                {
                    self.private_amount = grains_to_xus_plain(sv.balance as u128);
                }
                ui.label(
                    egui::RichText::new(format!("shielded {} XUS", xus(&sv.balance.to_string())))
                        .weak(),
                );
            });
            let priv_ok = for_this
                && priv_route.private()
                && matches!(priv_grains, Some(g) if g > 0 && g <= sv.balance as u128)
                && !sv.scanning
                && !busy;
            // Tell the user EXACTLY what's blocking the button (it was silently
            // disabled before). You do NOT need to de-shield to send privately —
            // a private send spends your shielded notes directly.
            let priv_reason: &str = if w_watch_only {
                "watch-only wallet — cannot send"
            } else if sv.scanning {
                "scanning the pool…"
            } else if !for_this || sv.scanned_height == 0 {
                "loading your shielded balance…"
            } else if sv.balance == 0 {
                "no shielded funds yet — use “Shield to pool” above to move XUS in (you do NOT \
                 need to de-shield to send privately)"
            } else if self.private_to.trim().is_empty() {
                "enter the recipient’s xus1…/uxus1… address"
            } else if !priv_route.private() {
                "recipient must be a shielded (xus1…) or unified address"
            } else if !matches!(priv_grains, Some(g) if g > 0) {
                "enter an amount"
            } else if matches!(priv_grains, Some(g) if g > sv.balance as u128) {
                "amount exceeds your shielded balance"
            } else {
                ""
            };
            if !priv_ok && !priv_reason.is_empty() {
                ui.label(
                    egui::RichText::new(format!("→ {priv_reason}"))
                        .small()
                        .color(palette::warning()),
                );
            }
            ui.add_enabled_ui(priv_ok, |ui| {
                if ui.button("Review private send →").clicked() {
                    if let Some(g) = priv_grains {
                        let to = self.private_to.trim().to_string();
                        let self_send = to == shielded || to == unified;
                        new_pending = Some(PendingSend {
                            from_label: label.clone(),
                            from_account: effective.clone(),
                            to,
                            amount_grains: g,
                            from_balance_grains: sv.balance as u128,
                            route_label: "shielded → shielded (fully private)".to_string(),
                            self_send,
                            links_public: false,
                            from_pool: true,
                        });
                    }
                }
            });

            // ── Offline / air-gapped signing (cold reserves) ──────────────────
            ui.add_space(6.0);
            egui::CollapsingHeader::new("🔌 Offline / air-gapped signing").show(ui, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Keep keys off the network. Build an UNSIGNED tx here, carry it to the \
                         air-gapped machine to SIGN, then BROADCAST the signed result from an \
                         online node. A watch-only wallet can do step 1 and 3.",
                    )
                    .weak()
                    .small(),
                );
                // 1. Build unsigned (online / watch-only).
                ui.label(egui::RichText::new("1 · Build unsigned transfer").strong());
                ui.horizontal(|ui| {
                    ui.label("To");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ofl_to)
                            .hint_text("recipient account id")
                            .desired_width(360.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Amount XUS");
                    ui.add(egui::TextEdit::singleline(&mut self.ofl_amount).desired_width(120.0));
                    if ui.button("Build unsigned").clicked() {
                        do_build_unsigned = true;
                    }
                });
                if !self.ofl_unsigned.is_empty() {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.ofl_unsigned)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.button("Copy unsigned").clicked() {
                        ui.output_mut(|o| o.copied_text = self.ofl_unsigned.clone());
                        did_copy = true;
                    }
                }
                ui.separator();
                // 2. Sign (offline machine that holds the seed).
                ui.label(egui::RichText::new("2 · Sign (machine with the seed)").strong());
                ui.add(
                    egui::TextEdit::multiline(&mut self.ofl_sign_in)
                        .hint_text("paste the unsigned tx JSON here")
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.button("Sign").clicked() {
                    do_sign_offline = true;
                }
                if !self.ofl_signed.is_empty() {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.ofl_signed)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.button("Copy signed").clicked() {
                        ui.output_mut(|o| o.copied_text = self.ofl_signed.clone());
                        did_copy = true;
                    }
                }
                ui.separator();
                // 3. Broadcast (online node).
                ui.label(egui::RichText::new("3 · Broadcast (online node)").strong());
                ui.add(
                    egui::TextEdit::multiline(&mut self.ofl_broadcast_in)
                        .hint_text("paste the signed tx JSON here")
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.button("Broadcast").clicked() {
                    do_broadcast = true;
                }
                if !self.ofl_msg.is_empty() {
                    status_label(ui, &self.ofl_msg);
                }
            });
        }

        // A freshly-reviewed send opens the confirmation modal.
        if new_pending.is_some() {
            self.pending_send = new_pending;
        }
        // ── Send confirmation modal (review before broadcast) ──
        if let Some(p) = self.pending_send.clone() {
            let ctx = ui.ctx().clone();
            let network = self.network;
            egui::Window::new(egui::RichText::new("Review transaction").strong())
                .collapsible(false)
                .resizable(false)
                .default_width(450.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.set_max_width(450.0);
                    // Hero amount + privacy state — the two things that matter most.
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(xus(&p.amount_grains.to_string()))
                                .size(28.0)
                                .strong()
                                .color(palette::text()),
                        );
                        ui.label(
                            egui::RichText::new("XUS")
                                .size(14.0)
                                .color(palette::text_dim()),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if p.links_public {
                                pill(ui, "PUBLIC", palette::warning());
                            } else {
                                pill(ui, "PRIVATE", palette::success());
                            }
                        });
                    });
                    ui.add_space(10.0);
                    egui::Grid::new("confirm_grid")
                        .num_columns(2)
                        .spacing([16.0, 8.0])
                        .show(ui, |ui| {
                            kv(
                                ui,
                                "From",
                                &format!("{} · {}", p.from_label, short_id(&p.from_account)),
                            );
                            // Full recipient address, monospace + wrapped so it never overflows.
                            ui.label(egui::RichText::new("To").weak());
                            ui.add(
                                egui::Label::new(egui::RichText::new(&p.to).monospace().size(11.0))
                                    .wrap(),
                            );
                            ui.end_row();
                            kv(ui, "Route", &p.route_label);
                            kv(
                                ui,
                                "Network",
                                &format!("{} · {}", network.label(), network.pow_algo()),
                            );
                            // The EXACT network fee for this route (from consensus via
                            // `sov_estimateFee`) and the resulting balance after amount +
                            // fee, so the full cost is visible before broadcast.
                            let fee = if p.links_public {
                                s.fee_transfer_grains
                            } else {
                                s.fee_shielded_grains
                            };
                            let fee_str = if fee == 0 {
                                "0 XUS  ·  no network fee on testnet".to_string()
                            } else {
                                format!("{} XUS", xus(&fee.to_string()))
                            };
                            kv(ui, "Network fee", &fee_str);
                            let after = p
                                .from_balance_grains
                                .saturating_sub(p.amount_grains)
                                .saturating_sub(fee);
                            kv(
                                ui,
                                "Balance after",
                                &format!("{} XUS", xus(&after.to_string())),
                            );
                        });
                    ui.add_space(8.0);
                    // Privacy + self-send context.
                    if p.links_public {
                        ui.colored_label(
                            palette::warning(),
                            "⚠ Public — sender, recipient, and amount are visible on-chain. Send \
                             to a xus1…/uxus1… address to keep it private.",
                        );
                    } else {
                        ui.colored_label(
                            palette::success(),
                            "🛡 Private — recipient and amount are shielded on-chain.",
                        );
                    }
                    if p.self_send {
                        ui.colored_label(
                            palette::text_dim(),
                            "↩ This is one of your own addresses.",
                        );
                    }
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("✓ Confirm & send")
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(palette::accent()),
                            )
                            .clicked()
                        {
                            // A pool spend (sender hidden) goes through shielded_send;
                            // every other route through the transparent/shield send.
                            if p.from_pool {
                                do_private_send = true;
                            } else {
                                do_send = true;
                            }
                            self.pending_send = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_send = None;
                        }
                    });
                });
        }

        // Action status — a spinner while broadcasting, then a green (success) or red
        // (failure) banner so the result of a sent transaction is unmistakable.
        ui.add_space(8.0);
        let (busy, msg) = self
            .action
            .lock()
            .map(|a| (a.busy, a.message.clone()))
            .unwrap_or((false, String::new()));
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                if !msg.is_empty() {
                    ui.label(egui::RichText::new(&msg).color(palette::text_dim()));
                }
            });
        } else {
            status_banner(ui, &msg);
        }

        // Activity feed — a running history of submitted actions, each line timestamped
        // and colored by outcome (green = succeeded, red = failed). Open by default so
        // you can always see what just happened.
        let log = self.activity.lock().map(|l| l.clone()).unwrap_or_default();
        if !log.is_empty() {
            ui.add_space(4.0);
            egui::CollapsingHeader::new(format!("Recent activity ({})", log.len()))
                .default_open(true)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("activity_log")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            for line in &log {
                                let (time, body) =
                                    line.split_once('\t').unwrap_or(("", line.as_str()));
                                let col = status_color(tx_status(body));
                                ui.horizontal_wrapped(|ui| {
                                    if !time.is_empty() {
                                        ui.label(
                                            egui::RichText::new(time)
                                                .monospace()
                                                .size(11.0)
                                                .color(palette::text_dim()),
                                        );
                                    }
                                    ui.label(
                                        egui::RichText::new(body).monospace().size(11.0).color(col),
                                    );
                                });
                            }
                        });
                    if ui.button("Clear").clicked() {
                        if let Ok(mut l) = self.activity.lock() {
                            l.clear();
                        }
                    }
                });
        }

        // Encrypted keystore — wallets survive restart (Argon2id + ChaCha20-Poly1305).
        ui.separator();
        ui.label(egui::RichText::new("Wallet file (encrypted keystore)").strong());
        ui.label(
            egui::RichText::new(
                "Save persists ALL wallets (keys + recovery phrases) to an encrypted file \
                 (Argon2id + ChaCha20-Poly1305) so they survive restart. Load restores them under \
                 the same passphrase.",
            )
            .weak(),
        );
        if let Ok(path) = keystore_path() {
            ui.label(egui::RichText::new(format!("file: {}", path.display())).weak());
        }
        // `do_save` is declared at the top of STATE 3 (the unsaved banner can set it).
        let mut do_load = false;
        ui.horizontal(|ui| {
            ui.label("Passphrase");
            ui.add(
                egui::TextEdit::singleline(&mut self.keystore_pass)
                    .password(true)
                    .desired_width(180.0),
            );
            if ui.button("Save wallets").clicked() {
                do_save = true;
            }
            if ui.button("Load wallets").clicked() {
                do_load = true;
            }
        });
        if !self.keystore_msg.is_empty() {
            status_label(ui, &self.keystore_msg);
        }

        // Dispatch collected actions (after the UI borrows end).
        if let Some(i) = select {
            if i != self.selected {
                // Switching wallets resets per-wallet UI so an action can never
                // land on the wrong account: clear the rename box, disarm forget,
                // and drop any "operate as" link from the previous wallet's view.
                self.selected = i;
                self.rename_field.clear();
                self.forget_armed = false;
                self.forget_confirm.clear();
                self.reveal_phrase = false;
                self.operate_msg.clear();
            }
        }
        if do_rename {
            self.rename_selected();
        }
        if do_forget {
            self.forget_selected();
        }
        if do_generate {
            self.generate_wallet();
        }
        if do_import {
            self.import_wallet();
        }
        if do_add_watch {
            self.add_watch_only();
        }
        if do_set_operate {
            self.set_operate_as();
        }
        if do_clear_operate {
            self.clear_operate_as();
        }
        if do_register_named {
            self.register_named(&ctx);
        }
        // SNS is foundational: refresh EVERY loaded wallet's names (keyed by the
        // account they resolve to) periodically (~4s), so each wallet's name shows
        // uniformly in the header and switch list, and a freshly-mined name appears
        // within seconds without switching wallets.
        let stale = self
            .names_refreshed_at
            .map(|t| t.elapsed() >= Duration::from_secs(4))
            .unwrap_or(true);
        if stale {
            self.names_refreshed_at = Some(Instant::now());
            let accounts: Vec<String> =
                self.wallets.iter().map(|w| w.effective_account()).collect();
            let rpc = self
                .config
                .lock()
                .map(|c| c.rpc.clone())
                .unwrap_or_default();
            let cache = self.names_by_account.clone();
            let ctxc = ctx.clone();
            std::thread::spawn(move || {
                let mut fresh: HashMap<String, Vec<String>> = HashMap::new();
                for acct in accounts {
                    if let Ok(names) = fetch_names_of(&rpc, &acct) {
                        fresh.insert(acct, names);
                    }
                }
                if let Ok(mut m) = cache.lock() {
                    *m = fresh;
                }
                ctxc.request_repaint();
            });
        }
        // Live availability check for the name being typed, keyed to the active
        // wallet's account (so a registered name resolves to it).
        if let Some(me) = self
            .wallets
            .get(self.selected)
            .map(|w| w.effective_account())
        {
            // Debounced availability check: at most one in flight per typed value.
            let typed = self.name_field.trim().to_string();
            let need = self
                .name_check
                .lock()
                .ok()
                .map(|c| c.name != typed && !c.checking)
                .unwrap_or(false);
            if !typed.is_empty() && need {
                match validate_name_format(&typed) {
                    Err(e) => {
                        if let Ok(mut c) = self.name_check.lock() {
                            *c = NameCheck {
                                name: typed,
                                message: format!("✗ {e}"),
                                ok: false,
                                checking: false,
                            };
                        }
                    }
                    Ok(()) => {
                        if let Ok(mut c) = self.name_check.lock() {
                            *c = NameCheck {
                                name: typed.clone(),
                                message: "checking…".into(),
                                ok: false,
                                checking: true,
                            };
                        }
                        let rpc = self
                            .config
                            .lock()
                            .map(|c| c.rpc.clone())
                            .unwrap_or_default();
                        let cache = self.name_check.clone();
                        let ctxc = ctx.clone();
                        std::thread::spawn(move || {
                            let (ok, msg) = check_name_registrable(&rpc, &typed, &me);
                            if let Ok(mut c) = cache.lock() {
                                if c.name == typed {
                                    c.ok = ok;
                                    c.message = msg;
                                    c.checking = false;
                                }
                            }
                            ctxc.request_repaint();
                        });
                    }
                }
            }
        }
        if do_send {
            self.send(&ctx);
        }
        if do_private_send {
            self.send_private(&ctx);
        }
        if do_scan {
            self.scan_shielded(&ctx);
        }
        // Auto-scan the shielded pool the first time a (spendable) wallet is shown,
        // so its private balance + notes appear WITHOUT a manual "Scan pool" — this
        // is what lets "Send privately" enable on its own (you never need to
        // de-shield to send). Debounced to once per account; skipped for watch-only
        // (no seed → no viewing key) and while a scan is already running.
        if !do_scan {
            if let Some((acct, watch)) = self
                .wallets
                .get(self.selected)
                .map(|w| (w.effective_account(), w.watch_only))
            {
                let scanning = self.shielded.lock().map(|v| v.scanning).unwrap_or(false);
                if !watch && self.shielded_scan_for != acct && !scanning {
                    self.shielded_scan_for = acct;
                    self.scan_shielded(&ctx);
                }
            }
        }
        if do_deshield {
            self.deshield(&ctx);
        }
        if do_build_unsigned {
            self.build_unsigned();
        }
        if do_sign_offline {
            self.sign_offline();
        }
        if do_broadcast {
            self.broadcast_signed(&ctx);
        }
        if do_save {
            self.save_wallets();
        }
        if do_load {
            self.load_wallets();
        }
        if did_copy {
            self.copied_at = Some(now_ms());
        }
    }
}

/// Format a block's wall-clock timestamp (Unix ms) as `HH:MM:SS` (UTC, matching the
/// node log) plus a relative age, for the Blocks tab. `0` (genesis/unknown) shows `—`.
fn block_time(ts_ms: u64) -> String {
    if ts_ms == 0 {
        return "—".to_string();
    }
    let secs = (ts_ms / 1000) % 86_400;
    let hms = format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );
    let now = now_ms();
    if now < ts_ms {
        return hms;
    }
    let age = (now - ts_ms) / 1000;
    if age < 60 {
        format!("{hms}  ({age}s ago)")
    } else if age < 3_600 {
        format!("{hms}  ({}m ago)", age / 60)
    } else {
        format!("{hms}  ({}h ago)", age / 3_600)
    }
}

fn blocks_panel(ui: &mut egui::Ui, s: &Snapshot, selected: &mut Option<u64>) {
    ui.heading("Blocks");
    ui.label(
        egui::RichText::new(
            "each block's coinbase — newly minted issuance, paid entirely to the miner (no tax)",
        )
        .weak(),
    );
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("click a height to inspect the block →").weak());
        ui.hyperlink_to("open explorer ↗", EXPLORER_URL);
    });
    ui.add_space(8.0);
    if s.blocks.is_empty() {
        empty_state(
            ui,
            "▦",
            "No blocks yet",
            "Start the local node (Node tab) to begin mining — solved blocks appear here.",
        );
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("blocks")
            .num_columns(4)
            .striped(true)
            .spacing([18.0, 5.0])
            .show(ui, |ui| {
                for h in ["Height", "Time", "Miner", "Coinbase"] {
                    ui.label(egui::RichText::new(h).weak());
                }
                ui.end_row();
                for b in &s.blocks {
                    // Height opens the in-app block-detail view (seal, nonce, hashes).
                    if ui
                        .link(egui::RichText::new(b.height.to_string()).monospace())
                        .on_hover_text("Inspect this block")
                        .clicked()
                    {
                        *selected = Some(b.height);
                    }
                    ui.monospace(block_time(b.timestamp_ms));
                    ui.monospace(short(&b.miner));
                    ui.monospace(xus(&b.reward));
                    ui.end_row();
                }
            });
    });
    // ── Block-detail view (click a height above) ──
    if let Some(height) = *selected {
        if let Some(b) = s.blocks.iter().find(|b| b.height == height) {
            block_detail_window(ui.ctx(), b, selected);
        } else {
            // The block scrolled out of the recent window — nothing to show.
            *selected = None;
        }
    }
}

/// The block-detail modal: full header identity (hash / prev / state root), the PoW
/// seal (nonce + compact target), timestamp, tx count, and the coinbase split — each
/// hash with a copy affordance, plus a deep link into the explorer.
fn block_detail_window(ctx: &egui::Context, b: &BlockRow, selected: &mut Option<u64>) {
    let mut open = true;
    egui::Window::new(egui::RichText::new(format!("Block #{}", b.height)).strong())
        .collapsible(false)
        .resizable(false)
        .default_width(460.0)
        .open(&mut open)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.add_space(2.0);
            egui::Grid::new("block_detail_grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    kv(ui, "Height", &b.height.to_string());
                    kv(ui, "Time", &block_time(b.timestamp_ms));
                    kv_copy(ui, "Hash", &b.hash);
                    kv_copy(ui, "Prev hash", &b.prev_hash);
                    kv_copy(ui, "State root", &b.state_root);
                    // The PoW seal — the nonce that satisfied the compact target.
                    ui.label(egui::RichText::new("Nonce (seal)").weak());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(b.nonce.to_string()).monospace());
                        copy_glyph(ui, &b.nonce.to_string());
                    });
                    ui.end_row();
                    kv(ui, "Target (nBits)", &format!("0x{:08x}", b.bits));
                    kv(ui, "Transactions", &b.tx_count.to_string());
                });
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Coinbase").strong());
            egui::Grid::new("block_detail_coinbase")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    kv(ui, "Reward", &format!("{} XUS", xus(&b.reward)));
                    kv_copy(ui, "Miner", &b.miner);
                    kv(ui, "To miner", &format!("{} XUS", xus(&b.miner_amount)));
                });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Close").clicked() {
                    *selected = None;
                }
                ui.hyperlink_to(
                    "open in explorer ↗",
                    format!("{EXPLORER_URL}/#/block/{}", b.height),
                );
            });
        });
    // The window's [x] close button.
    if !open {
        *selected = None;
    }
}

// ---------------------------------------------------------------------------
// wallet actions (run on worker threads)
// ---------------------------------------------------------------------------

fn begin(action: &Arc<Mutex<ActionState>>, msg: &str) {
    if let Ok(mut a) = action.lock() {
        a.busy = true;
        a.message = msg.to_string();
    }
}

fn finish(action: &Arc<Mutex<ActionState>>, msg: &str) {
    if let Ok(mut a) = action.lock() {
        a.busy = false;
        a.message = msg.to_string();
    }
}

/// Append a line to the activity log (newest first), capped so it stays bounded.
fn record(activity: &Arc<Mutex<Vec<String>>>, msg: &str) {
    if let Ok(mut log) = activity.lock() {
        // `time\tmessage` — the feed renders the time dim and colors the message by
        // outcome (see `tx_status`); the tab keeps the two cleanly separable.
        log.insert(0, format!("{}\t{}", clock_hms(), msg));
        log.truncate(100);
    }
}

/// On-chain control state of a named account, relative to a specific wallet key.
enum Control {
    /// This wallet's key is bound to the account — it can spend.
    Mine,
    /// A different key is bound — this wallet cannot spend it.
    DifferentKey,
    /// Keyless but funded (balance > 0): claimable now via `RotateKey`.
    KeylessFunded,
    /// Keyless and empty, or not on-chain yet: must be funded before it can be
    /// claimed (the claim transaction's fee is paid by the account itself).
    KeylessEmpty,
    /// The node could not be reached / queried.
    Unreachable(String),
}

/// Resolve how the wallet derived from `seed` relates to `account` on-chain by
/// comparing the account's bound key (and balance) to this wallet's key.
fn account_control(rpc: &str, seed: [u8; 32], id: &AccountId) -> Control {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(4));
    let mine = Keypair::hybrid_from_seed(seed).public_key();
    match client.account(id) {
        Ok(Some(a)) => match a.key {
            Some(k) if k == mine => Control::Mine,
            Some(_) => Control::DifferentKey,
            None if a.balance != Balance::ZERO => Control::KeylessFunded,
            None => Control::KeylessEmpty,
        },
        Ok(None) => Control::KeylessEmpty,
        Err(e) => Control::Unreachable(e.to_string()),
    }
}

/// A human-readable one-line status for `account` relative to this wallet.
fn check_control(rpc: &str, seed: [u8; 32], account: &str) -> String {
    let Ok(id) = AccountId::new(account) else {
        return "invalid account id".to_string();
    };
    match account_control(rpc, seed, &id) {
        Control::Mine => format!("✓ this wallet controls {account} — you can send from it"),
        Control::DifferentKey => {
            format!("✗ {account} is bound to a DIFFERENT key — this wallet cannot spend it")
        }
        Control::KeylessFunded => {
            format!("⚠ {account} is funded but keyless — click “Register name” to claim it")
        }
        Control::KeylessEmpty => {
            format!(
                "⚠ {account} is unclaimed — works once it is funded or genesis-bound to this key"
            )
        }
        Control::Unreachable(e) => format!("could not reach the node to check {account}: {e}"),
    }
}

/// Sign `action` with `seed`'s key as `signer` and submit it. The generic submit
/// path for token + HTLC actions; returns the tx id hex.
fn submit_action(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    action: Action,
) -> Result<String, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let kp = Keypair::hybrid_from_seed(seed);
    let id = AccountId::new(signer).map_err(|e| e.to_string())?;
    let nonce = client.nonce(&id).map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: id,
        public_key: kp.public_key(),
        nonce,
        action,
    };
    let stx = SignedTransaction::sign(tx, &kp).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    Ok(txid.to_hex())
}

/// The live format + availability check for a name being typed, so the GUI can
/// refuse to register a name that would not resolve (bad shape, already taken, or
/// shadowing an existing account) — the "checksum" guard.
#[derive(Default, Clone)]
struct NameCheck {
    /// The name this result describes (a stale result for an older field value
    /// is ignored by comparing against the current input).
    name: String,
    /// Human-readable status line.
    message: String,
    /// True only when the name is well-formed AND free to register right now.
    ok: bool,
    /// A check is in flight.
    checking: bool,
}

/// Client-side name **format** validation — the same rule consensus enforces, so
/// the GUI never even submits a name the chain would reject. A name must be a
/// valid `*.sov` account id and not a reserved 64-hex implicit id.
fn validate_name_format(name: &str) -> Result<(), String> {
    let id = AccountId::new(name).map_err(|e| e.to_string())?;
    if !id.is_registrable_name() {
        return Err("must end in .sov and use a–z, 0–9, - _ . (not a 64-hex address)".into());
    }
    Ok(())
}

/// Resolve a name to the account it points to via the node, if registered.
fn resolve_name_via_rpc(rpc: &str, name: &str) -> Option<String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(8));
    client
        .call("sov_resolveName", json!({ "name": name }))
        .ok()?
        .as_str()
        .map(str::to_string)
}

/// Whether an account already holds state on-chain (a name may not shadow one).
fn account_exists_onchain(rpc: &str, id: &str) -> bool {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(8));
    client
        .call("sov_getAccount", json!({ "account": id }))
        .map(|v| !v.is_null())
        .unwrap_or(false)
}

/// Check whether `name` can be registered to resolve to `me`: valid format, not
/// already taken by someone else, and not shadowing an existing account. Returns
/// `(registrable_now, status_message)`. This is the gate behind "won't let you
/// create a name that won't resolve".
fn check_name_registrable(rpc: &str, name: &str, me: &str) -> (bool, String) {
    if let Err(e) = validate_name_format(name) {
        return (false, format!("✗ {e}"));
    }
    if let Some(owner) = resolve_name_via_rpc(rpc, name) {
        return if owner == me {
            (
                false,
                "✓ already registered — this name resolves to you".into(),
            )
        } else {
            (false, format!("✗ already taken by {}", short_id(&owner)))
        };
    }
    if account_exists_onchain(rpc, name) {
        return (
            false,
            "✗ shadows an existing account — choose another".into(),
        );
    }
    (true, "✓ available — will resolve to your account".into())
}

/// Register `name` on-chain as an ENS/SNS alias to `signer`'s account. Re-checks
/// availability immediately before submitting (race-safe), submits `RegisterName`,
/// and returns the transaction id.
fn register_name_onchain(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    name: &str,
) -> Result<String, String> {
    validate_name_format(name)?;
    let (ok, why) = check_name_registrable(rpc, name, signer);
    if !ok {
        return Err(why
            .trim_start_matches("✗ ")
            .trim_start_matches("✓ ")
            .to_string());
    }
    submit_action(
        rpc,
        seed,
        signer,
        Action::RegisterName {
            name: name.to_string(),
        },
    )
}

/// Every name currently resolving to `account` (the reverse lookup), for the
/// wallet's "your names" list.
fn fetch_names_of(rpc: &str, account: &str) -> Result<Vec<String>, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(8));
    let v = client
        .call("sov_namesOf", json!({ "account": account }))
        .map_err(|e| e.to_string())?;
    Ok(v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// Resolve a payee for sending: a registered `*.sov` name resolves to the account
/// it points to; shielded/unified addresses, raw ids, and unregistered names pass
/// through unchanged (so genesis named accounts still work literally).
fn resolve_payee(rpc: &str, to: &str) -> String {
    if let Ok(id) = AccountId::new(to) {
        if id.is_registrable_name() {
            if let Some(owner) = resolve_name_via_rpc(rpc, to) {
                return owner;
            }
        }
    }
    to.to_string()
}

/// SHA-256 of `data` (the HTLC hashlock function — consensus checks
/// `sha256(preimage) == hashlock`).
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&sha256_bytes(data))
}

/// Set the Tokens view's status line from a worker and repaint.
fn set_token_view_msg(view: &Arc<Mutex<TokensView>>, ctx: &egui::Context, msg: &str) {
    if let Ok(mut v) = view.lock() {
        v.loading = false;
        v.message = msg.to_string();
    }
    ctx.request_repaint();
}

/// Set the Swaps view's status line from a worker and repaint.
fn set_swap_view_msg(view: &Arc<Mutex<SwapsView>>, ctx: &egui::Context, msg: &str) {
    if let Ok(mut v) = view.lock() {
        v.looking = false;
        v.message = msg.to_string();
    }
    ctx.request_repaint();
}

/// Sign and submit a payment. `to` may be a named account (transparent), a
/// `xus1…` shielded address, or a `uxus1…` unified address — `RpcClient::pay`
/// routes it. A shielded route builds (and caches) the Halo2 prover first.
fn send_payment(
    rpc: &str,
    seed: [u8; 32],
    from: &str,
    to: &str,
    grains: u128,
    params_cache: &Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    action: &Arc<Mutex<ActionState>>,
) -> Result<String, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(90));
    let kp = Keypair::hybrid_from_seed(seed);
    let from_id = AccountId::new(from).map_err(|e| e.to_string())?;
    let amount = Balance::from_grains(grains);
    // Resolve an ENS/SNS name to the account it points to (a registered `.sov`
    // name → its owner). Shielded/unified addresses, raw ids, and unregistered
    // names pass through unchanged, so genesis named accounts still work literally.
    let resolved = resolve_payee(rpc, to);
    let to = resolved.as_str();
    let shielded = AnyAddress::parse(to)
        .map(|a| matches!(a.receiver(), Receiver::Shielded(_)))
        .unwrap_or(false);
    let params: Option<Arc<ShieldedParams>> = if shielded {
        let cached = params_cache.lock().ok().and_then(|p| p.clone());
        Some(match cached {
            Some(p) => p,
            None => {
                begin(action, "building the shielded prover (one-time, ~seconds)…");
                let p = Arc::new(ShieldedParams::build());
                if let Ok(mut slot) = params_cache.lock() {
                    *slot = Some(p.clone());
                }
                p
            }
        })
    } else {
        None
    };
    if shielded {
        begin(action, "proving the shielded transfer (real Halo2)…");
    }
    let txid = client
        .pay(&kp, &from_id, to, amount, params.as_deref())
        .map_err(|e| e.to_string())?;
    Ok(txid.to_hex())
}

/// Path to a wallet's encrypted incremental note cache, keyed by its stable
/// implicit id (per seed). `<home>/.sov-station/notes/<id>.store`.
fn note_store_path(store_id: &str) -> Result<PathBuf, String> {
    Ok(home_dir()?
        .join(".sov-station")
        .join("notes")
        .join(format!("{store_id}.store")))
}

/// Encrypt `plaintext` with the 32-byte device `key` (ChaCha20-Poly1305, random
/// 12-byte nonce prepended) — the note cache holds note secrets, so it is never
/// written in the clear.
fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "encrypt failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob written by [`encrypt_blob`]. `None` on a wrong key or tamper.
fn decrypt_blob(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    if data.len() < 12 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
        .ok()
}

/// Sum the coinbase paid to any of `accounts` across the whole chain, by reading
/// each block's coinbase recipients. Returns `(total_grains, tip, rows)` where
/// rows are per-account earnings (label, role, blocks credited, grains). Real
/// on-chain data only — every grain is a coinbase the chain actually paid.
#[allow(clippy::type_complexity)]
fn scan_earnings(
    rpc: &str,
    accounts: &HashMap<String, String>,
) -> Result<(u128, u64, Vec<EarningRow>), String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let head = client.height().map_err(|e| e.to_string())?;
    // account -> (label, role, blocks, grains)
    let mut tally: HashMap<String, (String, String, u64, u128)> = HashMap::new();
    let mut total: u128 = 0;
    for h in 1..=head {
        let Ok(d) = client.call("sov_getBlockDigest", json!({ "height": h })) else {
            continue;
        };
        let Some(cb) = d.get("coinbase").filter(|c| !c.is_null()) else {
            continue;
        };
        let Some(Value::Array(recips)) = cb.get("recipients") else {
            continue;
        };
        for r in recips {
            let acct = field(r, "account");
            let Some(label) = accounts.get(&acct) else {
                continue;
            };
            let role = field(r, "role");
            let amt: u128 = field(r, "amount").parse().unwrap_or(0);
            total += amt;
            let e = tally
                .entry(acct.clone())
                .or_insert((label.clone(), role, 0, 0));
            e.2 += 1;
            e.3 += amt;
        }
    }
    let mut rows: Vec<EarningRow> = tally
        .into_iter()
        .map(|(account, (label, role, blocks, grains))| EarningRow {
            label,
            account,
            role,
            blocks,
            grains,
        })
        .collect();
    rows.sort_by(|a, b| b.grains.cmp(&a.grains));
    Ok((total, head, rows))
}

/// The canonical block hash at `height` (the header hash, matching what
/// [`NoteStore::ingest_block`] records), or `None` if the node has no block there
/// (e.g. the chain is now shorter). Used to detect a reorg before folding.
fn canonical_hash(client: &RpcClient, height: u64) -> Result<Option<[u8; 32]>, String> {
    Ok(client
        .block_by_height(height)
        .map_err(|e| e.to_string())?
        .map(|b| *b.hash().as_bytes()))
}

/// Incrementally scan for `seed`'s shielded notes, persisting an encrypted
/// [`NoteStore`] so each call only fetches + decrypts the **new** blocks since
/// last time (not the whole chain). Loads the cached store (decrypting with the
/// device key), folds in blocks `scanned_height+1..=tip`, persists, and returns
/// the up-to-date store. A `tip` below the cached height (a chain reset/reorg)
/// rebuilds from genesis.
fn scan_store(rpc: &str, seed: [u8; 32]) -> Result<NoteStore, String> {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(15));
    let zkey = ShieldedKey::from_seed(seed).ok_or("invalid shielded key")?;
    // The cache is keyed by this wallet's stable implicit id (one seed → one
    // shielded key → one note set). Encrypted at rest under a key derived from the
    // wallet's OWN seed (the secret we're already scanning with) — so there is no
    // device key on disk, and the cache is meaningless without the seed. It is a
    // rebuildable cache anyway: an unreadable file just forces a fresh scan.
    let store_id = Keypair::hybrid_from_seed(seed)
        .public_key()
        .implicit_account_id()
        .to_string();
    let path = note_store_path(&store_id)?;
    let dkey = notes_cache_key(&seed);

    let mut store = std::fs::read(&path)
        .ok()
        .and_then(|enc| decrypt_blob(&dkey, &enc))
        .and_then(|bytes| NoteStore::from_bytes(&bytes))
        .unwrap_or_else(|| NoteStore::new(0));

    let tip = client.height().map_err(|e| e.to_string())?;

    // Reconcile the cache with the canonical chain before folding forward. If the
    // chain reorged out from under us — the node's hash at our cached tip no
    // longer matches — walk our checkpoints newest→oldest to find the deepest
    // height that still agrees (the fork point) and roll back to it, so we never
    // extend an orphaned branch. A reorg deeper than the cached horizon rebuilds.
    if let Some((tip_h, cached_hash)) = store.tip_checkpoint() {
        if canonical_hash(&client, tip_h)? != Some(cached_hash) {
            let mut fork = None;
            for (h, our_hash) in store.checkpoints().into_iter().rev() {
                if canonical_hash(&client, h)? == Some(our_hash) {
                    fork = Some(h);
                    break;
                }
            }
            match fork {
                Some(f) if store.rollback_to(f) => {}
                // Fork is below our retained horizon (or not checkpointed) —
                // rebuild from the birthday; correctness over a faster path.
                _ => store = NoteStore::new(store.birthday()),
            }
        }
    }

    for h in (store.scanned_height() + 1)..=tip {
        let block = client
            .block_by_height(h)
            .map_err(|e| e.to_string())?
            // A missing block at h<=tip is a transient RPC gap; stop here and
            // resume next scan rather than desync the contiguous height.
            .ok_or_else(|| format!("block {h} unavailable; will resume"))?;
        let bundles: Vec<ShieldedBundle> = block
            .transactions
            .iter()
            .filter_map(|stx| match &stx.transaction.action {
                Action::Shielded { bundle } => ShieldedBundle::from_bytes(bundle).ok(),
                _ => None,
            })
            .collect();
        let refs: Vec<&ShieldedBundle> = bundles.iter().collect();
        store.ingest_block(&zkey, h, *block.hash().as_bytes(), &refs);
    }

    // Persist the updated cache (encrypted, owner-only).
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let enc = encrypt_blob(&dkey, &store.to_bytes())?;
    std::fs::write(&path, &enc).map_err(|e| e.to_string())?;
    restrict_to_owner(&path);
    Ok(store)
}

/// De-shield the wallet's largest unspent note back to its transparent account
/// (a real Halo2 spend, witnessed against a held anchor).
/// Poll the node for transaction `txid`'s receipt until it is mined, returning
/// `Ok(())` only when it actually **applied**, or `Err(reason)` if it was included
/// but rejected (e.g. the de-shield drain limit). This is what stops the GUI from
/// reporting "confirmed" for a transaction that silently failed on-chain — the
/// exact failure mode that made de-shielded funds look stuck.
fn await_receipt(client: &RpcClient, txid: &Hash, secs: u64) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(v) = client.call("sov_getReceipt", json!({ "txId": txid.to_hex() })) {
            let status = v.get("status");
            match status.and_then(|s| s.get("status")).and_then(Value::as_str) {
                Some("success") => return Ok(()),
                Some("failed") => {
                    let reason = status
                        .and_then(|s| s.get("reason"))
                        .and_then(Value::as_str)
                        .unwrap_or("rejected on-chain");
                    return Err(reason.to_string());
                }
                _ => {} // not mined yet
            }
        }
        if Instant::now() >= deadline {
            return Err("still pending (not yet mined) — check the receipt shortly".into());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// How much value can be de-shielded from the pool right now, per the node's live
/// drain-limiter state (`sov_getShieldedInfo`). `None` if the node does not report
/// it (older node) — callers then skip the pre-check rather than block.
fn deshieldable_now(client: &RpcClient) -> Option<u128> {
    let v = client.call("sov_getShieldedInfo", json!({})).ok()?;
    v.get("deshieldableNowGrains")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u128>().ok())
}

fn deshield_amount(
    rpc: &str,
    seed: [u8; 32],
    account: &str,
    amount_grains: u128,
    params_cache: &Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    action: &Arc<Mutex<ActionState>>,
) -> Result<String, String> {
    let amount = u64::try_from(amount_grains).map_err(|_| "amount too large".to_string())?;
    let store = scan_store(rpc, seed)?;
    let zkey = ShieldedKey::from_seed(seed).ok_or("invalid shielded key")?;
    let unspent = store.unspent();
    if unspent.is_empty() {
        return Err("no unspent shielded notes to de-shield".to_string());
    }
    // The node's live per-window drain budget: a de-shield over it would be mined
    // and REJECTED, leaving value in the pool looking "stuck". Pre-check and fail
    // fast with an actionable message instead of submitting a doomed transaction.
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(60));
    if let Some(budget) = deshieldable_now(&client) {
        if amount_grains > budget {
            return Err(format!(
                "only {} XUS can be de-shielded in the current window (per-window drain limit) — \
                 reduce the amount or wait for the window to reset",
                grains_to_xus_plain(budget),
            ));
        }
    }
    // Coin selection: de-shield from the SMALLEST single note that covers the
    // amount (minimizes the shielded change left behind). A partial de-shield keeps
    // the remainder shielded as change, so any variable amount up to a note's value
    // works. If no single note is large enough, ask the user to de-shield in parts
    // (each ≤ the largest note) — value is never trapped, just paced.
    let (note, pos) = unspent
        .iter()
        .filter(|(n, _)| n.value() >= amount)
        .min_by_key(|(n, _)| n.value())
        .ok_or_else(|| {
            let largest = unspent.iter().map(|(n, _)| n.value()).max().unwrap_or(0);
            format!(
                "no single shielded note covers {} XUS (largest note is {} XUS) — \
                 de-shield in parts of {} XUS or less",
                grains_to_xus_plain(amount_grains),
                grains_to_xus_plain(u128::from(largest)),
                grains_to_xus_plain(u128::from(largest)),
            )
        })?;
    let (path, anchor) = store.witness(*pos).ok_or("could not witness the note")?;
    let params = {
        let cached = params_cache.lock().ok().and_then(|p| p.clone());
        match cached {
            Some(p) => p,
            None => {
                begin(action, "building the shielded prover (one-time, ~seconds)…");
                let p = Arc::new(ShieldedParams::build());
                if let Ok(mut slot) = params_cache.lock() {
                    *slot = Some(p.clone());
                }
                p
            }
        }
    };
    begin(action, "proving the de-shield (real Halo2)…");
    let bundle =
        unshield_amount(&params, &zkey, note, path, anchor, amount).map_err(|e| e.to_string())?;
    // Wrap the de-shield bundle in a tx signed by the transparent account that
    // receives the funds and pays the fee.
    let kp = Keypair::hybrid_from_seed(seed);
    let from = AccountId::new(account).map_err(|e| e.to_string())?;
    let nonce = client.nonce(&from).map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: from,
        public_key: kp.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign(tx, &kp).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    // Wait for the receipt: only report success once the transaction actually
    // applied on-chain. A rejection (e.g. the drain limit) surfaces its reason
    // instead of being mistaken for a confirmed de-shield.
    begin(action, "submitted — waiting for on-chain confirmation…");
    await_receipt(&client, &txid, 90)?;
    Ok(txid.to_hex())
}

/// After a shielded action is submitted, re-scan the pool as new blocks arrive so
/// the shielded view reflects the spend (the spent note drops, change appears) —
/// no stale "note stayed behind". Polls for ~30s (a spend confirms within a block
/// or two); each rescan updates the shared view and repaints.
fn refresh_shielded_view(
    rpc: &str,
    seed: [u8; 32],
    account: &str,
    shielded: &Arc<Mutex<ShieldedView>>,
    ctx: &egui::Context,
) {
    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(5));
    let start_tip = client.height().unwrap_or(0);
    for _ in 0..15 {
        std::thread::sleep(Duration::from_secs(2));
        let Ok(store) = scan_store(rpc, seed) else {
            continue;
        };
        let scanned = store.scanned_height();
        if let Ok(mut v) = shielded.lock() {
            v.scanning = false;
            v.account = account.to_string();
            v.balance = store.balance();
            v.notes = store.unspent_count();
            v.scanned_height = scanned;
            v.message = format!("re-scanned to height {scanned}");
        }
        ctx.request_repaint();
        // Once a new block (which includes our tx) has been scanned, the view is
        // current — stop polling.
        if scanned > start_tip {
            break;
        }
    }
}

/// Fully-private send (shielded → shielded): spend one of `seed`'s scanned notes
/// to pay `recipient` (`xus1…`/`uxus1…`) `grains`, with private change back to the
/// sender. Sender, recipient, and amount are all hidden; value stays in the pool.
/// `signer` is the transparent account that submits the tx and pays its fee.
fn shielded_send(
    rpc: &str,
    seed: [u8; 32],
    signer: &str,
    recipient: &str,
    grains: u128,
    params_cache: &Arc<Mutex<Option<Arc<ShieldedParams>>>>,
    action: &Arc<Mutex<ActionState>>,
) -> Result<String, String> {
    let amount = u64::try_from(grains).map_err(|_| "amount too large".to_string())?;
    // Resolve the recipient to a shielded address (privacy-first for a unified one).
    let recipient_addr = match AnyAddress::parse(recipient)
        .map_err(|e| format!("invalid recipient: {e}"))?
        .receiver()
    {
        Receiver::Shielded(addr) => addr,
        Receiver::Transparent(_) => {
            return Err("recipient must be a shielded (xus1…) or unified address".to_string())
        }
    };

    let store = scan_store(rpc, seed)?;
    let zkey = ShieldedKey::from_seed(seed).ok_or("invalid shielded key")?;
    let unspent = store.unspent();
    // A spend consumes ONE note, so pick the smallest unspent note that covers the
    // amount (minimizes change); fail clearly if no single note is large enough.
    let (note, pos) = unspent
        .iter()
        .filter(|(n, _)| n.value() >= amount)
        .min_by_key(|(n, _)| n.value())
        .ok_or_else(|| {
            let largest = unspent.iter().map(|(n, _)| n.value()).max().unwrap_or(0);
            format!(
                "no single shielded note covers {} XUS (largest note is {} XUS) — \
                 de-shield/consolidate first",
                grains_to_xus_plain(grains),
                grains_to_xus_plain(largest as u128),
            )
        })?;
    let (path, anchor) = store.witness(*pos).ok_or("could not witness the note")?;

    let params = {
        let cached = params_cache.lock().ok().and_then(|p| p.clone());
        match cached {
            Some(p) => p,
            None => {
                begin(action, "building the shielded prover (one-time, ~seconds)…");
                let p = Arc::new(ShieldedParams::build());
                if let Ok(mut slot) = params_cache.lock() {
                    *slot = Some(p.clone());
                }
                p
            }
        }
    };
    begin(action, "proving the private transfer (real Halo2)…");
    let bundle =
        shielded_transfer_with_change(&params, &zkey, note, path, anchor, &recipient_addr, amount)
            .map_err(|e| e.to_string())?;

    let client = RpcClient::new(rpc.to_string()).with_timeout(Duration::from_secs(60));
    let kp = Keypair::hybrid_from_seed(seed);
    let from = AccountId::new(signer).map_err(|e| e.to_string())?;
    let nonce = client.nonce(&from).map_err(|e| e.to_string())?;
    let tx = Transaction {
        signer: from,
        public_key: kp.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign(tx, &kp).map_err(|e| e.to_string())?;
    let txid = client.submit_transaction(&stx).map_err(|e| e.to_string())?;
    // Confirm the spend actually applied on-chain before reporting success, so a
    // rejected private transfer is never mistaken for a confirmed one.
    begin(action, "submitted — waiting for on-chain confirmation…");
    await_receipt(&client, &txid, 90)?;
    Ok(txid.to_hex())
}

// ---------------------------------------------------------------------------
// encrypted wallet keystore (Argon2id + ChaCha20-Poly1305, via sov-rpc)
// ---------------------------------------------------------------------------

/// The user's home directory, cross-platform: `HOME` on Unix/macOS, `USERPROFILE`
/// on Windows (its standard home variable). This is why the wallet file, device
/// key, and auto-save all resolve identically on every OS.
fn home_dir() -> Result<PathBuf, String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .map_err(|_| "no home directory (HOME / USERPROFILE unset)".to_string())
}

/// `<home>/.sov-station/wallets.keystore`.
fn keystore_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".sov-station").join("wallets.keystore"))
}

fn write_keystore(json: &str) -> Result<String, String> {
    let path = keystore_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, format!("{json}\n")).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

fn read_keystore() -> Result<String, String> {
    let path = keystore_path()?;
    std::fs::read_to_string(&path).map_err(|e| format!("{e} (nothing saved yet?)"))
}

/// The auto-persist file: wallets are encrypted to this on every change and
/// reloaded from it on launch (no passphrase). `<home>/.sov-station/wallets.auto`.
fn autosave_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".sov-station").join("wallets.auto"))
}

/// The device key file (owner-only). Holds the random key the auto-persist file
/// is encrypted under, so auto-load needs no passphrase yet the file is not
/// plaintext. `<home>/.sov-station/device.key`.
fn device_key_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".sov-station").join("device.key"))
}

/// Restrict a file to owner read/write (0600) on Unix; best-effort elsewhere.
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path; // NTFS ACLs already default to the owning user.
    }
}

/// Read a LEGACY device key (64 hex chars) if one exists — read-only, never
/// created. Wallets used to be auto-encrypted under this on-disk key; the store is
/// now passphrase-encrypted, so this exists only to MIGRATE an old `wallets.auto`
/// on first unlock (decrypt with the device key → re-encrypt under the passphrase →
/// delete the file). Returns an error when there is no legacy key.
fn legacy_device_key_hex() -> Result<String, String> {
    let path = device_key_path()?;
    let s = std::fs::read_to_string(&path)
        .map_err(|_| "no legacy device key".to_string())?
        .trim()
        .to_string();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err("legacy device key is malformed".to_string())
    }
}

/// Delete the legacy device-key file once its `wallets.auto` has been migrated to
/// passphrase encryption — so no decryption key is ever left on disk.
fn remove_legacy_device_key() {
    if let Ok(path) = device_key_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Minimum length for a new master passphrase.
const PASSPHRASE_MIN_LEN: usize = 8;

/// Whether a first-run passphrase is acceptable to COMMIT: non-empty, at least
/// [`PASSPHRASE_MIN_LEN`] characters, and the confirmation matches exactly. The
/// match check is the whole point — it stops a typo from silently becoming the key.
fn passphrase_setup_valid(pw: &str, confirm: &str) -> bool {
    !pw.is_empty() && pw.chars().count() >= PASSPHRASE_MIN_LEN && pw == confirm
}

/// Which button (if any) the create-a-passphrase form reported this frame.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum SetupAction {
    None,
    Set,
    Cancel,
}

/// Render the create-a-passphrase form into `ui`. Returns which button fired and the
/// "Set passphrase" button's rect (exposed so a headless test can click it). The Set
/// button is ENABLED only when [`passphrase_setup_valid`] holds, so a mismatch or a
/// too-short passphrase can never be committed — this is the typo/lockout guard, and
/// the test drives this exact function.
fn render_passphrase_setup(
    ui: &mut egui::Ui,
    pw: &mut String,
    pw2: &mut String,
) -> (SetupAction, egui::Rect) {
    let red = egui::Color32::from_rgb(220, 80, 80);
    let amber = egui::Color32::from_rgb(220, 160, 60);
    let green = egui::Color32::from_rgb(80, 200, 120);
    ui.heading("🔐  Create a passphrase");
    ui.add_space(8.0);
    ui.label(
        "This encrypts your wallets on this device and is required on every launch. \
         There is no reset — if you forget it, the only recovery is re-importing each \
         wallet from its 24-word phrase. Write it down.",
    );
    ui.add_space(16.0);
    ui.add(
        egui::TextEdit::singleline(pw)
            .password(true)
            .hint_text("passphrase")
            .desired_width(280.0),
    );
    ui.add_space(6.0);
    ui.add(
        egui::TextEdit::singleline(pw2)
            .password(true)
            .hint_text("re-enter passphrase")
            .desired_width(280.0),
    );
    ui.add_space(10.0);
    let too_short = pw.chars().count() < PASSPHRASE_MIN_LEN;
    let mismatch = pw.as_str() != pw2.as_str();
    let ok = passphrase_setup_valid(pw, pw2);
    // Live feedback so a mismatch/typo is caught BEFORE it's committed.
    if pw.is_empty() && pw2.is_empty() {
        ui.label(
            egui::RichText::new(format!("at least {PASSPHRASE_MIN_LEN} characters"))
                .small()
                .weak(),
        );
    } else if too_short {
        ui.colored_label(
            amber,
            format!("use at least {PASSPHRASE_MIN_LEN} characters"),
        );
    } else if mismatch {
        ui.colored_label(red, "✗ passphrases don't match");
    } else {
        ui.colored_label(green, "✓ passphrases match");
    }
    ui.add_space(12.0);
    let mut action = SetupAction::None;
    let mut set_rect = egui::Rect::NOTHING;
    ui.horizontal(|ui| {
        let set = ui.add_enabled(ok, egui::Button::new("Set passphrase"));
        set_rect = set.rect;
        if set.clicked() {
            action = SetupAction::Set;
        }
        if ui.button("Cancel").clicked() {
            action = SetupAction::Cancel;
        }
    });
    (action, set_rect)
}

/// The at-rest key for a wallet's shielded-note CACHE, derived from that wallet's
/// own seed (domain-separated). The seed is the secret we already scan with, so the
/// cache needs no separate key on disk and is unreadable without the seed.
fn notes_cache_key(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sov-station/notes-cache/v1");
    h.update(seed);
    h.finalize().into()
}

/// Decode a 64-char hex string into a 32-byte seed.
fn hex_decode32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("seed must be 64 hex chars".to_string());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Decode an arbitrary-length hex string into bytes (for NFT token ids).
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("token id must be an even-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// local node supervision
// ---------------------------------------------------------------------------

/// Resolve a chain binary (`sov-testnet`, `sov-rpcd`) from the repo layout
/// (`node/` sits beside `chain/`). Picks the **most recently built** profile so a
/// stale `release` never shadows a fresh `debug` build (or vice-versa) during
/// development; a shipped app has only one profile, making this a no-op there.
fn chain_bin(name: &str) -> Option<PathBuf> {
    // Executable name carries the platform suffix (`.exe` on Windows, empty
    // elsewhere) so the lookup is identical on every OS.
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);

    // SHIPPED APP: look beside the running executable first (a packaged .dmg/.exe
    // bundles the chain helpers next to `sov-station` — on macOS in the .app's
    // Contents/MacOS), so a distributed build is self-contained, no checkout needed.
    if let Ok(cur) = std::env::current_exe() {
        if let Some(beside) = cur.parent().map(|d| d.join(&exe)) {
            if beside.exists() {
                return Some(beside);
            }
        }
    }

    // DEV CHECKOUT: fall back to the repo's build output (`node/` beside `chain/`).
    // PREFER the optimized `release` node — it is the one a station should run.
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?;
    ["release", "debug"]
        .iter()
        .map(|profile| repo.join("chain").join("target").join(profile).join(&exe))
        .find(|p| p.exists())
}

/// The directory the GUI's supervised local node keeps its chain + keystore in.
fn local_node_dir() -> PathBuf {
    std::env::temp_dir().join("sov-station-node")
}

/// Where the seed/bootstrap peer address is persisted. CRITICAL: this lives OUTSIDE the
/// node data dir, in the user's home directory, so that "Reset local chain" (which wipes
/// the data dir) and a fresh install NEVER lose the configured peer — peer connection
/// must survive a reset. Falls back to the temp dir if no home is available.
fn peer_config_path() -> PathBuf {
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(".sov-station-peer")
}

/// The seed/bootstrap peer the operator configured (if any), so the Peer field is
/// pre-filled and the node auto-dials it on every launch (Bitcoin-style: configure a
/// seed once, then it is automatic) — and, crucially, it persists across a chain reset.
fn read_saved_peer() -> String {
    std::fs::read_to_string(peer_config_path())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Persist the seed/bootstrap peer outside the data dir so the operator's choice survives
/// restarts, fresh installs, AND a "Reset local chain". (The per-launch node config still
/// gets it via `build_and_run_node`, for the node process to dial.)
fn save_peer(peer: &str) {
    let _ = std::fs::write(peer_config_path(), peer.trim());
}

/// Where the UI theme choice is persisted (next to the peer file, outside the data dir).
fn theme_config_path() -> PathBuf {
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(".sov-station-theme")
}

/// The saved theme mode — dark unless the operator chose light last time.
fn read_saved_theme() -> bool {
    match std::fs::read_to_string(theme_config_path()) {
        Ok(s) => s.trim() != "light",
        Err(_) => true,
    }
}

/// Persist the theme choice so it survives restarts.
fn save_theme(dark: bool) {
    let _ = std::fs::write(theme_config_path(), if dark { "dark" } else { "light" });
}

/// Add an inbound Windows Defender Firewall allow-rule for this executable, so LAN
/// peers can reach the P2P (9645/TCP) + discovery (9646/UDP) ports. Unsigned apps
/// are inbound-blocked by default on Windows, which silently prevents peering; this
/// requests the exception (one UAC prompt). Best-effort; a no-op off Windows.
#[cfg(windows)]
fn add_firewall_rule() {
    if let Ok(exe) = std::env::current_exe() {
        // Elevate via UAC and add a program-scoped inbound allow rule (covers both
        // the P2P and the multicast discovery ports).
        let ps = format!(
            "Start-Process netsh -Verb RunAs -WindowStyle Hidden -ArgumentList \
             'advfirewall firewall add rule name=\"SOV Station\" dir=in action=allow \
             program=\"{}\" enable=yes profile=any'",
            exe.display()
        );
        // Fire-and-forget (`spawn`, not `status`): the elevated `Start-Process -Verb
        // RunAs` raises a UAC prompt, and waiting on it would BLOCK node startup until
        // the user clicks (or indefinitely if they ignore it). Spawning lets the node
        // come up immediately while the rule is added in the background.
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps])
            .spawn();
    }
}
#[cfg(not(windows))]
fn add_firewall_rule() {}

/// Ensure the firewall exception exists, ONCE per machine (marker-gated), so a
/// fresh Windows install auto-allows itself on first node start — keeping LAN
/// discovery zero-config (no manual firewall navigation, no IP entry). No-op off
/// Windows and after the first successful attempt.
fn ensure_firewall(logs: &Arc<Mutex<Vec<String>>>) {
    #[cfg(windows)]
    {
        let marker = match home_dir() {
            Ok(h) => h.join(".sov-station").join("firewall.ok"),
            Err(_) => return,
        };
        if marker.exists() {
            return;
        }
        add_firewall_rule();
        if let Some(d) = marker.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(&marker, "1");
        push_log(
            logs,
            "requested Windows Firewall inbound allow for LAN peers (one-time)",
        );
    }
    #[cfg(not(windows))]
    {
        let _ = logs;
    }
}

/// This machine's LAN IPv4 address, for telling the operator what to seed the
/// OTHER machine to (e.g. `192.168.0.244`). Best-effort; `None` if offline.
fn lan_ipv4() -> Option<String> {
    // Open a UDP socket "to" a public address (no packets are sent for UDP connect)
    // and read back the local address the OS would route from — the standard
    // dependency-free way to discover the primary LAN IP.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4.to_string()),
        _ => None,
    }
}

/// File holding the running local node's PID, so it can be stopped even across a
/// GUI restart (otherwise an orphaned node keeps mining with no way to halt it).
fn node_pid_path() -> PathBuf {
    local_node_dir().join("node.pid")
}

/// The PID recorded in the pidfile, if any.
fn read_node_pid() -> Option<u32> {
    std::fs::read_to_string(node_pid_path())
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Whether process `pid` is alive. Unix: `kill -0` (a no-signal liveness probe).
/// Windows: `tasklist` filtered by PID (its output names the image only if the
/// process exists). Both are real probes, so adopt-on-launch behaves the same.
/// Force-stop process `pid`. The block log is append-only and crash-recovers, so
/// a hard kill is safe for the node.
fn kill_pid(pid: u32) {
    #[cfg(unix)]
    let mut cmd = Command::new("kill");
    #[cfg(unix)]
    cmd.arg("-9").arg(pid.to_string());
    #[cfg(windows)]
    let mut cmd = Command::new("taskkill");
    #[cfg(windows)]
    cmd.args(["/PID", &pid.to_string(), "/F"]);
    let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// Stop the local node recorded in the pidfile (if any) and clear the pidfile.
fn stop_tracked_node() {
    if let Some(pid) = read_node_pid() {
        kill_pid(pid);
    }
    let _ = std::fs::remove_file(node_pid_path());
}

/// SINGLE INSTANCE: terminate any OTHER running copy of this app before we start a node,
/// so a stale ghost (a previous launch that didn't fully exit and release its sockets)
/// cannot hold the P2P/RPC port and fail the start with "address already in use"
/// (os error 10048 on Windows, 48 on macOS). Best-effort; never kills THIS process. This
/// is the "I want exactly ONE node, no ghosts" guarantee enforced at the OS level.
fn kill_other_instances() {
    let self_pid = std::process::id();
    let Some(name) = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    else {
        return;
    };
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", &name, "/FI", &format!("PID ne {self_pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        if let Ok(out) = Command::new("pgrep").arg("-x").arg(&name).output() {
            for pid in String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
            {
                if pid != self_pid {
                    kill_pid(pid);
                }
            }
        }
    }
}

/// The testnet-1 genesis spec, COMPILED INTO the binary so a shipped app is fully
/// self-contained — no source checkout, no reliance on the build-machine path in
/// `CARGO_MANIFEST_DIR` (which does not exist on a user's machine). This is the same
/// frozen spec the dev tree ships in `chain/specs/testnet-1.json`.
const TESTNET_1_SPEC: &str = include_str!("../../chain/specs/testnet-1.json");

/// The genesis spec text for `spec_filename`, from the embedded copy. Only the
/// shipped testnet is bundled; other networks return a clear error rather than a
/// confusing missing-file failure.
fn embedded_spec(spec_filename: &str) -> Result<&'static str, String> {
    match spec_filename {
        "testnet-1.json" => Ok(TESTNET_1_SPEC),
        other => Err(format!(
            "no genesis spec bundled for this network ({other}) — this is a testnet build"
        )),
    }
}

/// Set up (if needed) and start a local node **in-process**, returning a handle
/// whose lifetime is the app's. The one-time chain setup (`sov-testnet join`, which
/// writes the genesis spec + config) is a transient helper that runs and exits; the
/// long-running node itself is embedded here via the [`sov_rpc`] library — no
/// `sov-rpcd` subprocess, so nothing can outlive the GUI.
fn build_and_run_node(
    spec_filename: &str,
    account: &str,
    seed: [u8; 32],
    peer: &str,
    logs: &Arc<Mutex<Vec<String>>>,
) -> Result<EmbeddedNode, String> {
    // SINGLE INSTANCE: kill any ghost copy of this app first, so a leftover process from
    // a previous launch can't still hold the P2P/RPC ports and fail our bind with
    // "address already in use" (os error 10048/48) — the real cause of "node start
    // FAILED: p2p bind". One node, no ghosts.
    kill_other_instances();
    // On Windows, make sure we're allowed inbound through the firewall (once), so LAN
    // peers can actually reach this node — otherwise discovery silently never connects.
    ensure_firewall(logs);
    let node_dir = local_node_dir();
    let testnet = chain_bin("sov-testnet")
        .ok_or("sov-testnet not built (run `cargo build --release` in chain/)")?;

    // Safety: never silently destroy a chain. If this chain was mined to a DIFFERENT
    // wallet, refuse rather than wiping it — the user selects that wallet, or uses
    // "Reset local chain" to wipe deliberately. (A real chain is never silently
    // erased from under you.)
    let marker = node_dir.join("miner.txt");
    let prev = std::fs::read_to_string(&marker).unwrap_or_default();
    if !prev.trim().is_empty() && prev.trim() != account {
        return Err(format!(
            "this local chain was mined to a different wallet ({}…); starting as {}… would wipe \
             it. Select that wallet, or use “Reset local chain” to start fresh deliberately.",
            &prev.trim()[..prev.trim().len().min(12)],
            &account[..account.len().min(12)],
        ));
    }

    // One-time setup: wrap a local node around the frozen spec, mining to THIS
    // wallet's implicit account (so its coinbase is claimable only by its key). The
    // genesis spec is EMBEDDED in the binary (see `embedded_spec`), so a shipped
    // app is self-contained — it does not depend on a source checkout or the
    // build-machine path baked into `CARGO_MANIFEST_DIR`.
    if !node_dir.join("testnet.json").exists() {
        let spec_text = embedded_spec(spec_filename)?;
        std::fs::create_dir_all(&node_dir).map_err(|e| format!("create node dir: {e}"))?;
        let spec_path = node_dir.join(spec_filename);
        std::fs::write(&spec_path, spec_text).map_err(|e| format!("write spec: {e}"))?;
        let status = Command::new(&testnet)
            .args(["join", "--spec"])
            .arg(&spec_path)
            .args(["--out"])
            .arg(&node_dir)
            .args(["--name", account])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("join failed to run: {e}"))?;
        if !status.success() {
            return Err("`sov-testnet join` failed".to_string());
        }
        // NOTE: block cadence is no longer a fixed sleep — the node mines CONTINUOUSLY
        // and the per-block difficulty retarget regulates the rate to the genesis
        // `block_time_ms` (30 s for testnet-1) for any number of miners, so the
        // node-config `block_time_ms` is intentionally left untouched (unused by the
        // continuous miner).
    }

    // Point the node's keystore at this wallet's account+seed, so the coinbase
    // funds a wallet the GUI controls. (Plaintext testnet keystore by design.)
    let keystore_json = json!({
        "miners": [{ "account": account, "seed_hex": hex_lower(&seed), "scheme": "hybrid65" }]
    });
    std::fs::write(
        node_dir.join("node-1/keystore.json"),
        keystore_json.to_string(),
    )
    .map_err(|e| format!("could not set miner keystore: {e}"))?;
    let _ = std::fs::write(&marker, account);

    // ── Run the node IN-PROCESS via the library (mirrors `sov-rpcd`'s `run`). ──
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("read {p:?}: {e}"));
    let mut config: NodeConfig =
        serde_json::from_str(&read(&node_dir.join("node-1/node-config.json"))?)
            .map_err(|e| format!("node-config: {e}"))?;
    // The config's data_dir is relative to the node dir (the old subprocess set its
    // cwd there); resolve it to an absolute path for the in-process daemon.
    config.data_dir = node_dir
        .join(&config.data_dir)
        .to_string_lossy()
        .into_owned();
    // Expose the JSON-RPC on the LAN (not just loopback), so the OTHER machine — and
    // the two-node conformance dashboard / a remote explorer — can reach this node's
    // RPC. The RPC surface is key-free (reads + submit of an ALREADY-signed tx; it
    // never signs or holds wallet keys), and P2P is already 0.0.0.0, so this matches
    // the node's posture. Migrated in place so existing installs pick it up with no reset.
    if let Some(port) = config.rpc_addr.strip_prefix("127.0.0.1:") {
        config.rpc_addr = format!("0.0.0.0:{port}");
    } else if let Some(port) = config.rpc_addr.strip_prefix("localhost:") {
        config.rpc_addr = format!("0.0.0.0:{port}");
    }
    // Seed/bootstrap peer (Bitcoin `addnode` style): auto-dial it on startup and
    // gossip-discover the rest. Persist it into the node config so it is automatic
    // on every future launch — configure a seed once, then it just works.
    let peer = peer.trim();
    if !peer.is_empty() {
        config.bootstrap_peers = vec![peer.to_string()];
        let cfg_path = node_dir.join("node-1/node-config.json");
        if let Ok(text) = std::fs::read_to_string(&cfg_path) {
            if let Ok(mut v) = serde_json::from_str::<Value>(&text) {
                v["bootstrap_peers"] = json!([peer]);
                let _ = std::fs::write(&cfg_path, v.to_string());
            }
        }
    }
    // Always refresh chain-spec.json from the EMBEDDED spec, so a new build's spec
    // changes take effect on an EXISTING chain instead of being frozen at first-run.
    // testnet-1's genesis is frozen (hash 5e9f3cc5…) and the de-shield limiter params
    // are NOT genesis-header fields, so this never alters the genesis ⇒ the persisted
    // chain still resumes, no reset. (`sov-testnet join` writes chain-spec.json as a
    // verbatim passthrough of the spec, so the embedded spec IS the on-disk content —
    // this just keeps the two consistent across upgrades.)
    let spec_text = embedded_spec(spec_filename)?;
    std::fs::write(node_dir.join("chain-spec.json"), spec_text)
        .map_err(|e| format!("refresh chain-spec: {e}"))?;
    let spec = ChainSpec::from_json(&read(&node_dir.join("chain-spec.json"))?)
        .map_err(|e| format!("chain-spec: {e}"))?;
    let keystore =
        Keystore::from_encrypted_or_plain(&read(&node_dir.join("node-1/keystore.json"))?, None)
            .map_err(|e| format!("keystore: {e}"))?;
    let genesis = spec
        .to_genesis_config()
        .map_err(|e| format!("genesis: {e}"))?;
    let miner_keys = keystore.keys().map_err(|e| format!("keys: {e}"))?;

    // Build + replay the persisted block log to resume state. This is the bulk of
    // startup time on a long chain — so STREAM live "indexing N/total" progress to the
    // node log (instead of appearing to hang), and log how long it took at the end.
    push_log(logs, "indexing local chain — replaying block log…");
    let t0 = std::time::Instant::now();
    let mut last_pct = u64::MAX;
    let mut daemon = Daemon::new_with_progress(
        &genesis,
        &config.data_dir,
        config.mempool_capacity,
        config.max_block_txs,
        miner_keys,
        &mut |done, total| {
            // One line per ~percent so it streams visibly without flooding.
            let pct = if total == 0 { 100 } else { done * 100 / total };
            if pct != last_pct {
                last_pct = pct;
                push_log(logs, format!("  indexing… {done}/{total} blocks ({pct}%)"));
            }
        },
    )
    .map_err(|e| format!("daemon: {e}"))?;
    push_log(
        logs,
        format!(
            "✓ indexed {} block(s) in {:.1}s — chain head at height {}",
            daemon.resumed_blocks(),
            t0.elapsed().as_secs_f64(),
            daemon.height()
        ),
    );
    let checkpoints = config
        .checkpoints
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("checkpoints: {e}"))?;
    if !checkpoints.is_empty() {
        daemon = daemon.with_checkpoints(checkpoints);
    }

    // Shared sync telemetry: the P2P engine writes it, the mining loop reads it to GATE
    // production (a joining node downloads the existing chain BEFORE it mines, instead of
    // forking), and the UI reads it for the live peer/sync status. One handle, cloned to
    // every party — this is what makes bootstrapping a new node deterministic.
    let sync = Arc::new(SyncShared::new());

    // P2P is ALWAYS on (the node discovers + peers with other machines); solo
    // mining works regardless, since a node produces blocks with zero peers. Bound
    // to the same shared node so blocks/txs flow both ways.
    let p2p = match config.p2p_addr.as_deref() {
        Some(p2p_addr) => {
            let (acct, keypair) = keystore
                .keys()
                .map_err(|e| format!("keys: {e}"))?
                .into_iter()
                .next()
                .ok_or("p2p_addr set but no miner key")?;
            let p2p = P2p::bind(
                daemon.node(),
                P2pConfig {
                    chain_id: genesis.chain_id.clone(),
                    genesis_hash: daemon.genesis_hash(),
                    account: acct,
                    keypair,
                },
                p2p_addr,
            )
            .map_err(|e| format!("p2p bind: {e}"))?
            .with_block_log(daemon.block_log())
            .with_bootstrap(config.bootstrap_peers.clone())
            .with_sync_status(Arc::clone(&sync))
            .with_log_sink(logs.clone());
            // Surface transport-level dial/handshake diagnostics in the Node tab too,
            // so peering is never a silent black box (dialing → tcp connected → link up,
            // or the exact failure).
            p2p.tcp().set_log_sink(logs.clone());
            // Kick an immediate, NON-BLOCKING dial of each saved seed peer and report
            // the resolved target (or a clear error) right away — no 5s startup stall on
            // a peer that is still down; the engine's reconnect loop keeps retrying.
            for peer in &config.bootstrap_peers {
                match p2p.tcp().request_reconnect(peer) {
                    Ok(addrs) => {
                        let list = addrs
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        push_log(logs, format!("seed peer {peer} → dialing {list}"));
                    }
                    Err(e) => push_log(
                        logs,
                        format!("seed peer '{peer}' is not a valid address: {e}"),
                    ),
                }
            }
            let bound = p2p.local_addr();
            // mDNS-style LAN auto-discovery: find + dial same-chain peers on the
            // local network with zero configuration (no seed address needed).
            p2p.tcp().enable_lan_discovery(&genesis.chain_id);
            daemon = daemon.with_gossip(p2p.tcp());
            push_log(
                logs,
                format!("P2P on {bound} — LAN auto-discovery on (peers welcome)"),
            );
            Some(p2p.start())
        }
        None => {
            push_log(logs, "P2P disabled in config (no p2p_addr)");
            None
        }
    };

    // Gate mining on the SAME telemetry the P2P engine writes: while behind a heavier
    // peer chain, the production loop does not mine (it would only fork). A solo node is
    // never behind, so it still bootstraps the network.
    let handle = daemon
        .with_sync_status(Arc::clone(&sync))
        .with_log_sink(logs.clone())
        .run(&config.rpc_addr, config.rpc_workers, config.block_time_ms)
        .map_err(|e| format!("run: {e}"))?;
    push_log(
        logs,
        format!(
            "node up — RPC on http://{} — mining every {}ms (paused while syncing a heavier peer)",
            handle.rpc_addr(),
            config.block_time_ms
        ),
    );
    Ok(EmbeddedNode {
        daemon: handle,
        p2p,
        account: account.to_string(),
        sync,
    })
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

/// Open the SOV Station window, polling `rpc` for live node state.
pub fn run(rpc: String) -> Result<(), String> {
    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let config = Arc::new(Mutex::new(Config {
        rpc,
        accounts: DEFAULT_ACCOUNTS.iter().map(|s| s.to_string()).collect(),
    }));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("SOV Station"),
        ..Default::default()
    };

    let poll_snap = snapshot.clone();
    let poll_cfg = config.clone();
    eframe::run_native(
        "SOV Station",
        options,
        Box::new(move |cc| {
            install_theme(&cc.egui_ctx, read_saved_theme());
            spawn_poller(poll_snap, poll_cfg, cc.egui_ctx.clone());
            Ok(Box::new(Station::new(snapshot, config)))
        }),
    )
    .map_err(|e| format!("GUI failed: {e}"))
}

/// Background poller: every second, read the node into the shared snapshot and
/// nudge the UI to repaint. Honors the (UI-editable) RPC endpoint and accounts.
fn spawn_poller(snapshot: Arc<Mutex<Snapshot>>, config: Arc<Mutex<Config>>, ctx: egui::Context) {
    thread::spawn(move || {
        // Count consecutive failed polls so a TRANSIENT timeout — e.g. while the
        // node is busy importing a batch during catch-up — does not flicker the UI
        // to "offline/transport error". We keep showing the last good snapshot and
        // only surface offline after several misses in a row.
        let mut consecutive_fail = 0u32;
        loop {
            let cfg = match config.lock() {
                Ok(c) => c.clone(),
                Err(_) => break,
            };
            // A generous timeout: RPC shares the node lock with block import, which
            // can briefly hold it during a sync burst.
            let client = RpcClient::new(cfg.rpc.clone()).with_timeout(Duration::from_secs(6));
            let snap = poll(&client, &cfg);
            if snap.online {
                consecutive_fail = 0;
                if let Ok(mut s) = snapshot.lock() {
                    *s = snap;
                }
            } else {
                consecutive_fail += 1;
                // Only commit the offline/error snapshot after 3 straight misses, so
                // a single busy/slow poll doesn't replace good live data.
                if consecutive_fail >= 3 {
                    if let Ok(mut s) = snapshot.lock() {
                        *s = snap;
                    }
                }
            }
            ctx.request_repaint();
            thread::sleep(Duration::from_millis(1000));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny keystore for the crypto round-trip tests below.
    fn one_wallet_keystore() -> Keystore {
        Keystore {
            miners: vec![KeystoreEntry {
                account: "test.wallet".to_string(),
                seed_hex: hex_lower(&[7u8; 32]),
                scheme: Some("hybrid65".to_string()),
                mnemonic: Some("abandon ability able".to_string()),
                public_key: None,
            }],
        }
    }

    #[test]
    fn passphrase_store_round_trips() {
        // What auto_save → try_unlock (current format) relies on: encrypt under a
        // passphrase, decrypt under the SAME passphrase, recover the entry.
        let json = one_wallet_keystore()
            .to_encrypted_json("correct horse battery staple")
            .expect("encrypt");
        let back = Keystore::from_encrypted_or_plain(&json, Some("correct horse battery staple"))
            .expect("decrypt");
        assert_eq!(back.miners.len(), 1);
        assert_eq!(back.miners[0].seed_hex, hex_lower(&[7u8; 32]));
        assert_eq!(
            back.miners[0].mnemonic.as_deref(),
            Some("abandon ability able")
        );
    }

    #[test]
    fn migration_invariant_device_key_then_passphrase() {
        // The safety property behind try_unlock's two-step: a store sealed under the
        // legacy DEVICE KEY does NOT decrypt under a (different) passphrase — so the
        // passphrase attempt cleanly fails and we fall through to the device-key
        // branch — yet decrypts under the device key, and re-encrypting under the
        // passphrase then decrypts under the passphrase. No wallet is ever orphaned.
        let device_key = "a".repeat(64); // shape of a legacy device key
        let passphrase = "my new passphrase";
        let legacy = one_wallet_keystore()
            .to_encrypted_json(&device_key)
            .expect("seal under device key");

        // passphrase-first attempt fails (wrong key) → migration branch taken
        assert!(Keystore::from_encrypted_or_plain(&legacy, Some(passphrase)).is_err());
        // device-key attempt succeeds → wallets recovered for migration
        let recovered = Keystore::from_encrypted_or_plain(&legacy, Some(&device_key))
            .expect("device-key decrypt");
        assert_eq!(recovered.miners[0].seed_hex, hex_lower(&[7u8; 32]));
        // re-seal under the passphrase → now opens with the passphrase
        let migrated = recovered.to_encrypted_json(passphrase).expect("re-seal");
        let after = Keystore::from_encrypted_or_plain(&migrated, Some(passphrase)).expect("open");
        assert_eq!(after.miners[0].seed_hex, hex_lower(&[7u8; 32]));
    }

    #[test]
    fn passphrase_setup_requires_match_and_length() {
        // The check that prevents a typo'd passphrase from becoming the key.
        assert!(!passphrase_setup_valid("", ""), "empty rejected");
        assert!(
            !passphrase_setup_valid("short", "short"),
            "too short rejected"
        );
        assert!(
            !passphrase_setup_valid("longenough", "longenuogh"),
            "mismatch rejected (typo in confirm)"
        );
        assert!(
            !passphrase_setup_valid("longenough", ""),
            "empty confirm rejected"
        );
        assert!(
            passphrase_setup_valid("correct horse", "correct horse"),
            "matching + long enough accepted"
        );
    }

    /// A real headless CLICK-TEST: render the actual create-a-passphrase screen and
    /// inject a genuine pointer press+release on the rendered "Set passphrase" button.
    /// It must fire ONLY when the two inputs match (and meet the length floor) — i.e.
    /// the disabled-button guard against a typo'd, unconfirmed passphrase actually
    /// works at the widget level, not just in the validity helper.
    #[test]
    fn setup_screen_set_button_clicks_only_when_inputs_match() {
        use egui::{Event, Modifiers, PointerButton, RawInput};

        // Run ONE headless frame; returns which button fired + the Set button's rect.
        fn frame(
            ctx: &egui::Context,
            p: &mut String,
            p2: &mut String,
            input: RawInput,
        ) -> (SetupAction, egui::Rect) {
            let mut action = SetupAction::None;
            let mut rect = egui::Rect::NOTHING;
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let (a, r) = render_passphrase_setup(ui, p, p2);
                    action = a;
                    rect = r;
                });
            });
            (action, rect)
        }

        fn click_set(pw: &str, pw2: &str) -> SetupAction {
            let ctx = egui::Context::default();
            let mut p = pw.to_string();
            let mut p2 = pw2.to_string();
            let btn = PointerButton::Primary;
            let m = Modifiers::default();
            // Frame 1: lay out the screen and capture the Set button's rect.
            let (_, rect) = frame(&ctx, &mut p, &mut p2, RawInput::default());
            let c = rect.center();
            // Frame 2: press on the button.
            frame(
                &ctx,
                &mut p,
                &mut p2,
                RawInput {
                    events: vec![
                        Event::PointerMoved(c),
                        Event::PointerButton {
                            pos: c,
                            button: btn,
                            pressed: true,
                            modifiers: m,
                        },
                    ],
                    ..Default::default()
                },
            );
            // Frame 3: release on the button → a click registers (if it's enabled).
            let (action, _) = frame(
                &ctx,
                &mut p,
                &mut p2,
                RawInput {
                    events: vec![
                        Event::PointerMoved(c),
                        Event::PointerButton {
                            pos: c,
                            button: btn,
                            pressed: false,
                            modifiers: m,
                        },
                    ],
                    ..Default::default()
                },
            );
            action
        }

        // Matching + long enough → the button is live, the click commits.
        assert_eq!(
            click_set("correct horse", "correct horse"),
            SetupAction::Set,
            "matching passphrases: Set should fire on click"
        );
        // A typo in the confirm → button disabled → clicking does nothing.
        assert_eq!(
            click_set("correct horse", "correct hoarse"),
            SetupAction::None,
            "mismatch: Set must NOT fire (no silent typo lockout)"
        );
        // Too short → button disabled.
        assert_eq!(
            click_set("short", "short"),
            SetupAction::None,
            "too short: Set must NOT fire"
        );
    }

    #[test]
    fn notes_cache_key_is_deterministic_and_seed_bound() {
        let a = notes_cache_key(&[1u8; 32]);
        let b = notes_cache_key(&[1u8; 32]);
        let c = notes_cache_key(&[2u8; 32]);
        assert_eq!(a, b, "same seed → same cache key");
        assert_ne!(a, c, "different seed → different cache key");
        assert_ne!(a, [1u8; 32], "not the raw seed (domain-separated)");
    }

    #[test]
    fn xus_groups_thousands_and_trims_fraction() {
        assert_eq!(xus("0"), "0");
        assert_eq!(xus("100000000"), "1");
        assert_eq!(xus("1250000000000"), "12,500"); // 12.5k XUS
        assert_eq!(xus("150000000"), "1.5");
        assert_eq!(xus("100000000000000000"), "1,000,000,000");
    }

    #[test]
    fn grains_to_xus_plain_has_no_separators_and_round_trips() {
        // The Max button writes this back into the input, so it must re-parse.
        for g in [
            0u128,
            1,
            100_000_000,
            150_000_000,
            1_250_000_000_000,
            999_999_999,
        ] {
            let s = grains_to_xus_plain(g);
            assert!(!s.contains(','), "{s} must be parseable by parse_xus");
            assert_eq!(parse_xus(&s), Some(g), "round-trip {g}");
        }
    }

    #[test]
    fn tx_status_colors_success_green_and_any_failure_red() {
        // Success: the ✓ convention.
        assert!(matches!(
            tx_status("✓ sent 5 XUS to alice.sov (tx ab12cd34)"),
            TxStatus::Ok
        ));
        assert!(matches!(
            tx_status("✓ HTLC opened — id = ff00"),
            TxStatus::Ok
        ));
        // Failure with the ✗ marker.
        assert!(matches!(
            tx_status("✗ send failed: insufficient balance"),
            TxStatus::Err
        ));
        // Failure WITHOUT a marker still goes red — the "for any reason" guarantee.
        assert!(matches!(
            tx_status("send failed: node unreachable"),
            TxStatus::Err
        ));
        assert!(matches!(
            tx_status("issue failed: bad symbol"),
            TxStatus::Err
        ));
        assert!(matches!(
            tx_status("insufficient balance for shielded value"),
            TxStatus::Err
        ));
        assert!(matches!(tx_status("invalid recipient: …"), TxStatus::Err));
        // Neutral / in-progress stays dim (not green, not red).
        assert!(matches!(
            tx_status("broadcasting signed tx…"),
            TxStatus::Info
        ));
        assert!(matches!(
            tx_status("scanning the shielded pool…"),
            TxStatus::Info
        ));
    }

    #[test]
    fn toast_chip_text_strips_the_glyph_and_caps_length() {
        // The leading status glyph (added by the action layer) is stripped — the
        // bottom-bar toast supplies its own colored glyph.
        assert_eq!(
            toast_chip_text("✓ sent 5 XUS to alice.sov", 96),
            "sent 5 XUS to alice.sov"
        );
        assert_eq!(
            toast_chip_text("✗ send failed: insufficient balance", 96),
            "send failed: insufficient balance"
        );
        assert_eq!(toast_chip_text("• broadcasting…", 96), "broadcasting…");
        // A short message is returned verbatim (no ellipsis).
        assert_eq!(toast_chip_text("ok", 96), "ok");
        // An over-long message is capped to exactly `max_chars` with a trailing ellipsis
        // so it can never blow out the single-line status bar.
        let long = "x".repeat(200);
        let capped = toast_chip_text(&long, 96);
        assert_eq!(capped.chars().count(), 96);
        assert!(capped.ends_with('…'));
        assert!(capped.starts_with(&"x".repeat(95)));
        // Char-safe truncation: a multi-byte boundary must never panic or split a glyph.
        let wide = "✓ ".to_string() + &"é".repeat(200);
        let capped = toast_chip_text(&wide, 10);
        assert_eq!(capped.chars().count(), 10);
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn send_route_detects_each_tier() {
        assert!(matches!(SendRoute::detect(""), SendRoute::Empty));
        assert!(matches!(
            SendRoute::detect("treasury.sov"),
            SendRoute::Transparent(_)
        ));
        assert!(matches!(SendRoute::detect("!!bad!!"), SendRoute::Invalid));
        // A transparent route is public; the others are private.
        assert!(!SendRoute::detect("treasury.sov").private());
        assert!(SendRoute::detect("treasury.sov").is_valid());
    }

    #[test]
    fn is_named_account_distinguishes_implicit_from_human_names() {
        assert!(is_named_account("alice.sov"));
        assert!(!is_named_account(&"a".repeat(64))); // 64-hex-ish implicit id
        assert!(!is_named_account("")); // invalid id
    }

    #[test]
    fn note_cache_blob_round_trips_and_rejects_wrong_key_or_tamper() {
        let key = [7u8; 32];
        let plaintext = b"shielded note cache: secrets must never sit in the clear";
        let blob = encrypt_blob(&key, plaintext).expect("encrypt");
        // Ciphertext is not the plaintext, and a fresh nonce is prepended.
        assert_ne!(&blob[12..], &plaintext[..]);
        // Correct key recovers exactly.
        assert_eq!(decrypt_blob(&key, &blob).as_deref(), Some(&plaintext[..]));
        // A two-different-encryptions check: random nonce ⇒ different ciphertext.
        let blob2 = encrypt_blob(&key, plaintext).expect("encrypt");
        assert_ne!(blob, blob2, "nonce must be random per write");
        // Wrong key fails closed (no panic, no plaintext).
        assert_eq!(decrypt_blob(&[8u8; 32], &blob), None);
        // Tampered ciphertext fails the AEAD tag.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(decrypt_blob(&key, &bad), None);
        // Truncated/short input is rejected, not panicked on.
        assert_eq!(decrypt_blob(&key, &blob[..8]), None);
    }

    #[test]
    fn block_row_parses_header_identity_seal_and_coinbase() {
        // A digest as `sov_getBlockDigest` returns it (incl. the new prevHash /
        // stateRoot fields the block-detail view shows).
        let digest = serde_json::json!({
            "hash": "aa".repeat(32),
            "prevHash": "bb".repeat(32),
            "stateRoot": "cc".repeat(32),
            "timestampMs": 1_700_000_000_000u64,
            "nonce": 42u64,
            "bits": 0x1d00ffffu64,
            "txIds": ["dd".repeat(32), "ee".repeat(32)],
            "coinbase": {
                "reward": "1250000000000",
                "recipients": [
                    { "role": "miner", "account": "miner.acct", "amount": "1250000000000" },
                ],
            },
        });
        let row = block_row(7, &digest);
        assert_eq!(row.height, 7);
        assert_eq!(row.hash, "aa".repeat(32));
        assert_eq!(row.prev_hash, "bb".repeat(32));
        assert_eq!(row.state_root, "cc".repeat(32));
        assert_eq!(row.nonce, 42);
        assert_eq!(row.bits, 0x1d00ffff);
        assert_eq!(row.tx_count, 2);
        assert_eq!(row.miner, "miner.acct");
        assert_eq!(row.reward, "1250000000000");
        // The entire coinbase goes to the miner — no tax.
        assert_eq!(row.miner_amount, "1250000000000");
        // Missing optional fields degrade gracefully (no panic, sensible defaults).
        let bare = block_row(0, &serde_json::json!({}));
        assert_eq!(bare.height, 0);
        assert_eq!(bare.tx_count, 0);
        assert!(bare.hash.is_empty());
    }

    #[test]
    fn palette_modes_differ_and_toggle() {
        // The light/dark accessor must actually return different values per mode, so
        // the toggle re-skins custom surfaces (not just egui's base visuals).
        palette::set_dark(true);
        assert!(palette::is_dark());
        let dark_bg = palette::bg();
        let dark_text = palette::text();
        // The SEMANTIC colors are mode-aware too — every status color, banner and
        // card tint now flows through these (no hardcoded dark RGBs left as "islands"
        // on a light background), so each must shift between modes.
        let (ds, de, dw, dl) = (
            palette::success(),
            palette::error(),
            palette::warning(),
            palette::link(),
        );
        palette::set_dark(false);
        assert!(!palette::is_dark());
        assert_ne!(dark_bg, palette::bg(), "bg differs by mode");
        assert_ne!(dark_text, palette::text(), "text differs by mode");
        assert_ne!(ds, palette::success(), "success differs by mode");
        assert_ne!(de, palette::error(), "error differs by mode");
        assert_ne!(dw, palette::warning(), "warning differs by mode");
        assert_ne!(dl, palette::link(), "link differs by mode");
        // Restore the process-wide default so nothing else observes light mode.
        palette::set_dark(true);
    }
}
