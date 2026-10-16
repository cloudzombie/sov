//! # sov-stratum — the SOV RandomX Stratum bridge
//!
//! A TCP daemon that speaks **Monero-lineage Stratum** (login/job/submit/keepalived
//! over line-delimited JSON-RPC — the dialect xmrig-class RandomX miners speak) to
//! miners on one side, and `sov_getBlockTemplate` / `sov_submitBlock` JSON-RPC to a
//! SOV node on the other. It is a **work-distribution layer only**: it adds no
//! consensus rule and can only relay a nonce the node independently re-seals and
//! fully re-validates on import (`.github/RELEASE-0.1.92.md`, Phase 2).
//!
//! Architecture (std threads, no async runtime — mirrors the other `tools/` crates):
//!
//! * a **poller** thread watches the node's height and refetches a template on tip
//!   change or refresh, then pushes a fresh job to every session;
//! * one **reader** thread per connection handles the four Stratum methods;
//! * a single **verifier** thread owns seal recomputation, so exactly one light
//!   RandomX VM (~256 MiB) exists no matter how many miners connect;
//! * optional **worker** threads (`--workers N`) grind the current template with
//!   the fast (full-dataset) VM — the built-in SOV-native miner path, so pool
//!   mining works day one with no third-party miner (each worker thread keeps its
//!   own RandomX VM; budget ~2.3 GiB per worker in fast mode).
//!
//! Every submitted share is re-sealed with the REAL `pow_seal` — the miner's
//! `result` field is cross-checked, never trusted. A seal that also clears the
//! network target is forwarded via `sov_submitBlock` with the job's **frozen**
//! `timestampMs` (the timestamp is inside the hashed blob, so miners never roll it).
//!
//! No secret material is handled anywhere in this process. In pool mode the
//! coinbase of a found block is the miner's own login account, and the payout
//! transfers inside that block were signed on the miner's machine. The pool
//! verifies those signatures and relays them. It never holds a key.
//!
//! `--solo` keeps the original single-account bridge: one `--coinbase`, no
//! sharechain. That mode is custodial if the coinbase is an operator account.
//! It exists for a miner who runs this process against their own node.

mod account;
mod guard;
mod job;
mod payout;
mod share;
mod stats;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sov_primitives::{AccountId, SigningDomain};
use sov_rpc::client::RpcClient;
use sov_sharechain::{Payouts, Share, ShareChain, ShareId};
use sov_types::{Action, SignedTransaction};

use account::parse_login;
use guard::Guard;
use job::{parse_nonce_hex, Template};
use payout::{outgoing_transfers, window_covered, TransferLeg};
use share::{
    classify_seal, difficulty_to_target256, effective_share_target, next_difficulty,
    stratum_target_hex, ShareOutcome, VardiffConfig,
};
use stats::Incoming;

/// How many issued jobs stay submittable at once (across all sessions). Old jobs
/// are evicted oldest-first; the whole book is cleared whenever the template
/// changes, so a submit against a superseded template is rejected as stale.
const MAX_LIVE_JOBS: usize = 4096;
/// Hard cap on concurrent miner connections. Past this the listener sheds new
/// connections instead of spawning unbounded threads — a flood on the (public-facing)
/// Stratum port cannot exhaust the bridge's threads/memory. Firewall :3333 too.
const MAX_CONNECTIONS: usize = 512;
static ACTIVE_CONNS: AtomicUsize = AtomicUsize::new(0);
/// Reader-side idle cutoff: xmrig sends `keepalived` every 60 s, so a session
/// silent for this long is dead and its thread should exit.
const READ_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Write timeout on miner sockets — a wedged peer must never block a broadcast
/// (the same lesson as the v0.1.75 p2p SO_SNDTIMEO fix).
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Nonces a built-in worker grinds between checks for a superseded template.
const WORKER_BATCH: u64 = 64;
/// One Stratum line. Larger requests are rejected; the id is recovered from
/// the prefix so the miner still gets an error reply.
const MAX_LINE: usize = 64 * 1024;
/// How far back pool hashrate looks. Only accepted shares count.
const HASHRATE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Runtime configuration, from CLI flags (see `usage`).
#[derive(Clone, Debug)]
struct Config {
    /// The SOV node's JSON-RPC endpoint, `host:port`.
    node: String,
    /// The Stratum listen address, `host:port`.
    bind: String,
    /// Coinbase account passed to `sov_getBlockTemplate` (None = the node's own).
    coinbase: Option<String>,
    /// Starting per-session share difficulty (vardiff tunes it from here).
    start_diff: u64,
    /// Vardiff knobs.
    vardiff: VardiffConfig,
    /// Node poll interval (height watch), milliseconds.
    poll_ms: u64,
    /// Template refresh interval even without a tip change (fresh timestamp +
    /// fresh mempool; also keeps templates far inside the node's 120 s cache TTL).
    refresh_secs: u64,
    /// Built-in SOV-native worker threads (0 = bridge only). Solo mode only.
    workers: u64,
    /// Solo bridge: one coinbase, no sharechain. Pool mode is the default.
    solo: bool,
    /// Public read-only stats bind address. `None` leaves the port closed.
    stats_bind: Option<String>,
    /// Simultaneous stratum connections from one address.
    max_per_ip: usize,
    /// Share attempts per second per address, counted before the seal.
    share_rate: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            node: "127.0.0.1:8645".into(),
            bind: "0.0.0.0:3333".into(),
            coinbase: None,
            start_diff: 5_000,
            vardiff: VardiffConfig::default(),
            poll_ms: 2_000,
            refresh_secs: 30,
            workers: 0,
            solo: false,
            stats_bind: None,
            max_per_ip: guard::DEFAULT_MAX_PER_IP,
            share_rate: guard::DEFAULT_SHARE_RATE,
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "sov-stratum — Monero-lineage RandomX Stratum bridge for SOV\n\n\
         USAGE: sov-stratum [FLAGS]\n\n\
         FLAGS (all optional):\n\
           --node <host:port>        SOV node JSON-RPC endpoint     [127.0.0.1:8645]\n\
           --bind <host:port>        Stratum listen address         [0.0.0.0:3333]\n\
           --coinbase <account-id>   mine to this account (else the node's configured one)\n\
           --start-diff <n>          initial per-session share difficulty [5000]\n\
           --min-diff <n>            vardiff floor                  [100]\n\
           --max-diff <n>            vardiff ceiling                [2^62]\n\
           --share-secs <n>          vardiff ideal seconds/share    [10]\n\
           --retarget-secs <n>       vardiff window seconds         [30]\n\
           --poll-ms <n>             node height poll interval, ms  [2000]\n\
           --refresh-secs <n>        template refresh interval, s   [30]\n\
                                     must stay under 120 (node template TTL)\n\
           --workers <n>             built-in miner threads; SOLO ONLY  [0]\n\
           --solo                    one --coinbase account, no sharechain\n\
           --stats-bind <addr|none>  read-only stats HTTP    [127.0.0.1:8080]\n\
           --max-conns-per-ip <n>    simultaneous connections per address [16]\n\
           --share-rate <n>          share attempts/sec/address, pre-seal [30]\n\
           --help                    this text\n\n\
         Pool mode (the default) pays each miner's login account. The pool\n\
         holds no key. Miners sign payouts with sov-miner-payout.\n\
         --coinbase and --workers require --solo."
    );
    std::process::exit(2);
}

fn parse_args() -> Config {
    // The library default leaves stats closed so unit tests do not bind a port.
    // A real process opens the aggregator endpoint unless asked not to.
    let mut cfg = Config {
        stats_bind: Some("127.0.0.1:8080".into()),
        ..Config::default()
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = |flag: &str| -> String {
            args.next().unwrap_or_else(|| {
                eprintln!("error: {flag} requires a value\n");
                usage()
            })
        };
        let parse_u64 = |flag: &str, raw: String| -> u64 {
            raw.parse().unwrap_or_else(|_| {
                eprintln!("error: {flag} wants an unsigned integer, got `{raw}`\n");
                usage()
            })
        };
        match flag.as_str() {
            "--node" => cfg.node = strip_http(&value("--node")),
            "--bind" => cfg.bind = value("--bind"),
            "--coinbase" => cfg.coinbase = Some(value("--coinbase")),
            "--start-diff" => cfg.start_diff = parse_u64("--start-diff", value("--start-diff")),
            "--min-diff" => cfg.vardiff.min_diff = parse_u64("--min-diff", value("--min-diff")),
            "--max-diff" => cfg.vardiff.max_diff = parse_u64("--max-diff", value("--max-diff")),
            "--share-secs" => {
                cfg.vardiff.target_share_secs =
                    parse_u64("--share-secs", value("--share-secs")) as f64
            }
            "--retarget-secs" => {
                cfg.vardiff.retarget_secs =
                    parse_u64("--retarget-secs", value("--retarget-secs")) as f64
            }
            "--poll-ms" => cfg.poll_ms = parse_u64("--poll-ms", value("--poll-ms")).max(250),
            "--refresh-secs" => {
                cfg.refresh_secs = parse_u64("--refresh-secs", value("--refresh-secs")).max(1)
            }
            "--workers" => cfg.workers = parse_u64("--workers", value("--workers")),
            "--solo" => cfg.solo = true,
            "--stats-bind" => {
                let raw = value("--stats-bind");
                cfg.stats_bind = if raw == "none" { None } else { Some(raw) };
            }
            "--max-conns-per-ip" => {
                cfg.max_per_ip =
                    parse_u64("--max-conns-per-ip", value("--max-conns-per-ip")).max(1) as usize
            }
            "--share-rate" => {
                cfg.share_rate = parse_u64("--share-rate", value("--share-rate")).max(1)
            }
            "--help" | "-h" => usage(),
            other => {
                eprintln!("error: unknown flag `{other}`\n");
                usage()
            }
        }
    }
    if cfg.vardiff.min_diff == 0 || cfg.vardiff.min_diff > cfg.vardiff.max_diff {
        eprintln!("error: --min-diff must be nonzero and <= --max-diff\n");
        usage()
    }
    cfg.start_diff = cfg
        .start_diff
        .clamp(cfg.vardiff.min_diff, cfg.vardiff.max_diff);
    if !cfg.solo && cfg.refresh_secs >= 120 {
        eprintln!(
            "error: pool mode --refresh-secs must be under 120 so a template is replaced before the node drops it\n"
        );
        usage()
    }
    if !cfg.solo && cfg.coinbase.is_some() {
        eprintln!(
            "error: --coinbase is solo-only. Pool mode pays each miner's login account and holds no key.\n"
        );
        usage()
    }
    if !cfg.solo && cfg.workers > 0 {
        eprintln!(
            "error: --workers is solo-only. Pool miners run xus-miner and sign payouts with sov-miner-payout.\n"
        );
        usage()
    }
    cfg
}

/// `RpcClient` wants `host:port`; tolerate a pasted `http://host:port/` URL.
fn strip_http(raw: &str) -> String {
    raw.trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

/// The exact `sov_submitBlock` params for a network-difficulty share: the cached
/// template's id, the winning nonce, and the job's FROZEN timestamp (it is inside
/// the hashed blob — forwarding anything else would describe a different preimage).
fn submit_params(template: &Template, nonce: u64) -> Value {
    json!({
        "templateId": template.template_id,
        "nonce": nonce,
        "timestampMs": template.timestamp_ms,
    })
}

/// One issued Stratum job: which template it grinds, which session it belongs
/// to, and the share difficulty it was issued at (retargets issue a NEW job, so
/// accounting stays bound to the difficulty the work was actually done under).
#[derive(Clone)]
struct JobEntry {
    template: Arc<Template>,
    miner_id: u64,
    difficulty: u64,
    share_target: [u8; 32],
    /// Nonces already submitted against this job (shared across clones of the
    /// entry). A repeat is rejected *before* seal recomputation, so a duplicate
    /// can neither be double-counted (share credit, and the eventual PPLNS
    /// weights), double-forwarded to `sov_submitBlock`, nor used to spin the
    /// verifier's RandomX VM on work it has already done.
    submitted: Arc<Mutex<HashSet<u64>>>,
    /// Sharechain parent this job's payout was computed against.
    share_parent: Option<ShareId>,
    /// What a block found on this job must embed. Empty in solo mode.
    expected: Payouts,
    /// The template already pays `expected`. A network-difficulty share on a
    /// job where this is false is recorded as work and not broadcast.
    payout_ok: bool,
}

/// The payout round miners are currently being asked to pay.
///
/// Unfrozen, it tracks the sharechain tip. It freezes once a miner's template
/// actually contains the outgoing transfers, so a share that arrives while the
/// block is being ground does not invalidate the signatures already in it.
#[derive(Clone, Debug, Default)]
struct Round {
    parent: Option<ShareId>,
    expected: Payouts,
    reward: u128,
    frozen: bool,
}

/// A payout transfer the pool has verified and is willing to relay.
#[derive(Clone)]
struct Relayed {
    leg: TransferLeg,
    stx: SignedTransaction,
}

/// One accepted share, for the honest hashrate window.
struct ShareSample {
    at: Instant,
    account: AccountId,
    work: u128,
}

/// A block this pool imported, with the payout map it carried.
#[derive(Clone)]
struct FoundBlock {
    height: u64,
    hash: String,
    at_unix: u64,
    payouts: Payouts,
}

/// What the stats page reports about the SOV node. Never used as pool hashrate.
#[derive(Clone, Debug)]
struct NetworkView {
    height: u64,
    difficulty: String,
    algo: String,
}

impl Default for NetworkView {
    fn default() -> Self {
        Self {
            height: 0,
            difficulty: "0".into(),
            algo: "Sha256d".into(),
        }
    }
}

/// Per-session vardiff measurement window.
struct ShareWindow {
    since: Instant,
    shares: u64,
}

/// One connected miner session.
struct Miner {
    id: u64,
    session: String,
    peer: String,
    /// Write half (a `try_clone` of the socket) — the poller pushes jobs here.
    writer: Mutex<TcpStream>,
    difficulty: AtomicU64,
    window: Mutex<ShareWindow>,
    accepted: AtomicU64,
    rejected: AtomicU64,
    logged_in: AtomicBool,
    alive: AtomicBool,
    /// Payout account from `login`. `None` in solo mode, where login is a label.
    payout: Mutex<Option<AccountId>>,
    /// Worker label. Not paid.
    worker: Mutex<String>,
    /// Peer address for the connection cap and the share-rate limit.
    ip: IpAddr,
    /// This miner's own template (their login is the coinbase). Solo mode uses
    /// [`Pool::current`] instead.
    work: RwLock<Option<Arc<Template>>>,
}

/// A seal-recomputation request for the single verifier thread.
struct VerifyReq {
    template: Arc<Template>,
    nonce: u64,
    reply: mpsc::Sender<[u8; 32]>,
}

/// Shared pool state.
struct Pool {
    cfg: Config,
    rpc: RpcClient,
    /// The template solo jobs grind (None until the first successful poll).
    /// Pool mode keeps a template per miner instead.
    current: RwLock<Option<Arc<Template>>>,
    /// The live job book: id → entry, plus insertion order for eviction.
    jobs: Mutex<(HashMap<String, JobEntry>, VecDeque<String>)>,
    job_seq: AtomicU64,
    miner_seq: AtomicU64,
    miners: Mutex<Vec<Arc<Miner>>>,
    verify_tx: mpsc::Sender<VerifyReq>,
    blocks_found: AtomicU64,
    sharechain: Mutex<ShareChain>,
    /// Next-block mint, in grains. `None` until the node answers — pool mode
    /// withholds blocks rather than guessing the split.
    reward_grains: Mutex<Option<u128>>,
    round: Mutex<Round>,
    relayed: Mutex<HashMap<AccountId, Vec<Relayed>>>,
    network: Mutex<NetworkView>,
    samples: Mutex<VecDeque<ShareSample>>,
    recent_blocks: Mutex<VecDeque<FoundBlock>>,
    guard: Guard,
    /// `None` = not fetched yet. `Some(None)` = tx-domain dormant (legacy
    /// signatures). `Some(Some(domain))` = signatures must bind to it.
    domain: Mutex<Option<Option<SigningDomain>>>,
}

impl Pool {
    /// Recompute a seal on the dedicated verifier thread (one light RandomX VM
    /// process-wide, regardless of connection count).
    fn seal(&self, template: &Arc<Template>, nonce: u64) -> Result<[u8; 32], String> {
        let (tx, rx) = mpsc::channel();
        self.verify_tx
            .send(VerifyReq {
                template: Arc::clone(template),
                nonce,
                reply: tx,
            })
            .map_err(|_| "verifier thread is gone".to_string())?;
        rx.recv().map_err(|_| "verifier thread is gone".to_string())
    }

    /// Difficulty a share at `share_target` actually proved.
    ///
    /// When the share target was clamped to the network target, the miner only
    /// had to meet network difficulty. The number returned is that difficulty
    /// when the node has published one, and never harder than `requested`.
    fn enforced_difficulty(
        &self,
        requested: u64,
        share_target: &[u8; 32],
        network_target: &[u8; 32],
    ) -> u64 {
        if share_target != network_target {
            return requested.max(1);
        }
        let raw = self.network.lock().expect("network").difficulty.clone();
        let network = raw.parse::<u128>().unwrap_or(0);
        if network == 0 {
            return requested.max(1);
        }
        let network = u64::try_from(network).unwrap_or(u64::MAX);
        requested.min(network).max(1)
    }

    /// Issue a fresh job for `miner` (None while the bridge has no work).
    ///
    /// Solo mode grinds the single pool template and always treats it as paid
    /// (the coinbase is the one account). Pool mode grinds that miner's
    /// template and records whether it already pays the current round.
    fn new_job_for(&self, miner: &Miner) -> Option<Value> {
        let template = if self.cfg.solo {
            self.current.read().expect("current lock").clone()?
        } else {
            miner.work.read().expect("work lock").clone()?
        };
        let (share_parent, expected, payout_ok) = if self.cfg.solo {
            (None, Payouts::new(), true)
        } else {
            let account = miner.payout.lock().expect("payout").clone()?;
            self.coverage(&template, &account)
        };
        let share_floor = if self.cfg.solo {
            1
        } else {
            let chain = self.sharechain.lock().expect("sharechain");
            u64::try_from(chain.next_share_difficulty().0).unwrap_or(u64::MAX)
        };
        let requested = miner
            .difficulty
            .load(Ordering::Relaxed)
            .max(share_floor)
            .max(1);
        let share_target =
            effective_share_target(difficulty_to_target256(requested), &template.network_target);
        // The target may have been clamped up to the network target. Crediting
        // the pre-clamp difficulty would publish a hashrate the miner did not
        // produce and would overweight that share in the payout window.
        let difficulty =
            self.enforced_difficulty(requested, &share_target, &template.network_target);
        let job_id = format!("{:016x}", self.job_seq.fetch_add(1, Ordering::Relaxed));
        {
            let (map, order) = &mut *self.jobs.lock().expect("jobs lock");
            map.insert(
                job_id.clone(),
                JobEntry {
                    template: Arc::clone(&template),
                    miner_id: miner.id,
                    difficulty,
                    share_target,
                    submitted: Arc::new(Mutex::new(HashSet::new())),
                    share_parent,
                    expected: expected.clone(),
                    payout_ok,
                },
            );
            order.push_back(job_id.clone());
            while order.len() > MAX_LIVE_JOBS {
                if let Some(old) = order.pop_front() {
                    map.remove(&old);
                }
            }
        }
        // Freeze only once a real split is already inside the template. A
        // finder-only window stays open so the next miner's share still counts.
        let payer = miner.payout.lock().expect("payout").clone();
        if !self.cfg.solo
            && payout_ok
            && payer
                .as_ref()
                .is_some_and(|account| !outgoing_transfers(&expected, account).is_empty())
        {
            let mut round = self.round.lock().expect("round");
            if round.parent == share_parent && round.expected == expected {
                round.frozen = true;
            }
        }
        Some(json!({
            // The Monero-dialect fields xmrig-class miners consume.
            "job_id": job_id,
            "blob": hex::encode(&template.blob),
            "target": stratum_target_hex(difficulty),
            "algo": template.stratum_algo(),
            "height": template.height,
            "seed_hash": template.seed_hash,
            // SOV extensions (unknown fields are ignored by stock miners): where
            // the nonce really lives, and the full big-endian share threshold for
            // miners that check the seal the way SOV consensus does.
            "nonce_offset": template.nonce_offset,
            "nonce_size": 8,
            "target_full": hex::encode(share_target),
            "network_target_full": hex::encode(template.network_target),
            "coinbase": template.proposer,
        }))
    }

    /// Whether `template` pays the current round for `account`.
    fn coverage(
        &self,
        template: &Template,
        account: &AccountId,
    ) -> (Option<ShareId>, Payouts, bool) {
        let round = self.round.lock().expect("round").clone();
        let reward_known = self.reward_grains.lock().expect("reward").is_some();
        let ids: HashSet<String> = template.tx_ids.iter().cloned().collect();
        let legs: Vec<TransferLeg> = self
            .relayed
            .lock()
            .expect("relayed")
            .get(account)
            .map(|rows| rows.iter().map(|r| r.leg.clone()).collect())
            .unwrap_or_default();
        let list_ok = round.expected.is_empty() || template.tx_ids_known;
        let ok = reward_known
            && list_ok
            && template.proposer == account.as_str()
            && window_covered(account, round.reward, &round.expected, &ids, &legs);
        (round.parent, round.expected, ok)
    }

    /// Drop every live job belonging to one session.
    fn drop_jobs(&self, miner_id: u64) {
        let (map, order) = &mut *self.jobs.lock().expect("jobs lock");
        map.retain(|_, entry| entry.miner_id != miner_id);
        order.retain(|id| map.contains_key(id));
    }

    /// Refresh live jobs after the round moves, without handing the miner a new
    /// job id.
    ///
    /// An empty-window job must not be forwarded once other miners have shares.
    /// [`accept_share`](Self::accept_share) already withholds it when the job's
    /// recorded window disagrees with the round; this updates that record so
    /// the next seal is judged against the window as it stands now.
    ///
    /// Pushing a fresh job id for the same template blob is the wrong tool.
    /// `xus-miner` restarts its nonce at the beginning of every job, so a new
    /// id on an unchanged blob re-hashes the same range forever and never
    /// reaches a block. The miner keeps this job id and walks forward.
    /// A frozen round is left alone: those templates already pay a fixed window.
    fn reissue_open_round(&self) {
        if self.cfg.solo || self.round.lock().expect("round").frozen {
            return;
        }
        let snapshots: Vec<(String, u64, Arc<Template>)> = {
            let (map, _) = &*self.jobs.lock().expect("jobs lock");
            map.iter()
                .map(|(id, entry)| (id.clone(), entry.miner_id, Arc::clone(&entry.template)))
                .collect()
        };
        let miners: Vec<Arc<Miner>> = self.miners.lock().expect("miners lock").clone();
        let mut updates = Vec::with_capacity(snapshots.len());
        for (job_id, miner_id, template) in snapshots {
            let Some(miner) = miners.iter().find(|m| m.id == miner_id) else {
                continue;
            };
            if !miner.alive.load(Ordering::Relaxed) || !miner.logged_in.load(Ordering::Relaxed) {
                continue;
            }
            let Some(account) = miner.payout.lock().expect("payout").clone() else {
                continue;
            };
            let (parent, expected, ok) = self.coverage(&template, &account);
            updates.push((job_id, parent, expected, ok));
        }
        let (map, _) = &mut *self.jobs.lock().expect("jobs lock");
        for (job_id, parent, expected, ok) in updates {
            if let Some(entry) = map.get_mut(&job_id) {
                entry.share_parent = parent;
                entry.expected = expected;
                entry.payout_ok = ok;
            }
        }
    }

    /// Drop signed payouts the current window no longer asks for, and tell the
    /// node to forget them so a stale transfer is not mined.
    fn forget_stale_payouts(&self) {
        let round = self.round.lock().expect("round").clone();
        let mut relayed = self.relayed.lock().expect("relayed");
        let mut drop_ids = Vec::new();
        relayed.retain(|account, rows| {
            let outgoing = outgoing_transfers(&round.expected, account);
            let fresh = rows.len() == outgoing.len()
                && rows.iter().zip(outgoing.iter()).all(|(row, (to, amount))| {
                    row.leg.from == *account && row.leg.to == *to && row.leg.amount == *amount
                });
            if !fresh {
                drop_ids.extend(rows.iter().map(|row| row.leg.tx_id.clone()));
            }
            fresh
        });
        drop(relayed);
        for id in drop_ids {
            if let Err(e) = self.rpc.call("sov_dropMempoolTx", json!({ "txId": id })) {
                log(&format!("drop stale payout {id}: {e}"));
            }
        }
    }

    /// Put this account's already-signed payouts back in the mempool.
    ///
    /// Building a template for account A evicts B's payout transactions: they
    /// fail execution in a block whose coinbase is A, and the node drops a
    /// front-of-line failure. A's previously cached template stays valid. The
    /// next fetch for B must resubmit B's transactions first.
    fn resubmit(&self, account: &AccountId) {
        let rows = self
            .relayed
            .lock()
            .expect("relayed")
            .get(account)
            .cloned()
            .unwrap_or_default();
        for row in rows {
            if let Err(e) = self.rpc.submit_transaction(&row.stx) {
                let msg = e.to_string();
                if msg.contains("NonceTaken")
                    || msg.contains("duplicate")
                    || msg.contains("already")
                {
                    continue;
                }
                log(&format!("resubmit {} ({msg})", row.leg.tx_id));
            }
        }
    }

    /// Fetch a template whose coinbase is this miner's login, then issue a job.
    fn refresh_miner(&self, miner: &Miner, push: bool) -> Result<Option<Value>, String> {
        let account = miner
            .payout
            .lock()
            .expect("payout")
            .clone()
            .ok_or_else(|| "miner has no payout account".to_string())?;
        self.resubmit(&account);
        let v = self
            .rpc
            .call(
                "sov_getBlockTemplate",
                json!({
                    "coinbaseAccount": account.as_str(),
                    // Only this miner's payout may ride in the block. Another
                    // miner's signed transfer stays in the mempool for their
                    // own template.
                    "coinbaseTxsOnly": true,
                }),
            )
            .map_err(|e| e.to_string())?;
        let template = Template::from_rpc(&v)?;
        if template.proposer != account.as_str() {
            return Err(format!(
                "node template pays `{}`, not `{}`",
                template.proposer,
                account.as_str()
            ));
        }
        *miner.work.write().expect("work lock") = Some(Arc::new(template));
        self.drop_jobs(miner.id);
        let job = self.new_job_for(miner);
        if push {
            if let Some(job) = &job {
                self.push(
                    miner,
                    &json!({"jsonrpc": "2.0", "method": "job", "params": job}),
                );
            }
        }
        Ok(job)
    }

    /// Push `line`-encoded JSON to one miner; a failed write marks it dead.
    fn push(&self, miner: &Miner, msg: &Value) {
        let mut writer = miner.writer.lock().expect("writer lock");
        let mut payload = msg.to_string();
        payload.push('\n');
        if writer.write_all(payload.as_bytes()).is_err() || writer.flush().is_err() {
            miner.alive.store(false, Ordering::Relaxed);
        }
    }

    /// Broadcast a fresh job to every logged-in session and prune dead ones.
    fn broadcast_jobs(&self) {
        let miners: Vec<Arc<Miner>> = self.miners.lock().expect("miners lock").clone();
        for m in &miners {
            if !m.alive.load(Ordering::Relaxed) || !m.logged_in.load(Ordering::Relaxed) {
                continue;
            }
            if let Some(job) = self.new_job_for(m) {
                self.push(
                    m,
                    &json!({"jsonrpc": "2.0", "method": "job", "params": job}),
                );
            }
        }
        self.miners
            .lock()
            .expect("miners lock")
            .retain(|m| m.alive.load(Ordering::Relaxed));
    }

    /// Forward a network-difficulty seal to the node. The node re-validates the
    /// whole block on import — the bridge's word counts for nothing, by design.
    ///
    /// Returns whether the node accepted the block. `payouts` is recorded for
    /// the stats page when it does (empty in solo mode).
    fn submit_block(
        &self,
        template: &Template,
        nonce: u64,
        seal: &[u8; 32],
        payouts: &Payouts,
    ) -> bool {
        log(&format!(
            "BLOCK CANDIDATE height {} nonce {:#x} seal {} — forwarding to {}",
            template.height,
            nonce,
            hex::encode(seal),
            self.cfg.node
        ));
        match self
            .rpc
            .call("sov_submitBlock", submit_params(template, nonce))
        {
            Ok(v) => {
                if v.get("accepted").and_then(Value::as_bool) == Some(true) {
                    let height = v
                        .get("height")
                        .and_then(Value::as_u64)
                        .unwrap_or(template.height);
                    let hash = v
                        .get("hash")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_string();
                    // Import returns success for a valid block that lost the
                    // same-height race. When the node can show the canonical
                    // block at this height, only that hash counts. A node that
                    // does not answer is trusted (the submit already said
                    // accepted).
                    let raced = self
                        .rpc
                        .call("sov_getBlockByHeight", json!({ "height": height }))
                        .ok()
                        .and_then(|block| {
                            block
                                .get("header")
                                .and_then(|header| header.get("hash"))
                                .and_then(Value::as_str)
                                .map(|got| got != hash)
                        })
                        .unwrap_or(false);
                    if raced {
                        log(&format!(
                            "block {hash} at height {height} lost the race — not counted"
                        ));
                        return false;
                    }
                    log(&format!("BLOCK ACCEPTED height {height} hash {hash}"));
                    let mut recent = self.recent_blocks.lock().expect("recent blocks");
                    // A heavier same-height block replaces the one just found.
                    // Counting both would report a race as two blocks.
                    let replaced = recent.back().is_some_and(|b| b.height == height);
                    if replaced {
                        recent.pop_back();
                    } else {
                        self.blocks_found.fetch_add(1, Ordering::Relaxed);
                    }
                    recent.push_back(FoundBlock {
                        height,
                        hash,
                        at_unix: unix_secs(),
                        payouts: payouts.clone(),
                    });
                    while recent.len() > 32 {
                        recent.pop_front();
                    }
                    true
                } else {
                    log(&format!(
                        "block import rejected: {}",
                        v.get("error").and_then(Value::as_str).unwrap_or("unknown")
                    ));
                    false
                }
            }
            Err(e) => {
                log(&format!("sov_submitBlock failed: {e}"));
                false
            }
        }
    }

    /// Move the open round onto the current sharechain tip. A frozen round is
    /// left exactly as the templates already pay it.
    fn sync_round_to_tip(&self) {
        if self.cfg.solo {
            return;
        }
        let reward = self.reward_grains.lock().expect("reward").unwrap_or(0);
        let mut round = self.round.lock().expect("round");
        if round.frozen {
            return;
        }
        let chain = self.sharechain.lock().expect("sharechain");
        round.parent = chain.tip();
        round.reward = reward;
        round.expected = chain.payouts_for(round.parent, reward);
    }

    /// Record one accepted pool share and, when it is a block whose template
    /// pays the round, return the payout map that must be forwarded.
    fn accept_share(
        &self,
        miner: &Miner,
        entry: &JobEntry,
        seal: [u8; 32],
        outcome: ShareOutcome,
    ) -> Result<Option<Payouts>, String> {
        let finder = miner
            .payout
            .lock()
            .expect("payout")
            .clone()
            .ok_or_else(|| "login is not a payout account".to_string())?;
        let reward_known = *self.reward_grains.lock().expect("reward");
        let round = self.round.lock().expect("round").clone();
        let mut chain = self.sharechain.lock().expect("sharechain");
        let wants_block = outcome == ShareOutcome::Block
            && entry.payout_ok
            && reward_known.is_some()
            && entry.share_parent == round.parent
            && entry.expected == round.expected;
        let prev = if wants_block {
            round.parent
        } else {
            chain.tip()
        };
        let reward = reward_known.unwrap_or(0);
        let mut embedded = Payouts::new();
        let mut forward = false;
        if wants_block {
            let expected = chain.payouts_for(prev, reward);
            if expected == entry.expected {
                embedded = expected;
                forward = true;
            }
        }
        let share = Share {
            id: seal,
            prev,
            uncles: Vec::new(),
            finder: finder.clone(),
            work: u128::from(entry.difficulty),
            is_block: forward,
            timestamp_ms: unix_millis(),
        };
        chain
            .accept(share, reward, &embedded)
            .map_err(|e| e.to_string())?;
        drop(chain);
        self.note_share(finder, u128::from(entry.difficulty));
        self.sync_round_to_tip();
        if forward {
            Ok(Some(embedded))
        } else {
            Ok(None)
        }
    }

    fn note_share(&self, account: AccountId, work: u128) {
        let mut samples = self.samples.lock().expect("samples");
        let now = Instant::now();
        samples.push_back(ShareSample {
            at: now,
            account,
            work,
        });
        while samples
            .front()
            .is_some_and(|s| now.saturating_duration_since(s.at) > HASHRATE_WINDOW)
        {
            samples.pop_front();
        }
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log(msg: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    println!("[{secs}] {msg}");
}

/// The single verifier thread: owns the light RandomX VM via `pow_seal`'s
/// thread-local storage (the key is genesis-constant, so the VM builds once).
fn spawn_verifier() -> mpsc::Sender<VerifyReq> {
    let (tx, rx) = mpsc::channel::<VerifyReq>();
    thread::Builder::new()
        .name("seal-verifier".into())
        .spawn(move || {
            for req in rx {
                let seal = req.template.seal_for_nonce(req.nonce);
                let _ = req.reply.send(seal);
            }
        })
        .expect("spawn verifier thread");
    tx
}

/// The poller: watch the node's height; refetch a template on tip change or
/// refresh interval; broadcast fresh jobs when the template changes.
fn poll_loop(pool: Arc<Pool>) {
    if pool.cfg.solo {
        poll_loop_solo(pool);
    } else {
        poll_loop_pool(pool);
    }
}

fn poll_loop_solo(pool: Arc<Pool>) {
    let mut last_height: Option<u64> = None;
    let mut last_fetch = Instant::now()
        .checked_sub(Duration::from_secs(pool.cfg.refresh_secs))
        .unwrap_or_else(Instant::now);
    let mut have_template = false;
    loop {
        let height = match pool.rpc.height() {
            Ok(h) => Some(h),
            Err(e) => {
                log(&format!("node poll failed ({}): {e}", pool.cfg.node));
                None
            }
        };
        let tip_moved = height.is_some() && height != last_height;
        let refresh_due = last_fetch.elapsed() >= Duration::from_secs(pool.cfg.refresh_secs);
        if height.is_some() && (tip_moved || refresh_due || !have_template) {
            let params = match &pool.cfg.coinbase {
                Some(cb) => json!({ "coinbaseAccount": cb }),
                None => json!({}),
            };
            match pool.rpc.call("sov_getBlockTemplate", params) {
                Ok(v) => match Template::from_rpc(&v) {
                    Ok(t) => {
                        last_fetch = Instant::now();
                        last_height = height;
                        have_template = true;
                        let t = Arc::new(t);
                        *pool.current.write().expect("current lock") = Some(Arc::clone(&t));
                        // The old template's jobs are superseded: clear the book so
                        // late submits against them are rejected as stale.
                        {
                            let (map, order) = &mut *pool.jobs.lock().expect("jobs lock");
                            map.clear();
                            order.clear();
                        }
                        let sessions = pool.miners.lock().expect("miners lock").len();
                        log(&format!(
                            "new work: height {} prev {} algo {:?} ({} session{})",
                            t.height,
                            &t.prev_hash[..16.min(t.prev_hash.len())],
                            t.algo,
                            sessions,
                            if sessions == 1 { "" } else { "s" }
                        ));
                        pool.broadcast_jobs();
                    }
                    Err(e) => log(&format!("bad template from node: {e}")),
                },
                Err(e) => log(&format!("sov_getBlockTemplate failed: {e}")),
            }
        }
        thread::sleep(Duration::from_millis(pool.cfg.poll_ms));
    }
}

fn poll_loop_pool(pool: Arc<Pool>) {
    let mut last_height: Option<u64> = None;
    let mut last_fetch = Instant::now()
        .checked_sub(Duration::from_secs(pool.cfg.refresh_secs))
        .unwrap_or_else(Instant::now);
    loop {
        refresh_network(&pool);
        let height = pool.network.lock().expect("network").height;
        let height_known = pool.rpc_height_known();
        let tip_moved = match (height_known, last_height) {
            (Some(h), Some(prev)) => h != prev,
            _ => false,
        };
        if tip_moved {
            // A new SOV block invalidates every template. Open the round again
            // so the next window is paid from the shares that follow, and drop
            // payouts signed for the window that just closed.
            {
                let mut round = pool.round.lock().expect("round");
                round.frozen = false;
            }
            pool.sync_round_to_tip();
            pool.forget_stale_payouts();
            log(&format!("SOV height {height} — payout round reopened"));
        }
        let refresh_due = last_fetch.elapsed() >= Duration::from_secs(pool.cfg.refresh_secs);
        if height_known.is_some() && (tip_moved || refresh_due || last_height.is_none()) {
            last_fetch = Instant::now();
            last_height = height_known;
            let miners: Vec<Arc<Miner>> = pool.miners.lock().expect("miners lock").clone();
            for miner in &miners {
                if !miner.alive.load(Ordering::Relaxed) || !miner.logged_in.load(Ordering::Relaxed)
                {
                    continue;
                }
                if let Err(e) = pool.refresh_miner(miner, true) {
                    log(&format!("{}: template refresh: {e}", miner.peer));
                }
            }
        }
        thread::sleep(Duration::from_millis(pool.cfg.poll_ms));
    }
}

/// Height, reward, difficulty, and the signing domain. Failures leave the
/// previous values in place — a blip must not zero the hashrate page or
/// un-freeze a round.
fn refresh_network(pool: &Pool) {
    if let Ok(h) = pool.rpc.height() {
        pool.network.lock().expect("network").height = h;
    }
    if let Ok(v) = pool.rpc.call("sov_getMintReward", json!({})) {
        if let Some(grains) = v.as_str().and_then(|s| s.parse::<u128>().ok()) {
            *pool.reward_grains.lock().expect("reward") = Some(grains);
            pool.sync_round_to_tip();
        }
    }
    if let Ok(v) = pool.rpc.call("sov_getDifficulty", json!({})) {
        let mut net = pool.network.lock().expect("network");
        if let Some(algo) = v.get("algo").and_then(Value::as_str) {
            net.algo = algo.to_string();
        }
        if let Some(diff) = v.get("sha256d").and_then(Value::as_str) {
            net.difficulty = diff.to_string();
        }
    }
    if pool.domain.lock().expect("domain").is_none() {
        if let Ok(domain) = pool.rpc.signing_domain() {
            *pool.domain.lock().expect("domain") = Some(domain);
        }
    }
}

impl Pool {
    /// `Some` when a height poll has succeeded at least once this process.
    /// Stored height `0` is a real genesis height, so it cannot be the signal.
    fn rpc_height_known(&self) -> Option<u64> {
        // `refresh_network` writes height only after a successful poll. The
        // zero default is also what a fresh chain reports, so the poller uses
        // the RPC result directly when it needs to distinguish "never" from 0.
        self.rpc.height().ok()
    }
}

fn open_pool(cfg: Config, template: Option<Template>) -> Arc<Pool> {
    Arc::new(Pool {
        rpc: RpcClient::new(cfg.node.clone()).with_timeout(Duration::from_secs(15)),
        guard: Guard::new(cfg.max_per_ip, cfg.share_rate),
        cfg,
        current: RwLock::new(template.map(Arc::new)),
        jobs: Mutex::new((HashMap::new(), VecDeque::new())),
        job_seq: AtomicU64::new(0),
        miner_seq: AtomicU64::new(0),
        miners: Mutex::new(Vec::new()),
        verify_tx: spawn_verifier(),
        blocks_found: AtomicU64::new(0),
        sharechain: Mutex::new(ShareChain::new()),
        reward_grains: Mutex::new(None),
        round: Mutex::new(Round::default()),
        relayed: Mutex::new(HashMap::new()),
        network: Mutex::new(NetworkView::default()),
        samples: Mutex::new(VecDeque::new()),
        recent_blocks: Mutex::new(VecDeque::new()),
        domain: Mutex::new(None),
    })
}

impl Pool {
    fn handle_http(&self, req: &Incoming) -> (u16, String) {
        let method = req.method.as_str();
        let path = req.path.trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };
        match (method, path) {
            ("GET", "/api/stats") | ("GET", "/") => (200, self.stats_json().to_string()),
            ("GET", p) if p.starts_with("/api/miner/") => {
                let account = &p["/api/miner/".len()..];
                match self.miner_json(account) {
                    Ok(v) => (200, v.to_string()),
                    Err(e) => (400, json!({"error": e}).to_string()),
                }
            }
            ("GET", p) if p.starts_with("/api/payouts/") => {
                let account = &p["/api/payouts/".len()..];
                match self.payouts_json(account) {
                    Ok(v) => (200, v.to_string()),
                    Err(e) => (400, json!({"error": e}).to_string()),
                }
            }
            ("POST", "/api/payout-txs") => {
                if !self.guard.allow_share(req.peer) {
                    return (429, json!({"error": "rate limit"}).to_string());
                }
                match self.accept_payout_txs(&req.body) {
                    Ok(v) => (200, v.to_string()),
                    Err(e) => (400, json!({"error": e}).to_string()),
                }
            }
            _ => (404, json!({"error": "not found"}).to_string()),
        }
    }

    fn hashrate_of(&self, account: Option<&AccountId>) -> f64 {
        let samples = self.samples.lock().expect("samples");
        let now = Instant::now();
        let mut sum: u128 = 0;
        let mut oldest: Option<Instant> = None;
        for sample in samples.iter() {
            if now.saturating_duration_since(sample.at) > HASHRATE_WINDOW {
                continue;
            }
            if account.is_some_and(|a| a != &sample.account) {
                continue;
            }
            sum += sample.work;
            oldest = Some(oldest.map(|t| t.min(sample.at)).unwrap_or(sample.at));
        }
        let Some(oldest) = oldest else {
            return 0.0;
        };
        let span = now.saturating_duration_since(oldest).as_secs_f64().max(1.0);
        sum as f64 / span
    }

    fn connected(&self) -> Vec<Arc<Miner>> {
        self.miners
            .lock()
            .expect("miners")
            .iter()
            .filter(|m| m.alive.load(Ordering::Relaxed) && m.logged_in.load(Ordering::Relaxed))
            .cloned()
            .collect()
    }

    fn stats_json(&self) -> Value {
        let miners = self.connected();
        let accounts: HashSet<String> = miners
            .iter()
            .filter_map(|m| {
                m.payout
                    .lock()
                    .expect("payout")
                    .as_ref()
                    .map(|a| a.as_str().to_string())
            })
            .collect();
        let net = self.network.lock().expect("network").clone();
        let recent: Vec<FoundBlock> = self
            .recent_blocks
            .lock()
            .expect("blocks")
            .iter()
            .cloned()
            .collect();
        let last = recent.last().cloned();
        let blocks_found = self.blocks_found.load(Ordering::Relaxed);
        json!({
            "hashrate": self.hashrate_of(None),
            "miners": accounts.len(),
            "workers": miners.len(),
            "blocksFound": blocks_found,
            "blocks": blocks_found,
            "lastBlock": last.as_ref().map(|b| b.height),
            "lastBlockFound": last.as_ref().map(|b| b.at_unix),
            "lastBlockHash": last.as_ref().map(|b| b.hash.clone()),
            "networkHeight": net.height,
            "networkDifficulty": net.difficulty,
            "networkAlgo": net.algo,
            "fee": 0,
            "feePercent": 0,
            "payoutScheme": "PPLNS",
            "recentBlocks": recent.iter().map(block_json).collect::<Vec<_>>(),
        })
    }

    fn miner_json(&self, raw: &str) -> Result<Value, String> {
        let account = account::parse_account(raw)?;
        let miners = self.connected();
        let workers: Vec<Value> = miners
            .iter()
            .filter(|m| m.payout.lock().expect("payout").as_ref() == Some(&account))
            .map(|m| {
                json!({
                    "name": m.worker.lock().expect("worker").clone(),
                    "accepted": m.accepted.load(Ordering::Relaxed),
                    "rejected": m.rejected.load(Ordering::Relaxed),
                    "difficulty": m.difficulty.load(Ordering::Relaxed),
                    "online": true,
                })
            })
            .collect();
        Ok(json!({
            "account": account.as_str(),
            "workers": workers,
            "hashrate": self.hashrate_of(Some(&account)),
        }))
    }

    fn payouts_json(&self, raw: &str) -> Result<Value, String> {
        let account = account::parse_account(raw)?;
        let round = self.round.lock().expect("round").clone();
        let reward = *self.reward_grains.lock().expect("reward");
        let Some(reward) = reward else {
            return Ok(json!({
                "account": account.as_str(),
                "rewardGrains": Value::Null,
                "satisfied": false,
                "transfers": [],
                "error": "block reward is not known yet",
            }));
        };
        let outgoing = outgoing_transfers(&round.expected, &account);
        let satisfied = self.legs_match(&account, &outgoing);
        let nonce = self
            .rpc
            .next_nonce(&account)
            .map_err(|e| format!("next nonce: {e}"))?;
        let domain = match self.domain.lock().expect("domain").clone().flatten() {
            Some(d) => json!({"chainId": d.chain_id(), "genesis": d.genesis().to_hex()}),
            None => Value::Null,
        };
        Ok(json!({
            "account": account.as_str(),
            "rewardGrains": reward.to_string(),
            "shareParent": round.parent.map(hex::encode),
            "frozen": round.frozen,
            "expected": payouts_json(&round.expected),
            "transfers": outgoing.iter().map(|(to, amount)| json!({
                "to": to.as_str(),
                "amount": amount.to_string(),
            })).collect::<Vec<_>>(),
            "nextNonce": nonce,
            "signingDomain": domain,
            "satisfied": satisfied,
        }))
    }

    fn legs_match(&self, account: &AccountId, outgoing: &[(AccountId, u128)]) -> bool {
        let relayed = self.relayed.lock().expect("relayed");
        let Some(rows) = relayed.get(account) else {
            return outgoing.is_empty();
        };
        if rows.len() != outgoing.len() {
            return false;
        }
        rows.iter().zip(outgoing.iter()).all(|(row, (to, amount))| {
            row.leg.from == *account && row.leg.to == *to && row.leg.amount == *amount
        })
    }

    fn accept_payout_txs(&self, body: &[u8]) -> Result<Value, String> {
        if self.cfg.solo {
            return Err("solo mode does not relay payout transactions".into());
        }
        let v: Value =
            serde_json::from_slice(body).map_err(|e| format!("body is not JSON: {e}"))?;
        let account = account::parse_account(
            v.get("account")
                .and_then(Value::as_str)
                .ok_or("body needs string `account`")?,
        )?;
        let txs = v
            .get("txs")
            .and_then(Value::as_array)
            .ok_or("body needs array `txs`")?;
        if txs.len() > 64 {
            return Err("too many transactions".into());
        }
        let domain = self.signing_domain()?;
        let round = self.round.lock().expect("round").clone();
        if round.reward == 0 && round.expected.is_empty() {
            return Err("no payout round yet".into());
        }
        let outgoing = outgoing_transfers(&round.expected, &account);
        if outgoing.is_empty() {
            return Ok(json!({"ok": true, "satisfied": true, "txIds": []}));
        }
        if txs.len() != outgoing.len() {
            return Err(format!(
                "round needs {} transfer(s), got {}",
                outgoing.len(),
                txs.len()
            ));
        }
        let mut relayed = Vec::with_capacity(txs.len());
        for (tx_value, (to, amount)) in txs.iter().zip(outgoing.iter()) {
            let stx: SignedTransaction = serde_json::from_value(tx_value.clone())
                .map_err(|e| format!("transaction does not decode: {e}"))?;
            if !stx.verify_signature_in(domain.as_ref()) {
                return Err("signature does not verify under the current signing domain".into());
            }
            if stx.transaction.signer != account {
                return Err("transaction signer is not the payout account".into());
            }
            if account.is_implicit() && stx.transaction.public_key.implicit_account_id() != account
            {
                return Err("implicit account does not match the signing key".into());
            }
            let Action::Transfer {
                to: payee,
                amount: paid,
            } = &stx.transaction.action
            else {
                return Err("payout transaction must be a transfer".into());
            };
            if payee != to || paid.grains() != *amount {
                return Err(format!(
                    "transfer pays {} {}, round requires {} {}",
                    payee.as_str(),
                    paid.grains(),
                    to.as_str(),
                    amount
                ));
            }
            relayed.push(Relayed {
                leg: TransferLeg {
                    tx_id: stx.id().to_hex(),
                    from: account.clone(),
                    to: to.clone(),
                    amount: *amount,
                },
                stx,
            });
        }
        let tx_ids: Vec<String> = relayed.iter().map(|r| r.leg.tx_id.clone()).collect();
        for row in &relayed {
            self.rpc
                .submit_transaction(&row.stx)
                .map_err(|e| format!("node rejected {}: {e}", row.leg.tx_id))?;
        }
        self.relayed
            .lock()
            .expect("relayed")
            .insert(account.clone(), relayed);
        let miners: Vec<Arc<Miner>> = self
            .connected()
            .into_iter()
            .filter(|m| m.payout.lock().expect("payout").as_ref() == Some(&account))
            .collect();
        for miner in &miners {
            if let Err(e) = self.refresh_miner(miner, true) {
                log(&format!("payout refresh {}: {e}", account.as_str()));
            }
        }
        Ok(json!({"ok": true, "satisfied": true, "txIds": tx_ids}))
    }

    fn signing_domain(&self) -> Result<Option<SigningDomain>, String> {
        if let Some(cached) = self.domain.lock().expect("domain").clone() {
            return Ok(cached);
        }
        let domain = self
            .rpc
            .signing_domain()
            .map_err(|e| format!("signing domain: {e}"))?;
        *self.domain.lock().expect("domain") = Some(domain.clone());
        Ok(domain)
    }
}

fn payouts_json(payouts: &Payouts) -> Value {
    let mut map = serde_json::Map::new();
    for (account, amount) in payouts {
        map.insert(account.as_str().to_string(), json!(amount.to_string()));
    }
    Value::Object(map)
}

fn block_json(block: &FoundBlock) -> Value {
    json!({
        "height": block.height,
        "hash": block.hash,
        "foundAt": block.at_unix,
        "payouts": payouts_json(&block.payouts),
    })
}

/// Handle one `submit`. Returns the Stratum `result` value, or `(code, message)`
/// for the error reply.
fn handle_submit(pool: &Pool, miner: &Miner, params: &Value) -> Result<Value, (i64, String)> {
    let job_id = params
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "missing string param `job_id`".to_string()))?;
    let nonce_hex = params
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or((-32602, "missing string param `nonce`".to_string()))?;
    let nonce = parse_nonce_hex(nonce_hex).map_err(|e| (-32602, e))?;
    let entry = pool
        .jobs
        .lock()
        .expect("jobs lock")
        .0
        .get(job_id)
        .cloned()
        .ok_or((
            -1,
            "block expired — stale job, wait for the next".to_string(),
        ))?;
    if entry.miner_id != miner.id {
        return Err((-1, "job belongs to a different session".to_string()));
    }
    // Duplicate check BEFORE the (expensive) seal recomputation: each nonce is
    // considered exactly once per job, whatever its outcome, so a replayed
    // submit can neither inflate share counts nor grind the verifier.
    if !entry
        .submitted
        .lock()
        .expect("submitted lock")
        .insert(nonce)
    {
        miner.rejected.fetch_add(1, Ordering::Relaxed);
        return Err((-1, "duplicate share".to_string()));
    }
    // Before the seal: a share flood must not pin the verifier.
    if !pool.guard.allow_share(miner.ip) {
        miner.rejected.fetch_add(1, Ordering::Relaxed);
        return Err((-1, "share rate limit".to_string()));
    }

    // Recompute the seal with the REAL pow_seal — never trust the miner's word.
    let seal = pool.seal(&entry.template, nonce).map_err(|e| (-1, e))?;
    if let Some(result_hex) = params.get("result").and_then(Value::as_str) {
        if !result_hex.eq_ignore_ascii_case(&hex::encode(seal)) {
            miner.rejected.fetch_add(1, Ordering::Relaxed);
            return Err((
                -1,
                "result hash mismatch — miner sealed different bytes".to_string(),
            ));
        }
    }
    match classify_seal(&seal, &entry.share_target, &entry.template.network_target) {
        ShareOutcome::TooWeak => {
            miner.rejected.fetch_add(1, Ordering::Relaxed);
            Err((-1, "low difficulty share".to_string()))
        }
        outcome => {
            let mut forwarded = false;
            if pool.cfg.solo {
                if outcome == ShareOutcome::Block {
                    forwarded = pool.submit_block(&entry.template, nonce, &seal, &Payouts::new());
                }
            } else {
                match pool.accept_share(miner, &entry, seal, outcome) {
                    Ok(Some(payouts)) => {
                        forwarded = pool.submit_block(&entry.template, nonce, &seal, &payouts);
                    }
                    Ok(None) => {
                        // Work counts. A network-difficulty share whose template
                        // does not pay the window is not a block.
                        pool.reissue_open_round();
                    }
                    Err(e) => {
                        miner.rejected.fetch_add(1, Ordering::Relaxed);
                        return Err((-1, e));
                    }
                }
            }
            let accepted = miner.accepted.fetch_add(1, Ordering::Relaxed) + 1;
            log(&format!(
                "share OK from {} (diff {}, total {}{})",
                miner.peer,
                entry.difficulty,
                accepted,
                if forwarded {
                    ", NETWORK difficulty — block submitted"
                } else if outcome == ShareOutcome::Block {
                    ", network difficulty withheld until the window is paid"
                } else {
                    ""
                }
            ));
            maybe_retarget(pool, miner);
            Ok(json!({ "status": "OK" }))
        }
    }
}

/// Vardiff bookkeeping after an accepted share: retarget when the window has run
/// its course (or the session is drastically outrunning it).
///
/// Solo mode pushes a fresh job immediately. Pool mode only stores the new
/// difficulty: the next template refresh picks it up. Pushing a new job id
/// for the same blob makes `xus-miner` restart its nonce, which re-hashes a
/// range it already proved is not a block.
fn maybe_retarget(pool: &Pool, miner: &Miner) {
    let cfg = &pool.cfg.vardiff;
    let mut changed = false;
    {
        let mut w = miner.window.lock().expect("window lock");
        w.shares += 1;
        let elapsed = w.since.elapsed().as_secs_f64();
        // Early exit while the window is still measuring — unless the session is
        // flooding (≫ the ideal rate), which warrants an immediate clamp-up.
        let flooding = (w.shares as f64) >= 4.0 * cfg.max_adjust;
        if elapsed < cfg.retarget_secs && !flooding {
            return;
        }
        let current = miner.difficulty.load(Ordering::Relaxed);
        let next = next_difficulty(current, w.shares, elapsed, cfg);
        if next != current {
            miner.difficulty.store(next, Ordering::Relaxed);
            log(&format!(
                "vardiff: {} {} -> {} ({} share(s) in {:.1}s)",
                miner.peer, current, next, w.shares, elapsed
            ));
            changed = true;
        }
        w.shares = 0;
        w.since = Instant::now();
    }
    if changed && pool.cfg.solo {
        if let Some(job) = pool.new_job_for(miner) {
            pool.push(
                miner,
                &json!({"jsonrpc": "2.0", "method": "job", "params": job}),
            );
        }
    }
}

/// One Stratum session: read line-delimited JSON-RPC requests until EOF/timeout.
fn serve_conn(pool: Arc<Pool>, stream: TcpStream) {
    let peer_addr = stream.peer_addr().ok();
    let peer = peer_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".into());
    let ip = peer_addr
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !pool.guard.allow_conn(ip) {
        log(&format!("{peer}: refused (per-address cap or ban)"));
        return;
    }
    let _release = ConnGuard {
        guard: &pool.guard,
        ip,
    };
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            log(&format!("{peer}: cannot clone socket: {e}"));
            return;
        }
    };
    let id = pool.miner_seq.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let miner = Arc::new(Miner {
        id,
        session: format!("{id:08x}{nanos:08x}"),
        peer: peer.clone(),
        writer: Mutex::new(writer),
        difficulty: AtomicU64::new(pool.cfg.start_diff),
        window: Mutex::new(ShareWindow {
            since: Instant::now(),
            shares: 0,
        }),
        accepted: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        logged_in: AtomicBool::new(false),
        alive: AtomicBool::new(true),
        payout: Mutex::new(None),
        worker: Mutex::new("default".into()),
        ip,
        work: RwLock::new(None),
    });
    pool.miners
        .lock()
        .expect("miners lock")
        .push(Arc::clone(&miner));
    log(&format!("{peer}: connected (session {})", miner.session));

    let mut reader = BufReader::new(stream);
    loop {
        let line = match read_stratum_line(&mut reader) {
            Ok(None) => break,
            Ok(Some(l)) => l,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                reply_err(
                    &pool,
                    &miner,
                    parse_id_from_overflow(&e.to_string()),
                    -32700,
                    "request line exceeds 64KiB",
                );
                continue;
            }
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                reply_err(
                    &pool,
                    &miner,
                    Value::Null,
                    -32700,
                    &format!("parse error: {e}"),
                );
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        match req.get("method").and_then(Value::as_str) {
            Some("login") => {
                if pool.cfg.solo {
                    // Solo coinbase is the operator flag. The login is only a label.
                    if let Some(who) = params.get("login").and_then(Value::as_str) {
                        log(&format!(
                            "{peer}: login `{who}` (solo, not a payout account)"
                        ));
                    }
                    miner.logged_in.store(true, Ordering::Relaxed);
                    match pool.new_job_for(&miner) {
                        Some(job) => reply_login_ok(&pool, &miner, id, job),
                        None => reply_err(&pool, &miner, id, -1, "no work yet — node unreachable?"),
                    }
                } else {
                    let who = params.get("login").and_then(Value::as_str).unwrap_or("");
                    match parse_login(who) {
                        Ok(login) => {
                            *miner.payout.lock().expect("payout") = Some(login.account.clone());
                            *miner.worker.lock().expect("worker") = login.worker.clone();
                            miner.logged_in.store(true, Ordering::Relaxed);
                            log(&format!(
                                "{peer}: payout {} worker {}",
                                login.account.as_str(),
                                login.worker
                            ));
                            match pool.refresh_miner(&miner, false) {
                                Ok(Some(job)) => reply_login_ok(&pool, &miner, id, job),
                                Ok(None) => reply_err(
                                    &pool,
                                    &miner,
                                    id,
                                    -1,
                                    "no work yet — node unreachable?",
                                ),
                                Err(e) => reply_err(&pool, &miner, id, -1, &e),
                            }
                        }
                        Err(e) => reply_err(&pool, &miner, id, -1, &e),
                    }
                }
            }
            Some("getjob") => match pool.new_job_for(&miner) {
                Some(job) => reply_ok(&pool, &miner, id, job),
                None => reply_err(&pool, &miner, id, -1, "no work yet — node unreachable?"),
            },
            Some("submit") => match handle_submit(&pool, &miner, &params) {
                Ok(result) => reply_ok(&pool, &miner, id, result),
                Err((code, msg)) => reply_err(&pool, &miner, id, code, &msg),
            },
            Some("keepalived") => reply_ok(&pool, &miner, id, json!({ "status": "KEEPALIVED" })),
            Some(other) => reply_err(
                &pool,
                &miner,
                id,
                -32601,
                &format!("unknown method `{other}`"),
            ),
            None => reply_err(&pool, &miner, id, -32600, "request has no method"),
        }
        if !miner.alive.load(Ordering::Relaxed) {
            break;
        }
    }

    miner.alive.store(false, Ordering::Relaxed);
    pool.miners
        .lock()
        .expect("miners lock")
        .retain(|m| m.id != miner.id);
    log(&format!(
        "{peer}: disconnected (accepted {}, rejected {})",
        miner.accepted.load(Ordering::Relaxed),
        miner.rejected.load(Ordering::Relaxed)
    ));
}

fn reply_login_ok(pool: &Pool, miner: &Miner, id: Value, job: Value) {
    reply_ok(
        pool,
        miner,
        id,
        json!({
            "id": miner.session,
            "job": job,
            "extensions": [],
            "status": "OK",
        }),
    );
}

/// Releases a per-address connection slot when the session ends.
struct ConnGuard<'a> {
    guard: &'a Guard,
    ip: IpAddr,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.guard.release_conn(self.ip);
    }
}

/// Read one Stratum line, rejecting anything past [`MAX_LINE`].
///
/// On overflow the error string starts with `overflow:` plus the first 512
/// bytes, so the caller can still answer the request id.
fn read_stratum_line(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<String>> {
    use std::io::BufRead;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let data = reader.fill_buf()?;
        if data.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if buf.len() >= MAX_LINE {
            if let Some(pos) = data.iter().position(|b| *b == b'\n') {
                reader.consume(pos + 1);
            } else {
                let n = data.len();
                reader.consume(n);
                continue;
            }
            let prefix = String::from_utf8_lossy(&buf[..512.min(buf.len())]).into_owned();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("overflow:{prefix}"),
            ));
        }
        let room = MAX_LINE - buf.len();
        let take = room.min(data.len());
        if let Some(pos) = data[..take].iter().position(|b| *b == b'\n') {
            buf.extend_from_slice(&data[..pos]);
            reader.consume(pos + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        buf.extend_from_slice(&data[..take]);
        reader.consume(take);
    }
}

fn parse_id_from_overflow(err: &str) -> Value {
    let Some(prefix) = err.strip_prefix("overflow:") else {
        return Value::Null;
    };
    let Some(i) = prefix.find("\"id\"") else {
        return Value::Null;
    };
    let rest = prefix[i + 4..].trim_start();
    let rest = rest.trim_start_matches(':').trim_start();
    if rest.starts_with("null") {
        return Value::Null;
    }
    if let Some(stripped) = rest.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            return Value::String(stripped[..end].to_string());
        }
    }
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if !digits.is_empty() {
        if let Ok(n) = digits.parse::<u64>() {
            return json!(n);
        }
    }
    Value::Null
}

fn reply_ok(pool: &Pool, miner: &Miner, id: Value, result: Value) {
    pool.push(
        miner,
        &json!({ "id": id, "jsonrpc": "2.0", "error": Value::Null, "result": result }),
    );
}

fn reply_err(pool: &Pool, miner: &Miner, id: Value, code: i64, message: &str) {
    pool.push(
        miner,
        &json!({
            "id": id,
            "jsonrpc": "2.0",
            "error": { "code": code, "message": message },
            "result": Value::Null,
        }),
    );
}

/// A built-in SOV-native worker: grind the current template with the fast VM,
/// abandoning the batch the moment the template is superseded. Workers bypass
/// share accounting (they are the operator's own hashrate) and submit network-
/// difficulty seals directly.
fn worker_loop(pool: Arc<Pool>, index: u64) {
    log(&format!("worker {index}: online"));
    let mut current: Option<Arc<Template>> = None;
    // Once a block is found on a template, the template is SPENT for this worker:
    // grinding (or worse, resubmitting) it again is wasted work — park until the
    // poller hands out the next one (which the found block itself triggers).
    let mut spent: Option<Arc<Template>> = None;
    let mut nonce: u64 = 0;
    loop {
        let latest = pool.current.read().expect("current lock").clone();
        let Some(template) = latest else {
            thread::sleep(Duration::from_millis(500));
            continue;
        };
        if let Some(s) = &spent {
            if Arc::ptr_eq(s, &template) {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            spent = None;
        }
        let fresh = match &current {
            Some(t) => !Arc::ptr_eq(t, &template),
            None => true,
        };
        if fresh {
            // Partition the nonce space so workers never duplicate effort.
            nonce = index << 56;
            current = Some(Arc::clone(&template));
        }
        for _ in 0..WORKER_BATCH {
            let seal = template.seal_for_nonce_mining(nonce);
            if seal <= template.network_target {
                pool.submit_block(&template, nonce, &seal, &Payouts::new());
                spent = Some(Arc::clone(&template));
                break; // abandon this template; the poller will bring the next
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

fn main() {
    let cfg = parse_args();
    log(&format!(
        "sov-stratum: node {} | stratum {} | start diff {} | mode {} | workers {}",
        cfg.node,
        cfg.bind,
        cfg.start_diff,
        if cfg.solo {
            format!(
                "solo coinbase {}",
                cfg.coinbase.as_deref().unwrap_or("(node's own)")
            )
        } else {
            "pool (miner login is the coinbase; this process holds no key)".into()
        },
        cfg.workers
    ));

    let listener = match TcpListener::bind(&cfg.bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };

    let pool = open_pool(cfg.clone(), None);
    if let Some(addr) = &cfg.stats_bind {
        let stats_pool = Arc::clone(&pool);
        let handler: stats::Handler = Arc::new(move |req| stats_pool.handle_http(req));
        match stats::spawn(addr, handler) {
            Ok(bound) => log(&format!("stats on http://{bound}/api/stats")),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }

    {
        let pool = Arc::clone(&pool);
        thread::Builder::new()
            .name("template-poller".into())
            .spawn(move || poll_loop(pool))
            .expect("spawn poller thread");
    }
    for index in 0..cfg.workers {
        let pool = Arc::clone(&pool);
        thread::Builder::new()
            .name(format!("worker-{index}"))
            .spawn(move || worker_loop(pool, index))
            .expect("spawn worker thread");
    }

    // Report the socket actually owned by this process (including an OS-assigned
    // port when --bind uses :0), only after worker initialization is complete.
    log(&format!(
        "listening for miners on {}",
        listener.local_addr().expect("bound listener address")
    ));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Shed load past the cap so a connection flood can't exhaust threads/memory.
                if ACTIVE_CONNS.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    log("connection cap reached — refusing new miner");
                    drop(s);
                    continue;
                }
                ACTIVE_CONNS.fetch_add(1, Ordering::Relaxed);
                let pool = Arc::clone(&pool);
                if thread::Builder::new()
                    .name("stratum-conn".into())
                    .spawn(move || {
                        serve_conn(pool, s);
                        ACTIVE_CONNS.fetch_sub(1, Ordering::Relaxed);
                    })
                    .is_err()
                {
                    ACTIVE_CONNS.fetch_sub(1, Ordering::Relaxed);
                    log("failed to spawn a connection thread");
                }
            }
            Err(e) => log(&format!("accept failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_pow::PowAlgo;
    use std::io::BufRead;

    #[test]
    fn submit_params_carry_the_frozen_job_timestamp() {
        // The timestamp is inside the hashed blob: sov_submitBlock must receive the
        // job's OWN timestampMs so the node reconstructs the identical preimage.
        let template = Template {
            template_id: "ab".repeat(32),
            height: 7,
            prev_hash: "cd".repeat(32),
            blob: vec![0; 176],
            nonce_offset: 168,
            network_target: [0xff; 32],
            algo: PowAlgo::Sha256d,
            pow_key: vec![],
            seed_hash: String::new(),
            timestamp_ms: 1_752_800_123_456,
            tx_ids: Vec::new(),
            tx_ids_known: true,
            proposer: String::new(),
        };
        let p = submit_params(&template, 42);
        assert_eq!(p["templateId"], json!("ab".repeat(32)));
        assert_eq!(p["nonce"], json!(42u64));
        assert_eq!(p["timestampMs"], json!(1_752_800_123_456u64));
    }

    #[test]
    fn strip_http_tolerates_pasted_urls() {
        assert_eq!(strip_http("http://127.0.0.1:8645/"), "127.0.0.1:8645");
        assert_eq!(
            strip_http("https://node.sovxus.org:8645"),
            "node.sovxus.org:8645"
        );
        assert_eq!(strip_http("64.225.10.34:8645"), "64.225.10.34:8645");
    }

    // ---- handler-level harness ---------------------------------------------
    //
    // These tests drive `new_job_for` / `handle_submit` / `maybe_retarget`
    // directly against a real `Pool` and a real socket-backed `Miner`, with
    // Sha256d templates (the same splice + `pow_seal` path RandomX rides —
    // the algo is a template parameter, so the logic under test is identical).

    /// An arbitrary Sha256d template. The blob need not be a valid header for
    /// share arithmetic — `pow_seal` hashes whatever bytes the node handed out.
    fn share_template(network_target: [u8; 32]) -> Template {
        Template {
            template_id: "ab".repeat(32),
            height: 100,
            prev_hash: "cd".repeat(32),
            blob: vec![0x5a; 64],
            nonce_offset: 56,
            network_target,
            algo: PowAlgo::Sha256d,
            pow_key: vec![],
            seed_hash: String::new(),
            timestamp_ms: 1_753_000_000_000,
            tx_ids: Vec::new(),
            tx_ids_known: true,
            proposer: String::new(),
        }
    }

    /// A network target no sha256d output will ever meet (only the all-zero
    /// hash would) — so every valid share stays a Share, never a Block.
    const UNREACHABLE: [u8; 32] = [0u8; 32];

    fn test_pool(node: &str, template: Option<Template>, start_diff: u64) -> Arc<Pool> {
        let mut cfg = Config {
            node: node.to_string(),
            start_diff,
            solo: true,
            share_rate: 1_000_000,
            ..Config::default()
        };
        cfg.vardiff.min_diff = 1;
        open_pool(cfg, template)
    }

    /// A registered miner whose writer is one end of a real loopback socket;
    /// the returned client end observes everything the pool pushes.
    fn test_miner(pool: &Pool, difficulty: u64) -> (Arc<Miner>, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let id = pool.miner_seq.fetch_add(1, Ordering::Relaxed);
        let miner = Arc::new(Miner {
            id,
            session: format!("{id:08x}"),
            peer: format!("test-miner-{id}"),
            writer: Mutex::new(server),
            difficulty: AtomicU64::new(difficulty),
            window: Mutex::new(ShareWindow {
                since: Instant::now(),
                shares: 0,
            }),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            logged_in: AtomicBool::new(true),
            alive: AtomicBool::new(true),
            payout: Mutex::new(None),
            worker: Mutex::new("default".into()),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            work: RwLock::new(None),
        });
        pool.miners.lock().unwrap().push(Arc::clone(&miner));
        (miner, client)
    }

    fn nonce_wire(nonce: u64) -> String {
        hex::encode(nonce.to_le_bytes())
    }

    fn job_id_of(job: &Value) -> String {
        job["job_id"].as_str().expect("job_id").to_string()
    }

    #[test]
    fn new_job_for_issues_a_monero_dialect_job_and_registers_it() {
        let template = share_template(UNREACHABLE);
        let pool = test_pool("127.0.0.1:1", Some(template.clone()), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job = pool.new_job_for(&miner).expect("template present");
        assert_eq!(job["blob"], json!(hex::encode(&template.blob)));
        assert_eq!(job["algo"], json!("sha256d"));
        assert_eq!(job["height"], json!(100u64));
        assert_eq!(job["target"], json!("ffffffff")); // difficulty 1
        assert_eq!(job["nonce_offset"], json!(56u64));
        assert_eq!(job["nonce_size"], json!(8u64));
        assert_eq!(job["target_full"], json!("ff".repeat(32))); // diff-1 share target
                                                                // The job is live in the book, keyed by its id.
        let jobs = pool.jobs.lock().unwrap();
        assert!(jobs.0.contains_key(&job_id_of(&job)));
        assert_eq!(jobs.1.len(), 1);
    }

    #[test]
    fn new_job_for_returns_none_without_a_template() {
        let pool = test_pool("127.0.0.1:1", None, 1);
        let (miner, _client) = test_miner(&pool, 1);
        assert!(pool.new_job_for(&miner).is_none());
    }

    #[test]
    fn handle_submit_accepts_a_share_and_rejects_every_duplicate() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());

        // Difficulty 1 accepts every hash — first submit is credited.
        let ok = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(7)}),
        )
        .expect("first submit is a share");
        assert_eq!(ok, json!({"status": "OK"}));
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 1);

        // The identical resubmit is rejected — no double credit, ever.
        let (code, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(7)}),
        )
        .expect_err("duplicate must be rejected");
        assert_eq!(code, -1);
        assert!(msg.contains("duplicate"), "got `{msg}`");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 1, "no double count");
        assert_eq!(miner.rejected.load(Ordering::Relaxed), 1);

        // A duplicate dressed up with a correct `result` hash is still a duplicate.
        let seal = hex::encode(share_template(UNREACHABLE).seal_for_nonce(7));
        let err = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(7), "result": seal}),
        )
        .expect_err("correct hash does not launder a duplicate");
        assert!(err.1.contains("duplicate"));

        // The u32 wire form of an already-seen nonce is the SAME nonce.
        let err = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": "07000000"}),
        )
        .expect_err("u32 encoding of nonce 7 is still nonce 7");
        assert!(err.1.contains("duplicate"));

        // A genuinely fresh nonce is credited again.
        handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(8)}),
        )
        .expect("fresh nonce accepted");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn handle_submit_rejects_low_difficulty_shares() {
        let template = share_template(UNREACHABLE);
        let pool = test_pool("127.0.0.1:1", Some(template.clone()), 1 << 32);
        let (miner, _client) = test_miner(&pool, 1 << 32);
        let job = pool.new_job_for(&miner).unwrap();
        // Difficulty 2^32 ⇒ share target (2^256−1)>>32: four leading zero bytes.
        let share_target = hex::decode(job["target_full"].as_str().unwrap()).unwrap();
        assert_eq!(&share_target[..4], &[0, 0, 0, 0]);
        // Find a nonce whose REAL seal misses that target (P(miss) ≈ 1 − 2⁻³²
        // per nonce, so the first candidate all but certainly fails).
        let weak_nonce = (0..1_000u64)
            .find(|&n| template.seal_for_nonce(n).as_slice() > share_target.as_slice())
            .expect("a weak nonce exists in 1000 tries");
        let (code, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id_of(&job), "nonce": nonce_wire(weak_nonce)}),
        )
        .expect_err("weak seal must be rejected");
        assert_eq!(code, -1);
        assert!(msg.contains("low difficulty"), "got `{msg}`");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(miner.rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_submit_rejects_a_lying_result_hash() {
        let template = share_template(UNREACHABLE);
        let pool = test_pool("127.0.0.1:1", Some(template.clone()), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());

        // The miner claims a hash that is not the seal of these bytes.
        let (code, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(9), "result": "00".repeat(32)}),
        )
        .expect_err("a lying result must be rejected");
        assert_eq!(code, -1);
        assert!(msg.contains("mismatch"), "got `{msg}`");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(miner.rejected.load(Ordering::Relaxed), 1);

        // An honest result — matched case-insensitively — is accepted.
        let honest = hex::encode(template.seal_for_nonce(10)).to_uppercase();
        handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(10), "result": honest}),
        )
        .expect("honest uppercase result accepted");
        assert_eq!(miner.accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_submit_rejects_stale_foreign_and_malformed_submissions() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner_a, _ca) = test_miner(&pool, 1);
        let (miner_b, _cb) = test_miner(&pool, 1);
        let job_a = job_id_of(&pool.new_job_for(&miner_a).unwrap());

        // A job id the pool never issued (or already evicted) is stale.
        let (code, msg) = handle_submit(
            &pool,
            &miner_a,
            &json!({"job_id": "beef000000000000", "nonce": nonce_wire(1)}),
        )
        .unwrap_err();
        assert_eq!(code, -1);
        assert!(msg.contains("stale"), "got `{msg}`");

        // Session B cannot ride session A's job (share-theft guard).
        let (_, msg) = handle_submit(
            &pool,
            &miner_b,
            &json!({"job_id": job_a, "nonce": nonce_wire(1)}),
        )
        .unwrap_err();
        assert!(msg.contains("different session"), "got `{msg}`");

        // Malformed parameter shapes: typed errors, never a panic or a credit.
        for (params, expect) in [
            (json!({}), "job_id"),
            (json!({"job_id": job_a}), "nonce"),
            (json!({"job_id": 7, "nonce": nonce_wire(1)}), "job_id"),
            (json!({"job_id": job_a, "nonce": 7}), "nonce"),
            (json!({"job_id": job_a, "nonce": "xyz"}), "hex"),
            (
                json!({"job_id": job_a, "nonce": "01020304050607"}),
                "16 hex",
            ),
            (
                json!({"job_id": job_a, "nonce": "0x".repeat(50_000)}),
                "hex",
            ),
        ] {
            let (code, msg) =
                handle_submit(&pool, &miner_a, &params).expect_err("malformed must fail");
            assert_eq!(code, -32602, "params {params} → wrong code");
            assert!(msg.contains(expect), "params {params} → `{msg}`");
        }
        assert_eq!(miner_a.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(miner_b.accepted.load(Ordering::Relaxed), 0);
    }

    /// A one-shot mock SOV node: accepts HTTP/1.1 JSON-RPC connections, records
    /// every `sov_submitBlock` params object, and answers `accepted: true`.
    fn spawn_mock_node() -> (String, Arc<Mutex<Vec<Value>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock node");
        let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let submits: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&submits);
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // Read headers, then exactly Content-Length body bytes.
                let header_end = loop {
                    match std::io::Read::read(&mut conn, &mut tmp) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(pos);
                            }
                        }
                    }
                };
                let Some(pos) = header_end else { continue };
                let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                let clen: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = buf[pos + 4..].to_vec();
                while body.len() < clen {
                    match std::io::Read::read(&mut conn, &mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&tmp[..n]),
                    }
                }
                let Ok(req) = serde_json::from_slice::<Value>(&body) else {
                    continue;
                };
                let result = match req["method"].as_str() {
                    Some("sov_submitBlock") => {
                        recorded.lock().unwrap().push(req["params"].clone());
                        json!({"accepted": true, "height": 101u64, "hash": "aa".repeat(32)})
                    }
                    Some("sov_getHeight") => json!(100u64),
                    _ => Value::Null,
                };
                let body = json!({"jsonrpc": "2.0", "id": req["id"].clone(), "result": result})
                    .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_all(resp.as_bytes());
            }
        });
        (addr, submits)
    }

    #[test]
    fn network_difficulty_share_is_forwarded_exactly_once_with_the_frozen_timestamp() {
        let (node_addr, submits) = spawn_mock_node();
        // An all-ones network target: EVERY seal clears it, so the first share
        // is a Block and must be forwarded via sov_submitBlock.
        let template = share_template([0xff; 32]);
        let pool = test_pool(&node_addr, Some(template.clone()), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());

        handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(3)}),
        )
        .expect("network-clearing share accepted");
        assert_eq!(pool.blocks_found.load(Ordering::Relaxed), 1);
        {
            let recorded = submits.lock().unwrap();
            assert_eq!(recorded.len(), 1, "exactly one sov_submitBlock call");
            assert_eq!(recorded[0]["templateId"], json!(template.template_id));
            assert_eq!(recorded[0]["nonce"], json!(3u64));
            assert_eq!(
                recorded[0]["timestampMs"],
                json!(template.timestamp_ms),
                "the job's FROZEN timestamp must ride along"
            );
        }
        // Replaying the winner cannot double-submit the block to the node.
        let err = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": job_id, "nonce": nonce_wire(3)}),
        )
        .expect_err("replayed winner rejected");
        assert!(err.1.contains("duplicate"));
        assert_eq!(submits.lock().unwrap().len(), 1, "still exactly one submit");
        assert_eq!(pool.blocks_found.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn job_book_evicts_oldest_jobs_beyond_capacity() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, _client) = test_miner(&pool, 1);
        let first_job = job_id_of(&pool.new_job_for(&miner).unwrap());
        for _ in 0..MAX_LIVE_JOBS + 5 {
            pool.new_job_for(&miner).unwrap();
        }
        {
            let jobs = pool.jobs.lock().unwrap();
            assert_eq!(jobs.0.len(), MAX_LIVE_JOBS, "book capped at MAX_LIVE_JOBS");
            assert_eq!(jobs.1.len(), MAX_LIVE_JOBS);
            assert!(
                !jobs.0.contains_key(&first_job),
                "oldest job must have been evicted"
            );
        }
        // A submit against the evicted job is now stale — not a panic, not a credit.
        let (_, msg) = handle_submit(
            &pool,
            &miner,
            &json!({"job_id": first_job, "nonce": nonce_wire(1)}),
        )
        .unwrap_err();
        assert!(msg.contains("stale"));
    }

    #[test]
    fn share_flood_triggers_an_immediate_vardiff_clamp_up_and_a_pushed_job() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, client) = test_miner(&pool, 1);
        // 16 distinct instant shares = 4 × max_adjust — the flood threshold in
        // `maybe_retarget`. Every submit needs its own job-independent nonce.
        for nonce in 0..16u64 {
            let job_id = job_id_of(&pool.new_job_for(&miner).unwrap());
            handle_submit(
                &pool,
                &miner,
                &json!({"job_id": job_id, "nonce": nonce_wire(nonce)}),
            )
            .expect("diff-1 share accepted");
        }
        // The clamp is ×4 per retarget: difficulty 1 → 4, no further.
        assert_eq!(miner.difficulty.load(Ordering::Relaxed), 4);
        // And the retarget pushed a fresh job at the new difficulty to the
        // miner's socket, unprompted.
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).expect("pushed job line");
        let msg: Value = serde_json::from_str(line.trim()).expect("pushed job is JSON");
        assert_eq!(msg["method"], json!("job"));
        assert_eq!(
            msg["params"]["target"],
            json!(stratum_target_hex(4)),
            "pushed job carries the retargeted difficulty"
        );
    }

    #[test]
    fn a_dead_miner_socket_is_detected_and_pruned() {
        let pool = test_pool("127.0.0.1:1", Some(share_template(UNREACHABLE)), 1);
        let (miner, client) = test_miner(&pool, 1);
        assert_eq!(pool.miners.lock().unwrap().len(), 1);
        // Kill the miner's end, then keep pushing until the OS surfaces the
        // failure (the first write after FIN can still land in the send buffer;
        // the RST that follows fails the next one).
        drop(client);
        let deadline = Instant::now() + Duration::from_secs(10);
        while miner.alive.load(Ordering::Relaxed) {
            pool.push(&miner, &json!({"method": "job", "params": {"probe": true}}));
            assert!(
                Instant::now() < deadline,
                "push to a closed socket never failed"
            );
            thread::sleep(Duration::from_millis(25));
        }
        // broadcast_jobs prunes dead sessions from the roster.
        pool.broadcast_jobs();
        assert!(pool.miners.lock().unwrap().is_empty());
    }

    fn share_template_for(
        proposer: &str,
        network_target: [u8; 32],
        tx_ids: Vec<String>,
    ) -> Template {
        let mut template = share_template(network_target);
        template.proposer = proposer.into();
        template.tx_ids_known = true;
        // The seal is the share id. Distinct blobs keep two templates from
        // colliding when they are ground at the same nonce.
        template.blob[0] = proposer.as_bytes().first().copied().unwrap_or(0);
        template.blob[1] = u8::try_from(tx_ids.len()).unwrap_or(255);
        template.tx_ids = tx_ids;
        template
    }

    /// Pool mode: a block that does not pay the window is withheld, and the
    /// same seal path forwards once the template carries the exact transfer.
    #[test]
    fn pool_withholds_a_block_until_the_window_is_paid() {
        let (node_addr, submits) = spawn_mock_node();
        let mut cfg = Config {
            node: node_addr,
            start_diff: 1,
            solo: false,
            share_rate: 1_000_000,
            ..Config::default()
        };
        cfg.vardiff.min_diff = 1;
        let pool = open_pool(cfg, None);
        *pool.reward_grains.lock().unwrap() = Some(1_000);

        let alice = AccountId::new("alice.sov").unwrap();
        let bob = AccountId::new("bob.sov").unwrap();
        let (miner_a, _) = test_miner(&pool, 1);
        let (miner_b, _) = test_miner(&pool, 1);
        *miner_a.payout.lock().unwrap() = Some(alice.clone());
        *miner_b.payout.lock().unwrap() = Some(bob.clone());
        *miner_a.work.write().unwrap() = Some(Arc::new(share_template_for(
            "alice.sov",
            UNREACHABLE,
            Vec::new(),
        )));
        *miner_b.work.write().unwrap() = Some(Arc::new(share_template_for(
            "bob.sov",
            UNREACHABLE,
            Vec::new(),
        )));

        let job_a = job_id_of(&pool.new_job_for(&miner_a).unwrap());
        handle_submit(
            &pool,
            &miner_a,
            &json!({"job_id": job_a, "nonce": nonce_wire(1)}),
        )
        .expect("alice share");
        let job_b = job_id_of(&pool.new_job_for(&miner_b).unwrap());
        handle_submit(
            &pool,
            &miner_b,
            &json!({"job_id": job_b, "nonce": nonce_wire(2)}),
        )
        .expect("bob share");
        assert!(
            submits.lock().unwrap().is_empty(),
            "shares below the network target are not blocks"
        );

        let round = pool.round.lock().unwrap().clone();
        assert!(round.expected.contains_key(&alice) && round.expected.contains_key(&bob));
        assert!(!round.frozen, "an unpaid split must stay open");

        // Alice finds a network block on a template that still pays only her.
        let unpaid_template = share_template_for("alice.sov", [0xff; 32], Vec::new());
        *miner_a.work.write().unwrap() = Some(Arc::new(unpaid_template.clone()));
        let unpaid_job = pool.new_job_for(&miner_a).unwrap();
        let unpaid_nonce = first_meeting_nonce(
            &unpaid_template,
            unpaid_job["target_full"].as_str().unwrap(),
        );
        handle_submit(
            &pool,
            &miner_a,
            &json!({"job_id": job_id_of(&unpaid_job), "nonce": nonce_wire(unpaid_nonce)}),
        )
        .expect("withheld block is still a valid share");
        assert!(
            submits.lock().unwrap().is_empty(),
            "a finder-takes-all block must not be forwarded once the window has two miners"
        );
        assert_eq!(pool.blocks_found.load(Ordering::Relaxed), 0);

        let owed = *pool
            .round
            .lock()
            .unwrap()
            .expected
            .get(&bob)
            .expect("bob still in the window");
        let tx_id = "aa".repeat(32);
        pool.relayed.lock().unwrap().insert(
            alice.clone(),
            vec![Relayed {
                leg: TransferLeg {
                    tx_id: tx_id.clone(),
                    from: alice.clone(),
                    to: bob.clone(),
                    amount: owed,
                },
                stx: dummy_transfer(&alice, &bob, owed),
            }],
        );
        let paid_template = share_template_for("alice.sov", [0xff; 32], vec![tx_id]);
        *miner_a.work.write().unwrap() = Some(Arc::new(paid_template.clone()));
        let paid_job = pool.new_job_for(&miner_a).unwrap();
        assert!(
            pool.round.lock().unwrap().frozen,
            "a template that pays the split freezes the round"
        );
        let paid_nonce =
            first_meeting_nonce(&paid_template, paid_job["target_full"].as_str().unwrap());
        // A different nonce from the withheld share: same blob, so the same
        // nonce would be the same share id and the sharechain would reject it.
        let paid_nonce = if paid_nonce == unpaid_nonce {
            first_meeting_nonce_after(
                &paid_template,
                paid_job["target_full"].as_str().unwrap(),
                unpaid_nonce,
            )
        } else {
            paid_nonce
        };
        handle_submit(
            &pool,
            &miner_a,
            &json!({"job_id": job_id_of(&paid_job), "nonce": nonce_wire(paid_nonce)}),
        )
        .expect("paid block");
        assert_eq!(submits.lock().unwrap().len(), 1, "exactly one forward");
        assert_eq!(pool.blocks_found.load(Ordering::Relaxed), 1);
        let recorded = pool.recent_blocks.lock().unwrap();
        let payouts = &recorded.back().unwrap().payouts;
        assert!(payouts.contains_key(&alice) && payouts.contains_key(&bob));
        assert_eq!(
            payouts.values().sum::<u128>(),
            1_000,
            "the payout map sums to the coinbase"
        );
    }

    fn first_meeting_nonce(template: &Template, target_hex: &str) -> u64 {
        first_meeting_nonce_after(template, target_hex, u64::MAX)
    }

    fn first_meeting_nonce_after(template: &Template, target_hex: &str, skip: u64) -> u64 {
        let target = hex::decode(target_hex).expect("target hex");
        (0..500_000)
            .find(|&nonce| {
                nonce != skip && template.seal_for_nonce(nonce).as_slice() <= target.as_slice()
            })
            .expect("a nonce meets the share target within 500k tries")
    }

    /// A signature the pool can store. The withhold test never relays it; the
    /// node mock is only asked to import the block.
    fn dummy_transfer(
        from: &AccountId,
        to: &AccountId,
        amount: u128,
    ) -> sov_types::SignedTransaction {
        use sov_crypto::Keypair;
        use sov_primitives::Balance;
        use sov_wallet::Wallet;
        let mut wallet = Wallet::new();
        let key = Keypair::from_seed([9; 32]);
        wallet.import(from.clone(), key);
        wallet
            .transfer(from, to.clone(), Balance::from_grains(amount), 0)
            .expect("sign")
    }
}
