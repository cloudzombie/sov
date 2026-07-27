//! REAL-mainnet block-log replay harness — the dormant byte-identity
//! evidence rig for consensus-adjacent slices (v0.2.0 program, W2).
//!
//! Points the PRODUCTION boot path (`Daemon::new`: baked mainnet activation
//! preset installed before replay, then the three-tier fast start) at a
//! **copy** of a real mainnet node's `blocks.log` and prints the resulting
//! head height, head hash, state root, and supply. Running the same log copy
//! through a baseline build (today's `main`) and a candidate build and
//! comparing the printed lines is the strongest available proof that a
//! dormant change left mainnet consensus byte-identical.
//!
//! Opt-in: does nothing (passes) unless `SOV_MAINNET_BLOCKS_LOG` names a log
//! copy — a CI runner has no mainnet log, and this must never touch a LIVE
//! node's data directory (always replay a copy).
//!
//! Run:
//! ```text
//! SOV_MAINNET_BLOCKS_LOG=/path/to/copied/blocks.log \
//!     cargo test -p sov-rpc --release --test mainnet_replay -- --nocapture
//! ```

use sov_rpc::{ChainSpec, Daemon};

const MAINNET_SPEC: &str = include_str!("../../../specs/mainnet.json");

#[test]
fn replay_real_mainnet_block_log_if_provided() {
    let Ok(log) = std::env::var("SOV_MAINNET_BLOCKS_LOG") else {
        eprintln!(
            "SOV_MAINNET_BLOCKS_LOG not set — skipping the real-mainnet replay \
             (evidence harness, not a CI gate)"
        );
        return;
    };

    // A scratch data dir holding ONLY the copied log (+ schema tag): no
    // snapshot exists, so the first boot MUST take the trusted-replay tier,
    // which re-executes every block on the ledger and verifies the resulting
    // state root against the head block's committed root.
    let dir = std::env::temp_dir().join(format!(
        "sov-mainnet-replay-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch data dir");
    std::fs::copy(&log, dir.join("blocks.log")).expect("copy the log into the scratch dir");
    // The source copy may be kept read-only (it SHOULD be — never point this
    // at a live node's data dir); the scratch copy must be writable for the
    // daemon's append handle to open.
    let mut perms = std::fs::metadata(dir.join("blocks.log"))
        .expect("copied log metadata")
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)] // scratch copy, test-only
    perms.set_readonly(false);
    std::fs::set_permissions(dir.join("blocks.log"), perms).expect("make scratch copy writable");
    std::fs::write(dir.join("schema_version"), b"1").expect("schema tag");

    // The FROZEN mainnet genesis, verified against the cb0272ff… pin.
    let spec = ChainSpec::from_json(MAINNET_SPEC).expect("mainnet spec parses");
    let genesis = spec
        .to_genesis_config_verified()
        .expect("mainnet genesis builds and matches the frozen pin");

    // Boot 1 — the production path: baked preset, then trusted replay of the
    // whole log (state root verified against the head block, falling back to
    // full verified import on any inconsistency).
    let daemon = Daemon::new(&genesis, &dir, 16, 16, vec![]).expect("mainnet log replays");
    let resumed = daemon.resumed_blocks();
    assert!(resumed > 0, "the provided log must contain real blocks");
    let (height, head, root, supply) = {
        let node = daemon.node();
        let n = node.lock().expect("node lock");
        let c = n.chain();
        assert_eq!(
            c.head().header.state_root,
            c.ledger().state_root(),
            "replayed ledger must reproduce the head block's committed state root"
        );
        // Dormancy: real mainnet history contains no pool-v2 activity, so the
        // v2 sub-state must be EXACTLY absent after a full replay — empty
        // pool, zero turnstile, default window (their state-root slots do not
        // exist, which is what keeps every historical root byte-identical).
        assert!(c.ledger().shielded_v2().is_empty());
        assert_eq!(
            c.ledger().shielded_v2_value(),
            sov_primitives::Balance::ZERO
        );
        assert_eq!(
            c.ledger().deshield_v2_window(),
            (0, sov_primitives::Balance::ZERO)
        );
        (
            c.height(),
            c.head().hash().to_hex(),
            c.ledger().state_root().to_hex(),
            c.ledger().total_supply().expect("supply sums").grains(),
        )
    };
    println!(
        "MAINNET REPLAY tier2: blocks={resumed} height={height} head={head} \
         state_root={root} supply_grains={supply}"
    );
    drop(daemon);

    // Boot 2 — tier-1 snapshot resume (boot 1 wrote a chainstate snapshot):
    // must land on the identical head and root through the OTHER code path.
    let daemon2 = Daemon::new(&genesis, &dir, 16, 16, vec![]).expect("snapshot resume");
    {
        let node = daemon2.node();
        let n = node.lock().expect("node lock");
        let c = n.chain();
        assert_eq!(c.height(), height, "tier-1 resume agrees on height");
        assert_eq!(c.head().hash().to_hex(), head, "…and head hash");
        assert_eq!(c.ledger().state_root().to_hex(), root, "…and state root");
    }
    println!("MAINNET REPLAY tier1: height/head/state_root identical on snapshot resume");
    drop(daemon2);

    // Boot 3 (optional) — a REAL chainstate snapshot written by a PRE-v0.2.0
    // binary (the LEGACY ledger-blob format, no pool-v2 element), if the
    // operator provides a copy: the daemon must tier-1 resume from it through
    // the legacy-decode fallback, trusted-replay the post-snapshot gap from
    // the log, and land on the identical head triple. This is the real-data
    // proof that upgrading in place keeps existing snapshots loadable.
    if let Ok(snap) = std::env::var("SOV_MAINNET_SNAPSHOT") {
        let dir_b = dir.with_file_name(format!(
            "{}-legacy-snap",
            dir.file_name().expect("dir name").to_string_lossy()
        ));
        let _ = std::fs::remove_dir_all(&dir_b);
        std::fs::create_dir_all(&dir_b).expect("legacy-snapshot scratch dir");
        for (src, dst) in [
            (log.as_str(), "blocks.log"),
            (snap.as_str(), "chainstate.snapshot"),
        ] {
            std::fs::copy(src, dir_b.join(dst)).expect("copy into scratch dir");
            let mut p = std::fs::metadata(dir_b.join(dst))
                .expect("metadata")
                .permissions();
            #[allow(clippy::permissions_set_readonly_false)] // scratch copy, test-only
            p.set_readonly(false);
            std::fs::set_permissions(dir_b.join(dst), p).expect("writable scratch copy");
        }
        std::fs::write(dir_b.join("schema_version"), b"1").expect("schema tag");
        let daemon3 = Daemon::new(&genesis, &dir_b, 16, 16, vec![]).expect("legacy resume");
        assert!(
            daemon3.resumed_from_snapshot(),
            "the pre-v0.2.0 snapshot must be ACCEPTED (tier-1), not discarded — \
             the legacy ledger-blob fallback is what this proves"
        );
        {
            let node = daemon3.node();
            let n = node.lock().expect("node lock");
            let c = n.chain();
            assert_eq!(c.height(), height, "legacy-snapshot boot agrees on height");
            assert_eq!(c.head().hash().to_hex(), head, "…and head hash");
            assert_eq!(c.ledger().state_root().to_hex(), root, "…and state root");
        }
        println!(
            "MAINNET REPLAY legacy-snapshot: tier-1 resume from a real pre-v0.2.0 \
             snapshot reproduces the identical head/state_root"
        );
        let _ = std::fs::remove_dir_all(&dir_b);
    } else {
        eprintln!("SOV_MAINNET_SNAPSHOT not set — legacy-snapshot leg skipped");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
