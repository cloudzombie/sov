//! Share-difficulty arithmetic and per-session vardiff — the pure math under the
//! Stratum server, kept free of all I/O so every rule is unit-testable.
//!
//! SOV's proof-of-work rule is Bitcoin's: the 32-byte seal is read **big-endian**
//! and must be `<=` the target (`Target::is_met_by`, `chain/crates/pow/src/target.rs`).
//! Share targets here follow the *same* rule so that "a block is just a share that
//! also cleared network difficulty" holds by construction: the set of seals meeting
//! the (harder) network target is always a subset of those meeting the share target.

/// The 256-bit big-endian share threshold for `difficulty`:
/// `floor((2^256 − 1) / difficulty)`. Difficulty 1 accepts every hash; each
/// doubling of difficulty halves the accepting fraction — the standard pool
/// relation `P(share) = 1/difficulty` per hash.
pub fn difficulty_to_target256(difficulty: u64) -> [u8; 32] {
    let d = difficulty.max(1) as u128;
    // Long division of the 256-bit all-ones value by `d`, big-endian, one 64-bit
    // limb at a time (remainder never exceeds d − 1 < 2^64, so `(rem << 64) | limb`
    // fits in u128 and the per-limb quotient fits in u64).
    let mut out = [0u8; 32];
    let mut rem: u128 = 0;
    for limb in 0..4 {
        let cur = (rem << 64) | u64::MAX as u128;
        out[limb * 8..limb * 8 + 8].copy_from_slice(&((cur / d) as u64).to_be_bytes());
        rem = cur % d;
    }
    out
}

/// A share target must never be **harder** (numerically smaller) than the network
/// target — a pool share is a superset of a block find, never the reverse. If
/// vardiff ever drives a session's target below the network threshold, clamp it.
pub fn effective_share_target(share: [u8; 32], network: &[u8; 32]) -> [u8; 32] {
    if &share < network {
        *network
    } else {
        share
    }
}

/// The compact `target` field of a Monero-dialect Stratum job: hex of the
/// **little-endian** bytes of `floor(2^32 − 1) / D` (8 hex chars) when the
/// difficulty fits, else of `floor(2^64 − 1) / D` (16 hex chars) — the two
/// encodings xmrig-class miners accept.
pub fn stratum_target_hex(difficulty: u64) -> String {
    let d = difficulty.max(1);
    if d <= u32::MAX as u64 {
        hex::encode(((u32::MAX as u64 / d) as u32).to_le_bytes())
    } else {
        hex::encode((u64::MAX / d).to_le_bytes())
    }
}

/// What a verified seal amounts to, under the universal big-endian `<=` rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareOutcome {
    /// Meets neither threshold — rejected ("low difficulty share").
    TooWeak,
    /// Meets the share target but not the network target — credited, NOT forwarded.
    Share,
    /// Meets the network target — credited AND forwarded to `sov_submitBlock`.
    Block,
}

/// Classify a recomputed seal against the session's share target and the
/// template's network target. Equality counts as met on both, exactly like
/// `Target::is_met_by`.
pub fn classify_seal(
    seal: &[u8; 32],
    share_target: &[u8; 32],
    network_target: &[u8; 32],
) -> ShareOutcome {
    if seal <= network_target {
        ShareOutcome::Block
    } else if seal <= share_target {
        ShareOutcome::Share
    } else {
        ShareOutcome::TooWeak
    }
}

/// Vardiff tuning knobs (CLI-overridable; see `Config` in `main.rs`).
#[derive(Clone, Debug)]
pub struct VardiffConfig {
    /// Ideal seconds between shares from one session (~10 s is pool custom:
    /// responsive stats without drowning the bridge in verification work).
    pub target_share_secs: f64,
    /// How long a measurement window runs before a retarget is considered.
    pub retarget_secs: f64,
    /// Difficulty floor (protects the bridge from a share flood).
    pub min_diff: u64,
    /// Difficulty ceiling.
    pub max_diff: u64,
    /// Per-retarget clamp: the new difficulty moves at most this factor per
    /// window, so one lucky/unlucky window can't whipsaw a session.
    pub max_adjust: f64,
}

impl Default for VardiffConfig {
    fn default() -> Self {
        VardiffConfig {
            target_share_secs: 10.0,
            retarget_secs: 30.0,
            min_diff: 100,
            max_diff: 1 << 62,
            max_adjust: 4.0,
        }
    }
}

/// The retarget rule: estimate the session's share rate over the window and scale
/// difficulty so the rate returns to one share per `target_share_secs`.
///
/// `ratio = shares · target_share_secs / elapsed` — above 1 the session is too
/// fast (raise difficulty), below 1 too slow (lower it). A window with **zero**
/// shares counts as half a share so a stalled session drifts down instead of
/// freezing at an unreachable difficulty. The move is clamped to `max_adjust`
/// per window and to `[min_diff, max_diff]` absolutely.
pub fn next_difficulty(current: u64, shares: u64, elapsed_secs: f64, cfg: &VardiffConfig) -> u64 {
    let clamped_current = current.clamp(cfg.min_diff, cfg.max_diff);
    if elapsed_secs <= 0.0 {
        return clamped_current;
    }
    let effective_shares = if shares == 0 { 0.5 } else { shares as f64 };
    let ratio = effective_shares * cfg.target_share_secs / elapsed_secs;
    let bounded = ratio.clamp(1.0 / cfg.max_adjust, cfg.max_adjust);
    // `as u64` saturates on overflow/NaN per Rust's float-to-int cast rules.
    let next = (clamped_current as f64 * bounded).round() as u64;
    next.clamp(cfg.min_diff, cfg.max_diff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_one_accepts_every_hash() {
        assert_eq!(difficulty_to_target256(1), [0xff; 32]);
        // Difficulty 0 is nonsense; it is treated as 1 rather than dividing by zero.
        assert_eq!(difficulty_to_target256(0), [0xff; 32]);
    }

    #[test]
    fn difficulty_two_halves_the_space() {
        let t = difficulty_to_target256(2);
        let mut expected = [0xff; 32];
        expected[0] = 0x7f;
        assert_eq!(t, expected);
    }

    #[test]
    fn power_of_two_difficulty_shifts_whole_bits() {
        // D = 2^8: exactly one leading zero byte, then all-ones.
        let t = difficulty_to_target256(256);
        assert_eq!(t[0], 0x00);
        assert!(t[1..].iter().all(|&b| b == 0xff));
        // D = 2^16: two leading zero bytes.
        let t = difficulty_to_target256(1 << 16);
        assert_eq!(&t[..2], &[0, 0]);
        assert!(t[2..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn higher_difficulty_is_a_strictly_harder_target() {
        assert!(difficulty_to_target256(2_000) < difficulty_to_target256(1_000));
        assert!(difficulty_to_target256(u64::MAX) < difficulty_to_target256(u64::MAX / 2));
    }

    #[test]
    fn stratum_compact_target_matches_known_pool_vectors() {
        // The canonical Monero-pool encodings: hex of LE(0xFFFFFFFF / D).
        assert_eq!(stratum_target_hex(1), "ffffffff");
        assert_eq!(stratum_target_hex(2), "ffffff7f");
        // 0xFFFFFFFF / 10000 = 0x00068DB8 → LE b8 8d 06 00.
        assert_eq!(stratum_target_hex(10_000), "b88d0600");
        // Above u32 range the 64-bit form kicks in: u64::MAX / 2^40 = 0x00FFFFFF.
        assert_eq!(stratum_target_hex(1 << 40), "ffffff0000000000");
    }

    #[test]
    fn effective_share_target_never_undercuts_the_network_target() {
        let network = difficulty_to_target256(1_000_000);
        // An easier share target passes through untouched.
        let easy = difficulty_to_target256(100);
        assert_eq!(effective_share_target(easy, &network), easy);
        // A harder-than-network share target clamps up to the network threshold.
        let too_hard = difficulty_to_target256(u64::MAX);
        assert_eq!(effective_share_target(too_hard, &network), network);
    }

    #[test]
    fn classify_seal_boundaries_count_equality_as_met() {
        let network = difficulty_to_target256(1 << 16);
        let share = difficulty_to_target256(256);
        // Exactly on the network threshold → Block (mirrors Target::is_met_by's `<=`).
        assert_eq!(
            classify_seal(&network, &share, &network),
            ShareOutcome::Block
        );
        // Exactly on the share threshold → Share, not forwarded.
        assert_eq!(classify_seal(&share, &share, &network), ShareOutcome::Share);
        // Above both → rejected.
        assert_eq!(
            classify_seal(&[0xff; 32], &share, &network),
            ShareOutcome::TooWeak
        );
        // Below both → Block (a block IS a share that cleared network difficulty).
        assert_eq!(
            classify_seal(&[0x00; 32], &share, &network),
            ShareOutcome::Block
        );
    }

    #[test]
    fn vardiff_raises_difficulty_on_fast_shares_with_clamp() {
        let cfg = VardiffConfig::default();
        // 10 shares in 10 s at a 10 s ideal → ratio 10, clamped to max_adjust 4×.
        assert_eq!(next_difficulty(1_000, 10, 10.0, &cfg), 4_000);
        // Modestly fast: 2 shares in 10 s → exactly 2×.
        assert_eq!(next_difficulty(1_000, 2, 10.0, &cfg), 2_000);
    }

    #[test]
    fn vardiff_lowers_difficulty_on_slow_or_absent_shares() {
        let cfg = VardiffConfig::default();
        // One share in 40 s at a 10 s ideal → ×0.25 (the clamp boundary exactly).
        assert_eq!(next_difficulty(1_000, 1, 40.0, &cfg), 250);
        // Zero shares counts as half a share: 0 in 30 s → ratio 1/6, clamped to ×1/4.
        assert_eq!(next_difficulty(1_000, 0, 30.0, &cfg), 250);
    }

    #[test]
    fn vardiff_respects_absolute_bounds_and_degenerate_windows() {
        let cfg = VardiffConfig {
            min_diff: 500,
            max_diff: 8_000,
            ..VardiffConfig::default()
        };
        // Floor: even a dead-slow session never drops below min_diff.
        assert_eq!(next_difficulty(600, 0, 300.0, &cfg), 500);
        // Ceiling: a firehose session caps at max_diff.
        assert_eq!(next_difficulty(4_000, 100, 10.0, &cfg), 8_000);
        // A zero-length window changes nothing (but still clamps into bounds).
        assert_eq!(next_difficulty(1_000, 5, 0.0, &cfg), 1_000);
        assert_eq!(next_difficulty(10, 5, 0.0, &cfg), 500);
    }

    // ---- exhaustive difficulty→target long-division coverage ----------------

    /// Multiply a 256-bit big-endian value by a u64 and add `addend`, returning
    /// (overflow_limb, product). Test-side reference arithmetic for proving the
    /// long division exact: `target * d + rem == 2^256 − 1` with `rem < d`.
    fn mul256_add(value: &[u8; 32], factor: u64, addend: u64) -> (u64, [u8; 32]) {
        let mut limbs = [0u64; 4]; // big-endian limb order, as in the target
        for (i, l) in limbs.iter_mut().enumerate() {
            *l = u64::from_be_bytes(value[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let mut out = [0u64; 4];
        let mut carry = addend as u128;
        for i in (0..4).rev() {
            let cur = limbs[i] as u128 * factor as u128 + carry;
            out[i] = cur as u64;
            carry = cur >> 64;
        }
        let mut bytes = [0u8; 32];
        for (i, l) in out.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&l.to_be_bytes());
        }
        (carry as u64, bytes)
    }

    /// `2^256 − 1 − x` for a big-endian 256-bit value (no borrow can escape
    /// because the minuend is all-ones): just the bitwise complement.
    fn all_ones_minus(x: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (o, b) in out.iter_mut().zip(x.iter()) {
            *o = !b;
        }
        out
    }

    /// A 256-bit big-endian value compared against a u64.
    fn lt_u64(x: &[u8; 32], d: u64) -> bool {
        x[..24].iter().all(|&b| b == 0) && u64::from_be_bytes(x[24..].try_into().unwrap()) < d
    }

    #[test]
    fn long_division_is_exact_floor_division_for_sampled_difficulties() {
        // For every sampled D: target·D + rem == 2^256 − 1 with 0 <= rem < D —
        // the defining property of floor((2^256 − 1) / D), checked with
        // independent test-side big-integer arithmetic (not the code under test).
        let samples: [u64; 18] = [
            1,
            2,
            3,
            5,
            7,
            10,
            255,
            256,
            1_000,
            5_000,
            65_537,
            1_000_003,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u32::MAX as u64 + 2,
            u64::MAX / 3,
            u64::MAX - 1,
            u64::MAX,
        ];
        for d in samples {
            let target = difficulty_to_target256(d);
            let (overflow, product) = mul256_add(&target, d, 0);
            assert_eq!(overflow, 0, "target·{d} must not overflow 256 bits");
            let rem = all_ones_minus(&product); // (2^256−1) − target·d
            assert!(lt_u64(&rem, d), "remainder for D={d} must be < D");
        }
    }

    #[test]
    fn known_closed_form_divisors_produce_exact_repeating_targets() {
        // (2^256−1)/3 = 0x5555…55, /5 = 0x3333…33, /255 = 0x0101…01 — all exact
        // because 3, 5, 255 divide 2^256 − 1. And (2^256−1)/(2^64−1) is the
        // 4-limb repunit [0,0,0,0,0,0,0,1] × 4.
        assert_eq!(difficulty_to_target256(3), [0x55; 32]);
        assert_eq!(difficulty_to_target256(5), [0x33; 32]);
        assert_eq!(difficulty_to_target256(255), [0x01; 32]);
        let mut repunit = [0u8; 32];
        for limb in 0..4 {
            repunit[limb * 8 + 7] = 1;
        }
        assert_eq!(difficulty_to_target256(u64::MAX), repunit);
    }

    #[test]
    fn every_power_of_two_difficulty_is_an_exact_right_shift() {
        // D = 2^k ⇒ target = (2^256 − 1) >> k for every representable k:
        // k/8 zero bytes, one 0xff >> (k%8) boundary byte, then all-ones.
        for k in 0..64u32 {
            let t = difficulty_to_target256(1u64 << k);
            let zeros = (k / 8) as usize;
            let boundary = 0xffu8 >> (k % 8);
            let mut expected = [0xffu8; 32];
            expected[..zeros].fill(0);
            expected[zeros] = boundary;
            assert_eq!(t, expected, "target for D=2^{k}");
        }
    }

    #[test]
    fn target_is_monotonically_non_increasing_in_difficulty() {
        let ladder: [u64; 10] = [
            1,
            2,
            3,
            100,
            101,
            65_536,
            1_000_000,
            u32::MAX as u64,
            1 << 40,
            u64::MAX,
        ];
        for pair in ladder.windows(2) {
            assert!(
                difficulty_to_target256(pair[1]) < difficulty_to_target256(pair[0]),
                "D={} must be strictly harder than D={}",
                pair[1],
                pair[0]
            );
        }
    }

    #[test]
    fn stratum_compact_target_boundary_widths() {
        // Exactly at u32::MAX the 32-bit form still applies (quotient 1).
        assert_eq!(stratum_target_hex(u32::MAX as u64), "01000000");
        // One past it, the 64-bit form kicks in: u64::MAX / 2^32 = 0xFFFFFFFF.
        assert_eq!(stratum_target_hex(u32::MAX as u64 + 1), "ffffffff00000000");
        // The hardest representable difficulty.
        assert_eq!(stratum_target_hex(u64::MAX), "0100000000000000");
        // Width invariant across the whole range: 8 hex chars ≤ u32::MAX, 16 above.
        for d in [1u64, 1000, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            let hex = stratum_target_hex(d);
            let want = if d <= u32::MAX as u64 { 8 } else { 16 };
            assert_eq!(hex.len(), want, "compact width for D={d}");
        }
    }

    #[test]
    fn effective_share_target_passes_equality_through() {
        // share == network is NOT clamped (nothing to fix): byte-identical output.
        let network = difficulty_to_target256(4096);
        assert_eq!(effective_share_target(network, &network), network);
    }

    // ---- classify_seal: exact one-off boundary sweep ------------------------

    /// x + 1 over a 256-bit big-endian value (must not be all-ones).
    fn incremented(x: &[u8; 32]) -> [u8; 32] {
        let mut out = *x;
        for b in out.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                return out;
            }
        }
        panic!("increment overflowed 256 bits");
    }

    /// x − 1 over a 256-bit big-endian value (must not be zero).
    fn decremented(x: &[u8; 32]) -> [u8; 32] {
        let mut out = *x;
        for b in out.iter_mut().rev() {
            let (v, borrow) = b.overflowing_sub(1);
            *b = v;
            if !borrow {
                return out;
            }
        }
        panic!("decrement underflowed 256 bits");
    }

    #[test]
    fn classify_seal_exact_one_off_boundaries() {
        // network (D = 2^16) is strictly harder than share (D = 2^8).
        let network = difficulty_to_target256(1 << 16);
        let share = difficulty_to_target256(1 << 8);
        assert!(network < share, "test premise: network strictly harder");
        // The six seals that pin both thresholds to the exact byte:
        assert_eq!(
            classify_seal(&decremented(&network), &share, &network),
            ShareOutcome::Block,
            "one below the network target is a block"
        );
        assert_eq!(
            classify_seal(&network, &share, &network),
            ShareOutcome::Block,
            "equality with the network target is a block (<= rule)"
        );
        assert_eq!(
            classify_seal(&incremented(&network), &share, &network),
            ShareOutcome::Share,
            "one above the network target is only a share"
        );
        assert_eq!(
            classify_seal(&decremented(&share), &share, &network),
            ShareOutcome::Share,
            "one below the share target is a share"
        );
        assert_eq!(
            classify_seal(&share, &share, &network),
            ShareOutcome::Share,
            "equality with the share target is a share (<= rule)"
        );
        assert_eq!(
            classify_seal(&incremented(&share), &share, &network),
            ShareOutcome::TooWeak,
            "one above the share target is rejected"
        );
    }

    #[test]
    fn classify_seal_degenerate_equal_targets_prefer_block() {
        // When vardiff clamps the share target TO the network target, the two
        // thresholds coincide; a met seal must classify as Block (forwarded),
        // never silently downgraded to Share.
        let t = difficulty_to_target256(1 << 20);
        assert_eq!(classify_seal(&t, &t, &t), ShareOutcome::Block);
        assert_eq!(
            classify_seal(&incremented(&t), &t, &t),
            ShareOutcome::TooWeak
        );
    }

    // ---- vardiff: convergence + adversarial windows -------------------------

    /// Deterministic expected-value miner: at difficulty D and hashrate `h`
    /// (difficulty-units/sec), a window of `secs` yields round(secs·h/D) shares.
    fn simulate_windows(mut d: u64, h: f64, windows: usize, cfg: &VardiffConfig) -> Vec<u64> {
        let mut history = Vec::with_capacity(windows);
        for _ in 0..windows {
            let shares = (cfg.retarget_secs * h / d as f64).round() as u64;
            d = next_difficulty(d, shares, cfg.retarget_secs, cfg);
            history.push(d);
        }
        history
    }

    #[test]
    fn vardiff_converges_from_below_and_stays_locked() {
        let cfg = VardiffConfig::default();
        // h = 10_000 diff-units/s ⇒ ideal difficulty = h · 10 s = 100_000.
        // Integer share counts make the lock band [30h/3.5, 30h/2.5].
        let h = 10_000.0;
        let (lo, hi) = ((30.0 * h / 3.5) as u64, (30.0 * h / 2.5) as u64);
        let history = simulate_windows(cfg.min_diff, h, 25, &cfg);
        let final_d = *history.last().unwrap();
        assert!(
            (lo..=hi).contains(&final_d),
            "converged difficulty {final_d} outside lock band [{lo}, {hi}]"
        );
        // Once locked, it is a fixed point: the last windows do not move.
        assert_eq!(history[23], history[24], "converged vardiff must be stable");
        // And every step respected the ×4 per-window clamp.
        let mut prev = cfg.min_diff;
        for &d in &history {
            assert!(
                d <= prev.saturating_mul(4) && d >= prev / 4,
                "clamp violated: {prev} -> {d}"
            );
            prev = d;
        }
    }

    #[test]
    fn vardiff_converges_from_far_above_via_zero_share_windows() {
        let cfg = VardiffConfig::default();
        let h = 10_000.0;
        let (lo, hi) = ((30.0 * h / 3.5) as u64, (30.0 * h / 2.5) as u64);
        // Start absurdly high (2^40): windows see ZERO shares, which must count
        // as half a share and walk difficulty down ×4 per window, never freezing.
        let history = simulate_windows(1 << 40, h, 25, &cfg);
        let final_d = *history.last().unwrap();
        assert!(
            (lo..=hi).contains(&final_d),
            "descent difficulty {final_d} outside lock band [{lo}, {hi}]"
        );
        // The first windows are exactly the ×1/4 zero-share descent.
        assert_eq!(history[0], (1u64 << 40) / 4);
        assert_eq!(history[1], (1u64 << 40) / 16);
    }

    #[test]
    fn vardiff_share_burst_is_clamped_to_one_quadrupling() {
        let cfg = VardiffConfig::default();
        // A thousand shares in one window — a flood — still moves at most ×4.
        assert_eq!(next_difficulty(1_000, 1_000, 30.0, &cfg), 4_000);
        // And an equally extreme drought still moves at most ×1/4.
        assert_eq!(next_difficulty(1_000, 0, 1e9, &cfg), 250);
    }

    #[test]
    fn vardiff_out_of_bounds_current_is_clamped_before_scaling() {
        let cfg = VardiffConfig {
            min_diff: 500,
            max_diff: 8_000,
            ..VardiffConfig::default()
        };
        // current below the floor: clamped to 500 first, then scaled from there.
        // 3 shares in 30 s at 10 s ideal = ratio 1.0 ⇒ stays at the clamped 500.
        assert_eq!(next_difficulty(1, 3, 30.0, &cfg), 500);
        // current above the ceiling: clamped to 8_000 even when shares say "raise".
        assert_eq!(next_difficulty(u64::MAX, 100, 10.0, &cfg), 8_000);
    }

    #[test]
    fn vardiff_never_panics_or_escapes_bounds_on_pathological_inputs() {
        let cfg = VardiffConfig::default();
        for (shares, elapsed) in [
            (0u64, f64::NAN),
            (u64::MAX, f64::NAN),
            (u64::MAX, 1e-300),
            (0, f64::INFINITY),
            (u64::MAX, f64::INFINITY),
            (u64::MAX, 30.0),
            (0, -5.0),
        ] {
            for current in [0u64, 1, cfg.min_diff, cfg.max_diff, u64::MAX] {
                let next = next_difficulty(current, shares, elapsed, &cfg);
                assert!(
                    (cfg.min_diff..=cfg.max_diff).contains(&next),
                    "next_difficulty({current}, {shares}, {elapsed}) = {next} escaped bounds"
                );
            }
        }
    }
}
