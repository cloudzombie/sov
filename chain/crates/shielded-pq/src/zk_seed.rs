//! Seed-preimage ownership constraints for the hiding proof.
//!
//! Legacy traces exposed NSK registers, not the BLAKE3 seed that generated
//! them. Requiring that preimage strengthens ownership without changing notes,
//! roots or nullifiers. This is a single-block BLAKE3 derive-key computation,
//! constrained alongside the original Rescue circuit in the same hiding proof.

use crate::air::{INPUT_SEGMENT_ROWS, NSK_COL, NUM_SLOTS, TRACE_LENGTH};
use crate::domains::B3_NSK;
use crate::hash::Felt;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use winter_math::FieldElement;

pub(super) const WIDTH: usize = 512 + 256 + 2;
const MESSAGE: usize = 512;
const CARRY: usize = 768;
const STEPS: usize = 7 * 8 * 4;
const GROUPS: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const P_ACTIVE: usize = 0;
const P_INIT: usize = 1;
const P_GROUP: usize = 2;
const P_PHASE: usize = 10;
const P_MESSAGE: usize = 14;
const P_END: usize = 22;

fn schedules() -> [[usize; 16]; 7] {
    let mut rows = [[0; 16]; 7];
    rows[0] = std::array::from_fn(|i| i);
    for round in 1..7 {
        rows[round] = std::array::from_fn(|i| rows[round - 1][PERMUTATION[i]]);
    }
    rows
}
fn initial(key: [u32; 8], length: u32, flags: u32) -> [u32; 16] {
    let mut state = [0; 16];
    state[..8].copy_from_slice(&key);
    state[8..12].copy_from_slice(&IV[..4]);
    state[14] = length;
    state[15] = flags;
    state
}
fn step(state: &mut [u32; 16], message: &[u32; 16], number: usize) -> u64 {
    let [a, b, c, d] = GROUPS[(number / 4) % 8];
    let phase = number % 4;
    let schedule = schedules();
    let words = schedule[number / 32];
    let (dest, left, right, extra, xor_dest, rotation) = match phase {
        0 => (a, a, b, message[words[2 * ((number / 4) % 8)]], d, 16),
        1 => (c, c, d, 0, b, 12),
        2 => (a, a, b, message[words[2 * ((number / 4) % 8) + 1]], d, 8),
        _ => (c, c, d, 0, b, 7),
    };
    let sum = state[left] as u64 + state[right] as u64 + extra as u64;
    state[dest] = sum as u32;
    state[xor_dest] = (state[xor_dest] ^ state[dest]).rotate_right(rotation);
    sum >> 32
}
fn compression(key: [u32; 8], block: [u32; 16], length: u32, flags: u32) -> [u32; 8] {
    let mut state = initial(key, length, flags);
    for number in 0..STEPS {
        step(&mut state, &block, number);
    }
    std::array::from_fn(|i| state[i] ^ state[i + 8])
}
fn context_key() -> [u32; 8] {
    assert!(
        B3_NSK.len() <= 64,
        "fixed ownership domain must fit one BLAKE3 block"
    );
    let mut bytes = [0; 64];
    bytes[..B3_NSK.len()].copy_from_slice(B3_NSK.as_bytes());
    let block = std::array::from_fn(|i| {
        u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("word"))
    });
    // CHUNK_START | CHUNK_END | ROOT | DERIVE_KEY_CONTEXT.
    compression(IV, block, B3_NSK.len() as u32, 1 | 2 | 8 | 32)
}

pub(super) fn periodic() -> Vec<Vec<Goldilocks>> {
    let mut columns = vec![vec![Goldilocks::ZERO; TRACE_LENGTH]; P_END + NUM_SLOTS];
    let schedule = schedules();
    for slot in 0..NUM_SLOTS {
        let start = slot * INPUT_SEGMENT_ROWS;
        columns[P_INIT][start] = Goldilocks::ONE;
        columns[P_END + slot][start + STEPS] = Goldilocks::ONE;
        for number in 0..STEPS {
            let row = start + number;
            let group = (number / 4) % 8;
            let phase = number % 4;
            columns[P_ACTIVE][row] = Goldilocks::ONE;
            columns[P_GROUP + group][row] = Goldilocks::ONE;
            columns[P_PHASE + phase][row] = Goldilocks::ONE;
            if phase == 0 || phase == 2 {
                let index = schedule[number / 32][group * 2 + usize::from(phase == 2)];
                if index < 8 {
                    columns[P_MESSAGE + index][row] = Goldilocks::ONE;
                }
            }
        }
    }
    columns
}

pub(super) fn columns(seeds: &[[u8; 32]; NUM_SLOTS]) -> Vec<Vec<Felt>> {
    let mut columns = vec![vec![Felt::ZERO; TRACE_LENGTH]; WIDTH];
    let init = initial(context_key(), 32, 1 | 2 | 8 | 64);
    for (slot, seed) in seeds.iter().enumerate() {
        let mut message = [0; 16];
        for (index, word) in message[..8].iter_mut().enumerate() {
            *word = u32::from_le_bytes(
                seed[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("seed word"),
            );
        }
        let start = slot * INPUT_SEGMENT_ROWS;
        let mut state = init;
        for local in 0..INPUT_SEGMENT_ROWS {
            let row = start + local;
            for (word, value) in state.iter().enumerate() {
                for bit in 0..32 {
                    columns[word * 32 + bit][row] = Felt::new(((value >> bit) & 1) as u64);
                }
            }
            for (word, value) in message[..8].iter().enumerate() {
                for bit in 0..32 {
                    columns[MESSAGE + word * 32 + bit][row] =
                        Felt::new(((value >> bit) & 1) as u64);
                }
            }
            if local < STEPS {
                let carry = step(&mut state, &message, local);
                columns[CARRY][row] = Felt::new(carry & 1);
                columns[CARRY + 1][row] = Felt::new(carry >> 1);
            }
        }
    }
    columns
}

fn word<E: PrimeCharacteristicRing>(bits: &[E]) -> E {
    bits.iter().enumerate().fold(E::ZERO, |sum, (bit, value)| {
        sum + value.clone() * E::from_u64(1u64 << bit)
    })
}
/// Evaluate a fixed BLAKE3 computation and bind its private output to the
/// private NSK columns of the original note circuit.
pub(super) fn evaluate<AB: AirBuilder<F = Goldilocks>>(
    builder: &mut AB,
    cur: &[AB::Expr],
    next: &[AB::Expr],
    periodic: &[AB::Expr],
    old_cur: &[AB::Expr],
    constant_keys: AB::Expr,
    dummy: &[bool; NUM_SLOTS],
) {
    for value in cur {
        builder.assert_zero(value.clone() * (value.clone() - AB::Expr::ONE));
    }
    for bit in 0..256 {
        builder.assert_zero(
            constant_keys.clone() * (next[MESSAGE + bit].clone() - cur[MESSAGE + bit].clone()),
        );
    }
    let init = initial(context_key(), 32, 1 | 2 | 8 | 64);
    for (index, value) in init.iter().enumerate() {
        for bit in 0..32 {
            builder.assert_zero(
                periodic[P_INIT].clone()
                    * (cur[index * 32 + bit].clone()
                        - AB::Expr::from_u64(((value >> bit) & 1) as u64)),
            );
        }
    }
    let message: AB::Expr = (0..8).fold(AB::Expr::ZERO, |sum, index| {
        sum + periodic[P_MESSAGE + index].clone()
            * word(&cur[MESSAGE + index * 32..MESSAGE + (index + 1) * 32])
    });
    let carry = cur[CARRY].clone() + cur[CARRY + 1].clone() * AB::Expr::from_u64(2);
    for (group, [a, b, c, d]) in GROUPS.iter().copied().enumerate() {
        for phase in 0..4 {
            let mask = periodic[P_ACTIVE].clone()
                * periodic[P_GROUP + group].clone()
                * periodic[P_PHASE + phase].clone();
            let (dest, left, right, xor_dest, rotation) = match phase {
                0 => (a, a, b, d, 16),
                1 => (c, c, d, b, 12),
                2 => (a, a, b, d, 8),
                _ => (c, c, d, b, 7),
            };
            let extra = if phase == 0 || phase == 2 {
                message.clone()
            } else {
                AB::Expr::ZERO
            };
            builder.assert_zero(
                mask.clone()
                    * (word(&cur[left * 32..left * 32 + 32])
                        + word(&cur[right * 32..right * 32 + 32])
                        + extra
                        - word(&next[dest * 32..dest * 32 + 32])
                        - carry.clone() * AB::Expr::from_u64(1u64 << 32)),
            );
            for bit in 0..32 {
                let position = (bit + rotation) % 32;
                let x = cur[xor_dest * 32 + position].clone();
                let y = next[dest * 32 + position].clone();
                builder.assert_zero(
                    mask.clone()
                        * (next[xor_dest * 32 + bit].clone() - x.clone() - y.clone()
                            + x * y * AB::Expr::from_u64(2)),
                );
            }
            for index in 0..16 {
                if index == dest || index == xor_dest {
                    continue;
                }
                for bit in 0..32 {
                    builder.assert_zero(
                        mask.clone()
                            * (next[index * 32 + bit].clone() - cur[index * 32 + bit].clone()),
                    );
                }
            }
        }
    }
    for (slot, is_dummy) in dummy.iter().copied().enumerate() {
        if is_dummy {
            continue;
        }
        for limb in 0..4 {
            let mut result = AB::Expr::ZERO;
            for bit in 0..64 {
                let index = limb * 2 + bit / 32;
                let position = bit % 32;
                let x = cur[index * 32 + position].clone();
                let y = cur[(index + 8) * 32 + position].clone();
                result += (x.clone() + y.clone() - x * y * AB::Expr::from_u64(2))
                    * AB::Expr::from_u64(1u64 << bit);
            }
            builder.assert_zero(
                periodic[P_END + slot].clone() * (result - old_cur[NSK_COL + limb].clone()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seed_compression_matches_the_unchanged_blake3_key_derivation() {
        for byte in [0, 1, 42, 255] {
            let seed = [byte; 32];
            let mut block = [0; 16];
            for word in &mut block[..8] {
                *word = u32::from_le_bytes([byte; 4]);
            }
            let actual = compression(context_key(), block, 32, 1 | 2 | 8 | 64);
            let expected = blake3::derive_key(B3_NSK, &seed);
            let actual: Vec<_> = actual.into_iter().flat_map(u32::to_le_bytes).collect();
            assert_eq!(actual, expected);
        }
    }
}
