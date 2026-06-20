/**
 * Cross-implementation EMISSION verification: the SDK's `rewardAt` (a mirror of
 * `MiningPolicy::reward_at`) must reproduce the node's coinbase subsidy at every
 * pinned height — across halving boundaries, the budget backstop, and decay to
 * zero. With tens of thousands of independent miners, an off-by-one subsidy is a
 * fork. Vector: `cargo run -p sov-rpc --bin sov-katgen -- emission >
 * sdk/vectors/emission.json`.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { rewardAt, type BlockContext } from "../src/stf.js";

const here = dirname(fileURLToPath(import.meta.url));

interface EmissionVector {
  policy: {
    base_reward_grains: string;
    halving_interval_blocks: number;
    mining_budget_grains: string;
  };
  samples: { height: number; mined_supply_grains: string; reward_grains: string }[];
}

const vec: EmissionVector = JSON.parse(
  readFileSync(join(here, "..", "vectors", "emission.json"), "utf8"),
);

describe("emission schedule (reward_at) cross-impl KAT", () => {
  // Only the emission fields matter to `rewardAt`; the rest are unused placeholders.
  const ctx = {
    height: 0,
    gasPrice: 0n,
    taxPrimaryBps: 0,
    taxSecondaryBps: 0,
    maxCodeBytes: 0,
    taxPrimaryRecipient: "",
    taxSecondaryRecipient: "",
    miner: "",
    baseReward: BigInt(vec.policy.base_reward_grains),
    halvingIntervalBlocks: BigInt(vec.policy.halving_interval_blocks),
    miningBudgetGrains: BigInt(vec.policy.mining_budget_grains),
  } satisfies BlockContext;

  for (const s of vec.samples) {
    it(`reward_at(height=${s.height}, mined=${s.mined_supply_grains}) = ${s.reward_grains}`, () => {
      const got = rewardAt(BigInt(s.height), BigInt(s.mined_supply_grains), ctx);
      expect(got.toString()).toBe(s.reward_grains);
    });
  }
});
