# SOV Station v0.2.15 — quantum hardening and migration

Prepared 2026-10-08 for release from current `origin/main` under
[release-version-contract.md](release-version-contract.md). The owner requested
the Rust main client changes on `main` and new 0.2.15 platform binaries.

## Changes

- Bind peer authentication to the complete Noise and ML-KEM transcript, chain,
  genesis and claimed account. Mainnet and reserved PQ rehearsal networks require
  hybrid peer identities. Protocol version 3 requires coordinated peer upgrades;
  older binaries cannot authenticate with the corrected implementation.
- Extend scheduled legacy authorization retirement to intent owners, multisig
  approvals, vault operations and key changes. Preserve historical replay before
  activation and allow an explicit legacy-to-hybrid migration before sunset.
- Add a review/confirm legacy-key migration in Station, preserve original imported
  legacy keys, enforce watch-only restrictions and require hybrid vault members.
- Verify Orchard spend and binding signatures as well as proofs. During an
  activated recovery window, bind v1 withdrawals to their recipient, chain,
  genesis and nonce. Retirement freezes v1 deposits and ultimately v1 spends.
- Quarantine new pool-v2 creation and broadcast. The current Winterfell trace is
  unmasked and does not establish privacy; activation alone does not make this
  proof suite safe. Preserve historical verification and inspection.
- Expose actual quantum policy through RPC and Station. Provide a separate fresh
  `sov-pq-rehearsal-` chain with retirement at 48 and sunset at 64, tested through
  migration, hybrid spending and cold replay.
- Retain the Station UI and wallet operation improvements prepared for 0.2.14.

## Deployment limits

Mainnet genesis, chain identity and existing activation schedules remain unchanged.
The mainnet PQ sunset deployment is **unarmed**; shipping this release does not
activate legacy signature retirement on the live chain. Protocol-3 peer admission
does require coordinated operator upgrades and hybrid node identities.

This is not a claim of complete post-quantum security. A reviewed replacement
proof suite, quantified quantum soundness and a versioned hash migration remain
required. Current 256-bit hash commitments do not provide a 128-bit generic
quantum collision margin. See [quantum-posture.md](../chain/docs/quantum-posture.md)
and [pq-proof-remediation.md](../chain/docs/pq-proof-remediation.md).

## Validation and packaging

Before release preparation, all 170 active Station tests passed (one intentional
ignore), alongside real Orchard authorization/proof tests, runtime retirement
tests, transport and peer policy tests, RPC quarantine tests and the 66-block
produce/import/replay rehearsal. Relevant Clippy checks with warnings denied and
formatting checks passed. This does not claim real-fund transaction testing.

The release gate independently verifies frozen genesis, the complete workspace,
KATs, Station, mining tools, contracts, reproducibility and dependency advisories.
The release workflow also requires the five-node E2E policy checks before creating
Windows x64 Station ZIP, Apple Silicon macOS Station DMG and Linux x64 headless
node TAR.GZ artifacts. Station, the daemon and the macOS bundle must prove their
release version; the operator helper is checked for stale git-describe strings.
Publication is complete only after those jobs and the provenance checks succeed.
