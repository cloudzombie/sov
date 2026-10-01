# SOV Station 0.2.14 — UI operations and preservation map

Recorded 2026-10-01 for the `codex/station-next-gen-ui` worktree. This is the
operation inventory for the native Station UI, compared with the v0.2.13 source
at commit `29e7a11`. It is a feature-location map, not a release announcement or a claim
that every transaction has been exercised with real funds.

The refactor retains the eight existing `Tab` destinations and six wallet task
views. `Assets` is the display name of the existing `Tab::Tokens`; `Vaults` is
the display name of the existing `Tab::Vault`. Operation handlers remain in
[`node/src/gui.rs`](../node/src/gui.rs); reusable appearance helpers moved to
[`node/src/gui/design.rs`](../node/src/gui/design.rs). No chain reset, genesis
change, or migration to a new chain is required by the UI work.

## Find an operation

Use UI names and Rust identifiers below as search terms. For example, from the
repository root:

```sh
rg -n 'Pool v2|shield_v2|deshield_v2|send_private_v2|scan_shielded_v2' node/src/gui.rs notes
rg -n 'build_unsigned|sign_offline|broadcast_signed|PendingSend|PendingBump' node/src/gui.rs
rg -n 'vault_create|vault_propose|vault_decide|htlc_|issue_token|send_nft' node/src
rg -n 'station-ui-feature-map|shielded-v2' README.md node/README.md notes
```

The production GUI reads the connected node and wallet-owned note scans. A
missing RPC response or unscanned wallet is **unknown**, not a fabricated zero.
The historical activation record in [`notes/STATUS.md`](STATUS.md) lists
mainnet `shielded-v2` (signal bit 2) **Active from height 15552**. Station still
reads `sov_getShieldedV2Info.active` from its connected node: activation is a
chain fact, not a theme setting or a preview-only permission.

## Wallet navigation and lifecycle

All rows below are existing production GUI operations unless marked otherwise.
The wallet selector, Manage wallets, and Backup shortcuts remain available above
the wallet task navigation. Background dispatch, pending-send tracking, SNS
refresh, and automatic scans remain outside the individual task-view scopes.

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| View confirmed public XUS balance, account, wallet label and name | Wallet → Overview; compact public balance on other wallet tasks | `balance_card`, `account_row`, `LoadedWallet::effective_account`; public funds stay separate from v1/v2 notes |
| Switch active wallet | Wallet selector; Wallet → Identity → Switch wallet | Queued selection in `wallet_panel`; clears transaction reviews, rename/remove confirmation and phrase reveal |
| Generate wallet / 24-word BIP-39 recovery phrase | First-run wallet choices; Wallet → Identity → Add or import a wallet | `generate_wallet`, `LoadedWallet::from_seed`, `require_passphrase`; hybrid Ed25519 + ML-DSA key derivation |
| Import mnemonic or raw 64-hex seed | First-run restore; Wallet → Identity → Add or import a wallet | `import_wallet`; deterministic wallet derivation; invalid input reported |
| Add watch-only public key | Wallet → Identity → Add or import a wallet | `add_watch_only`, `LoadedWallet::watch_only`; does not possess a signing seed or private receive addresses |
| Rename local wallet label | Wallet → Identity → Active wallet | `rename_selected`; label is local metadata, not account identity |
| Remove / forget loaded wallet | Wallet → Identity → Active wallet → Remove wallet | `forget_selected`; typed confirmation; removes that wallet's cached scanned views and updates saved wallet state |
| Account details, nonce/key state, copy account / public key / shielded / unified address | Wallet → Identity | `wallet_panel`, `account_row`, `copy_glyph`, `kv_copy`; public key is shareable, recovery material is not |
| Device passphrase setup, confirmation, cancellation | First protected wallet action | `require_passphrase`, `show_setup_screen`, `render_passphrase_setup`, `passphrase_setup_valid`; minimum-length and matching-input gate |
| Unlock persisted wallets / recognize wallet store | App start when encrypted wallet storage exists | `show_unlock_screen`, `try_unlock`; stored recognition code and unlock errors; legacy storage upgrades on successful unlock |
| Automatic encrypted local save | Wallet lifecycle; unsaved wallet banner if persistence fails | `auto_save`, `wallets_to_keystore`, `autosave_path`; uses the device passphrase |
| Backup acknowledgement after generation | Mandatory recovery screen before normal wallet tasks | `backup_mnemonic` branch of `wallet_panel`; phrase acknowledgement is not bypassed by selecting another task |
| Recovery phrase reveal / export, copy and hide | Wallet → Backup → Recovery phrase | `reveal_phrase`; hidden on leaving Backup or changing wallet; raw-seed imports use encrypted backup when no mnemonic is available |
| Save all wallets in portable encrypted keystore / load it | Wallet → Backup → Encrypted wallet backup | `save_wallets`, `load_wallets`, `write_keystore`, `read_keystore`; separate backup passphrase; Argon2id + ChaCha20-Poly1305 |
| Unsaved wallet warning, create encrypted backup / Save now | Above wallet tasks when needed | `keystore_saved` / `do_save` in `wallet_panel`; quit warning also remains |
| First-run readiness | Wallet → Overview | `first_run_checklist`; create/restore, connect/start node, receive/earn, review payment; mining is optional |

## Public sends, routing, fees, review and pending transactions

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| Enter recipient and fractional XUS amount | Wallet → Send → To / Amount XUS | `SendRoute::detect`, `parse_xus`, `send_payment`; exact integer grains, up to eight decimal places |
| Pay a named account or SNS `.sov` alias | Wallet → Send | `resolve_payee`, `SendRoute::Transparent`; SNS resolves to its account before signing |
| Pay transparent `xust1…` or raw account ID | Wallet → Send | `TransparentForm::{Checksummed,RawHexUnchecked,Named}`; checksum/error disclosure and public-route warning |
| Pay v1 shielded `xus1…` or unified `uxus1…` receiver from public funds | Wallet → Send | `SendRoute::{Shielded,Unified}`, `send_payment`, `mint_to_shielded`; privacy-first unified routing; real Halo2 production path |
| Shield public funds into own v1 pool / Undo recipient shortcut | Wallet → Send → Shield to my pool; Wallet → Privacy → Shield into pool v1 opens Send | `send_to_undo`; fills own v1 recipient, then amount and review remain required |
| Recognize v2 `xusq1…`, truncated or invalid address | Wallet → Send | `SendRoute::{ShieldedV2Unsupported,TruncatedV2,Invalid}`; directs to Privacy v2 controls; no silent public fallback |
| Max public amount | Wallet → Send → Max | `SendCost`, `tip_for`; deducts network fee and selected priority tip from available public funds |
| Priority tip / suggested bid | Wallet → Send → Fees & priority | `auction_controls`, `tip_for`, `fee_auction_active`; operator-entered bid and Suggested reset; dormant fee-auction state remains distinct |
| Live floor, inclusion outlook, congestion and bid histogram | Wallet → Send → Live auction & inclusion details | `auction_readout`, `bid_outlook_view`, `fee_histogram`, `tip_rationale`; unavailable floor is unknown, not free |
| Available balance, network fee, tip, total debit, balance after | Wallet → Send | `SendCost`, `auction_controls`; recalculated from current form values |
| Review, Cancel, Confirm & send | Wallet → Send → Review send → Review transaction | `PendingSend`, `SendReviewContext`, `validate_reviewed_send`, `send`; review captures wallet/account, network/RPC, recipient, amount, source and bid |
| Review privacy consequences and self-send | Review transaction modal | `SendSource::confirm_line`, `links_public`, `self_send`; shows public leakage or shielded route, explicit pool and cryptography for a pool spend |
| Pending, winning/outbid, mined, failed, replaced or superseded sends | Below any loaded-wallet task | `pending_sends_view`, `SentTx`, `SendState`, `refresh_outbox`; session outbox with receipt-based results |
| Bump fee / replacement review / Keep waiting | Pending send row → Bump fee | `PendingBump`, `validate_reviewed_bump`, `bump_send`, `bump_explainer`; same original recipient/amount/nonce, reviewed new tip, original payment not duplicated |
| Pending history across same-chain node changes; cross-network isolation | Pending sends | `SentTx::{on_chain,on_origin}`; another node on the same chain can refresh/settle the payment or host a newly reviewed replacement. Original RPC remains history metadata; another chain cannot settle or replace it. Reviews pin the wallet/account, network and current RPC |
| Transaction status, proof/broadcast progress and session result | Wallet tasks and footer | `ActionState`, `begin`, `finish`, `status_banner`, `show_bottom_toast`, `record`; a pending receipt is not a confirmed success or failure |

Wallet → Send refuses online signing for watch-only wallets. Their unsigned-build and
already-signed broadcast paths remain available in the offline section. Reviews
are revalidated both at confirmation and after queued wallet/account changes;
stale forms do not authorize changed terms or silently drop a priority tip.

## Privacy — both v1 and live v2

**Pool v1** uses Orchard / Halo2 and is explicitly **not post-quantum**.
**Pool v2** uses ML-KEM-768 note carriers and STARK spend proofs. The pools are
separate value spaces; a v1 address is not a v2 recipient. Overview and Privacy
show wallet-owned amounts, unspent note counts and scan heights for **both**
pools. They do not combine those amounts with the public balance.

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| v1 / v2 own shielded balance, unspent notes, scan height | Wallet → Overview → Privacy pools; Wallet → Privacy | `pool_balance_card`, `ShieldedView::own_figures`, `ShieldedV2View::own_figures`, `ScannedPools::view_for`; per-wallet view, unknown until scanned |
| Active / Dormant / Unavailable state and crypto disclosure | Both pool cards, details, source selector and v2 Receive | `Pool`, `PoolState::classify_v1`, `PoolState::classify_v2`; real connected-node state governs controls |
| Global pool value, de-shield window budget, notes/nullifiers/anchor where reported | Wallet → Privacy → Pool details · drain budgets, cryptography & network totals | `shielded_pools_view`, `pool_rows`, `shielded_v2_info`; network totals are not own balance; v1 RPC fields it does not report remain explicitly not reported |
| Scan v1 notes / automatic first scan | Wallet → Privacy → Scan pool; automatic once per loaded signing wallet | `scan_shielded`, `scan_store`, `refresh_shielded_view`; canonical-chain receipt filtering, encrypted incremental note cache |
| Rebuild v1 note cache / confirm or cancel rescan | Wallet → Privacy → Rescan from scratch | `rescan_shielded`, `rescan_armed`, `note_store_path`; explicit two-step cache-reset confirmation; chain data is not reset |
| Shield into v1 from public funds | Wallet → Privacy → Shield into pool v1; then Wallet → Send | Existing `send_payment` Halo2 route; shortcut only prepares the recipient |
| Variable v1 de-shield amount / Max | Wallet → Privacy → Pool v1 · shield and de-shield | `deshield`, `deshield_amount`, `deshieldable_now`; own scanned notes, change stays shielded; Max bounded by own balance and live drain budget |
| Scan v2 notes / refresh after confirmed v2 action | Wallet → Privacy → Scan pool v2; existing worker refresh after a confirmed move | `scan_shielded_v2`, `scan_store_v2`, `note_store_v2_path`, `run_v2_action`; ML-KEM trial-decapsulation; per-wallet cached view |
| Choose private-send source v1 or v2 | Wallet → Privacy → Send privately — choose a pool | `PoolSelection`, `armed_pool`, `arm_banner`, `Pool::selector_label`; neither pool preselected; choice belongs to the selected wallet |
| v1 → v1 private send, amount / Max / review | Same private-send section with Pool v1 explicitly selected | `pool_recipient_check`, `private_send_dispatch`, `send_private`, `shielded_send`; `xus1…` / v1-capable `uxus1…`; scanned balance required |
| v2 → v2 private send, amount / Max / review | Same private-send section with Pool v2 explicitly selected | `v2_allows`, `V2Intent::Send`, `send_private_v2`, `zsend_v2_amount`; `xusq1…` only, live v2 and own scanned notes required |
| Shield public value into v2 / optional recipient, blank=self | Wallet → Privacy → Pool v2 — shield in / de-shield out → Shield in | `shield_v2`, `V2Intent::Shield`, `shield_v2_amount`; no input-note scan required; recipient must be v2; affordability guard before STARK proving |
| Variable v2 de-shield amount / Max | Same v2 move section → De-shield out | `deshield_v2`, `V2Intent::Deshield`, `deshield_v2_amount`, `deshieldable_v2_now`; own notes and live drain budget cap; change stays in v2 |
| v2 proof progress and pending/confirmed/failed/not-broadcast outcome | Privacy action status and activity | `run_v2_action`, `submit_v2_bundle`, `require_v2_live`, `ReceiptStatus`, `v2_status_line`, `v2_not_broadcast_line`; STARK proving time stated; only an actual receipt declares execution outcome |
| Move value between pool generations | Existing staged operations, no atomic cross-pool button | De-shield from source pool to public account, then shield into destination pool; do not pass a cross-pool recipient to private Send |

`V2Guard` / `v2_allows` retain the activation, busy, wallet ownership, scan,
positive amount, balance, recipient-kind, public affordability and de-shield
budget checks. Rendering and dispatch use the same decisions. A stale or
unavailable v2 choice never silently falls back to v1. Pool-spend review shows
the shielded **pool debit** separately from fees paid by the public carrier
account; pool sends do not pretend to carry a priority tip that is not wired.
The v2 proof's final fee is unavailable until its bundle is built.

## Receive, address inspection and exports

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| Shielded v1 address / QR / copy | Wallet → Receive → Shielded (private) | `ReceiveKind::Shielded`, `qr_widget`; private receive choice retained |
| Unified address / QR / copy | Wallet → Receive → Unified | `ReceiveKind::Unified`; existing encoding and routing retained |
| Account ID / QR / copy checksummed spelling | Wallet → Receive → Account | `ReceiveKind::Account`, `encode_transparent`; raw hex warning and `xust1…` copy |
| Live v2 address, owner tag, length and state | Wallet → Receive → Post-quantum (v2) | `ReceiveKind::ShieldedV2`, `v2_address_block`; elided identity plus bounded selectable full-address inspection |
| Full v2 address clipboard copy / text-file export | Same v2 Receive view → Copy address / Export to file | `export_v2_address`, `v2_address_document`, `v2_address_filename`; full address, owner tag and pool state recorded in Station data directory |
| v2 address QR limitation | Same v2 Receive view | Full ML-KEM address needs a very large QR; existing copy/file transport is retained rather than presenting an unreadable QR |
| Watch-only receive | Wallet → Receive | Account receive works; unavailable seed-derived v1/unified/v2 addresses show a reason, not an empty QR |

## Offline signing, SNS and controlled accounts

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| Build unsigned public transfer / copy unsigned JSON | Wallet → Send → Open offline signing; also Wallet → Backup → Offline / air-gapped signing | `build_unsigned`; queue-aware nonce, node signing domain; watch-only may build |
| Sign unsigned JSON / copy signed JSON | Offline / air-gapped signing → Sign | `sign_offline`, `require_signing`; signing device must hold seed; domain/chain checks retained |
| Broadcast previously signed JSON | Offline / air-gapped signing → Broadcast | `broadcast_signed`; online device need not hold private signing key |
| SNS availability and format check / register name | Wallet → Identity → Sovereign Name Service (SNS) | `validate_name_format`, `check_name_registrable`, `register_named`, `register_name_onchain`; on-chain availability gate and fee |
| Display all loaded wallets' SNS names / resolve payee | Wallet header, Overview, Identity, selector, Assets collectibles | `fetch_names_of`, `names_by_account`, `resolve_payee`; periodic per-account refresh |
| Attach / detach a named account controlled by current key | Wallet → Identity → Operate a named account (advanced) | `set_operate_as`, `clear_operate_as`, `account_control`, `Control`; effective transaction identity changes without changing the note-decryption key |
| Account control state | Same advanced section and account details | `Control::{Mine,DifferentKey,KeylessFunded,KeylessEmpty,Unreachable}`, `control_message`; foreign merely linked accounts are not attributed as this wallet's miner |

## Assets, Swaps, Vaults and Activity

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| Refresh token holdings / NFT and SNS collectibles | Assets | `tokens_panel`, `refresh_tokens`, `token_card`, `nft_tile`; selected effective account |
| Issue token, symbol / amount / optional recipient | Assets → Issue or send a token → Issue | `issue_token`; existing issue transaction |
| Transfer native token, asset ID / recipient / amount | Assets → Issue or send a token → Send token | `transfer_token`; existing transfer transaction |
| Token registry, issuer / supply / asset ID and pagination | Assets → Token registry → Prev / Next | `registry_card`, `tok_offset`, `refresh_tokens`; page size 50 |
| Send NFT or SNS name | Assets → Collectibles & names → recipient, then collectible tile | `send_nft`; SNS transfer re-points the name; existing recipient/busy dispatch and transaction path retained |
| Generate HTLC secret / lock amount with relative timeout | Swaps → Lock (open an HTLC) | `random_secret_hex`, `htlc_lock`; OS randomness, secret entropy gate, minimum future timeout; secret remains masked |
| Look up HTLC ID and terms | Swaps → Find / claim / refund → Look up | `htlc_lookup`; locker, recipient, amount, hashlock and timeout |
| Claim / reveal secret or refund after timeout | Same Swaps section | `htlc_claim`, `htlc_refund`; existing chain-enforced settlement conditions |
| Create M-of-N vault, members / keys / threshold | Vaults → Create a vault | `vault_create`, `vault::Vault::validate`, `vault::Vault::set_multisig_action`; Add / Add me / remove member / Use selected wallet retained |
| List saved vaults / Forget local vault record | Vaults → Your vaults | `vault::load_vaults`, `vault::save_vaults`; Forget affects local record, not on-chain multisig policy |
| Propose vault spend | Vaults → Send from a vault → Propose spend | `vault_propose`; signing member required |
| Refresh approval inbox / Approve / Cancel proposal | Vaults → Needs your approval | `fetch_proposals`, `vault_decide`; `sov_getMultisigProposals`, member approval state and on-chain proposal coordination |
| Session submitted-action log / Clear | Activity; Wallet → Overview → Recent activity | `activity_panel`, `record`, `tx_status`; timestamps, outcome colors, bounded session history; Clear affects UI history |

## Node, Mining, Blocks and settings

| Operation / searchable terms | Current UI location | Implementation identifiers / constraints |
|---|---|---|
| RPC endpoint / Connect | Header → Connection & node controls | `rpc_field`, `Config.rpc`, `spawn_poller`; existing RPC connection surface |
| Start / Stop local validating node | Header → Connection & node controls | `start_local_node`, `stop_local_node`, `build_and_run_node`, `NodeRun`; selected wallet supplies payout identity; starts with mining off |
| Existing destructive local-chain reset | Header → Connection & node controls → Reset local chain, available with local node stopped | `reset_local_chain`; wipes local chain directory, retained from v0.2.13; **not used or required for this UI update** |
| Mainnet / Testnet switch and confirmation | Header network selector | `switch_network`, `Network`; stops supervised node, clears stale reviews, selects that network's RPC/data directory; Mainnet confirmation retained |
| Live connection / sync / mining heartbeat | Header | `draw_heartbeat`, `LinkState`, `BeatState`, `Snapshot::is_mining`; actual node/miner observations, payout identity alone does not claim mining |
| Chain health, height/head/state root/supply/reward/difficulty/mempool/peers | Node | `node_panel`, `poll`, `apply_local_status`; in-process state augments RPC view while local node replays |
| Seed-peer entry, save, dial and real result | Node → Peering → Connect | `node_peering_ui`, `normalize_peer_addr`, `save_peer`, `EmbeddedNode::dial`; saved separately per network; LAN discovery/relay bootstrap retained |
| LAN RPC exposure opt-in and advertised local endpoints | Node → Peering → Expose node RPC on LAN | `read_expose_rpc_lan`, `save_expose_rpc_lan`; unauthenticated RPC defaults to loopback; applies on next node start |
| Re-request Windows firewall allowance | Node → Peering on Windows | `add_firewall_rule`, `ensure_firewall`; platform-specific UAC path |
| Operational node log, scroll and resize | Node | `node_log_panel`, `push_log`, `append_session_log`, `prune_old_session_logs`; top-edge height grip, disk session logs and transition reporting retained |
| Explicit Start mining / Stop mining | Mining | `mining_control_ui`, `apply_set_mining`, `EmbeddedNode::set_mining`; synced node can run without mining; payout key binding checked |
| In-process hashrate, difficulty/target/nonce, reward and observed network cadence | Mining | `mining_panel`, `fmt_hashrate`, `fmt_difficulty`, `interval_sparkline`; unavailable measurements not invented |
| External miner evidence / last win / own account attribution | Mining and heartbeat | `assess_external_mining`, `external_miner_card`, `ExternalMinerFacts`; owned accounts and witnessed block deltas, not a stale registry row |
| Compute wallet mining earnings | Mining → Your mining earnings → Compute earnings | `compute_earnings`, `scan_earnings`; scans actual block coinbase payments and displays scan height/roles |
| Recent blocks, selected block details, coinbase and explorer link | Blocks | `blocks_panel`, `block_detail_window`, `block_row`; hash/parent/state root/seal/reward details from `sov_getBlockDigest` |
| Dark / light theme | Header theme button | `install_theme`, `palette::set_dark`, `save_theme`, `read_saved_theme`; persistence retained |
| Version/network footer, clipboard feedback, bounded status toast | Footer | `show_bottom_toast`, `footer_reserved_width`, `copied_recent`; long status has full hover text |
| Unsaved-wallet quit warning / Stay / Quit anyway | App close | `eframe::App::update`, `on_exit`, `shutdown_node`; existing exit guard and supervised-node shutdown |
| Durable node directories and old temporary-directory migration | Node startup, no new UI action | `ensure_durable_node_dir`, `migrate_node_dir_from_temp`; existing persistence behavior retained |

## CLI / chain capabilities are not omitted UI buttons

The README contains product vision as well as a historical GUI list. The current
GUI inventory above is verified against both v0.2.13 commit `29e7a11` and the refactored
source. These distinctions prevent roadmap items from being mistaken for lost
buttons:

| Capability | Existing access / coverage |
|---|---|
| Station read-only `status`, `mining`, `wallet`, `watch`, `version`, `help` | `node/src/main.rs`; retained CLI commands, not additional task-view buttons |
| CLI v1 balance / private send / de-shield | `chain/crates/rpc/src/bin/sov-wallet.rs`: `z-balance`, `z-send`, `unshield`; corresponding Station GUI operations are mapped above |
| CLI v2 info / address / balance / shield / private send / de-shield | Same CLI: `z2-info`, `z2-address`, `z2-balance`, `shield2`, `z2-send`, `unshield2`; corresponding Station GUI operations are mapped above |
| CLI generation / key derivation / mnemonic restore options | Same CLI: `new`, `keygen`, `import`; includes CLI-specific HD account/index and legacy-key options, not new Station GUI choices |
| Stratum bridge, sharechain and pool-mining operator tools | `tools/sov-stratum`, `tools/sov-sharechain`, `notes/pool-public-launch.md`; these are **mining pools**, distinct from wallet shielded pools v1/v2; no existing Station pool-management page is claimed |
| Signed intent settle/cancel, token burn/policy changes, NFT mint/metadata, contract deploy/call, generic RotateKey | Chain action types and SDK encoders (`sdk/src/types.ts`, `sdk/src/borsh.ts`); no dedicated v0.2.13 Station GUI handlers found. Existing HTLC, token issue/transfer, NFT transfer and vault buttons remain |
| Standalone “activate account” button mentioned in old `node/README.md` | Historical documentation mismatch: neither v0.2.13 HEAD nor current `gui.rs` has a standalone `activate` handler/button. Account control / SNS / operate-as behavior is mapped above; do not claim a RotateKey GUI operation was tested or added |
| Full signed-intent book, issuer policy editor, automated cross-pool migration planner | Product-roadmap items in `node/README.md`; not silently represented as delivered features of this UI refactor |

## Preview and verification boundaries

The separate **SOV Station PREVIEW 0.2.14-preview** is for visual inspection. It
uses known throwaway keys, synthetic public/v1/v2 balances and a live-shaped
v2 fixture (`active: true`) and active fee-auction inputs/histogram so the source selector, v2 scan, shield/de-shield
forms, review and v2 receive/export UI can all be inspected. A populated v2
fixture is intentional because v2 is live on mainnet; it is not evidence of a
new chain scan or a real submitted transaction.

The disposable preview fixes RPC to `127.0.0.1:0`, uses a separate
`SOV_STATION_DIR`, and disables real proof generation, signing, broadcasting,
node launch, mining and wallet persistence. Its scan controls report simulated
preview completion. Its code is generated outside the repo; the disabled
action bodies are not production changes. Address display/export uses only
throwaway public receiving data. The running v0.2.13 wallet/node is separate
and is not replaced by the preview.

Regression checks in `node/src/gui.rs` cover task reachability and the recovery
gate (`wallet_task_navigation_keeps_features_and_recovery_gate_reachable`), all
destinations (`workspace_navigation_contains_every_existing_destination_once`),
honest unknown/dormant balances, per-wallet scanned views, live-v2 receiving
copy/export text, the complete v2 guard matrix, explicit source selection,
cross-pool refusal, review context/fee preservation, replacement context,
chain-scoped outbox updates, same-chain node migration and compact review controls. The design module
tests bright foreground text (`dark_strong_text_keeps_the_body_foreground`).

Native preview inspection checks presentation and navigation. Unit tests and
build checks do not assert that this UI session executed a real Halo2/STARK
proof, signed with an operator's key, moved real funds, or validated every
remote node integration. Production transaction handlers and existing guards
are retained; release/integration gates remain separate.
