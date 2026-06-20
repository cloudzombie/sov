# SOV Station

SOV Station is the wallet and mining-node infrastructure for SOV: one operator-grade suite for full validation, Nakamoto mining, shielded funds, native tokens, and atomic asset settlement.

The goal is not to clone Bitcoin Core, Zashi, Sparrow, or Ledger Live. The goal is to take what SOV already has and make the user-facing infrastructure feel cleaner than all of them:

- full validation by default
- private wallet by default
- native token support by default
- mining as a first-class user workflow
- atomic swaps as a wallet primitive, not a separate product
- no command-line seeds
- no trusted state snapshots
- no proof-of-stake assumptions

## Native app (current)

`node/` builds **`sov-station`** — a native desktop GUI (eframe/egui; macOS, Windows,
Linux) that is both a **wallet** and a **mining-node operator console**, plus a
read-only CLI for scripting. Everything shown is real data read from a running
node over JSON-RPC — the app fabricates nothing.

Launch the desktop window (no arguments open the GUI):

```sh
cargo run --manifest-path node/Cargo.toml
```

Or use the read-only CLI:

```sh
cargo run --manifest-path node/Cargo.toml -- status [rpc_addr]
cargo run --manifest-path node/Cargo.toml -- mining [rpc_addr]
cargo run --manifest-path node/Cargo.toml -- wallet [rpc_addr] <account>...
cargo run --manifest-path node/Cargo.toml -- watch  [rpc_addr] [account]... [--interval-ms 3000]
```

### What the GUI does today

- **Node / Mining / Blocks** — live chain id, height, head, state root, supply,
  difficulty, mempool, block reward, the miner registry, and each block's
  **coinbase** with its 93% / 5% / 2% miner / founder / dev split.
- **Wallet** — real keys, held in-session (and encryptable to disk):
  - **generate** a fresh wallet (BIP-39 24-word mnemonic + hybrid post-quantum
    key; shown once for backup) or **import** one;
  - **activate** an account (binds the key on-chain via `RotateKey`) so it can spend;
  - **send** — one box, auto-routed: a named account → transparent, a
    `xus1…`/`uxus1…` address → shielded (real Halo2 proof);
  - **shield** value into your own pool;
  - **shielded balance** — scan the chain by trial-decryption for your unspent
    notes and total them (the pool is private; only the holder can);
  - **de-shield** — spend your largest note back to transparent (real Halo2
    spend, witnessed against a chain-held anchor);
  - **encrypted keystore** — save/load all wallets under a passphrase (Argon2id +
    ChaCha20-Poly1305) so they survive restart;
  - copy account / shielded / unified addresses.
- **Run a node** — Start/Stop a local testnet-1 node the app supervises; it mines
  to the selected wallet, so the wallet self-funds from coinbase.

The roadmap below is the broader product vision; the list above is what ships now.

## Product Shape

SOV Station has two faces over shared core infrastructure:

1. SOV Wallet
2. SOV Mining Node

The wallet and node should feel like one cockpit. A user can receive funds, shield them, mine blocks, inspect finality, issue tokens, run swaps, and watch node health without switching mental models.

The first screen should show:

- Private Balance
- Public Balance
- Mining
- Tokens
- Swaps
- Node Health

## SOV Wallet

The wallet is privacy-first and full-stack. It manages transparent accounts, shielded addresses, unified addresses, tokens, HTLCs, and atomic-swap intents.

### Key Model

- One seed can derive multiple identities.
- Transparent account keys authorize named SOV accounts.
- Shielded keys derive Orchard receivers.
- Unified addresses carry both transparent and shielded receivers.
- Mining payout identity is explicit and visible to the operator.
- Post-quantum hybrid keys should be supported as the preferred account key path.

### Vault

The wallet must not require secrets on the command line.

Required vault features:

- BIP-39 mnemonic import/export.
- HD derivation for transparent account keys.
- Shielded key derivation from the same root.
- Argon2id key derivation for encrypted storage.
- AEAD-sealed wallet database.
- Watch-only mode.
- Offline signing mode.
- Account map backup.
- Shielded birthday height backup.
- Rescan metadata backup.

CLI seed arguments should be considered dev-only and eventually hidden behind an explicit unsafe flag.

### Address UX

Address tiers:

- Transparent account: `name.sov`
- Shielded address: `sov1...`
- Unified address: `usov1...`

Rules:

- Unified address routes to shielded when a shielded receiver exists.
- Transparent fallback must be explicit.
- The wallet warns when an action links public sender, public recipient, amount, or token identity.
- Shielded receive should be the default receive screen.

### Shielded Wallet

The wallet needs a local shielded-note database.

Required state:

- recovered notes
- note values
- note commitments
- witnesses
- anchors
- nullifier status
- spent/unspent state
- scan height
- rescan checkpoints

Required workflows:

- scan from birthday height
- recover outputs belonging to wallet keys
- update witnesses as new commitments arrive
- build shielded transfer
- build de-shield transaction
- detect spent notes by nullifier
- recover after reorg

Privacy rule: shielded funds should never be shown as a vague global number without explaining whether the wallet is fully scanned.

### Transaction Planner

The wallet should not expose raw action construction as the main UX. It should plan transactions.

Planner inputs:

- recipient string
- amount
- asset
- privacy preference
- max fee
- expiry/finality preference

Planner outputs:

- route type
- public metadata leaked
- required fee
- required proof build
- expected confirmation/finality
- transaction preview

Route types:

- transparent SOV transfer
- transparent token transfer
- transparent to shielded
- shielded to shielded
- shielded to transparent
- HTLC lock
- HTLC claim
- HTLC refund
- intent settle
- token issue
- token policy update

### Native Tokens

The wallet should treat SOV native tokens as first-class assets.

Required features:

- show token balances
- issue token
- transfer token
- view issuer
- view supply
- view compliance policy
- view vault inventory
- warn when issuer policy can pause/freeze/restrict transfer

Token UX should distinguish:

- SOV
- issuer assets
- mineable assets, once implemented
- vault inventory assets

### Atomic Swaps

Swaps should appear as wallet actions, not external scripts.

Supported swap primitives:

- signed intents
- HTLC lock/claim/refund
- solver fills
- finality-aware settlement

The wallet should track swap state:

- created
- funded
- counterparty funded
- claimable
- claimed
- refundable
- expired
- failed

No laundering/evasion framing belongs in the product. The frame is lawful privacy and atomic settlement.

## SOV Mining Node

The mining node is a full validating node with operator-grade mining, P2P, RPC, observability, and recovery.

### Node Roles

Supported modes:

- full validating node
- mining node
- wallet-connected local node
- public RPC node
- testnet node
- bootstrap node

Each mode should make unsafe exposure obvious. Public RPC should not accidentally expose wallet secrets, local filesystem paths, or privileged mining controls.

### Mining Engine

Initial mining engine:

- internal SHA-256d header grind
- coinbase paid to configured miner account
- continuous block attempt cadence
- empty blocks allowed
- difficulty/target visible
- stale/orphan tracking

Later mining engine:

- external miner protocol
- stratum-like job distribution
- miner worker identity
- submitted share tracking
- local pool mode

### Mining Dashboard

The mining node needs a status surface better than logs.

Required fields:

- chain id
- height
- head hash
- chainwork
- finalized height
- current difficulty
- current target bits
- mempool size
- peer count
- sync state
- miner account
- blocks mined
- accepted blocks
- stale blocks
- last mined height
- last mined hash
- estimated hash rate
- coinbase earned
- node uptime
- block log path
- p2p address
- rpc address

### P2P Status

Operator should see:

- connected peers
- authenticated peers
- peer height
- peer head
- peer chainwork
- sync cursor
- rejected blocks
- duplicate blocks
- last message time
- reconnect state

### Reorg Monitor

The node should make Nakamoto behavior legible.

Alerts:

- local head reorged
- mined block orphaned
- peer advertised heavier chain
- block rejected due to invalid PoW
- block rejected due to state root mismatch
- side branch stored
- finalized height advanced

### Persistence

Rules:

- blocks log is source of truth
- state is rebuilt by replay
- no trusted state snapshot
- corrupted log recovers valid prefix
- peer sync refills missing tail
- wallet database is separate from chain database

### RPC

Add typed status APIs rather than making tools scrape scattered methods.

Needed methods:

- `sov_getNodeStatus`
- `sov_getMiningStatus`
- `sov_getPeerStatus`
- `sov_getWalletScanStatus` when wallet service exists
- `sov_getTokenBalance`
- `sov_getTokenInfo`
- `sov_getTokenPolicy`
- `sov_getShieldedPoolStatus`

Status RPC should return structured values, not display strings.

## Shared Crates

Target structure:

- `sov-keyring`: encrypted vault, HD derivation, account/shielded key management.
- `sov-wallet-core`: transaction planner, note scanner, token accounting.
- `sov-node-core`: validation, mempool, mining, P2P status.
- `sov-rpc-api`: typed request/response structs shared by server, CLI, GUI, SDK.
- `sov-cli`: power-user commands.
- `sov-station`: desktop GUI or local web UI.

The current repo already has pieces of this:

- `chain/crates/wallet`
- `chain/crates/rpc`
- `chain/crates/node`
- `chain/crates/shielded`
- `chain/crates/state`
- `chain/crates/types`

The next work is to make those pieces feel like one infrastructure product.

## Security Rules

Hard requirements:

- never pass seeds on command line in normal wallet flows
- never log seed material
- never serialize raw keypairs unencrypted
- reject privacy downgrade by default
- verify shielded proofs before applying bundles
- check shielded anchors before applying bundles
- reject duplicate nullifiers atomically
- track wallet scan completeness
- make reorgs visible to wallet and miner
- bind transactions to chain id if/when transaction format is upgraded
- use typed RPC structs for critical status surfaces

## Build Order

### Phase 1: Safe Wallet Basics

- Add encrypted wallet vault.
- Add `sov-wallet init`.
- Add `sov-wallet unlock`.
- Add `sov-wallet address`.
- Add `sov-wallet status`.
- Stop documenting seed-on-command-line as normal usage.

### Phase 2: Node Status

- Add `sov_getNodeStatus`.
- Add `sov_getMiningStatus`.
- Add `sov_getPeerStatus`.
- Add CLI `sov-node status`.
- Add miner operator summary.

### Phase 3: Shielded Wallet

- Add local note database.
- Add scan/rescan.
- Add witness tracking.
- Add shielded balance.
- Add shielded send.
- Add de-shield.
- Add reorg-aware note rollback/rescan.

### Phase 4: Token Wallet

- Add token list.
- Add token balances.
- Add token send.
- Add token issue.
- Add token policy view.
- Add vault inventory accounting.

### Phase 5: Mining Operator UX

- Add mining dashboard.
- Add stale/orphan tracking.
- Add chainwork display.
- Add peer sync diagnostics.
- Add metrics endpoint.

### Phase 6: Atomic Settlement

- Add swap planner.
- Add HTLC lifecycle UI.
- Add signed intent book.
- Add solver fills.
- Add BTC/ZEC ingress adapters only under lawful atomic-swap framing.

### Phase 7: GUI

- Local-first desktop app or local web UI.
- Wallet and node in one cockpit.
- Private/public balance split.
- Mining panel.
- Tokens panel.
- Swaps panel.
- Node health panel.

## Product Sentence

SOV Station is a privacy wallet and mining node in one: full validation, native tokens, shielded funds, atomic swaps, and Nakamoto mining from a single operator-grade interface.
