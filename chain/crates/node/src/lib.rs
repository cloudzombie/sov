//! # sov-node
//!
//! The node that runs a SOV chain: it owns the [`Blockchain`](sov_chain::Blockchain)
//! and a [`Mempool`](sov_mempool::Mempool), accepts submitted transactions, and
//! on each [`Node::produce`] step builds, imports, and finalizes a block.
//!
//! The library here is the deterministic engine; the accompanying binary
//! (`src/main.rs`) wires it into a runnable single-node devnet.
//!
//! Alongside that engine the node keeps one piece of purely NODE-LOCAL
//! bookkeeping: the [`timing`] index, which records how long each mined
//! transaction waited **as this node observed it**. It is built from the node's
//! own mempool admission stamps, persisted beside `mempool.dat`, and reachable
//! only over RPC — never from block validation, execution, or fork choice, and
//! never committed to any root. See [`timing`] for why that separation is
//! structural rather than merely intended.

#![forbid(unsafe_code)]

pub mod node;
pub mod timing;

pub use node::{Node, NodeError, Produced};
pub use sov_mempool::Admitted;
pub use timing::{TxTiming, TxTimingIndex, DEFAULT_MAX_ENTRIES, DEFAULT_RETENTION_BLOCKS};
