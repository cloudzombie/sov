//! # sov-node
//!
//! The node that runs a SOV chain: it owns the [`Blockchain`](sov_chain::Blockchain)
//! and a [`Mempool`](sov_mempool::Mempool), accepts submitted transactions, and
//! on each [`Node::produce`] step builds, imports, and finalizes a block.
//!
//! The library here is the deterministic engine; the accompanying binary
//! (`src/main.rs`) wires it into a runnable single-node devnet.

#![forbid(unsafe_code)]

pub mod node;

pub use node::{Node, NodeError, Produced};
