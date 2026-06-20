//! Per-contract key/value storage.
//!
//! A contract's persistent state is an ordered byte-keyed map. Ordering is
//! deterministic ([`BTreeMap`]) so the same writes always produce the same state
//! — a hard requirement for consensus, where every node must agree byte-for-byte.

use std::collections::BTreeMap;

/// A contract's key/value store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractStorage {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ContractStorage {
    /// An empty store.
    pub fn new() -> Self {
        ContractStorage::default()
    }

    /// Read the value at `key`.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.map.get(key).map(Vec::as_slice)
    }

    /// Write `value` at `key`, returning the previous value if any.
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.map.insert(key, value)
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.map.iter()
    }
}
