//! Block height: the position of a block in the canonical chain.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A block's height. Genesis is height `0`; each subsequent block increments by
/// one. A monotonic counter, distinct from a [`crate::Hash`], which identifies a
/// block by content rather than position.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct BlockHeight(u64);

impl BlockHeight {
    /// The genesis height.
    pub const GENESIS: BlockHeight = BlockHeight(0);

    /// Construct from a raw `u64`.
    pub const fn new(h: u64) -> Self {
        BlockHeight(h)
    }

    /// The raw `u64`.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next height, or `None` at `u64::MAX` (the chain would have to outlive
    /// the universe to reach it, but we refuse to wrap rather than corrupt order).
    pub fn next(self) -> Option<BlockHeight> {
        self.0.checked_add(1).map(BlockHeight)
    }

    /// Whether this is the genesis height.
    pub const fn is_genesis(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl fmt::Debug for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHeight({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_and_succession() {
        assert!(BlockHeight::GENESIS.is_genesis());
        assert_eq!(BlockHeight::GENESIS.next().unwrap(), BlockHeight::new(1));
        assert!(!BlockHeight::new(1).is_genesis());
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(BlockHeight::new(2) > BlockHeight::new(1));
    }

    #[test]
    fn refuses_to_wrap() {
        assert_eq!(BlockHeight::new(u64::MAX).next(), None);
    }
}
