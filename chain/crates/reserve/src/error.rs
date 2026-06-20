//! Errors surfaced by reserve modeling.

/// Errors returned by reserve-modeling operations.
///
/// Every variant denotes a *caller* mistake in describing a scenario (an invalid
/// height range, an out-of-range basis-points fraction, arithmetic that would
/// exceed the representable range). None of them denote a chain fault: this crate
/// only ever reads real state and computes projections from it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReserveError {
    /// A height range was given with `end` below `start`.
    #[error("invalid height range: end #{end} is below start #{start}")]
    InvalidRange {
        /// The first height of the requested range.
        start: u64,
        /// The last height of the requested range.
        end: u64,
    },

    /// A height-range step of zero was given (no progress could be made).
    #[error("height-range step must be non-zero")]
    ZeroStep,

    /// A basis-points value exceeded `10_000` (i.e. claimed to be more than 100%).
    #[error("basis points {got} exceed 100% (10000): {context}")]
    BpsOutOfRange {
        /// The offending basis-points value.
        got: u32,
        /// What the value was describing, for a legible message.
        context: &'static str,
    },

    /// An assumption implied a locked supply exceeding the supply available at
    /// that point — a contradiction the model refuses to silently absorb.
    #[error("assumed locked supply {locked_grains} grains exceeds available supply {available_grains} grains")]
    LockedExceedsSupply {
        /// The locked amount implied by the assumptions, in grains.
        locked_grains: u128,
        /// The supply actually available to be locked, in grains.
        available_grains: u128,
    },

    /// An arithmetic step overflowed the representable range. The supply cap makes
    /// this unreachable for in-protocol values, but explicit assumptions are
    /// caller-supplied and are checked rather than trusted.
    #[error("reserve arithmetic overflowed")]
    Overflow,
}
