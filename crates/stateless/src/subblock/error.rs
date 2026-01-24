//! Error types for subblock proving.

use alloc::string::String;
use alloy_primitives::B256;

use crate::validation::StatelessValidationError;

/// Errors that can occur during subblock validation.
#[derive(Debug, thiserror::Error)]
pub enum SubblockValidationError {
    /// Transaction range is out of bounds.
    #[error(
        "transaction range {start}..{end} is out of bounds (block has {tx_count} transactions)"
    )]
    TxRangeOutOfBounds {
        /// Start of the requested range.
        start: usize,
        /// End of the requested range.
        end: usize,
        /// Number of transactions in the block.
        tx_count: usize,
    },

    /// Error from the underlying stateless validation.
    #[error("stateless validation error: {0}")]
    StatelessValidation(#[from] StatelessValidationError),

    /// Error during block execution.
    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    /// BAL error (account or slot not found).
    #[error("BAL error: {0}")]
    BalError(String),
}

/// Errors that can occur during aggregation validation.
#[derive(Debug, thiserror::Error)]
pub enum AggregationValidationError {
    /// Transaction ranges are not contiguous.
    #[error("transaction ranges are not contiguous: range {index} ends at {end}, but range {next_index} starts at {start}")]
    NonContiguousRanges {
        /// Index of the first range.
        index: usize,
        /// End of the first range.
        end: usize,
        /// Index of the second range.
        next_index: usize,
        /// Start of the second range.
        start: usize,
    },

    /// Transaction ranges don't cover all transactions.
    #[error("transaction ranges don't cover all transactions: ranges cover 0..{covered}, block has {tx_count} transactions")]
    IncompleteRanges {
        /// End of coverage.
        covered: usize,
        /// Number of transactions in the block.
        tx_count: usize,
    },

    /// Transaction ranges don't start at 0.
    #[error("transaction ranges must start at 0, but first range starts at {start}")]
    RangesNotStartingAtZero {
        /// Start of the first range.
        start: usize,
    },

    /// No subblock outputs provided.
    #[error("no subblock outputs provided")]
    NoSubblockOutputs,

    /// Mismatched number of outputs and ranges.
    #[error("mismatched subblock outputs ({outputs}) and ranges ({ranges})")]
    MismatchedOutputsAndRanges {
        /// Number of outputs.
        outputs: usize,
        /// Number of ranges.
        ranges: usize,
    },

    /// Gas chaining mismatch.
    #[error("gas chaining mismatch: subblock {index} ended with {expected} gas, but subblock {next_index} implies starting gas doesn't match")]
    GasChainingMismatch {
        /// Index of the subblock.
        index: usize,
        /// Expected gas from previous subblock.
        expected: u64,
        /// Index of the next subblock.
        next_index: usize,
    },

    /// Error from the underlying stateless validation.
    #[error("stateless validation error: {0}")]
    StatelessValidation(#[from] StatelessValidationError),

    /// Consensus validation error.
    #[error("consensus validation error: {0}")]
    ConsensusValidation(#[from] reth_errors::ConsensusError),

    /// Post-state root mismatch.
    #[error("post-state root mismatch: computed {computed}, expected {expected}")]
    PostStateRootMismatch {
        /// Computed state root.
        computed: B256,
        /// Expected state root from block header.
        expected: B256,
    },
}
