//! Error types for subblock proving.

use alloc::string::String;
use alloy_primitives::{Address, B256, U256};

use crate::validation::StatelessValidationError;

/// Errors that can occur during subblock validation.
#[derive(Debug, thiserror::Error)]
pub enum SubblockValidationError {
    /// BAL index range is out of bounds.
    #[error("BAL range {start}..{end} is out of bounds (max BAL index is {max_bal_index})")]
    BalRangeOutOfBounds {
        /// Start of the requested BAL range.
        start: u64,
        /// End of the requested BAL range.
        end: u64,
        /// Maximum valid BAL index (`tx_count` + 2).
        max_bal_index: u64,
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

    /// BAL was not built during execution when it was expected.
    #[error("BAL was not built during execution")]
    BalNotBuilt,

    /// Account found in built BAL but missing from provided BAL.
    #[error("account {address} in built BAL not found in provided BAL")]
    BalAccountMissing {
        /// The missing account address.
        address: Address,
    },

    /// Balance change mismatch between built and provided BAL.
    #[error("balance mismatch for {address} at index {index}: built {built}, provided {provided}")]
    BalBalanceMismatch {
        /// Account address.
        address: Address,
        /// BAL index where mismatch occurred.
        index: u64,
        /// Value from built BAL.
        built: U256,
        /// Value from provided BAL.
        provided: U256,
    },

    /// Nonce change mismatch between built and provided BAL.
    #[error("nonce mismatch for {address} at index {index}: built {built}, provided {provided}")]
    BalNonceMismatch {
        /// Account address.
        address: Address,
        /// BAL index where mismatch occurred.
        index: u64,
        /// Value from built BAL.
        built: u64,
        /// Value from provided BAL.
        provided: u64,
    },

    /// Storage change mismatch between built and provided BAL.
    #[error("storage mismatch for {address} slot {slot} at index {index}: built {built}, provided {provided}")]
    BalStorageMismatch {
        /// Account address.
        address: Address,
        /// Storage slot.
        slot: U256,
        /// BAL index where mismatch occurred.
        index: u64,
        /// Value from built BAL.
        built: U256,
        /// Value from provided BAL.
        provided: U256,
    },

    /// Code change mismatch between built and provided BAL.
    #[error("code mismatch for {address} at index {index}")]
    BalCodeMismatch {
        /// Account address.
        address: Address,
        /// BAL index where mismatch occurred.
        index: u64,
    },
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

    /// Block access list hash missing from header (required post-Amsterdam).
    #[error("block access list hash missing from header")]
    MissingBlockAccessListHash,

    /// Block access list hash mismatch.
    #[error("BAL hash mismatch: computed {computed}, expected {expected}")]
    BalHashMismatch {
        /// Computed hash from provided BAL.
        computed: B256,
        /// Expected hash from block header.
        expected: B256,
    },
}
