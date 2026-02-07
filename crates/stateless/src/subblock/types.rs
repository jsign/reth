//! Data structures for subblock proving.
//!
//! This module defines the input and output types for subblock validation:
//!
//! - [`SubblockInput`]: Input to a worker for executing a transaction range
//! - [`SubblockOutput`]: Output from a worker containing receipts and bloom
//! - [`AggregationInput`]: Input to the aggregator for combining subblock outputs

use alloc::{sync::Arc, vec::Vec};
use alloy_consensus::Receipt;
use alloy_eips::eip7685::Requests;
use alloy_genesis::ChainConfig;
use alloy_primitives::Bloom;
use core::ops::Range;
use reth_ethereum_primitives::Block;
use revm_state::bal::Bal;

use crate::ExecutionWitness;

/// Input to the worker guest program for subblock proving.
///
/// Contains all data needed to execute a range of transactions within a block.
///
/// # BAL Range Semantics
///
/// The `bal_range` uses EIP-7928 BAL index semantics:
///
/// | Index | Operation |
/// |-------|-----------|
/// | `0` | Pre-execution system calls (beacon root, blockhashes) |
/// | `1..N` | Transactions (transaction `i-1` at index `i`) |
/// | `N+1` | Post-execution (withdrawals) |
///
/// For a block with N transactions, valid ranges are subsets of `[0, N+2)`.
///
/// # Example
///
/// ```ignore
/// // Execute transactions 2, 3, 4 (BAL indices 3, 4, 5)
/// let input = SubblockInput {
///     block: full_block.clone(),
///     witness: witness.clone(),
///     bal: Arc::new(bal),
///     bal_range: 3..6, // Covers tx indices 2, 3, 4
///     chain_config,
/// };
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SubblockInput {
    /// The full block (header + body with ALL transactions).
    ///
    /// Even though only a subset of transactions will be executed, the full block
    /// is needed for context (header fields, transaction recovery, etc.).
    pub block: Block,
    /// `ExecutionWitness` for the entire block (pre-state).
    ///
    /// Contains the sparse Merkle trie with account/storage proofs and bytecode.
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block.
    ///
    /// Used for fast-forwarding state reads and validating execution correctness.
    pub bal: Arc<Bal>,
    /// BAL index range per EIP-7928.
    ///
    /// Defines which transactions to execute. The range determines:
    /// - `is_first`: Whether to run pre-execution (`start == 0`)
    /// - `is_last`: Whether to process withdrawals (`end > tx_count`)
    pub bal_range: Range<u64>,
    /// Chain config for fork rules.
    pub chain_config: ChainConfig,
}

/// Output committed by the worker (lightweight - no intermediate state roots).
///
/// # Cumulative Gas Semantics
///
/// **Important**: Receipts contain LOCAL cumulative gas, starting from 0 for this
/// subblock. The aggregator adjusts these to GLOBAL cumulative gas when combining
/// outputs from multiple subblocks.
///
/// # Example
///
/// For a subblock executing transactions 3 and 4 (each using 21000 gas):
/// - `receipts[0].cumulative_gas_used = 21000` (LOCAL)
/// - `receipts[1].cumulative_gas_used = 42000` (LOCAL)
///
/// After aggregation (if prior subblocks used 100000 gas total):
/// - `receipts[0].cumulative_gas_used = 121000` (GLOBAL)
/// - `receipts[1].cumulative_gas_used = 142000` (GLOBAL)
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SubblockOutput<R = alloy_consensus::Receipt> {
    /// Receipts for transactions in this range.
    ///
    /// Contains LOCAL cumulative gas (starting from 0 for this subblock).
    /// The aggregator adjusts to global cumulative gas when combining outputs.
    pub receipts: Vec<R>,
    /// Logs bloom for this range.
    ///
    /// Accumulated bloom filter from all logs emitted by transactions in this range.
    pub logs_bloom: Bloom,
    /// EIP-7685 requests from this range.
    ///
    /// Only populated for the last subblock (`is_last = true`), which processes
    /// withdrawals and generates deposit/withdrawal requests.
    pub requests: Requests,
    /// Total gas used by transactions in this subblock.
    pub gas_used: u64,
}

/// Input to the master/aggregator guest program.
///
/// Contains verified subblock outputs for combining and final validation.
///
/// # Range Requirements
///
/// The `bal_ranges` must be:
/// 1. **Complete**: Cover `[0, tx_count + 2)` (all indices including pre/post execution)
/// 2. **Contiguous**: `ranges[i].end == ranges[i+1].start` for all adjacent ranges
/// 3. **Ordered**: Ranges must be in ascending order
///
/// # Example
///
/// ```ignore
/// // For a block with 10 transactions, valid aggregation:
/// let input = AggregationInput {
///     block,
///     witness,
///     bal,
///     chain_config,
///     subblock_outputs: vec![output1, output2, output3],
///     bal_ranges: vec![0..4, 4..8, 8..12], // Complete: [0, 12)
/// };
/// ```
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AggregationInput<R = Receipt> {
    /// The full block being validated.
    pub block: Block,
    /// `ExecutionWitness` for the entire block.
    ///
    /// Used to compute the final state root from BAL changes.
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block.
    ///
    /// Used for state root computation and BAL hash verification.
    pub bal: Arc<Bal>,
    /// Chain config for fork rules.
    pub chain_config: ChainConfig,
    /// Subblock outputs (in order), verified by ZK proofs.
    ///
    /// Each output contains receipts with LOCAL cumulative gas. The aggregator
    /// adjusts these to global positions when combining.
    pub subblock_outputs: Vec<SubblockOutput<R>>,
    /// The BAL ranges each subblock covered (for verification).
    ///
    /// Must be contiguous and complete, covering `[0, tx_count + 2)`.
    /// Uses EIP-7928 BAL index semantics.
    pub bal_ranges: Vec<Range<u64>>,
}
