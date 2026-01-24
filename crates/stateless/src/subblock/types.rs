//! Data structures for subblock proving.

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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SubblockInput {
    /// The full block (header + body with ALL transactions).
    pub block: Block,
    /// ExecutionWitness for the entire block (pre-state).
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block.
    pub bal: Arc<Bal>,
    /// Transaction range to execute: [start_tx_index, end_tx_index).
    pub tx_range: Range<usize>,
    /// Chain config for fork rules.
    pub chain_config: ChainConfig,
    /// Whether this is the first subblock (runs pre-block logic).
    pub is_first: bool,
    /// Whether this is the last subblock (runs post-block logic).
    pub is_last: bool,
}

/// Output committed by the worker (lightweight - no intermediate state roots).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SubblockOutput<R = alloy_consensus::Receipt> {
    /// Receipts for transactions in this range.
    pub receipts: Vec<R>,
    /// Logs bloom for this range.
    pub logs_bloom: Bloom,
    /// EIP-7685 requests from this range (only populated if is_last).
    pub requests: Requests,
    /// Cumulative gas used at end of range.
    pub cumulative_gas_used: u64,
}

/// Input to the master/aggregator guest program.
///
/// Contains verified subblock outputs for combining and final validation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AggregationInput<R = Receipt> {
    /// The full block being validated.
    pub block: Block,
    /// ExecutionWitness for the entire block.
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block.
    pub bal: Arc<Bal>,
    /// Chain config for fork rules.
    pub chain_config: ChainConfig,
    /// Subblock outputs (in order), verified by ZK proofs.
    pub subblock_outputs: Vec<SubblockOutput<R>>,
    /// The tx ranges each subblock covered (for verification).
    pub tx_ranges: Vec<Range<usize>>,
}
