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
    /// `ExecutionWitness` for the entire block (pre-state).
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block.
    pub bal: Arc<Bal>,
    /// BAL index range per EIP-7928.
    /// - Index 0 = pre-execution system calls (beacon root, blockhashes)
    /// - Index 1..n = transactions (tx i-1 at index i)
    /// - Index n+1 = post-execution (withdrawals)
    pub bal_range: Range<u64>,
    /// Chain config for fork rules.
    pub chain_config: ChainConfig,
}

/// Output committed by the worker (lightweight - no intermediate state roots).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SubblockOutput<R = alloy_consensus::Receipt> {
    /// Receipts for transactions in this range.
    pub receipts: Vec<R>,
    /// Logs bloom for this range.
    pub logs_bloom: Bloom,
    /// EIP-7685 requests from this range (only populated if `is_last`).
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
    /// `ExecutionWitness` for the entire block.
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block.
    pub bal: Arc<Bal>,
    /// Chain config for fork rules.
    pub chain_config: ChainConfig,
    /// Subblock outputs (in order), verified by ZK proofs.
    pub subblock_outputs: Vec<SubblockOutput<R>>,
    /// The BAL ranges each subblock covered (for verification).
    /// Uses EIP-7928 BAL index semantics.
    pub bal_ranges: Vec<Range<u64>>,
}
