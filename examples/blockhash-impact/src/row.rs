//! Public row data model emitted by the scanner and helpers shared between the inspector and the
//! scan orchestrator.
//!
//! Each [`BlockhashRow`] is one BLOCKHASH execution event annotated with the canonical observed
//! cost and the EIP-7709 cost model classification. [`BlockExecutionContext`] and
//! [`TxExecutionMetadata`] are the per-block / per-tx coordinates the inspector needs to fill rows
//! after execution.

use alloy_consensus::{
    transaction::{Recovered, TxHashRef},
    Transaction,
};
use alloy_primitives::{Address, B256};
use reth_revm::revm::{self as revm};
use std::fmt;

use crate::eip7709::BASE_BLOCKHASH_COST;

/// Pre-EIP-7709 BLOCKHASH cost; used to compute `extra_gas_headroom` against canonical execution.
pub(crate) const CURRENT_BLOCKHASH_COST: u64 = BASE_BLOCKHASH_COST;

#[derive(Debug, Clone, Copy)]
pub struct BlockExecutionContext {
    pub block_number: u64,
    pub block_hash: B256,
}

#[derive(Debug, Clone)]
pub struct TxExecutionMetadata {
    pub tx_index: u64,
    pub tx_hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub tx_type: u8,
    pub gas_limit: u64,
}

#[derive(Debug, Clone)]
pub struct BlockhashRow {
    pub block_number: u64,
    pub block_hash: String,
    pub tx_index: u64,
    pub tx_hash: String,
    pub tx_from: String,
    pub tx_to: Option<String>,
    pub tx_nonce: u64,
    pub tx_type: u8,
    pub tx_gas_limit: u64,
    pub tx_gas_used: u64,
    pub tx_status: String,
    pub event_index: u64,
    pub frame_id: u64,
    pub parent_frame_id: Option<u64>,
    pub frame_depth: u32,
    pub frame_kind: String,
    pub frame_caller: String,
    pub frame_target: Option<String>,
    pub frame_code_address: Option<String>,
    pub frame_gas_limit: u64,
    pub frame_is_static: bool,
    pub frame_end_status: Option<String>,
    pub pc: u64,
    pub requested_block_number: Option<u64>,
    pub requested_block_delta: Option<i64>,
    pub gas_before: u64,
    pub gas_after: u64,
    pub observed_gas_cost: u64,
    pub extra_gas_headroom: i64,
    /// `requested_block_number % HISTORY_SERVE_WINDOW` — None when `requested_block_number` is.
    pub slot_index: Option<u64>,
    /// `delta in [1, 256]` — calls outside this window pay no SLOAD under EIP-7709.
    pub is_in_window: bool,
    /// `"cold" | "warm" | "out_of_window" | "unknown"` per [`crate::eip7709::WarmthClass`].
    pub slot_warmth_class: String,
    /// SLOAD-equivalent extra gas (2100 cold, 100 warm, 0 otherwise) charged on top of the base
    /// 20.
    pub eip7709_extra_cost: u64,
    /// Total EIP-7709 cost: `BASE_BLOCKHASH_COST + eip7709_extra_cost`.
    pub eip7709_new_cost: u64,
    /// `gas_before - eip7709_new_cost`; negative means the frame would not afford this BLOCKHASH.
    pub eip7709_new_headroom: i64,
    /// `true` iff the frame would OOG at this BLOCKHASH under EIP-7709 (`gas_before < new_cost`).
    pub eip7709_would_oog_frame: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum FrameKind {
    TxCall,
    TxCreate,
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    Create,
    Create2,
}

impl FrameKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TxCall => "tx_call",
            Self::TxCreate => "tx_create",
            Self::Call => "call",
            Self::CallCode => "callcode",
            Self::DelegateCall => "delegatecall",
            Self::StaticCall => "staticcall",
            Self::Create => "create",
            Self::Create2 => "create2",
        }
    }
}

pub(crate) fn transaction_metadata<T>(tx_index: u64, tx: &Recovered<T>) -> TxExecutionMetadata
where
    T: Transaction + TxHashRef,
{
    TxExecutionMetadata {
        tx_index,
        tx_hash: *tx.tx_hash(),
        from: tx.signer(),
        to: tx.to(),
        nonce: tx.nonce(),
        tx_type: tx.ty(),
        gas_limit: tx.gas_limit(),
    }
}

pub(crate) fn format_tx_status<H>(result: &revm::context::result::ExecutionResult<H>) -> String
where
    H: fmt::Debug,
{
    match result {
        revm::context::result::ExecutionResult::Success { reason, .. } => {
            format!("Success({reason:?})")
        }
        revm::context::result::ExecutionResult::Revert { .. } => "Revert".to_string(),
        revm::context::result::ExecutionResult::Halt { reason, .. } => {
            format!("Halt({reason:?})")
        }
    }
}

pub(crate) fn block_number_delta(block_number: u64, requested_block_number: u64) -> Option<i64> {
    let block_number = i64::try_from(block_number).ok()?;
    let requested_block_number = i64::try_from(requested_block_number).ok()?;
    Some(block_number - requested_block_number)
}

pub(crate) fn gas_headroom(gas_before: u64) -> i64 {
    i64::try_from(gas_before).unwrap_or(i64::MAX) - CURRENT_BLOCKHASH_COST as i64
}

pub(crate) fn hex<T: fmt::LowerHex>(value: T) -> String {
    format!("{value:#x}")
}
