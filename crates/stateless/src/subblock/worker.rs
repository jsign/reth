//! Worker guest program for subblock validation.
//!
//! Executes a range of transactions within a block using BAL fast-forwarding.

use alloc::{fmt::Debug, sync::Arc, vec::Vec};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_primitives::{keccak256, Bloom};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_primitives::{EthPrimitives, EthereumReceipt};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_primitives_traits::SealedHeader;

use crate::{
    recover_block::{recover_block_with_public_keys, UncompressedPublicKey},
    subblock::{error::SubblockValidationError, BalWitnessDatabase, SubblockInput, SubblockOutput},
    trie::StatelessSparseTrie,
    validation::StatelessValidationError,
};

/// Executes a subblock (range of transactions) using BAL fast-forwarding.
///
/// This function validates and executes transactions in the BAL index range `[bal_range.start,
/// bal_range.end)` using the provided BAL to fast-forward state to the starting BAL index.
///
/// # Arguments
///
/// * `input` - The subblock input containing block, witness, BAL, and BAL index range
/// * `public_keys` - Public keys for transaction signature recovery
/// * `chain_spec` - Chain specification for fork rules
/// * `evm_config` - EVM configuration
///
/// # Returns
///
/// Returns `SubblockOutput` containing receipts, logs bloom, requests, and cumulative gas.
pub fn subblock_validation<ChainSpec, E>(
    input: SubblockInput,
    public_keys: Vec<UncompressedPublicKey>,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<SubblockOutput<EthereumReceipt>, SubblockValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    let SubblockInput { block, witness, bal, bal_range, chain_config: _ } = input;

    // Validate BAL range
    let tx_count = block.body.transactions.len();
    // BAL index semantics per EIP-7928:
    // - Index 0 = pre-execution system calls
    // - Index 1..n = transactions (tx i-1 at index i)
    // - Index n+1 = post-execution (withdrawals)
    // Max valid index is tx_count + 1 (inclusive), so range.end can be at most tx_count + 2
    let max_bal_index = (tx_count + 2) as u64;
    if bal_range.end > max_bal_index {
        return Err(SubblockValidationError::BalRangeOutOfBounds {
            start: bal_range.start,
            end: bal_range.end,
            max_bal_index,
        });
    }
    // Recover signers
    let recovered_block = recover_block_with_public_keys(block, public_keys, &*chain_spec)?;

    // Parse ancestor headers from witness
    let mut ancestor_headers: Vec<_> = witness
        .headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes).map(|h| SealedHeader::new(h, hash)).map_err(
                |_| {
                    SubblockValidationError::StatelessValidation(
                        StatelessValidationError::HeaderDeserializationFailed,
                    )
                },
            )
        })
        .collect::<Result<_, _>>()?;
    ancestor_headers.sort_by_key(|header| header.number());

    // Get parent header for pre-state root
    let parent = ancestor_headers.last().ok_or(StatelessValidationError::MissingAncestorHeader)?;

    // Build the trie from witness
    let (trie, bytecode) = StatelessSparseTrie::new(&witness, parent.state_root)?;

    // Build ancestor hashes map
    let mut ancestor_hashes = alloc::collections::BTreeMap::new();
    let mut child_header = recovered_block.sealed_header();
    for parent_header in ancestor_headers.iter().rev() {
        ancestor_hashes.insert(parent_header.number, child_header.parent_hash());
        child_header = parent_header;
    }

    // Start BAL index comes directly from the bal_range
    let start_bal_index = bal_range.start;

    // Create BAL-aware database
    let db = BalWitnessDatabase::new(&trie, bytecode, ancestor_hashes, bal, start_bal_index);

    // Pre-block logic (if first subblock)
    // Pre-execution system calls (beacon root, blockhashes) happen at BAL index 0.
    // The executor handles the actual calls and BAL index bumping internally.
    // After pre-execution, index becomes 1 (ready for tx 0).

    // Execute transactions in range
    // Note: We create a partial block view for the executor containing only our tx range
    // However, the current executor API expects the full block. We'll need to handle
    // receipt cumulative gas adjustment.

    // For now, we execute the full block but only collect receipts for our range
    // TODO: Optimize to only execute our tx range once executor supports partial execution
    let executor = evm_config.executor(db);
    let output = executor.execute(&recovered_block).map_err(|e| {
        SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e))
    })?;

    // Convert BAL range to tx indices for receipt extraction.
    // BAL index i corresponds to tx i-1 (index 1 = tx 0, index 2 = tx 1, etc.)
    // tx_start = first tx index in range (BAL index 0 has no tx, so clamp to 1)
    // tx_end = tx index after last tx in range (capped at tx_count)
    let tx_start = if bal_range.start == 0 { 0 } else { (bal_range.start - 1) as usize };
    let tx_end = ((bal_range.end.saturating_sub(1)) as usize).min(tx_count);

    // Extract only the receipts for our range
    let receipts: Vec<_> = output
        .receipts
        .iter()
        .skip(tx_start)
        .take(tx_end.saturating_sub(tx_start))
        .cloned()
        .collect();

    // Compute logs bloom for this range
    let mut logs_bloom = Bloom::default();
    for receipt in &receipts {
        logs_bloom.accrue_bloom(&receipt.bloom());
    }

    // Get cumulative gas used at end of our range
    let cumulative_gas_used = receipts.last().map(|r| r.cumulative_gas_used()).unwrap_or(0);

    // Requests are only collected if this is the last subblock
    // Last subblock must include post-execution (BAL index tx_count + 1)
    let is_last = bal_range.end > tx_count as u64;
    let requests = if is_last { output.requests.clone() } else { Default::default() };

    Ok(SubblockOutput { receipts, logs_bloom, requests, cumulative_gas_used })
}
