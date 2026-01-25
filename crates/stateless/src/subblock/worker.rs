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
/// This function validates and executes transactions in the range `[tx_range.start, tx_range.end)`
/// using the provided BAL to fast-forward state to the starting transaction index.
///
/// # Arguments
///
/// * `input` - The subblock input containing block, witness, BAL, and tx range
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
    let SubblockInput { block, witness, bal, tx_range, chain_config: _, is_first, is_last } = input;

    // Validate tx range
    let tx_count = block.body.transactions.len();
    if tx_range.end > tx_count {
        return Err(SubblockValidationError::TxRangeOutOfBounds {
            start: tx_range.start,
            end: tx_range.end,
            tx_count,
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

    // BAL index semantics per EIP-7928:
    // - Index 0 = pre-execution system contract calls (beacon root, blockhashes)
    // - Index 1..n = individual transactions (tx 0 at index 1, tx 1 at index 2, ...)
    // - Index n+1 = post-execution (withdrawals)
    //
    // If is_first, we start at index 0 (pre-execution system calls).
    // Otherwise, we start at tx_range.start + 1 (the index for that transaction).
    let start_bal_index = if is_first {
        0
    } else {
        (tx_range.start + 1) as u64
    };

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

    // Extract only the receipts for our range
    let receipts: Vec<_> = output
        .receipts
        .iter()
        .skip(tx_range.start)
        .take(tx_range.end - tx_range.start)
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
    let requests = if is_last { output.requests.clone() } else { Default::default() };

    Ok(SubblockOutput { receipts, logs_bloom, requests, cumulative_gas_used })
}
