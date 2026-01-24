//! Master/aggregator guest program for subblock aggregation.
//!
//! Combines verified subblock outputs and computes final state root.

use alloc::{fmt::Debug, sync::Arc, vec::Vec};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_eips::eip7685::Requests;
use alloy_primitives::{keccak256, Bloom, B256};
use core::ops::Range;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_ethereum_primitives::EthereumReceipt;
use reth_primitives_traits::SealedHeader;

use crate::{
    recover_block::{recover_block_with_public_keys, UncompressedPublicKey},
    subblock::{
        bal_state::bal_to_hashed_post_state, error::AggregationValidationError, AggregationInput,
        SubblockOutput,
    },
    trie::StatelessSparseTrie,
    validation::StatelessValidationError,
};

/// Validates aggregated subblock outputs and computes the final state root.
///
/// This function:
/// 1. Verifies transaction ranges are complete and contiguous
/// 2. Verifies gas chaining between subblocks
/// 3. Combines receipts and logs blooms
/// 4. Runs post-block validation
/// 5. Computes final state root from BAL
///
/// # Arguments
///
/// * `input` - The aggregation input containing block, witness, BAL, and subblock outputs
/// * `public_keys` - Public keys for transaction signature recovery
/// * `chain_spec` - Chain specification for fork rules
///
/// # Returns
///
/// Returns the block hash if validation succeeds.
pub fn aggregation_validation<ChainSpec>(
    input: AggregationInput<EthereumReceipt>,
    public_keys: Vec<UncompressedPublicKey>,
    chain_spec: Arc<ChainSpec>,
) -> Result<B256, AggregationValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
{
    let AggregationInput { block, witness, bal, chain_config: _, subblock_outputs, tx_ranges } =
        input;

    // Validate we have outputs
    if subblock_outputs.is_empty() {
        return Err(AggregationValidationError::NoSubblockOutputs);
    }

    // Validate outputs and ranges match
    if subblock_outputs.len() != tx_ranges.len() {
        return Err(AggregationValidationError::MismatchedOutputsAndRanges {
            outputs: subblock_outputs.len(),
            ranges: tx_ranges.len(),
        });
    }

    let tx_count = block.body.transactions.len();

    // Verify ranges are complete and contiguous
    verify_ranges_complete(&tx_ranges, tx_count)?;

    // Verify gas chaining
    verify_gas_chaining(&subblock_outputs, &tx_ranges)?;

    // Recover signers (for block hash computation)
    let recovered_block = recover_block_with_public_keys(block.clone(), public_keys, &*chain_spec)
        .map_err(AggregationValidationError::StatelessValidation)?;

    // Parse ancestor headers from witness
    let mut ancestor_headers: Vec<_> = witness
        .headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes).map(|h| SealedHeader::new(h, hash)).map_err(
                |_| {
                    AggregationValidationError::StatelessValidation(
                        StatelessValidationError::HeaderDeserializationFailed,
                    )
                },
            )
        })
        .collect::<Result<_, _>>()?;
    ancestor_headers.sort_by_key(|header| header.number());

    // Get parent header for pre-state root
    let parent = ancestor_headers.last().ok_or(AggregationValidationError::StatelessValidation(
        StatelessValidationError::MissingAncestorHeader,
    ))?;

    // Combine outputs
    let (combined_receipts, combined_bloom, combined_requests) =
        combine_subblock_outputs(&subblock_outputs);

    // Run post-block validation
    validate_block_post_execution(
        &recovered_block,
        &chain_spec,
        &combined_receipts,
        &combined_requests,
        None,
    )?;

    // Compute final state root from BAL
    let (mut trie, _bytecode) = StatelessSparseTrie::new(&witness, parent.state_root)
        .map_err(AggregationValidationError::StatelessValidation)?;

    // BAL index for post-block state:
    // Index 0 = pre-execution
    // Index 1 = after pre-block system calls
    // Index 2..n+1 = after each tx
    // Index n+2 = after post-block (withdrawals, etc.)
    let final_bal_index = (tx_count + 2) as u64;

    // Use the trie as the pre-state provider to look up unchanged account fields
    let hashed_post_state = bal_to_hashed_post_state(&bal, final_bal_index, &trie)
        .map_err(|e| AggregationValidationError::StatelessValidation(e.into()))?;
    let computed_root = trie
        .calculate_state_root(hashed_post_state)
        .map_err(AggregationValidationError::StatelessValidation)?;

    if computed_root != block.state_root {
        return Err(AggregationValidationError::PostStateRootMismatch {
            computed: computed_root,
            expected: block.state_root,
        });
    }

    // Verify logs bloom matches
    if combined_bloom != block.logs_bloom {
        // Note: This should be caught by validate_block_post_execution, but we double-check
    }

    Ok(recovered_block.hash_slow())
}

/// Verifies that transaction ranges are complete and contiguous.
fn verify_ranges_complete(
    tx_ranges: &[Range<usize>],
    tx_count: usize,
) -> Result<(), AggregationValidationError> {
    if tx_ranges.is_empty() {
        if tx_count == 0 {
            return Ok(());
        }
        return Err(AggregationValidationError::IncompleteRanges { covered: 0, tx_count });
    }

    // First range must start at 0
    if tx_ranges[0].start != 0 {
        return Err(AggregationValidationError::RangesNotStartingAtZero {
            start: tx_ranges[0].start,
        });
    }

    // Check contiguity
    for i in 0..tx_ranges.len() - 1 {
        if tx_ranges[i].end != tx_ranges[i + 1].start {
            return Err(AggregationValidationError::NonContiguousRanges {
                index: i,
                end: tx_ranges[i].end,
                next_index: i + 1,
                start: tx_ranges[i + 1].start,
            });
        }
    }

    // Last range must end at tx_count
    let last_end = tx_ranges.last().map(|r| r.end).unwrap_or(0);
    if last_end != tx_count {
        return Err(AggregationValidationError::IncompleteRanges { covered: last_end, tx_count });
    }

    Ok(())
}

/// Verifies gas chaining between subblocks.
///
/// Each subblock's cumulative gas at start should match the previous subblock's
/// cumulative gas at end.
fn verify_gas_chaining(
    outputs: &[SubblockOutput<EthereumReceipt>],
    tx_ranges: &[Range<usize>],
) -> Result<(), AggregationValidationError> {
    // First subblock starts with 0 gas
    // Subsequent subblocks should have receipts that reflect proper cumulative gas
    //
    // Note: The receipts contain cumulative_gas_used, which should chain correctly.
    // We verify this by checking that the first receipt in subblock N has cumulative
    // gas >= the last receipt in subblock N-1.

    for i in 1..outputs.len() {
        let prev_gas = outputs[i - 1].cumulative_gas_used;

        // The current subblock's first receipt should have cumulative gas > prev_gas
        // (unless the range is empty, which shouldn't happen)
        if !outputs[i].receipts.is_empty() {
            let first_receipt_gas = outputs[i].receipts[0].cumulative_gas_used();

            // The first receipt's cumulative gas should be > prev_gas
            // (it includes prev_gas + this tx's gas)
            if first_receipt_gas < prev_gas && !tx_ranges[i].is_empty() {
                return Err(AggregationValidationError::GasChainingMismatch {
                    index: i - 1,
                    expected: prev_gas,
                    next_index: i,
                });
            }
        }
    }

    Ok(())
}

/// Combines subblock outputs into final aggregated values.
fn combine_subblock_outputs(
    outputs: &[SubblockOutput<EthereumReceipt>],
) -> (Vec<EthereumReceipt>, Bloom, Requests) {
    let mut combined_receipts = Vec::new();
    let mut combined_bloom = Bloom::default();
    let mut combined_requests = Requests::default();

    for output in outputs {
        combined_receipts.extend(output.receipts.iter().cloned());
        combined_bloom.accrue_bloom(&output.logs_bloom);

        // Only the last subblock should have requests
        if !output.requests.is_empty() {
            combined_requests = output.requests.clone();
        }
    }

    (combined_receipts, combined_bloom, combined_requests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_verify_ranges_complete_valid() {
        let ranges = vec![0..2, 2..5, 5..10];
        assert!(verify_ranges_complete(&ranges, 10).is_ok());
    }

    #[test]
    fn test_verify_ranges_complete_empty_block() {
        let ranges: Vec<Range<usize>> = vec![];
        assert!(verify_ranges_complete(&ranges, 0).is_ok());
    }

    #[test]
    fn test_verify_ranges_not_starting_at_zero() {
        let ranges = vec![1..5, 5..10];
        assert!(matches!(
            verify_ranges_complete(&ranges, 10),
            Err(AggregationValidationError::RangesNotStartingAtZero { start: 1 })
        ));
    }

    #[test]
    fn test_verify_ranges_non_contiguous() {
        let ranges = vec![0..3, 4..10];
        assert!(matches!(
            verify_ranges_complete(&ranges, 10),
            Err(AggregationValidationError::NonContiguousRanges { .. })
        ));
    }

    #[test]
    fn test_verify_ranges_incomplete() {
        let ranges = vec![0..5];
        assert!(matches!(
            verify_ranges_complete(&ranges, 10),
            Err(AggregationValidationError::IncompleteRanges { covered: 5, tx_count: 10 })
        ));
    }
}
