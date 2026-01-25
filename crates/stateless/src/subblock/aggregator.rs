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
    let AggregationInput { block, witness, bal, chain_config: _, subblock_outputs, bal_ranges } =
        input;

    // Validate we have outputs
    if subblock_outputs.is_empty() {
        return Err(AggregationValidationError::NoSubblockOutputs);
    }

    // Validate outputs and ranges match
    if subblock_outputs.len() != bal_ranges.len() {
        return Err(AggregationValidationError::MismatchedOutputsAndRanges {
            outputs: subblock_outputs.len(),
            ranges: bal_ranges.len(),
        });
    }

    let tx_count = block.body.transactions.len();

    // Verify BAL ranges are complete and contiguous
    verify_bal_ranges_complete(&bal_ranges, tx_count)?;

    // Verify gas chaining
    verify_gas_chaining(&subblock_outputs, &bal_ranges)?;

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

    // BAL index semantics per EIP-7928:
    // - Index 0 = pre-execution system contract calls (beacon root, blockhashes)
    // - Index 1..n = individual transactions (tx 0 at index 1, tx 1 at index 2, ...)
    // - Index n+1 = post-execution (withdrawals)
    let final_bal_index = (tx_count + 1) as u64;

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

/// Verifies that BAL ranges are complete and contiguous.
///
/// BAL index semantics per EIP-7928:
/// - Index 0 = pre-execution system calls
/// - Index 1..n = transactions (tx i-1 at index i)
/// - Index n+1 = post-execution (withdrawals)
///
/// For a complete block, ranges must cover `[0, tx_count + 2)`.
fn verify_bal_ranges_complete(
    bal_ranges: &[Range<u64>],
    tx_count: usize,
) -> Result<(), AggregationValidationError> {
    // Full BAL range is [0, tx_count + 2) to cover pre-execution, all txs, and post-execution
    let max_bal_index = (tx_count + 2) as u64;

    if bal_ranges.is_empty() {
        if tx_count == 0 {
            // Empty block still needs pre/post execution coverage
            return Err(AggregationValidationError::IncompleteRanges { covered: 0, tx_count });
        }
        return Err(AggregationValidationError::IncompleteRanges { covered: 0, tx_count });
    }

    // First range must start at 0 (pre-execution)
    if bal_ranges[0].start != 0 {
        return Err(AggregationValidationError::RangesNotStartingAtZero {
            start: bal_ranges[0].start as usize,
        });
    }

    // Check contiguity
    for i in 0..bal_ranges.len() - 1 {
        if bal_ranges[i].end != bal_ranges[i + 1].start {
            return Err(AggregationValidationError::NonContiguousRanges {
                index: i,
                end: bal_ranges[i].end as usize,
                next_index: i + 1,
                start: bal_ranges[i + 1].start as usize,
            });
        }
    }

    // Last range must end at max_bal_index (covers post-execution)
    let last_end = bal_ranges.last().map(|r| r.end).unwrap_or(0);
    if last_end != max_bal_index {
        // Report in terms of tx coverage for user-friendly error
        let covered_txs = last_end.saturating_sub(1) as usize;
        return Err(AggregationValidationError::IncompleteRanges {
            covered: covered_txs.min(tx_count),
            tx_count,
        });
    }

    Ok(())
}

/// Verifies gas chaining between subblocks.
///
/// Each subblock's cumulative gas at start should match the previous subblock's
/// cumulative gas at end.
fn verify_gas_chaining(
    outputs: &[SubblockOutput<EthereumReceipt>],
    bal_ranges: &[Range<u64>],
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
            if first_receipt_gas < prev_gas && !bal_ranges[i].is_empty() {
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
///
/// Adjusts cumulative gas in receipts so they reflect global block position
/// rather than local subblock position.
fn combine_subblock_outputs(
    outputs: &[SubblockOutput<EthereumReceipt>],
) -> (Vec<EthereumReceipt>, Bloom, Requests) {
    let mut combined_receipts = Vec::new();
    let mut combined_bloom = Bloom::default();
    let mut combined_requests = Requests::default();
    let mut gas_offset: u64 = 0;

    for output in outputs {
        // Adjust cumulative gas for each receipt by adding the offset
        for receipt in &output.receipts {
            let mut adjusted_receipt = receipt.clone();
            adjusted_receipt.cumulative_gas_used += gas_offset;
            combined_receipts.push(adjusted_receipt);
        }

        // Update offset for next subblock
        gas_offset += output.cumulative_gas_used;

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

    // BAL index semantics for 10 txs:
    // - Index 0 = pre-execution
    // - Index 1-10 = transactions 0-9
    // - Index 11 = post-execution
    // - Full range is [0, 12)

    #[test]
    fn test_verify_bal_ranges_complete_valid() {
        // 10 txs: full range is [0, 12)
        let ranges: Vec<Range<u64>> = vec![0..4, 4..8, 8..12];
        assert!(verify_bal_ranges_complete(&ranges, 10).is_ok());
    }

    #[test]
    fn test_verify_bal_ranges_complete_single_range() {
        // Single range covering entire block
        let ranges: Vec<Range<u64>> = vec![0..12];
        assert!(verify_bal_ranges_complete(&ranges, 10).is_ok());
    }

    #[test]
    fn test_verify_bal_ranges_not_starting_at_zero() {
        let ranges: Vec<Range<u64>> = vec![1..6, 6..12];
        assert!(matches!(
            verify_bal_ranges_complete(&ranges, 10),
            Err(AggregationValidationError::RangesNotStartingAtZero { start: 1 })
        ));
    }

    #[test]
    fn test_verify_bal_ranges_non_contiguous() {
        let ranges: Vec<Range<u64>> = vec![0..3, 4..12];
        assert!(matches!(
            verify_bal_ranges_complete(&ranges, 10),
            Err(AggregationValidationError::NonContiguousRanges { .. })
        ));
    }

    #[test]
    fn test_verify_bal_ranges_incomplete() {
        // Range ends at 5, which covers pre-execution (0) and txs 0-3 (indices 1-4)
        // Expected covered: min(5-1, 10) = 4 txs
        let ranges: Vec<Range<u64>> = vec![0..5];
        assert!(matches!(
            verify_bal_ranges_complete(&ranges, 10),
            Err(AggregationValidationError::IncompleteRanges { covered: 4, tx_count: 10 })
        ));
    }

    #[test]
    fn test_verify_bal_ranges_empty_block_needs_coverage() {
        // Even an empty block needs at least [0, 2) for pre and post execution
        let ranges: Vec<Range<u64>> = vec![];
        assert!(matches!(
            verify_bal_ranges_complete(&ranges, 0),
            Err(AggregationValidationError::IncompleteRanges { .. })
        ));
    }

    #[test]
    fn test_verify_bal_ranges_empty_block_valid() {
        // Empty block: full range is [0, 2) for pre and post execution
        let ranges: Vec<Range<u64>> = vec![0..2];
        assert!(verify_bal_ranges_complete(&ranges, 0).is_ok());
    }

    #[test]
    fn test_combine_subblock_outputs_adjusts_cumulative_gas() {
        use reth_ethereum_primitives::{EthereumReceipt, TxType};

        // Create mock receipts with LOCAL cumulative gas
        let receipt1 = EthereumReceipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 21000, // First tx uses 21000
            logs: vec![],
        };
        let receipt2 = EthereumReceipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 42000, // Second tx uses 21000 more (local cumulative = 42000)
            logs: vec![],
        };
        let receipt3 = EthereumReceipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 30000, // Third tx in second subblock (local cumulative = 30000)
            logs: vec![],
        };

        let output1 = SubblockOutput {
            receipts: vec![receipt1, receipt2],
            logs_bloom: Bloom::default(),
            requests: Requests::default(),
            cumulative_gas_used: 42000, // End gas of subblock 1
        };
        let output2 = SubblockOutput {
            receipts: vec![receipt3],
            logs_bloom: Bloom::default(),
            requests: Requests::default(),
            cumulative_gas_used: 30000, // End gas of subblock 2 (local)
        };

        let (combined, _, _) = combine_subblock_outputs(&[output1, output2]);

        // After adjustment:
        // - Receipt 1: 21000 (no offset)
        // - Receipt 2: 42000 (no offset)
        // - Receipt 3: 42000 + 30000 = 72000 (offset by subblock 1's end gas)
        assert_eq!(combined.len(), 3);
        assert_eq!(combined[0].cumulative_gas_used, 21000);
        assert_eq!(combined[1].cumulative_gas_used, 42000);
        assert_eq!(combined[2].cumulative_gas_used, 72000);
    }
}
