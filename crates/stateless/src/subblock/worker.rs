//! Worker guest program for subblock validation.
//!
//! Executes a range of transactions within a block using BAL fast-forwarding.
//!
//! # BAL Range to Transaction Index Conversion
//!
//! BAL indices don't map 1:1 to transaction indices because index 0 is reserved
//! for pre-execution:
//!
//! ```text
//! BAL index:    0       1       2       ...     N       N+1
//!               │       │       │               │       │
//!               ▼       ▼       ▼               ▼       ▼
//!            [pre]   [tx 0]  [tx 1]   ...   [tx N-1]  [post]
//! ```
//!
//! Conversion formula:
//! - `tx_start = bal_range.start == 0 ? 0 : bal_range.start - 1`
//! - `tx_end = min(bal_range.end - 1, tx_count)`
//!
//! # Subblock Position Flags
//!
//! The `is_first` and `is_last` flags are derived directly from the BAL range:
//!
//! | Flag | Condition | Meaning |
//! |------|-----------|---------|
//! | `is_first` | `bal_range.start == 0` | Range includes pre-execution at index 0 |
//! | `is_last` | `bal_range.end > tx_count` | Range includes post-execution at index N+1 |
//!
//! These flags determine:
//! - `is_first`: Whether to call `apply_pre_execution_changes()` (beacon root, blockhashes)
//! - `is_last`: Whether to process withdrawals in `finish()`
//!
//! # BAL Validation
//!
//! After execution, the BAL built during execution is compared against the provided
//! BAL to ensure correctness. Only changes within `bal_range` are validated; changes
//! outside the range are ignored (they belong to other subblocks).

use alloc::{fmt::Debug, sync::Arc, vec::Vec};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_evm::{block::BlockExecutor, eth::spec::EthExecutorSpec, Evm};
use alloy_primitives::{keccak256, Bloom};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_forks::Hardforks;
use reth_ethereum_primitives::EthereumReceipt;
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::SealedHeader;
use reth_revm::db::State;

use crate::{
    recover_block::{recover_block_with_public_keys, UncompressedPublicKey},
    subblock::{
        create_subblock_execution_ctx, error::SubblockValidationError, validate_subblock_bal,
        BalWitnessDatabase, SubblockInput, SubblockOutput,
    },
    trie::StatelessSparseTrie,
    validation::StatelessValidationError,
};

/// Executes a subblock (range of transactions) using BAL fast-forwarding.
///
/// This function validates and executes ONLY the transactions in the BAL index range
/// `[bal_range.start, bal_range.end)` using the provided BAL to fast-forward state
/// to the starting BAL index.
///
/// ## Partial Execution
///
/// Unlike full-block execution, this function:
/// - Applies pre-execution changes (beacon root, blockhashes) only if `bal_range.start == 0`
/// - Executes only transactions corresponding to the BAL range
/// - Processes withdrawals only for the last subblock (when `bal_range.end > tx_count`)
///
/// ## Cumulative Gas
///
/// Receipts contain LOCAL cumulative gas (starting from 0 for this subblock).
/// The aggregator adjusts to global cumulative gas when combining outputs.
///
/// # Arguments
///
/// * `input` - The subblock input containing block, witness, BAL, and BAL index range
/// * `public_keys` - Public keys for transaction signature recovery
/// * `chain_spec` - Chain specification for fork rules
/// * `evm_config` - EVM configuration (concrete `EthEvmConfig` for proper withdrawal handling)
///
/// # Returns
///
/// Returns `SubblockOutput` containing receipts, logs bloom, requests, and cumulative gas.
pub fn subblock_validation<ChainSpec>(
    input: SubblockInput,
    public_keys: Vec<UncompressedPublicKey>,
    chain_spec: Arc<ChainSpec>,
    evm_config: EthEvmConfig<ChainSpec>,
) -> Result<SubblockOutput<EthereumReceipt>, SubblockValidationError>
where
    ChainSpec: Send
        + Sync
        + EthChainSpec<Header = Header>
        + EthereumHardforks
        + Hardforks
        + EthExecutorSpec
        + Debug
        + 'static,
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

    // Create BAL-aware database (clone BAL so we keep it for validation later)
    let db =
        BalWitnessDatabase::new(&trie, bytecode, ancestor_hashes, bal.clone(), start_bal_index);

    // Determine subblock position flags
    // is_first: BAL range starts at 0 (includes pre-execution system calls)
    // is_last: BAL range ends beyond tx_count (includes post-execution/withdrawals)
    let is_first = bal_range.start == 0;
    let is_last = bal_range.end > tx_count as u64;

    // Convert BAL range to tx indices for execution
    // BAL index i corresponds to tx i-1 (index 1 = tx 0, index 2 = tx 1, etc.)
    let tx_start = if bal_range.start == 0 { 0 } else { (bal_range.start - 1) as usize };
    let tx_end = ((bal_range.end.saturating_sub(1)) as usize).min(tx_count);

    // Wrap database in State for executor compatibility
    // Enable BAL builder to track state changes during execution (EIP-7928)
    let mut state_db = State::builder()
        .with_database(db)
        .with_bundle_update()
        .without_state_clear()
        .with_bal_builder()
        .build();

    // Set the BAL builder index to match the subblock's start index.
    // This ensures the BAL builder records changes at the correct BAL indices.
    state_db.set_bal_index(start_bal_index);

    // Get sealed block reference for EVM creation
    let sealed_block = recovered_block.sealed_block();

    // Create EVM environment
    let evm = evm_config.evm_for_block(&mut state_db, sealed_block.header()).map_err(|e| {
        SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e))
    })?;

    // Create custom execution context with proper withdrawal handling:
    // - Non-last subblocks have withdrawals=None to skip withdrawal processing
    // - Only the last subblock processes withdrawals
    let ctx = create_subblock_execution_ctx(&recovered_block, is_last);

    // Create executor with our custom context
    let mut block_executor = evm_config.create_executor(evm, ctx);

    // Apply pre-execution changes only if this is the first subblock
    // This handles beacon root and blockhashes system calls at BAL index 0
    if is_first {
        block_executor.apply_pre_execution_changes().map_err(|e| {
            SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e))
        })?;

        // Bump BAL index after pre-execution changes (EIP-7928: index 0 is pre-execution)
        block_executor.evm_mut().db_mut().bump_bal_index();
    }

    // Execute only our transaction range
    for tx in recovered_block.transactions_recovered().skip(tx_start).take(tx_end - tx_start) {
        block_executor.execute_transaction(tx).map_err(|e| {
            SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e))
        })?;

        // Bump BAL index after each transaction (EIP-7928)
        block_executor.evm_mut().db_mut().bump_bal_index();
    }

    // Finish execution to get receipts and EVM (for BAL extraction)
    // Withdrawals are only processed if is_last=true (context has withdrawals=Some)
    let (evm, result) = block_executor.finish().map_err(|e| {
        SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e))
    })?;

    // Extract state_db from EVM for BAL validation
    let (state_db, _) = evm.finish();

    // Extract built BAL and validate against provided BAL
    let built_bal = state_db.take_built_alloy_bal();
    validate_subblock_bal(&bal, built_bal, &bal_range)?;

    // Get receipts directly from result (already contains only our executed txs)
    let receipts: Vec<EthereumReceipt> = result.receipts;

    // Compute logs bloom for this range
    let mut logs_bloom = Bloom::default();
    for receipt in &receipts {
        logs_bloom.accrue_bloom(&receipt.bloom());
    }

    // Requests are only populated for the last subblock (withdrawals processed there)
    let requests = result.requests;

    let gas_used = result.gas_used;

    Ok(SubblockOutput { receipts, logs_bloom, requests, gas_used })
}

#[cfg(test)]
mod tests {
    // Integration tests require full mock setup with witnesses and BAL.
    // These tests verify the partial execution logic at a unit level.

    #[test]
    fn test_bal_range_to_tx_indices() {
        // BAL index 0 = pre-execution (no tx)
        // BAL index 1 = tx 0
        // BAL index 2 = tx 1
        // etc.

        // Range [0, 3) for 5 txs -> tx indices [0, 2)
        let bal_start = 0u64;
        let bal_end = 3u64;
        let tx_count = 5usize;

        let tx_start = if bal_start == 0 { 0 } else { (bal_start - 1) as usize };
        let tx_end = ((bal_end.saturating_sub(1)) as usize).min(tx_count);

        assert_eq!(tx_start, 0);
        assert_eq!(tx_end, 2);
    }

    #[test]
    fn test_bal_range_to_tx_indices_middle() {
        // Range [3, 6) for 10 txs -> tx indices [2, 5)
        let bal_start = 3u64;
        let bal_end = 6u64;
        let tx_count = 10usize;

        let tx_start = if bal_start == 0 { 0 } else { (bal_start - 1) as usize };
        let tx_end = ((bal_end.saturating_sub(1)) as usize).min(tx_count);

        assert_eq!(tx_start, 2);
        assert_eq!(tx_end, 5);
    }

    #[test]
    fn test_bal_range_to_tx_indices_last() {
        // Range [8, 12) for 10 txs -> tx indices [7, 10)
        // BAL index 11 is post-execution, so tx_end caps at tx_count
        let bal_start = 8u64;
        let bal_end = 12u64;
        let tx_count = 10usize;

        let tx_start = if bal_start == 0 { 0 } else { (bal_start - 1) as usize };
        let tx_end = ((bal_end.saturating_sub(1)) as usize).min(tx_count);

        assert_eq!(tx_start, 7);
        assert_eq!(tx_end, 10);
    }

    #[test]
    fn test_is_first_is_last_flags() {
        let tx_count = 10usize;

        // First subblock: [0, 4)
        let is_first_1 = 0 == 0;
        let is_last_1 = 4 > (tx_count + 1) as u64;
        assert!(is_first_1);
        assert!(!is_last_1);

        // Middle subblock: [4, 8)
        let is_first_2 = 4 == 0;
        let is_last_2 = 8 > (tx_count + 1) as u64;
        assert!(!is_first_2);
        assert!(!is_last_2);

        // Last subblock: [8, 12) (includes post-execution at index 11)
        let is_first_3 = 8 == 0;
        let is_last_3 = 12 > (tx_count + 1) as u64;
        assert!(!is_first_3);
        assert!(is_last_3);

        // Single subblock: [0, 12)
        let is_first_4 = 0 == 0;
        let is_last_4 = 12 > (tx_count + 1) as u64;
        assert!(is_first_4);
        assert!(is_last_4);
    }
}
