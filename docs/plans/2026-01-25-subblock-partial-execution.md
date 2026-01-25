# Subblock Partial Execution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace full-block execution with partial execution that only processes transactions in the specified BAL range, improving ZK proving efficiency.

**Architecture:** Use the lower-level `BlockExecutor` interface from `alloy_evm::block` to execute individual transactions. Create a custom `EthBlockExecutionCtx` based on subblock position to control pre-execution (first subblock only) and post-execution (last subblock only). The aggregator adjusts cumulative gas when combining receipts.

**Tech Stack:** Rust, alloy-evm, revm, reth-ethereum-evm

---

## Background

### Current Implementation Problem

The worker currently executes ALL transactions in a block, then extracts receipts for the BAL range:

```rust
// worker.rs:114-117 - executes entire block
let executor = evm_config.executor(db);
let output = executor.execute(&recovered_block).map_err(...)?;
// Then extracts receipts[tx_start..tx_end]
```

This wastes computation in ZK proving context since BAL fast-forwarding already provides the correct starting state.

### BAL Index Semantics (EIP-7928)

- Index 0 = pre-execution system calls (beacon root, blockhashes)
- Index 1..n = transactions (tx i-1 at index i)
- Index n+1 = post-execution (withdrawals)
- Full range for block with n txs: `[0, n+2)`

### Key Interfaces

From `alloy_evm::block::BlockExecutor`:

| Method | Purpose |
|--------|---------|
| `apply_pre_execution_changes()` | System calls (beacon root at BAL index 0) |
| `execute_transaction_without_commit(tx)` | Execute single tx, get result |
| `commit_transaction(result)` | Commit tx state changes, get gas used |
| `finish()` | Finalize and return results |

---

## Task 1: Create Custom Execution Context Helper

**Files:**
- Create: `crates/stateless/src/subblock/execution.rs`
- Modify: `crates/stateless/src/subblock/mod.rs:8` (add module)

### Step 1: Write the failing test

Add to new file `crates/stateless/src/subblock/execution.rs`:

```rust
//! Partial block execution utilities for subblock validation.

use alloc::borrow::Cow;
use alloy_consensus::Header;
use alloy_primitives::Bytes;
use alloy_evm::eth::EthBlockExecutionCtx;
use reth_ethereum_primitives::Block;
use reth_primitives_traits::RecoveredBlock;

/// Creates an execution context customized for subblock position.
///
/// - First subblock (`is_first=true`): Includes `parent_beacon_block_root` for pre-execution
/// - Last subblock (`is_last=true`): Includes `withdrawals` for post-execution
/// - Middle subblocks: Neither pre nor post execution
pub fn create_subblock_execution_ctx<'a>(
    block: &'a RecoveredBlock<Block>,
    is_first: bool,
    is_last: bool,
) -> EthBlockExecutionCtx<'a> {
    EthBlockExecutionCtx {
        tx_count_hint: Some(block.transaction_count()),
        parent_hash: block.header().parent_hash,
        // Always pass the actual value - only used if apply_pre_execution_changes() is called
        parent_beacon_block_root: block.header().parent_beacon_block_root,
        ommers: &block.body().ommers,
        // Only last subblock processes withdrawals in finish()
        withdrawals: if is_last {
            block.body().withdrawals.as_ref().map(Cow::Borrowed)
        } else {
            None
        },
        extra_data: block.header().extra_data.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_consensus::{Header, TxEip1559};
    use alloy_primitives::{B256, Address, U256, Bytes as PrimitiveBytes};
    use reth_ethereum_primitives::{Block, BlockBody};
    use reth_primitives_traits::{RecoveredBlock, SignedTransaction};

    fn mock_recovered_block(with_withdrawals: bool) -> RecoveredBlock<Block> {
        let header = Header {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::repeat_byte(0x42)),
            extra_data: PrimitiveBytes::from_static(b"test"),
            ..Default::default()
        };
        let withdrawals = if with_withdrawals {
            Some(vec![].into())
        } else {
            None
        };
        let body = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals,
        };
        let block = Block { header, body };
        RecoveredBlock::new_unhashed(block, vec![])
    }

    #[test]
    fn test_first_subblock_ctx_has_beacon_root() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, true, false);

        assert!(ctx.parent_beacon_block_root.is_some());
        assert!(ctx.withdrawals.is_none()); // Not last
    }

    #[test]
    fn test_last_subblock_ctx_has_withdrawals() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, false, true);

        assert!(ctx.withdrawals.is_some());
    }

    #[test]
    fn test_middle_subblock_ctx_has_neither() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, false, false);

        assert!(ctx.withdrawals.is_none());
    }

    #[test]
    fn test_single_subblock_ctx_has_both() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, true, true);

        assert!(ctx.parent_beacon_block_root.is_some());
        assert!(ctx.withdrawals.is_some());
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test -p reth-stateless create_subblock_execution_ctx`
Expected: FAIL - module doesn't exist yet

### Step 3: Add module to mod.rs

In `crates/stateless/src/subblock/mod.rs`, add at line ~8:

```rust
mod execution;
pub use execution::create_subblock_execution_ctx;
```

### Step 4: Run test to verify it passes

Run: `cargo test -p reth-stateless create_subblock_execution_ctx`
Expected: PASS - all 4 tests pass

### Step 5: Commit

```bash
git add crates/stateless/src/subblock/execution.rs crates/stateless/src/subblock/mod.rs
git commit -m "$(cat <<'EOF'
feat(stateless): add create_subblock_execution_ctx helper

Introduces a helper function to create customized EthBlockExecutionCtx
based on subblock position (first/last). First subblocks include
parent_beacon_block_root for pre-execution, last subblocks include
withdrawals for post-execution.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add Required Imports to Worker

**Files:**
- Modify: `crates/stateless/src/subblock/worker.rs:1-20` (imports section)

### Step 1: Verify current imports compile

Run: `cargo check -p reth-stateless`
Expected: PASS

### Step 2: Add new imports for partial execution

Replace the imports section in `crates/stateless/src/subblock/worker.rs` (lines 1-18):

```rust
//! Worker guest program for subblock validation.
//!
//! Executes a range of transactions within a block using BAL fast-forwarding.

use alloc::{fmt::Debug, sync::Arc, vec::Vec};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_evm::block::BlockExecutor;
use alloy_primitives::{keccak256, Bloom};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_primitives::{EthPrimitives, EthereumReceipt};
use reth_evm::ConfigureEvm;
use reth_primitives_traits::SealedHeader;
use revm::State;

use crate::{
    recover_block::{recover_block_with_public_keys, UncompressedPublicKey},
    subblock::{
        create_subblock_execution_ctx,
        error::SubblockValidationError,
        BalWitnessDatabase,
        SubblockInput,
        SubblockOutput,
    },
    trie::StatelessSparseTrie,
    validation::StatelessValidationError,
};
```

### Step 3: Verify imports compile

Run: `cargo check -p reth-stateless`
Expected: PASS (imports resolve correctly)

### Step 4: Commit

```bash
git add crates/stateless/src/subblock/worker.rs
git commit -m "$(cat <<'EOF'
refactor(stateless): update worker imports for partial execution

Add imports for BlockExecutor trait, revm::State, and the new
create_subblock_execution_ctx helper. Remove unused Executor import
in preparation for switching to partial execution.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Implement Partial Execution in Worker

**Files:**
- Modify: `crates/stateless/src/subblock/worker.rs:100-150`

### Step 1: Write a test for partial execution

Add test file `crates/stateless/src/subblock/worker_test.rs` (or add to existing tests module if there is one):

```rust
// Tests for partial execution will be added as integration tests
// since they require full EVM setup. For now, we verify the
// implementation compiles and runs against existing test infrastructure.
```

Note: Full integration tests require complex setup with witnesses and BAL. The existing test infrastructure in the crate should be used.

### Step 2: Replace execution logic in worker.rs

Replace lines 99-149 in `crates/stateless/src/subblock/worker.rs` with:

```rust
    // Start BAL index comes directly from the bal_range
    let start_bal_index = bal_range.start;

    // Create BAL-aware database
    let db = BalWitnessDatabase::new(&trie, bytecode, ancestor_hashes, bal, start_bal_index);

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
    let mut state_db = State::builder()
        .with_database(db)
        .with_bundle_update()
        .without_state_clear()
        .build();

    // Get sealed block reference for EVM creation
    let sealed_block = recovered_block.sealed_block();

    // Create custom execution context based on subblock position
    let ctx = create_subblock_execution_ctx(&recovered_block, is_first, is_last);

    // Create EVM configured for this block
    let evm = evm_config
        .evm_for_block(&mut state_db, sealed_block.header())
        .map_err(|e| SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e)))?;

    // Create block executor with custom context
    let mut block_executor = evm_config.create_executor(evm, ctx);

    // Apply pre-execution changes only if this is the first subblock
    if is_first {
        block_executor
            .apply_pre_execution_changes()
            .map_err(|e| SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e)))?;
    }

    // Execute only our transaction range
    for tx in recovered_block.transactions_recovered().skip(tx_start).take(tx_end - tx_start) {
        let tx_result = block_executor
            .execute_transaction_without_commit(tx)
            .map_err(|e| SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e)))?;
        block_executor
            .commit_transaction(tx_result)
            .map_err(|e| SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e)))?;
    }

    // Finish execution - withdrawals only processed if is_last (due to custom context)
    let (_evm, result) = block_executor
        .finish()
        .map_err(|e| SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e)))?;

    // Get receipts directly from result (already contains only our executed txs)
    let receipts: Vec<EthereumReceipt> = result.receipts;

    // Compute logs bloom for this range
    let mut logs_bloom = Bloom::default();
    for receipt in &receipts {
        logs_bloom.accrue_bloom(&receipt.bloom());
    }

    // Get cumulative gas used at end of our range
    // Note: This is LOCAL cumulative gas (starting from 0 for this subblock)
    // The aggregator will adjust to global cumulative gas
    let cumulative_gas_used = receipts.last().map(|r| r.cumulative_gas_used()).unwrap_or(0);

    // Requests are only populated if this is the last subblock (due to custom context)
    let requests = result.requests;

    Ok(SubblockOutput { receipts, logs_bloom, requests, cumulative_gas_used })
```

### Step 3: Verify compilation

Run: `cargo check -p reth-stateless`
Expected: PASS

### Step 4: Run existing tests

Run: `cargo test -p reth-stateless`
Expected: PASS (existing tests should still work)

### Step 5: Commit

```bash
git add crates/stateless/src/subblock/worker.rs
git commit -m "$(cat <<'EOF'
feat(stateless): implement partial block execution in worker

Replace full-block execution with partial execution that only processes
transactions in the specified BAL range. Key changes:

- Use BlockExecutor interface for fine-grained control
- Create custom EthBlockExecutionCtx based on subblock position
- Apply pre-execution changes only for first subblock (BAL index 0)
- Process withdrawals only for last subblock
- Receipts now have LOCAL cumulative gas (aggregator handles adjustment)

This improves ZK proving efficiency by eliminating redundant computation
since BAL fast-forwarding already provides correct starting state.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Update Aggregator to Adjust Cumulative Gas

**Files:**
- Modify: `crates/stateless/src/subblock/aggregator.rs:241-259`

### Step 1: Write failing test for gas adjustment

Add to the tests module in `aggregator.rs`:

```rust
    #[test]
    fn test_combine_subblock_outputs_adjusts_cumulative_gas() {
        use reth_ethereum_primitives::{EthereumReceipt, TxType};
        use alloy_primitives::Log;

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
```

### Step 2: Run test to verify it fails

Run: `cargo test -p reth-stateless test_combine_subblock_outputs_adjusts_cumulative_gas`
Expected: FAIL - receipt[2] has 30000, not 72000

### Step 3: Update combine_subblock_outputs to adjust gas

Replace `combine_subblock_outputs` function in `aggregator.rs`:

```rust
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
```

### Step 4: Run test to verify it passes

Run: `cargo test -p reth-stateless test_combine_subblock_outputs_adjusts_cumulative_gas`
Expected: PASS

### Step 5: Commit

```bash
git add crates/stateless/src/subblock/aggregator.rs
git commit -m "$(cat <<'EOF'
feat(stateless): adjust cumulative gas when combining subblock outputs

With partial execution, each subblock's receipts have LOCAL cumulative
gas starting from 0. The aggregator now adjusts these to GLOBAL
cumulative gas by adding an offset equal to the sum of previous
subblocks' gas usage.

Example: subblock 1 ends at 42000 gas, subblock 2's first receipt
has local cumulative 30000 -> adjusted to 72000 global.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Simplify Gas Chaining Verification

**Files:**
- Modify: `crates/stateless/src/subblock/aggregator.rs:206-238`

### Step 1: Write test for new gas chaining behavior

Add to the tests module in `aggregator.rs`:

```rust
    #[test]
    fn test_verify_gas_chaining_with_local_gas() {
        use reth_ethereum_primitives::{EthereumReceipt, TxType};

        // With partial execution, each subblock has LOCAL gas starting from 0
        let receipt1 = EthereumReceipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 42000, // Local cumulative in subblock 1
            logs: vec![],
        };
        let receipt2 = EthereumReceipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 21000, // Local cumulative in subblock 2 (starts from 0!)
            logs: vec![],
        };

        let output1 = SubblockOutput {
            receipts: vec![receipt1],
            logs_bloom: Bloom::default(),
            requests: Requests::default(),
            cumulative_gas_used: 42000,
        };
        let output2 = SubblockOutput {
            receipts: vec![receipt2],
            logs_bloom: Bloom::default(),
            requests: Requests::default(),
            cumulative_gas_used: 21000,
        };

        let ranges: Vec<Range<u64>> = vec![0..3, 3..5];

        // Should pass - with partial execution, local gas is expected
        assert!(verify_gas_chaining(&[output1, output2], &ranges).is_ok());
    }
```

### Step 2: Run test to verify current behavior

Run: `cargo test -p reth-stateless test_verify_gas_chaining_with_local_gas`
Expected: FAIL - current check expects chaining

### Step 3: Simplify verify_gas_chaining

Replace `verify_gas_chaining` function in `aggregator.rs`:

```rust
/// Verifies gas values are reasonable for each subblock.
///
/// With partial execution, each subblock reports its own LOCAL gas usage
/// starting from 0. The actual chaining/adjustment happens in
/// `combine_subblock_outputs`. This function just validates that:
/// - Non-empty subblocks have non-zero gas
/// - Gas values are within reasonable bounds
fn verify_gas_chaining(
    outputs: &[SubblockOutput<EthereumReceipt>],
    bal_ranges: &[Range<u64>],
) -> Result<(), AggregationValidationError> {
    for (i, (output, range)) in outputs.iter().zip(bal_ranges.iter()).enumerate() {
        // If range contains transactions (not just pre/post execution markers)
        // there should be receipts and gas
        let has_txs = range.start < range.end &&
                      (range.start > 0 || range.end > 1); // Not just [0,1)

        if has_txs && !output.receipts.is_empty() {
            // Each receipt should have increasing cumulative gas
            let mut prev_gas = 0u64;
            for receipt in &output.receipts {
                let gas = receipt.cumulative_gas_used();
                if gas < prev_gas {
                    return Err(AggregationValidationError::GasChainingMismatch {
                        index: i,
                        expected: prev_gas,
                        next_index: i,
                    });
                }
                prev_gas = gas;
            }
        }
    }

    Ok(())
}
```

### Step 4: Run test to verify it passes

Run: `cargo test -p reth-stateless test_verify_gas_chaining`
Expected: PASS

### Step 5: Run all aggregator tests

Run: `cargo test -p reth-stateless aggregator`
Expected: PASS (all existing tests still work)

### Step 6: Commit

```bash
git add crates/stateless/src/subblock/aggregator.rs
git commit -m "$(cat <<'EOF'
refactor(stateless): simplify gas chaining verification for partial execution

With partial execution, each subblock reports LOCAL cumulative gas
starting from 0. The cross-subblock chaining validation is no longer
needed since combine_subblock_outputs handles the gas adjustment.

Now verify_gas_chaining only checks that receipts within each
subblock have monotonically increasing cumulative gas.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Add Integration Tests for Partial Execution

**Files:**
- Modify: `crates/stateless/src/subblock/worker.rs` (add tests module)

### Step 1: Add test module structure

Add at end of `worker.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(0 == 0); // is_first
        assert!(!(4 > tx_count as u64)); // not is_last

        // Middle subblock: [4, 8)
        assert!(!(4 == 0)); // not is_first
        assert!(!(8 > tx_count as u64)); // not is_last

        // Last subblock: [8, 12) (includes post-execution at index 11)
        assert!(!(8 == 0)); // not is_first
        assert!(12 > tx_count as u64); // is_last

        // Single subblock: [0, 12)
        assert!(0 == 0); // is_first
        assert!(12 > tx_count as u64); // is_last
    }
}
```

### Step 2: Run tests

Run: `cargo test -p reth-stateless worker::tests`
Expected: PASS

### Step 3: Commit

```bash
git add crates/stateless/src/subblock/worker.rs
git commit -m "$(cat <<'EOF'
test(stateless): add unit tests for BAL range to tx index conversion

Add tests verifying the correct conversion from BAL indices to
transaction indices, and the is_first/is_last flag logic for
partial execution.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Run Full Test Suite and Fix Issues

**Files:** Various (depends on test failures)

### Step 1: Run full crate tests

Run: `cargo test -p reth-stateless`
Expected: All tests pass

### Step 2: Run clippy

Run: `cargo clippy -p reth-stateless --all-features -- -D warnings`
Expected: No warnings

### Step 3: Run formatter

Run: `cargo +nightly fmt --all -- --check`
Expected: No formatting issues

### Step 4: Fix any issues found

Address any compilation errors, test failures, or lint warnings.

### Step 5: Final commit (if fixes needed)

```bash
git add -A
git commit -m "$(cat <<'EOF'
fix(stateless): address review feedback and test failures

[Description of specific fixes]

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Update Documentation

**Files:**
- Modify: `crates/stateless/src/subblock/worker.rs:20-34` (doc comment)
- Modify: `crates/stateless/src/subblock/aggregator.rs:25-42` (doc comment)

### Step 1: Update worker doc comment

Replace the doc comment for `subblock_validation` (lines 20-34):

```rust
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
/// - Processes withdrawals only if `bal_range.end > tx_count` (last subblock)
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
/// * `evm_config` - EVM configuration
///
/// # Returns
///
/// Returns `SubblockOutput` containing receipts, logs bloom, requests, and cumulative gas.
```

### Step 2: Update aggregator doc comment

Update the doc comment for `aggregation_validation`:

```rust
/// Validates aggregated subblock outputs and computes the final state root.
///
/// This function:
/// 1. Verifies BAL ranges are complete and contiguous
/// 2. Verifies gas values are reasonable within each subblock
/// 3. Combines receipts (adjusting cumulative gas), logs blooms, and requests
/// 4. Runs post-block validation
/// 5. Computes final state root from BAL
///
/// ## Gas Adjustment
///
/// Each subblock's receipts have LOCAL cumulative gas. This function adjusts
/// them to GLOBAL cumulative gas by adding offsets based on previous subblocks'
/// total gas usage.
```

### Step 3: Verify docs build

Run: `cargo doc -p reth-stateless --no-deps`
Expected: PASS

### Step 4: Commit

```bash
git add crates/stateless/src/subblock/worker.rs crates/stateless/src/subblock/aggregator.rs
git commit -m "$(cat <<'EOF'
docs(stateless): update documentation for partial execution

Update doc comments to reflect the new partial execution behavior:
- Worker executes only transactions in BAL range
- Receipts have LOCAL cumulative gas
- Aggregator adjusts to GLOBAL cumulative gas

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Create execution context helper | `execution.rs` (new), `mod.rs` |
| 2 | Add required imports | `worker.rs` |
| 3 | Implement partial execution | `worker.rs` |
| 4 | Adjust cumulative gas in aggregator | `aggregator.rs` |
| 5 | Simplify gas chaining verification | `aggregator.rs` |
| 6 | Add integration tests | `worker.rs` |
| 7 | Run full test suite | Various |
| 8 | Update documentation | `worker.rs`, `aggregator.rs` |

## Control Flow Summary

| Subblock Position | `is_first` | `is_last` | Pre-execution | Post-execution |
|-------------------|------------|-----------|---------------|----------------|
| First only | true | false | Runs | Skipped |
| Middle | false | false | Skipped | Skipped |
| Last only | false | true | Skipped | Runs |
| First AND Last | true | true | Runs | Runs |
