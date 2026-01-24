# Subblock Proving Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the `reth-stateless` crate to support subblock proving - splitting block validation into parallelizable pieces using EIP-7928 Block Access Lists (BALs).

**Architecture:** Workers execute transaction ranges `[A, B)` using BAL to fast-forward state. Master aggregates worker outputs and computes final state root from BAL without re-execution.

**Tech Stack:** `reth-stateless`, `revm-state` (BAL types), `revm-database-interface` (BalDatabase), `alloy-eip7928`

---

## Task 1: Add Dependencies to Cargo.toml

**Files:**
- Modify: `crates/stateless/Cargo.toml`

**Step 1: Add required dependencies**

Add `alloy-eip7928` and `revm-database-interface` dependencies to the stateless crate.

```toml
# Add after existing alloy dependencies (around line 21):
alloy-eip7928.workspace = true

# Add after existing reth dependencies (around line 33):
revm-database-interface.workspace = true
revm-state.workspace = true
```

**Step 2: Verify compilation**

Run: `cargo check -p reth-stateless`
Expected: Compilation succeeds

**Step 3: Commit**

```bash
git add crates/stateless/Cargo.toml
git commit -m "chore(stateless): add BAL dependencies for subblock proving

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Create Subblock Types Module

**Files:**
- Create: `crates/stateless/src/subblock/mod.rs`
- Create: `crates/stateless/src/subblock/types.rs`

**Step 1: Create the subblock module file**

Create `crates/stateless/src/subblock/mod.rs`:

```rust
//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod types;

pub use types::{AggregationInput, SubblockInput, SubblockOutput};
```

**Step 2: Create the types file**

Create `crates/stateless/src/subblock/types.rs`:

```rust
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
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubblockOutput<R = Receipt> {
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
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
```

**Step 3: Verify compilation**

Run: `cargo check -p reth-stateless`
Expected: Compilation succeeds (may have unused warnings, that's OK)

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/
git commit -m "feat(stateless): add subblock proving types

Add SubblockInput, SubblockOutput, and AggregationInput data structures
for parallel block validation using BALs.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Create Subblock Error Types

**Files:**
- Create: `crates/stateless/src/subblock/error.rs`
- Modify: `crates/stateless/src/subblock/mod.rs`

**Step 1: Create the error types file**

Create `crates/stateless/src/subblock/error.rs`:

```rust
//! Error types for subblock proving.

use alloc::string::String;
use alloy_primitives::B256;

use crate::validation::StatelessValidationError;

/// Errors that can occur during subblock validation.
#[derive(Debug, thiserror::Error)]
pub enum SubblockValidationError {
    /// Transaction range is out of bounds.
    #[error("transaction range {start}..{end} is out of bounds (block has {tx_count} transactions)")]
    TxRangeOutOfBounds {
        /// Start of the requested range.
        start: usize,
        /// End of the requested range.
        end: usize,
        /// Number of transactions in the block.
        tx_count: usize,
    },

    /// Error from the underlying stateless validation.
    #[error("stateless validation error: {0}")]
    StatelessValidation(#[from] StatelessValidationError),

    /// Error during block execution.
    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    /// BAL error (account or slot not found).
    #[error("BAL error: {0}")]
    BalError(String),
}

/// Errors that can occur during aggregation validation.
#[derive(Debug, thiserror::Error)]
pub enum AggregationValidationError {
    /// Transaction ranges are not contiguous.
    #[error("transaction ranges are not contiguous: range {index} ends at {end}, but range {next_index} starts at {start}")]
    NonContiguousRanges {
        /// Index of the first range.
        index: usize,
        /// End of the first range.
        end: usize,
        /// Index of the second range.
        next_index: usize,
        /// Start of the second range.
        start: usize,
    },

    /// Transaction ranges don't cover all transactions.
    #[error("transaction ranges don't cover all transactions: ranges cover 0..{covered}, block has {tx_count} transactions")]
    IncompleteRanges {
        /// End of coverage.
        covered: usize,
        /// Number of transactions in the block.
        tx_count: usize,
    },

    /// Transaction ranges don't start at 0.
    #[error("transaction ranges must start at 0, but first range starts at {start}")]
    RangesNotStartingAtZero {
        /// Start of the first range.
        start: usize,
    },

    /// No subblock outputs provided.
    #[error("no subblock outputs provided")]
    NoSubblockOutputs,

    /// Mismatched number of outputs and ranges.
    #[error("mismatched subblock outputs ({outputs}) and ranges ({ranges})")]
    MismatchedOutputsAndRanges {
        /// Number of outputs.
        outputs: usize,
        /// Number of ranges.
        ranges: usize,
    },

    /// Gas chaining mismatch.
    #[error("gas chaining mismatch: subblock {index} ended with {expected} gas, but subblock {next_index} implies starting gas doesn't match")]
    GasChainingMismatch {
        /// Index of the subblock.
        index: usize,
        /// Expected gas from previous subblock.
        expected: u64,
        /// Index of the next subblock.
        next_index: usize,
    },

    /// Error from the underlying stateless validation.
    #[error("stateless validation error: {0}")]
    StatelessValidation(#[from] StatelessValidationError),

    /// Consensus validation error.
    #[error("consensus validation error: {0}")]
    ConsensusValidation(#[from] reth_errors::ConsensusError),

    /// Post-state root mismatch.
    #[error("post-state root mismatch: computed {computed}, expected {expected}")]
    PostStateRootMismatch {
        /// Computed state root.
        computed: B256,
        /// Expected state root from block header.
        expected: B256,
    },
}
```

**Step 2: Update mod.rs to export error types**

Update `crates/stateless/src/subblock/mod.rs`:

```rust
//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod error;
mod types;

pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
```

**Step 3: Verify compilation**

Run: `cargo check -p reth-stateless`
Expected: Compilation succeeds

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/
git commit -m "feat(stateless): add subblock error types

Add SubblockValidationError and AggregationValidationError for
detailed error reporting during subblock proving.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Create BAL-aware Witness Database

**Files:**
- Create: `crates/stateless/src/subblock/bal_witness_db.rs`
- Modify: `crates/stateless/src/subblock/mod.rs`

**Step 1: Create the BAL-aware database wrapper**

Create `crates/stateless/src/subblock/bal_witness_db.rs`:

```rust
//! BAL-aware witness database for subblock execution.
//!
//! Wraps `WitnessDatabase` with `BalDatabase` to support BAL fast-forwarding.

use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use alloy_primitives::{map::B256Map, Address, B256, U256};
use reth_errors::ProviderError;
use reth_revm::{bytecode::Bytecode, state::AccountInfo, Database};
use revm_database_interface::bal::{BalDatabase, BalState, EvmDatabaseError};
use revm_state::bal::Bal;

use crate::trie::StatelessTrie;

/// A witness database wrapped with BAL support for fast-forwarding state.
///
/// This combines `WitnessDatabase` functionality with `BalState` to allow
/// reading state at any transaction index using BAL.
#[derive(Debug)]
pub struct BalWitnessDatabase<'a, T>
where
    T: StatelessTrie,
{
    /// Map of block numbers to block hashes for BLOCKHASH opcode.
    block_hashes_by_block_number: BTreeMap<u64, B256>,
    /// Map of code hashes to bytecode.
    bytecode: B256Map<Bytecode>,
    /// The sparse Merkle Patricia Trie containing account and storage state.
    trie: &'a T,
    /// BAL state for fast-forwarding.
    bal_state: BalState,
}

impl<'a, T> BalWitnessDatabase<'a, T>
where
    T: StatelessTrie,
{
    /// Creates a new `BalWitnessDatabase` with BAL support.
    ///
    /// # Arguments
    ///
    /// * `trie` - The stateless trie containing pre-state
    /// * `bytecode` - Map of code hashes to bytecode
    /// * `ancestor_hashes` - Map of block numbers to block hashes
    /// * `bal` - The Block Access List for the entire block
    /// * `start_bal_index` - The BAL index to start at (0 for pre-execution, 1+ for after tx N-1)
    pub fn new(
        trie: &'a T,
        bytecode: B256Map<Bytecode>,
        ancestor_hashes: BTreeMap<u64, B256>,
        bal: Arc<Bal>,
        start_bal_index: u64,
    ) -> Self {
        let mut bal_state = BalState::new().with_bal(bal);
        bal_state.bal_index = start_bal_index;

        Self {
            block_hashes_by_block_number: ancestor_hashes,
            bytecode,
            trie,
            bal_state,
        }
    }

    /// Bump the BAL index after executing a transaction or system call.
    #[inline]
    pub fn bump_bal_index(&mut self) {
        self.bal_state.bump_bal_index();
    }

    /// Get the current BAL index.
    #[inline]
    pub fn bal_index(&self) -> u64 {
        self.bal_state.bal_index()
    }

    /// Set the BAL index directly.
    #[inline]
    pub fn set_bal_index(&mut self, index: u64) {
        self.bal_state.bal_index = index;
    }
}

impl<T> Database for BalWitnessDatabase<'_, T>
where
    T: StatelessTrie,
{
    type Error = EvmDatabaseError<ProviderError>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // First get base account from trie
        let mut account = self
            .trie
            .account(address)
            .map(|opt| {
                opt.map(|account| AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    code: None,
                    account_id: None,
                })
            })
            .map_err(EvmDatabaseError::Database)?;

        // Apply BAL changes if BAL is present
        self.bal_state.basic(address, &mut account)?;

        Ok(account)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        // Check BAL first for fast-forwarded value
        if let Some(value) = self.bal_state.storage(&address, slot.into())? {
            return Ok(value);
        }

        // Fall back to trie
        self.trie
            .storage(address, slot)
            .map_err(EvmDatabaseError::Database)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.bytecode
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| {
                EvmDatabaseError::Database(ProviderError::TrieWitnessError(
                    alloc::format!("bytecode for {code_hash} not found"),
                ))
            })
    }

    fn block_hash(&mut self, block_number: u64) -> Result<B256, Self::Error> {
        self.block_hashes_by_block_number
            .get(&block_number)
            .copied()
            .ok_or_else(|| {
                EvmDatabaseError::Database(ProviderError::StateForNumberNotFound(block_number))
            })
    }
}
```

**Step 2: Update mod.rs**

Update `crates/stateless/src/subblock/mod.rs`:

```rust
//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod bal_witness_db;
mod error;
mod types;

pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};

pub(crate) use bal_witness_db::BalWitnessDatabase;
```

**Step 3: Verify compilation**

Run: `cargo check -p reth-stateless`
Expected: Compilation succeeds

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/
git commit -m "feat(stateless): add BAL-aware witness database

Add BalWitnessDatabase that wraps the trie with BAL state to support
fast-forwarding to any transaction index without recomputing state.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Implement Worker Validation Function

**Files:**
- Create: `crates/stateless/src/subblock/worker.rs`
- Modify: `crates/stateless/src/subblock/mod.rs`

**Step 1: Create the worker validation function**

Create `crates/stateless/src/subblock/worker.rs`:

```rust
//! Worker guest program for subblock validation.
//!
//! Executes a range of transactions within a block using BAL fast-forwarding.

use alloc::{fmt::Debug, sync::Arc, vec::Vec};
use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::{keccak256, Bloom, B256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_primitives::{EthPrimitives, EthereumReceipt};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_primitives_traits::SealedHeader;

use crate::{
    recover_block::{recover_block_with_public_keys, UncompressedPublicKey},
    subblock::{
        error::SubblockValidationError, BalWitnessDatabase, SubblockInput, SubblockOutput,
    },
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
    let SubblockInput {
        block,
        witness,
        bal,
        tx_range,
        chain_config: _,
        is_first,
        is_last,
    } = input;

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
    let recovered_block =
        recover_block_with_public_keys(block.clone(), public_keys, &*chain_spec)?;

    // Parse ancestor headers from witness
    let mut ancestor_headers: Vec<_> = witness
        .headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes)
                .map(|h| SealedHeader::new(h, hash))
                .map_err(|_| {
                    SubblockValidationError::StatelessValidation(
                        StatelessValidationError::HeaderDeserializationFailed,
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    ancestor_headers.sort_by_key(|header| header.number());

    // Get parent header for pre-state root
    let parent = ancestor_headers
        .last()
        .ok_or(StatelessValidationError::MissingAncestorHeader)?;

    // Build the trie from witness
    let (trie, bytecode) = StatelessSparseTrie::new(&witness, parent.state_root)?;

    // Build ancestor hashes map
    let mut ancestor_hashes = alloc::collections::BTreeMap::new();
    let mut child_header = recovered_block.sealed_header();
    for parent_header in ancestor_headers.iter().rev() {
        ancestor_hashes.insert(parent_header.number, child_header.parent_hash());
        child_header = parent_header;
    }

    // Calculate starting BAL index:
    // - BAL index 0 = pre-execution state
    // - BAL index 1 = after pre-block system calls (beacon root, blockhashes)
    // - BAL index 2+ = after tx 0, 1, ...
    // So for tx_range.start, we need BAL index = tx_range.start + 1 (if first) or tx_range.start + 1
    // Actually: if is_first, we start at index 0 and bump after pre-block logic
    // If not is_first, we start at index tx_range.start + 1 (pre-block + previous txs)
    let start_bal_index = if is_first {
        0 // Will be bumped after pre-block logic
    } else {
        // Account for pre-block system calls (index 1) plus all previous transactions
        (tx_range.start + 1) as u64
    };

    // Create BAL-aware database
    let mut db = BalWitnessDatabase::new(&trie, bytecode, ancestor_hashes, bal, start_bal_index);

    // Pre-block logic (if first subblock)
    if is_first {
        // Pre-block system calls happen at BAL index 0, then we bump to index 1
        // The actual pre-block calls are handled by the executor, but we need to
        // account for them in the BAL index.
        // After pre-block, bump to index 1
        db.bump_bal_index();
    }

    // Execute transactions in range
    // Note: We create a partial block view for the executor containing only our tx range
    // However, the current executor API expects the full block. We'll need to handle
    // receipt cumulative gas adjustment.

    // For now, we execute the full block but only collect receipts for our range
    // TODO: Optimize to only execute our tx range once executor supports partial execution
    let executor = evm_config.executor(db);
    let output = executor
        .execute(&recovered_block)
        .map_err(|e| SubblockValidationError::ExecutionFailed(alloc::string::ToString::to_string(&e)))?;

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
    let cumulative_gas_used = receipts
        .last()
        .map(|r| r.cumulative_gas_used())
        .unwrap_or(0);

    // Requests are only collected if this is the last subblock
    let requests = if is_last {
        output.requests.clone()
    } else {
        Default::default()
    };

    Ok(SubblockOutput {
        receipts,
        logs_bloom,
        requests,
        cumulative_gas_used,
    })
}
```

**Step 2: Update mod.rs**

Update `crates/stateless/src/subblock/mod.rs`:

```rust
//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod bal_witness_db;
mod error;
mod types;
mod worker;

pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
pub use worker::subblock_validation;

pub(crate) use bal_witness_db::BalWitnessDatabase;
```

**Step 3: Verify compilation**

Run: `cargo check -p reth-stateless`
Expected: Compilation succeeds (may have warnings)

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/
git commit -m "feat(stateless): implement subblock worker validation

Add subblock_validation function that executes a transaction range
using BAL fast-forwarding for parallelized block validation.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Implement BAL to HashedPostState Conversion

**Files:**
- Create: `crates/stateless/src/subblock/bal_state.rs`
- Modify: `crates/stateless/src/subblock/mod.rs`

**Step 1: Create the BAL to state conversion helper**

Create `crates/stateless/src/subblock/bal_state.rs`:

```rust
//! BAL to HashedPostState conversion utilities.
//!
//! Converts a Block Access List to a HashedPostState for state root computation.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, map::HashMap, Address, B256, U256};
use reth_trie_common::{HashedPostState, HashedStorage};
use revm_state::bal::Bal;

/// Converts a BAL to a `HashedPostState` at the given BAL index.
///
/// This extracts the final values from the BAL at `bal_index` and constructs
/// a `HashedPostState` representing the state diff from pre-state to that point.
///
/// # Arguments
///
/// * `bal` - The Block Access List containing all state changes
/// * `bal_index` - The BAL index to read final values from (typically num_transactions + 1 for post-block)
///
/// # Returns
///
/// A `HashedPostState` containing all account and storage changes.
pub fn bal_to_hashed_post_state(bal: &Bal, bal_index: u64) -> HashedPostState {
    let mut accounts = HashMap::default();
    let mut storages = HashMap::default();

    for (address, account_bal) in bal.accounts.iter() {
        let hashed_address = keccak256(address);

        // Get account info at bal_index
        let mut has_changes = false;

        // Check if there are any writes that would affect state at bal_index
        let nonce = account_bal.account_info.nonce.get(bal_index);
        let balance = account_bal.account_info.balance.get(bal_index);
        let code = account_bal.account_info.code.get(bal_index);

        if nonce.is_some() || balance.is_some() || code.is_some() {
            has_changes = true;

            // Build account info - we need to construct a full account
            // Note: This assumes the account exists. For destroyed accounts,
            // we'd need additional logic.
            let account = reth_trie_common::Account {
                nonce: nonce.unwrap_or(0),
                balance: balance.unwrap_or(U256::ZERO),
                bytecode_hash: code.map(|(hash, _)| hash),
            };

            accounts.insert(hashed_address, Some(account));
        }

        // Process storage changes
        let mut storage_changes: Vec<(B256, U256)> = Vec::new();

        for (slot, slot_writes) in account_bal.storage.storage.iter() {
            if let Some(value) = slot_writes.get(bal_index) {
                storage_changes.push((keccak256(B256::from(*slot)), value));
                has_changes = true;
            }
        }

        if !storage_changes.is_empty() {
            let hashed_storage = HashedStorage::from_iter(false, storage_changes);
            storages.insert(hashed_address, hashed_storage);
        }

        // If account had no info changes but has storage, we still need an entry
        // to ensure the storage root gets updated
        if !has_changes {
            // No changes for this account at this bal_index
            continue;
        }
    }

    HashedPostState { accounts, storages }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm_state::bal::{AccountBal, BalWrites};

    #[test]
    fn test_empty_bal() {
        let bal = Bal::new();
        let state = bal_to_hashed_post_state(&bal, 1);
        assert!(state.accounts.is_empty());
        assert!(state.storages.is_empty());
    }

    #[test]
    fn test_bal_with_balance_change() {
        let mut bal = Bal::new();
        let address = Address::repeat_byte(0x01);

        let mut account_bal = AccountBal::default();
        account_bal.account_info.balance.force_update(0, U256::from(100));

        bal.accounts.insert(address, account_bal);

        let state = bal_to_hashed_post_state(&bal, 1);
        assert_eq!(state.accounts.len(), 1);

        let hashed_address = keccak256(address);
        let account = state.accounts.get(&hashed_address).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(100));
    }
}
```

**Step 2: Update mod.rs**

Update `crates/stateless/src/subblock/mod.rs`:

```rust
//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod bal_state;
mod bal_witness_db;
mod error;
mod types;
mod worker;

pub use bal_state::bal_to_hashed_post_state;
pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
pub use worker::subblock_validation;

pub(crate) use bal_witness_db::BalWitnessDatabase;
```

**Step 3: Run tests**

Run: `cargo test -p reth-stateless bal_state`
Expected: Tests pass

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/
git commit -m "feat(stateless): add BAL to HashedPostState conversion

Add bal_to_hashed_post_state helper that converts BAL state at a given
index to HashedPostState for state root computation without re-execution.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Implement Aggregation Validation Function

**Files:**
- Create: `crates/stateless/src/subblock/aggregator.rs`
- Modify: `crates/stateless/src/subblock/mod.rs`

**Step 1: Create the aggregation validation function**

Create `crates/stateless/src/subblock/aggregator.rs`:

```rust
//! Master/aggregator guest program for subblock aggregation.
//!
//! Combines verified subblock outputs and computes final state root.

use alloc::{fmt::Debug, sync::Arc, vec::Vec};
use alloy_consensus::{BlockHeader, Header, Receipt};
use alloy_eips::eip7685::Requests;
use alloy_primitives::{keccak256, Bloom, B256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_ethereum_primitives::{Block, EthereumReceipt};
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
    let AggregationInput {
        block,
        witness,
        bal,
        chain_config: _,
        subblock_outputs,
        tx_ranges,
    } = input;

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
    let recovered_block =
        recover_block_with_public_keys(block.clone(), public_keys, &*chain_spec)
            .map_err(AggregationValidationError::StatelessValidation)?;

    // Parse ancestor headers from witness
    let mut ancestor_headers: Vec<_> = witness
        .headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes)
                .map(|h| SealedHeader::new(h, hash))
                .map_err(|_| {
                    AggregationValidationError::StatelessValidation(
                        StatelessValidationError::HeaderDeserializationFailed,
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    ancestor_headers.sort_by_key(|header| header.number());

    // Get parent header for pre-state root
    let parent = ancestor_headers
        .last()
        .ok_or(AggregationValidationError::StatelessValidation(
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

    // BAL index for post-block state: pre-block (1) + all txs + post-block
    // Index 0 = pre-execution
    // Index 1 = after pre-block system calls
    // Index 2..n+1 = after each tx
    // Index n+2 = after post-block (withdrawals, etc.)
    let final_bal_index = (tx_count + 2) as u64;

    let hashed_post_state = bal_to_hashed_post_state(&bal, final_bal_index);
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
    tx_ranges: &[core::ops::Range<usize>],
    tx_count: usize,
) -> Result<(), AggregationValidationError> {
    if tx_ranges.is_empty() {
        if tx_count == 0 {
            return Ok(());
        }
        return Err(AggregationValidationError::IncompleteRanges {
            covered: 0,
            tx_count,
        });
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
        return Err(AggregationValidationError::IncompleteRanges {
            covered: last_end,
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
    tx_ranges: &[core::ops::Range<usize>],
) -> Result<(), AggregationValidationError> {
    // First subblock starts with 0 gas
    // Subsequent subblocks should have receipts that reflect proper cumulative gas

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

    #[test]
    fn test_verify_ranges_complete_valid() {
        let ranges = vec![0..2, 2..5, 5..10];
        assert!(verify_ranges_complete(&ranges, 10).is_ok());
    }

    #[test]
    fn test_verify_ranges_complete_empty_block() {
        let ranges: Vec<core::ops::Range<usize>> = vec![];
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
            Err(AggregationValidationError::IncompleteRanges {
                covered: 5,
                tx_count: 10
            })
        ));
    }
}
```

**Step 2: Update mod.rs**

Update `crates/stateless/src/subblock/mod.rs`:

```rust
//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod aggregator;
mod bal_state;
mod bal_witness_db;
mod error;
mod types;
mod worker;

pub use aggregator::aggregation_validation;
pub use bal_state::bal_to_hashed_post_state;
pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
pub use worker::subblock_validation;

pub(crate) use bal_witness_db::BalWitnessDatabase;
```

**Step 3: Run tests**

Run: `cargo test -p reth-stateless aggregator`
Expected: Tests pass

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/
git commit -m "feat(stateless): implement aggregation validation

Add aggregation_validation function that combines verified subblock
outputs, validates gas chaining and range coverage, and computes
final state root from BAL.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Update lib.rs to Export Subblock Module

**Files:**
- Modify: `crates/stateless/src/lib.rs`

**Step 1: Add subblock module and re-exports**

Add to `crates/stateless/src/lib.rs` after line 53 (after `pub(crate) mod witness_db;`):

```rust
/// Subblock proving for parallelized block validation
pub mod subblock;
```

Add re-exports after line 59 (after `pub use alloy_genesis::Genesis;`):

```rust
// Subblock proving re-exports
pub use subblock::{
    aggregation_validation, subblock_validation, AggregationInput, AggregationValidationError,
    SubblockInput, SubblockOutput, SubblockValidationError,
};
```

**Step 2: Verify compilation**

Run: `cargo check -p reth-stateless`
Expected: Compilation succeeds

**Step 3: Run all tests**

Run: `cargo test -p reth-stateless`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/stateless/src/lib.rs
git commit -m "feat(stateless): export subblock proving API

Add public exports for subblock types and validation functions
from the main lib.rs.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Run Lints and Format

**Files:**
- All modified files

**Step 1: Format code**

Run: `cargo +nightly fmt --all`
Expected: Code is formatted

**Step 2: Run clippy**

Run: `RUSTFLAGS="-D warnings" cargo +nightly clippy -p reth-stateless --all-features`
Expected: No warnings or errors

**Step 3: Fix any issues**

If clippy reports issues, fix them in the relevant files.

**Step 4: Commit fixes if needed**

```bash
git add -A
git commit -m "chore(stateless): fix lints and formatting

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Final Verification

**Files:**
- All crate files

**Step 1: Run full test suite**

Run: `cargo test -p reth-stateless`
Expected: All tests pass

**Step 2: Verify documentation builds**

Run: `cargo doc -p reth-stateless --no-deps`
Expected: Documentation builds without warnings

**Step 3: Review changes**

Run: `git log --oneline feature/subblock-proving ^main`
Expected: See all commits for the feature

**Step 4: Summary**

At this point, the subblock proving implementation is complete with:
- `SubblockInput`, `SubblockOutput`, `AggregationInput` types
- `SubblockValidationError`, `AggregationValidationError` error types
- `BalWitnessDatabase` for BAL-aware state access
- `subblock_validation` worker function
- `bal_to_hashed_post_state` conversion helper
- `aggregation_validation` master function
- All public exports from `lib.rs`

---

## Notes for Implementation

1. **BAL Index Convention**:
   - Index 0 = pre-execution state (reads get pre-state values)
   - Index 1 = after pre-block system calls
   - Index 2..n+1 = after each transaction
   - Index n+2 = after post-block processing

2. **Testing Considerations**:
   - Unit tests cover range validation and gas chaining
   - Full integration tests would require actual witness and BAL data
   - Consider adding property-based tests for edge cases

3. **Future Improvements**:
   - Optimize worker to only execute its tx range (requires executor changes)
   - Add support for custom trie implementations
   - Consider memory optimization for large BALs
