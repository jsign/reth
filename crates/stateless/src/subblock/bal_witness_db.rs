//! BAL-aware witness database for subblock execution.
//!
//! Wraps the stateless trie with `BalState` to support BAL fast-forwarding.
//!
//! # Layered Database Approach
//!
//! This database combines two data sources:
//!
//! 1. **Pre-state from the witness trie**: The original state before block execution
//! 2. **Fast-forwarded state from the BAL**: State changes up to the current BAL index
//!
//! # Lookup Priority
//!
//! For each database operation, the BAL is checked first:
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │  Database Request (address, slot, etc.) │
//! └──────────────────┬──────────────────────┘
//!                    │
//!        ┌───────────▼───────────┐
//!        │  Check BalState       │
//!        │  (at current index)   │
//!        └───────────┬───────────┘
//!                    │
//!           Has value at bal_index?
//!          /                      \
//!        Yes                       No
//!          │                        │
//!   Return BAL value         Query StatelessTrie
//!   (fast-forwarded)          (pre-state)
//! ```
//!
//! This allows subblocks to "see" the correct state at their starting BAL index
//! without re-executing prior transactions.

use alloc::{collections::btree_map::BTreeMap, format, sync::Arc};
use alloy_primitives::{map::B256Map, Address, B256, U256};
use reth_errors::ProviderError;
use reth_revm::{bytecode::Bytecode, state::AccountInfo, Database};
use revm_database_interface::bal::{BalState, EvmDatabaseError};
use revm_state::bal::Bal;

use crate::trie::StatelessTrie;

/// A witness database wrapped with BAL support for fast-forwarding state.
///
/// This combines `WitnessDatabase` functionality with `BalState` to allow
/// reading state at any transaction index using BAL.
#[derive(Debug)]
pub(crate) struct BalWitnessDatabase<'a, T>
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
    /// * `start_bal_index` - The BAL index to start at per EIP-7928 (0 for pre-execution, N for tx
    ///   N-1)
    pub(crate) fn new(
        trie: &'a T,
        bytecode: B256Map<Bytecode>,
        ancestor_hashes: BTreeMap<u64, B256>,
        bal: Arc<Bal>,
        start_bal_index: u64,
    ) -> Self {
        let mut bal_state = BalState::new().with_bal(bal);
        bal_state.bal_index = start_bal_index;

        Self { block_hashes_by_block_number: ancestor_hashes, bytecode, trie, bal_state }
    }

    /// Bump the BAL index after executing a transaction or system call.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn bump_bal_index(&mut self) {
        self.bal_state.bump_bal_index();
    }

    /// Get the current BAL index.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn bal_index(&self) -> u64 {
        self.bal_state.bal_index()
    }

    /// Set the BAL index directly.
    #[inline]
    #[allow(dead_code)]
    pub(crate) const fn set_bal_index(&mut self, index: u64) {
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
        if let Some(value) = self.bal_state.storage(&address, slot)? {
            return Ok(value);
        }

        // Fall back to trie
        self.trie.storage(address, slot).map_err(EvmDatabaseError::Database)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.bytecode.get(&code_hash).cloned().ok_or_else(|| {
            EvmDatabaseError::Database(ProviderError::TrieWitnessError(format!(
                "bytecode for {code_hash} not found"
            )))
        })
    }

    fn block_hash(&mut self, block_number: u64) -> Result<B256, Self::Error> {
        self.block_hashes_by_block_number.get(&block_number).copied().ok_or_else(|| {
            EvmDatabaseError::Database(ProviderError::StateForNumberNotFound(block_number))
        })
    }
}
