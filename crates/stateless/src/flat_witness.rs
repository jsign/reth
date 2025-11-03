//! Flat execution witness for stateless block validation.
//!
//! This module provides a simplified witness structure containing the minimal state
//! data required for stateless execution of a block. The "flat" representation stores
//! state directly in a cache rather than as a Merkle proof, optimizing for execution
//! speed. This is useful if the flat execution witness is later cryptographically proven
//! correct in an independent proof.

use core::error;

use alloc::collections::btree_map::BTreeMap;
use alloc::{collections::btree_set::BTreeSet, fmt};
use alloy_primitives::{Address, Bytes, StorageValue, B256, U256};
use reth_execution_types::FlatPreState;
use reth_revm::db::DbAccount;
use reth_revm::{
    db::{Cache, CacheDB, DBErrorMarker},
    primitives::StorageKey,
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};

/// A flat execution witness containing the state and context needed for stateless block execution.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FlatExecutionWitness {
    /// The state required for executing the block.
    pub pre_state: FlatPreState,
    /// The block hashes required for executing the block.
    pub block_hashes: BTreeMap<U256, B256>,
    /// The parent block header required for pre-execution validations.
    pub parent_header: Bytes,
}

impl FlatExecutionWitness {
    /// Creates a new flat execution witness from state components.
    pub const fn new(
        pre_state: FlatPreState,
        block_hashes: BTreeMap<U256, B256>,
        parent_header: Bytes,
    ) -> Self {
        Self { pre_state, block_hashes, parent_header }
    }

    /// Creates a cached database from the witness state.
    ///
    /// Returns a `CacheDB` backed by `FailingDB`, which ensures all state must come from the
    /// cache. Any cache miss results in an error, enforcing stateless execution constraints.
    // pub fn create_db(self) -> CacheDB<reth_revm::db::EmptyDB> {
    pub fn create_db(self) -> CacheDB<SelfDestructCompatibleFailingDB> {
        CacheDB {
            cache: Cache {
                accounts: self
                    .pre_state
                    .accounts
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            DbAccount {
                                account_state: v.account_state,
                                info: v.info,
                                storage: v.storage.into_iter().collect(),
                            },
                        )
                    })
                    .collect(),
                contracts: self
                    .pre_state
                    .contracts
                    .into_iter()
                    .map(|(k, v)| (k, Bytecode::new_raw(v)))
                    .collect(),
                block_hashes: self.block_hashes.into_iter().collect(),
                logs: Default::default(),
            },
            db: SelfDestructCompatibleFailingDB::new(self.pre_state.destructed_addresses),
        }
    }
}

/// Database backend that fails on all accesses except storage reads from self-destructed accounts.
///
/// This enforces that all state accesses during execution must be present in the cache. Cache
/// misses indicate missing witness data and must fail, since only cached accesses are
/// cryptographically verified against the trie witness proof. Returning default values would bypass
/// verification.
///
/// **Exception: Self-destructed account storage**
///
/// Storage reads from self-destructed accounts return zero (`Default::default()`) on cache miss.
/// This is safe because the trie witness includes complete storage tries for self-destructed
/// accounts, not just accessed slots—allowing any non-existent slot to be proven as zero. This
/// behavior matches the witness generation in `TrieWitness::get_proof_targets` and compensates for
/// `StateDB` not tracking individual storage accesses of self-destructed accounts.
#[derive(Debug, Clone)]
pub struct SelfDestructCompatibleFailingDB {
    destructed_addresses: BTreeSet<Address>,
}

impl SelfDestructCompatibleFailingDB {
    /// Creates a new instance with the given set of self-destructed addresses.
    pub const fn new(destructed_addresses: BTreeSet<Address>) -> Self {
        Self { destructed_addresses }
    }
}

/// Error indicating that a database access was attempted outside the captured state.
#[derive(Debug)]
pub struct NonCapturedStateError;

impl fmt::Display for NonCapturedStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Database access not allowed in stateless execution context")
    }
}

impl error::Error for NonCapturedStateError {}
impl DBErrorMarker for NonCapturedStateError {}

impl DatabaseRef for SelfDestructCompatibleFailingDB {
    type Error = NonCapturedStateError;

    fn basic_ref(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Err(NonCapturedStateError)
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Err(NonCapturedStateError)
    }

    fn storage_ref(
        &self,
        _address: Address,
        _index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        if self.destructed_addresses.contains(&_address) {
            return Ok(Default::default());
        }
        Err(NonCapturedStateError)
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        Err(NonCapturedStateError)
    }
}
