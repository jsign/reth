use crate::{
    providers::state::macros::delegate_provider_impls, AccountReader, BlockHashReader,
    HashedPostStateProvider, StateProvider, StateRootProvider,
};
use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, StorageValue, B256, U256};
use reth_db::cursor::DbCursorRO;
use reth_db_api::{cursor::DbDupCursorRO, tables, transaction::DbTx};
use reth_execution_types::{AccessedAccount, FlatPreState, FlatWitnessRecord};
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{BytecodeReader, DBProvider, StateProofProvider, StorageRootProvider};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use reth_trie::{
    proof::{Proof, StorageProof},
    updates::TrieUpdates,
    witness::TrieWitness,
    AccountProof, HashedPostState, HashedStorage, KeccakKeyHasher, MultiProof, MultiProofTargets,
    StateRoot, StorageMultiProof, StorageRoot, TrieInput,
};
use reth_trie_db::{
    DatabaseProof, DatabaseStateRoot, DatabaseStorageProof, DatabaseStorageRoot,
    DatabaseTrieWitness,
};
use revm_database::DbAccount;

/// State provider over latest state that takes tx reference.
///
/// Wraps a [`DBProvider`] to get access to database.
#[derive(Debug)]
pub struct LatestStateProviderRef<'b, Provider>(&'b Provider);

impl<'b, Provider: DBProvider> LatestStateProviderRef<'b, Provider> {
    /// Create new state provider
    pub const fn new(provider: &'b Provider) -> Self {
        Self(provider)
    }

    fn tx(&self) -> &Provider::Tx {
        self.0.tx_ref()
    }
}

impl<Provider: DBProvider> AccountReader for LatestStateProviderRef<'_, Provider> {
    /// Get basic account information.
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.tx().get_by_encoded_key::<tables::PlainAccountState>(address).map_err(Into::into)
    }
}

impl<Provider: BlockHashReader> BlockHashReader for LatestStateProviderRef<'_, Provider> {
    /// Get block hash by number.
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.0.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.0.canonical_hashes_range(start, end)
    }
}

impl<Provider: DBProvider + Sync> StateRootProvider for LatestStateProviderRef<'_, Provider> {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        StateRoot::overlay_root(self.tx(), hashed_state)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        StateRoot::overlay_root_from_nodes(self.tx(), input)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        StateRoot::overlay_root_with_updates(self.tx(), hashed_state)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        StateRoot::overlay_root_from_nodes_with_updates(self.tx(), input)
            .map_err(|err| ProviderError::Database(err.into()))
    }
}

impl<Provider: DBProvider + Sync> StorageRootProvider for LatestStateProviderRef<'_, Provider> {
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        StorageRoot::overlay_root(self.tx(), address, hashed_storage)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<reth_trie::StorageProof> {
        StorageProof::overlay_storage_proof(self.tx(), address, slot, hashed_storage)
            .map_err(ProviderError::from)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        StorageProof::overlay_storage_multiproof(self.tx(), address, slots, hashed_storage)
            .map_err(ProviderError::from)
    }
}

impl<Provider: DBProvider + BlockHashReader + Sync> StateProofProvider
    for LatestStateProviderRef<'_, Provider>
{
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Proof::overlay_account_proof(self.tx(), input, address, slots).map_err(ProviderError::from)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        Proof::overlay_multiproof(self.tx(), input, targets).map_err(ProviderError::from)
    }

    fn witness(&self, input: TrieInput, target: HashedPostState) -> ProviderResult<Vec<Bytes>> {
        TrieWitness::overlay_witness(self.tx(), input, target)
            .map_err(ProviderError::from)
            .map(|hm| hm.into_values().collect())
    }

    fn flat_witness(&self, record: FlatWitnessRecord) -> ProviderResult<FlatPreState> {
        let mut prestate = FlatPreState::default();
        for (code_hash, code) in &record.contracts {
            match code {
                Some(bytecode) => {
                    prestate.contracts.insert(*code_hash, bytecode.original_bytes());
                }
                None => {
                    // Fetch code from provider if not present in record
                    if let Some(code) = self.bytecode_by_hash(code_hash)? {
                        prestate.contracts.insert(*code_hash, code.0.original_bytes());
                    }
                }
            }
        }

        for (address, account) in &record.accounts {
            let provider_account = self.basic_account(address)?;

            let mut db_account = match provider_account {
                Some(account) => DbAccount { info: account.into(), ..Default::default() },
                None => DbAccount::new_not_existing(),
            };

            match account {
                AccessedAccount::Destroyed => {
                    // When an account is destroyed, statedb discards all storage slots, losing
                    // track of which slots were accessed pre-destruction. We
                    // fetch all storage slots for destroyed accounts (mirroring
                    // TrieWitness::get_proof_targets in trie/trie/src/witness.rs),
                    // requiring a lower-level db cursor. Only relevant pre-Cancun where
                    // SELFDESTRUCT clears storage.
                    let tx = self.tx();
                    let mut storage_cursor = tx.cursor_dup_read::<tables::PlainStorageState>()?;
                    if let Some((_, first_entry)) = storage_cursor.seek_exact(*address)? {
                        db_account
                            .storage
                            .insert(U256::from_be_bytes(first_entry.key.0), first_entry.value);

                        while let Some((_, entry)) = storage_cursor.next_dup()? {
                            db_account
                                .storage
                                .insert(U256::from_be_bytes(entry.key.0), entry.value);
                        }
                    }
                    prestate.destructed_addresses.insert(*address);
                }
                AccessedAccount::StorageKeys(storage_keys) => {
                    // Fetch pre-state storage for accessed slots
                    for slot in storage_keys {
                        let val = self.storage(*address, (*slot).into())?.unwrap_or_default();
                        db_account.storage.insert(*slot, val);
                    }
                }
            }
            prestate.accounts.insert(
                *address,
                reth_execution_types::witness::Account {
                    account_state: db_account.account_state,
                    info: db_account.info,
                    storage: db_account.storage.into_iter().collect(),
                },
            );
        }

        Ok(prestate)
    }
}

impl<Provider: DBProvider + Sync> HashedPostStateProvider for LatestStateProviderRef<'_, Provider> {
    fn hashed_post_state(&self, bundle_state: &revm_database::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state())
    }
}

impl<Provider: DBProvider + BlockHashReader> StateProvider
    for LatestStateProviderRef<'_, Provider>
{
    /// Get storage.
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let mut cursor = self.tx().cursor_dup_read::<tables::PlainStorageState>()?;
        if let Some(entry) = cursor.seek_by_key_subkey(account, storage_key)?
            && entry.key == storage_key
        {
            return Ok(Some(entry.value));
        }
        Ok(None)
    }
}

impl<Provider: DBProvider + BlockHashReader> BytecodeReader
    for LatestStateProviderRef<'_, Provider>
{
    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.tx().get_by_encoded_key::<tables::Bytecodes>(code_hash).map_err(Into::into)
    }
}

/// State provider for the latest state.
#[derive(Debug)]
pub struct LatestStateProvider<Provider>(Provider);

impl<Provider: DBProvider> LatestStateProvider<Provider> {
    /// Create new state provider
    pub const fn new(db: Provider) -> Self {
        Self(db)
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    const fn as_ref(&self) -> LatestStateProviderRef<'_, Provider> {
        LatestStateProviderRef::new(&self.0)
    }
}

// Delegates all provider impls to [LatestStateProviderRef]
delegate_provider_impls!(LatestStateProvider<Provider> where [Provider: DBProvider + BlockHashReader ]);

#[cfg(test)]
mod tests {
    use super::*;

    const fn assert_state_provider<T: StateProvider>() {}
    #[expect(dead_code)]
    const fn assert_latest_state_provider<T: DBProvider + BlockHashReader>() {
        assert_state_provider::<LatestStateProvider<T>>();
    }
}
