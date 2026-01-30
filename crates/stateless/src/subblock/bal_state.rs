//! BAL to `HashedPostState` conversion utilities.
//!
//! Converts a Block Access List to a `HashedPostState` for state root computation.

use alloc::vec::Vec;
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_trie::TrieAccount;
use reth_primitives_traits::Account;
use reth_trie_common::{HashedPostState, HashedStorage};
use revm_state::bal::Bal;

/// Provider for pre-state account data during BAL conversion.
///
/// Used to look up existing account values when BAL only contains partial changes.
///
/// # Purpose
///
/// When converting a BAL to `HashedPostState`, some account fields may not have
/// changed during execution. For example, if only the balance changed, we need
/// to look up the existing nonce and code hash from pre-state.
///
/// # Implementers
///
/// Typical implementations include:
/// - The stateless trie (provides pre-state from witness proofs)
/// - A mock provider (for testing)
///
/// # Example
///
/// ```ignore
/// impl PreStateAccountProvider for StatelessSparseTrie {
///     type Error = StatelessValidationError;
///
///     fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error> {
///         // Look up account in the sparse trie
///         self.get_account(address)
///     }
/// }
/// ```
pub trait PreStateAccountProvider {
    /// Error type for account lookups.
    type Error;

    /// Returns the pre-state account for the given address.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(account))` - Account exists in pre-state with the given values
    /// - `Ok(None)` - Account proven to not exist (new account created during execution)
    /// - `Err(...)` - Witness incomplete, cannot determine pre-state
    fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error>;
}

/// Converts a BAL to a `HashedPostState` at the given BAL index.
///
/// This extracts the final values from the BAL at `bal_index` and constructs
/// a `HashedPostState` representing the state diff from pre-state to that point.
///
/// # Arguments
///
/// * `bal` - The Block Access List containing all state changes
/// * `bal_index` - The BAL index to read final values from (typically `num_transactions + 1` for
///   post-execution per EIP-7928)
///
/// # Returns
///
/// A `HashedPostState` containing all account and storage changes.
///
/// # Note
///
/// BAL index semantics per EIP-7928:
/// - Index 0 = pre-execution system contract calls (beacon root, blockhashes)
/// - Index 1..n = individual transactions (tx 0 at index 1, tx 1 at index 2, ...)
/// - Index n+1 = post-execution (withdrawals)
///
/// To get the final state, use `bal_index = num_transactions + 2`.
pub fn bal_to_hashed_post_state<P>(
    bal: &Bal,
    bal_index: u64,
    pre_state: &P,
) -> Result<HashedPostState, P::Error>
where
    P: PreStateAccountProvider,
{
    let mut accounts = alloy_primitives::map::HashMap::default();
    let mut storages = alloy_primitives::map::HashMap::default();

    for (address, account_bal) in &bal.accounts {
        let hashed_address = keccak256(address);

        // Get account info at bal_index
        let nonce = account_bal.account_info.nonce.get(bal_index);
        let balance = account_bal.account_info.balance.get(bal_index);
        let code = account_bal.account_info.code.get(bal_index);

        // Check if there are any account info changes
        let has_account_changes = nonce.is_some() || balance.is_some() || code.is_some();

        // Process storage changes first to check if we have any
        let mut storage_changes: Vec<(B256, U256)> = Vec::new();

        for (slot, slot_writes) in &account_bal.storage.storage {
            if let Some(value) = slot_writes.get(bal_index) {
                let hashed_slot = keccak256(B256::from(*slot));
                storage_changes.push((hashed_slot, value));
            }
        }

        let has_storage_changes = !storage_changes.is_empty();

        // Include account if it has account info changes OR storage changes.
        // Storage changes affect the account's storage_root, so the account must be included.
        if has_account_changes || has_storage_changes {
            // Query pre-state for any missing account fields
            let pre_state_account = if nonce.is_none() || balance.is_none() || code.is_none() {
                pre_state.account(*address)?
            } else {
                None
            };

            let account = Account {
                nonce: nonce.unwrap_or_else(|| pre_state_account.map(|a| a.nonce).unwrap_or(0)),
                balance: balance
                    .unwrap_or_else(|| pre_state_account.map(|a| a.balance).unwrap_or(U256::ZERO)),
                bytecode_hash: code.map(|(hash, _)| hash).or_else(|| {
                    pre_state_account.and_then(|a| {
                        // KECCAK_EMPTY means no code, represented as None in Account
                        if a.code_hash == KECCAK_EMPTY {
                            None
                        } else {
                            Some(a.code_hash)
                        }
                    })
                }),
            };

            accounts.insert(hashed_address, Some(account));
        }

        if has_storage_changes {
            // wiped = false because we're applying changes, not clearing
            let hashed_storage = HashedStorage::from_iter(false, storage_changes);
            storages.insert(hashed_address, hashed_storage);
        }
    }

    Ok(HashedPostState { accounts, storages })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec};
    use alloy_primitives::Address;
    use alloy_trie::TrieAccount;
    use revm_state::bal::AccountBal;

    /// Mock pre-state provider for testing.
    struct MockPreState {
        accounts: BTreeMap<Address, TrieAccount>,
    }

    impl MockPreState {
        fn new() -> Self {
            Self { accounts: BTreeMap::new() }
        }

        fn with_account(mut self, address: Address, account: TrieAccount) -> Self {
            self.accounts.insert(address, account);
            self
        }
    }

    impl PreStateAccountProvider for MockPreState {
        type Error = core::convert::Infallible;

        fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error> {
            Ok(self.accounts.get(&address).copied())
        }
    }

    /// Empty mock that returns None for all accounts (simulates all-new accounts).
    fn empty_pre_state() -> MockPreState {
        MockPreState::new()
    }

    #[test]
    fn test_empty_bal() {
        let bal = Bal::new();
        let state = bal_to_hashed_post_state(&bal, 1, &empty_pre_state()).unwrap();
        assert!(state.accounts.is_empty());
        assert!(state.storages.is_empty());
    }

    #[test]
    fn test_bal_with_balance_change() {
        let mut bal = Bal::new();
        let address = Address::repeat_byte(0x01);

        let mut account_bal = AccountBal::default();
        // Write balance at index 0
        account_bal.account_info.balance.force_update(0, U256::from(100));

        bal.accounts.insert(address, account_bal);

        // Query at index 1 should see the value written at index 0
        // Using empty pre-state, so unchanged fields get defaults
        let state = bal_to_hashed_post_state(&bal, 1, &empty_pre_state()).unwrap();
        assert_eq!(state.accounts.len(), 1);

        let hashed_address = keccak256(address);
        let account = state.accounts.get(&hashed_address).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(100));
        assert_eq!(account.nonce, 0); // default (no pre-state)
        assert!(account.bytecode_hash.is_none()); // default
    }

    #[test]
    fn test_bal_with_storage_change() {
        let mut bal = Bal::new();
        let address = Address::repeat_byte(0x02);

        let mut account_bal = AccountBal::default();
        // Write storage at index 0
        let slot = U256::from(42);
        let value = U256::from(123);
        account_bal
            .storage
            .storage
            .insert(slot.into(), revm_state::bal::BalWrites::new(vec![(0, value)]));

        bal.accounts.insert(address, account_bal);

        // Query at index 1 should see the value written at index 0
        let state = bal_to_hashed_post_state(&bal, 1, &empty_pre_state()).unwrap();

        let hashed_address = keccak256(address);
        assert!(state.storages.contains_key(&hashed_address));

        let storage = state.storages.get(&hashed_address).unwrap();
        let hashed_slot = keccak256(B256::from(slot));
        assert_eq!(storage.storage.get(&hashed_slot), Some(&value));
    }

    #[test]
    fn test_bal_partial_change_uses_prestate() {
        use alloy_consensus::constants::KECCAK_EMPTY;
        use alloy_trie::EMPTY_ROOT_HASH;

        let address = Address::repeat_byte(0x03);

        // Pre-state: account with nonce=5, balance=100
        let pre_account = TrieAccount {
            nonce: 5,
            balance: U256::from(100),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        };

        let mock = MockPreState::new().with_account(address, pre_account);

        // BAL: only balance changed to 200 at index 0
        let mut bal = Bal::new();
        let mut account_bal = AccountBal::default();
        account_bal.account_info.balance.force_update(0, U256::from(200));
        bal.accounts.insert(address, account_bal);

        // Query at index 1
        let state = bal_to_hashed_post_state(&bal, 1, &mock).unwrap();

        let hashed_address = keccak256(address);
        let account = state.accounts.get(&hashed_address).unwrap().unwrap();

        // Balance should come from BAL
        assert_eq!(account.balance, U256::from(200));
        // Nonce should come from pre-state, NOT default 0
        assert_eq!(account.nonce, 5);
        // bytecode_hash should be None (KECCAK_EMPTY maps to None)
        assert!(account.bytecode_hash.is_none());
    }
}
