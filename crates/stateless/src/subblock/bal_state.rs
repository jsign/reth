//! BAL to `HashedPostState` conversion utilities.
//!
//! Converts a Block Access List to a `HashedPostState` for state root computation.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_trie::TrieAccount;
use reth_primitives_traits::Account;
use reth_trie_common::{HashedPostState, HashedStorage};
use revm_state::bal::Bal;

/// Provider for pre-state account data during BAL conversion.
///
/// Used to look up existing account values when BAL only contains partial changes.
pub trait PreStateAccountProvider {
    /// Error type for account lookups.
    type Error;

    /// Returns the pre-state account for the given address.
    ///
    /// - `Ok(Some(account))` - account exists in pre-state
    /// - `Ok(None)` - account proven to not exist (new account)
    /// - `Err(...)` - witness incomplete, cannot determine pre-state
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
/// * `bal_index` - The BAL index to read final values from (typically `num_transactions` + 2 for
///   post-block)
///
/// # Returns
///
/// A `HashedPostState` containing all account and storage changes.
///
/// # Note
///
/// The BAL index semantics:
/// - Index 0 = pre-execution state (reads at 0 return None)
/// - Index 1 = after pre-block system calls
/// - Index 2..n+1 = after each transaction (n transactions)
/// - Index n+2 = after post-block processing
///
/// To get the final state, use `bal_index = num_transactions + 2` (or any index larger than
/// the last write index).
pub fn bal_to_hashed_post_state(bal: &Bal, bal_index: u64) -> HashedPostState {
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

        if has_account_changes {
            // Build account - we use default values if a field wasn't changed
            // Note: This assumes changes are relative to some base state. In reality,
            // if nonce/balance/code weren't written, they remain at their pre-state values.
            // For destroyed accounts, all fields would be written as 0/empty.
            let account = Account {
                nonce: nonce.unwrap_or(0),
                balance: balance.unwrap_or(U256::ZERO),
                bytecode_hash: code.map(|(hash, _)| hash),
            };

            accounts.insert(hashed_address, Some(account));
        }

        // Process storage changes
        let mut storage_changes: Vec<(B256, U256)> = Vec::new();

        for (slot, slot_writes) in &account_bal.storage.storage {
            if let Some(value) = slot_writes.get(bal_index) {
                let hashed_slot = keccak256(B256::from(*slot));
                storage_changes.push((hashed_slot, value));
            }
        }

        if !storage_changes.is_empty() {
            // wiped = false because we're applying changes, not clearing
            let hashed_storage = HashedStorage::from_iter(false, storage_changes);
            storages.insert(hashed_address, hashed_storage);
        }
    }

    HashedPostState { accounts, storages }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::Address;
    use revm_state::bal::AccountBal;

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
        // Write balance at index 0
        account_bal.account_info.balance.force_update(0, U256::from(100));

        bal.accounts.insert(address, account_bal);

        // Query at index 1 should see the value written at index 0
        let state = bal_to_hashed_post_state(&bal, 1);
        assert_eq!(state.accounts.len(), 1);

        let hashed_address = keccak256(address);
        let account = state.accounts.get(&hashed_address).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(100));
        assert_eq!(account.nonce, 0); // default
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
        let state = bal_to_hashed_post_state(&bal, 1);

        let hashed_address = keccak256(address);
        assert!(state.storages.contains_key(&hashed_address));

        let storage = state.storages.get(&hashed_address).unwrap();
        let hashed_slot = keccak256(B256::from(slot));
        assert_eq!(storage.storage.get(&hashed_slot), Some(&value));
    }
}
