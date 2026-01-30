//! BAL validation utilities for subblock execution.
//!
//! Validates that the BAL built during execution matches the provided BAL.
//!
//! # Validation Strategy
//!
//! During subblock execution, the EVM's BAL builder records all state changes.
//! After execution, this module compares the built BAL against the provided
//! (full-block) BAL to ensure correctness within the executed range.
//!
//! Only changes within `bal_range` are validated; changes outside the range are
//! ignored (they belong to other subblocks).
//!
//! # BalWrites Index Semantics
//!
//! `BalWrites::get(i)` returns the value **visible at the START of index `i`**,
//! which is the state **AFTER** a write at index `i-1`. Therefore:
//!
//! - A change recorded at `block_access_index: N` with value `V`
//! - Is validated by checking `provided_writes.get(N + 1) == Some(V)`
//!
//! ```text
//! Index:    0     1     2     3     4
//!           │     │     │     │     │
//! Value:   [?]   [A]   [A]   [B]   [B]
//!                 ▲           ▲
//!                 │           │
//!          Write A at 0   Write B at 2
//!
//! get(0) = None     (no prior state)
//! get(1) = Some(A)  (visible after write at 0)
//! get(2) = Some(A)  (no write at 1, still A)
//! get(3) = Some(B)  (visible after write at 2)
//! get(4) = Some(B)  (no write at 3, still B)
//! ```
//!
//! This offset-by-one is why all validation functions check `get(index + 1)`.

use alloc::sync::Arc;
use alloy_eip7928::BlockAccessList;
use alloy_primitives::Address;
use core::ops::Range;
use revm_state::bal::Bal;

use super::error::SubblockValidationError;

/// Validates that the built BAL matches the provided BAL for the given range.
///
/// This compares state changes recorded during execution against the provided BAL
/// to ensure the BAL is valid for the executed transaction range.
///
/// # Arguments
///
/// * `provided_bal` - The BAL provided as input (from the full block)
/// * `built_bal` - The BAL built during subblock execution
/// * `bal_range` - The BAL index range that was executed
///
/// # Returns
///
/// `Ok(())` if validation passes, or an error describing the mismatch.
pub(crate) fn validate_subblock_bal(
    provided_bal: &Arc<Bal>,
    built_bal: Option<BlockAccessList>,
    bal_range: &Range<u64>,
) -> Result<(), SubblockValidationError> {
    let Some(built) = built_bal else {
        return Err(SubblockValidationError::BalNotBuilt);
    };

    for built_account in &built {
        let address = built_account.address;

        // Find corresponding account in provided BAL
        let provided_account = provided_bal
            .accounts
            .get(&address)
            .ok_or(SubblockValidationError::BalAccountMissing { address })?;

        // Validate balance changes within our range
        validate_balance_changes(
            address,
            &built_account.balance_changes,
            &provided_account.account_info.balance,
            bal_range,
        )?;

        // Validate nonce changes within our range
        validate_nonce_changes(
            address,
            &built_account.nonce_changes,
            &provided_account.account_info.nonce,
            bal_range,
        )?;

        // Validate storage changes within our range
        validate_storage_changes(
            address,
            &built_account.storage_changes,
            &provided_account.storage,
            bal_range,
        )?;

        // Validate code changes within our range
        validate_code_changes(
            address,
            &built_account.code_changes,
            &provided_account.account_info.code,
            bal_range,
        )?;
    }

    Ok(())
}

/// Validates balance changes match between built and provided BAL.
///
/// Note: `BalWrites::get(i)` returns the value visible at the START of index `i`,
/// which is the state AFTER the write at index `i-1`. So to validate a change
/// at `block_access_index: i` with `post_balance: v`, we check `get(i+1) == Some(v)`.
fn validate_balance_changes(
    address: Address,
    built_changes: &[alloy_eip7928::BalanceChange],
    provided_writes: &revm_state::bal::BalWrites<alloy_primitives::U256>,
    bal_range: &Range<u64>,
) -> Result<(), SubblockValidationError> {
    for change in built_changes {
        let index = change.block_access_index;

        // Only validate changes within our range
        if index < bal_range.start || index >= bal_range.end {
            continue;
        }

        // Check that the post_balance is visible at index+1 (after the change takes effect)
        // BalWrites::get(i) returns the value visible at the START of index i,
        // so get(index+1) gives us the value AFTER the change at index.
        let provided_value = provided_writes.get(index + 1);

        if provided_value != Some(change.post_balance) {
            return Err(SubblockValidationError::BalBalanceMismatch {
                address,
                index,
                built: change.post_balance,
                provided: provided_value.unwrap_or_default(),
            });
        }
    }
    Ok(())
}

/// Validates nonce changes match between built and provided BAL.
fn validate_nonce_changes(
    address: Address,
    built_changes: &[alloy_eip7928::NonceChange],
    provided_writes: &revm_state::bal::BalWrites<u64>,
    bal_range: &Range<u64>,
) -> Result<(), SubblockValidationError> {
    for change in built_changes {
        let index = change.block_access_index;

        if index < bal_range.start || index >= bal_range.end {
            continue;
        }

        // Check at index+1 (see validate_balance_changes for explanation)
        let provided_value = provided_writes.get(index + 1);

        if provided_value != Some(change.new_nonce) {
            return Err(SubblockValidationError::BalNonceMismatch {
                address,
                index,
                built: change.new_nonce,
                provided: provided_value.unwrap_or_default(),
            });
        }
    }
    Ok(())
}

/// Validates storage changes match between built and provided BAL.
fn validate_storage_changes(
    address: Address,
    built_changes: &[alloy_eip7928::SlotChanges],
    provided_storage: &revm_state::bal::StorageBal,
    bal_range: &Range<u64>,
) -> Result<(), SubblockValidationError> {
    for slot_changes in built_changes {
        let slot = slot_changes.slot;

        // Get the provided slot writes
        let provided_slot_writes = provided_storage.storage.get(&slot);

        for change in &slot_changes.changes {
            let index = change.block_access_index;

            if index < bal_range.start || index >= bal_range.end {
                continue;
            }

            // Check at index+1 (see validate_balance_changes for explanation)
            let provided_value = provided_slot_writes.and_then(|w| w.get(index + 1));

            if provided_value != Some(change.new_value) {
                return Err(SubblockValidationError::BalStorageMismatch {
                    address,
                    slot,
                    index,
                    built: change.new_value,
                    provided: provided_value.unwrap_or_default(),
                });
            }
        }
    }
    Ok(())
}

/// Validates code changes match between built and provided BAL.
fn validate_code_changes(
    address: Address,
    built_changes: &[alloy_eip7928::CodeChange],
    provided_writes: &revm_state::bal::BalWrites<(
        alloy_primitives::B256,
        reth_revm::bytecode::Bytecode,
    )>,
    bal_range: &Range<u64>,
) -> Result<(), SubblockValidationError> {
    for change in built_changes {
        let index = change.block_access_index;

        if index < bal_range.start || index >= bal_range.end {
            continue;
        }

        // Check at index+1 (see validate_balance_changes for explanation)
        let provided_code = provided_writes.get(index + 1);

        // Compare by checking if the code bytes match
        let matches = provided_code.is_some_and(|(_, bytecode)| {
            bytecode.original_byte_slice() == change.new_code.as_ref()
        });

        if !matches {
            return Err(SubblockValidationError::BalCodeMismatch { address, index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_eip7928::{AccountChanges, BalanceChange};
    use alloy_primitives::U256;
    use revm_state::bal::AccountBal;

    #[test]
    fn test_validate_empty_built_bal() {
        let provided = Arc::new(Bal::new());
        let built = Some(vec![]);
        let range = 0..5;

        // Empty built BAL should pass
        assert!(validate_subblock_bal(&provided, built, &range).is_ok());
    }

    #[test]
    fn test_validate_bal_not_built() {
        let provided = Arc::new(Bal::new());
        let range = 0..5;

        let result = validate_subblock_bal(&provided, None, &range);
        assert!(matches!(result, Err(SubblockValidationError::BalNotBuilt)));
    }

    #[test]
    fn test_validate_missing_account() {
        let provided = Arc::new(Bal::new());
        let address = Address::repeat_byte(0x01);

        let built = Some(vec![AccountChanges {
            address,
            balance_changes: vec![BalanceChange::new(1, U256::from(100))],
            nonce_changes: vec![],
            code_changes: vec![],
            storage_changes: vec![],
            storage_reads: vec![],
        }]);
        let range = 0..5;

        let result = validate_subblock_bal(&provided, built, &range);
        assert!(matches!(
            result,
            Err(SubblockValidationError::BalAccountMissing { address: a }) if a == address
        ));
    }

    #[test]
    fn test_validate_balance_match() {
        let address = Address::repeat_byte(0x01);

        // Create provided BAL with balance write at index 1
        // This means the value 100 is visible starting at get(2) (after index 1)
        let mut provided = Bal::new();
        let mut account_bal = AccountBal::default();
        account_bal.account_info.balance.force_update(1, U256::from(100));
        provided.accounts.insert(address, account_bal);
        let provided = Arc::new(provided);

        // Verify our understanding: get(1) returns None, get(2) returns Some(100)
        let bal_val_at_1 = provided.accounts.get(&address).unwrap().account_info.balance.get(1);
        let bal_val_at_2 = provided.accounts.get(&address).unwrap().account_info.balance.get(2);
        assert_eq!(bal_val_at_1, None, "get(1) should return None (value not yet visible)");
        assert_eq!(
            bal_val_at_2,
            Some(U256::from(100)),
            "get(2) should return Some(100) (visible after change at 1)"
        );

        // Create built BAL with matching balance change at index 1
        // Validation will check get(1+1) = get(2) which should equal post_balance
        let built = Some(vec![AccountChanges {
            address,
            balance_changes: vec![BalanceChange::new(1, U256::from(100))],
            nonce_changes: vec![],
            code_changes: vec![],
            storage_changes: vec![],
            storage_reads: vec![],
        }]);
        let range = 0..5;

        assert!(validate_subblock_bal(&provided, built, &range).is_ok());
    }

    #[test]
    fn test_validate_balance_mismatch() {
        let address = Address::repeat_byte(0x01);

        // Create provided BAL with balance 100
        let mut provided = Bal::new();
        let mut account_bal = AccountBal::default();
        account_bal.account_info.balance.force_update(1, U256::from(100));
        provided.accounts.insert(address, account_bal);
        let provided = Arc::new(provided);

        // Create built BAL with different balance (200)
        let built = Some(vec![AccountChanges {
            address,
            balance_changes: vec![BalanceChange::new(1, U256::from(200))],
            nonce_changes: vec![],
            code_changes: vec![],
            storage_changes: vec![],
            storage_reads: vec![],
        }]);
        let range = 0..5;

        let result = validate_subblock_bal(&provided, built, &range);
        assert!(matches!(result, Err(SubblockValidationError::BalBalanceMismatch { .. })));
    }

    #[test]
    fn test_validate_changes_outside_range_ignored() {
        let address = Address::repeat_byte(0x01);

        // Create provided BAL (empty - no writes)
        let mut provided = Bal::new();
        provided.accounts.insert(address, AccountBal::default());
        let provided = Arc::new(provided);

        // Create built BAL with balance change at index 10 (outside range 0..5)
        let built = Some(vec![AccountChanges {
            address,
            balance_changes: vec![BalanceChange::new(10, U256::from(999))],
            nonce_changes: vec![],
            code_changes: vec![],
            storage_changes: vec![],
            storage_reads: vec![],
        }]);
        let range = 0..5;

        // Should pass because index 10 is outside range 0..5
        assert!(validate_subblock_bal(&provided, built, &range).is_ok());
    }
}
