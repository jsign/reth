# Fix `bal_to_hashed_post_state` Pre-State Fallback Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix bug where partial BAL changes incorrectly use default values instead of querying pre-state from the trie.

**Architecture:** Add a `PreStateAccountProvider` trait for querying pre-state accounts. Implement it for `StatelessSparseTrie`. Update `bal_to_hashed_post_state` to accept a provider and use it for fallback values.

**Tech Stack:** Rust, no_std compatible, reth-stateless crate

---

## Task 1: Add `PreStateAccountProvider` Trait

**Files:**
- Modify: `crates/stateless/src/subblock/bal_state.rs:1-10`

**Step 1: Add trait definition and imports**

Add after line 9 (after `use revm_state::bal::Bal;`):

```rust
use alloy_primitives::Address;
use alloy_trie::TrieAccount;

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
```

**Step 2: Verify it compiles**

Run: `cargo check -p reth-stateless`
Expected: Compiles successfully (trait is defined but not used yet)

**Step 3: Commit**

```bash
git add crates/stateless/src/subblock/bal_state.rs
git commit -m "feat(stateless): add PreStateAccountProvider trait"
```

---

## Task 2: Add Test Mock Implementation

**Files:**
- Modify: `crates/stateless/src/subblock/bal_state.rs:85-148` (test module)

**Step 1: Add mock implementation in test module**

Add after line 90 (after `use revm_state::bal::AccountBal;`):

```rust
use alloc::collections::BTreeMap;
use alloy_trie::TrieAccount;

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
```

**Step 2: Verify it compiles**

Run: `cargo check -p reth-stateless`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add crates/stateless/src/subblock/bal_state.rs
git commit -m "test(stateless): add MockPreState for bal_state tests"
```

---

## Task 3: Write Failing Test for Pre-State Fallback

**Files:**
- Modify: `crates/stateless/src/subblock/bal_state.rs` (test module)

**Step 1: Add the failing test**

Add at end of test module (before final `}`):

```rust
#[test]
fn test_bal_partial_change_uses_prestate() {
    use alloy_trie::EMPTY_ROOT_HASH;
    use alloy_consensus::constants::KECCAK_EMPTY;

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
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p reth-stateless test_bal_partial_change_uses_prestate -- --nocapture`
Expected: FAIL - function signature doesn't accept provider yet

**Step 3: Commit**

```bash
git add crates/stateless/src/subblock/bal_state.rs
git commit -m "test(stateless): add failing test for pre-state fallback"
```

---

## Task 4: Update Function Signature

**Files:**
- Modify: `crates/stateless/src/subblock/bal_state.rs:36-83`

**Step 1: Update function signature and add KECCAK_EMPTY import**

Add to imports at top of file (after line 6):
```rust
use alloy_consensus::constants::KECCAK_EMPTY;
```

Replace lines 36-36 (just the function signature line):

```rust
pub fn bal_to_hashed_post_state<P>(
    bal: &Bal,
    bal_index: u64,
    pre_state: &P,
) -> Result<HashedPostState, P::Error>
where
    P: PreStateAccountProvider,
{
```

Replace line 82 (the return statement `HashedPostState { accounts, storages }`):

```rust
    Ok(HashedPostState { accounts, storages })
```

**Step 2: Verify it compiles (with errors in existing tests)**

Run: `cargo check -p reth-stateless`
Expected: Errors in existing tests (missing provider argument) - this is expected

**Step 3: Commit**

```bash
git add crates/stateless/src/subblock/bal_state.rs
git commit -m "feat(stateless): update bal_to_hashed_post_state signature to accept provider"
```

---

## Task 5: Implement Pre-State Fallback Logic

**Files:**
- Modify: `crates/stateless/src/subblock/bal_state.rs:51-63`

**Step 1: Replace the account building logic**

Replace lines 51-63 (the `if has_account_changes { ... }` block):

```rust
        if has_account_changes {
            // Query pre-state only if we need fallback values
            let pre_state_account = if nonce.is_none() || balance.is_none() || code.is_none() {
                pre_state.account(*address)?
            } else {
                None
            };

            let account = Account {
                nonce: nonce.unwrap_or_else(|| {
                    pre_state_account.map(|a| a.nonce).unwrap_or(0)
                }),
                balance: balance.unwrap_or_else(|| {
                    pre_state_account.map(|a| a.balance).unwrap_or(U256::ZERO)
                }),
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
```

**Step 2: Verify it compiles**

Run: `cargo check -p reth-stateless`
Expected: Still errors in existing tests (expected)

**Step 3: Commit**

```bash
git add crates/stateless/src/subblock/bal_state.rs
git commit -m "feat(stateless): implement pre-state fallback in bal_to_hashed_post_state"
```

---

## Task 6: Update Existing Tests

**Files:**
- Modify: `crates/stateless/src/subblock/bal_state.rs` (test module)

**Step 1: Create empty mock helper**

Add after the `MockPreState` impl block:

```rust
/// Empty mock that returns None for all accounts (simulates all-new accounts).
fn empty_pre_state() -> MockPreState {
    MockPreState::new()
}
```

**Step 2: Update test_empty_bal**

Replace the test:

```rust
#[test]
fn test_empty_bal() {
    let bal = Bal::new();
    let state = bal_to_hashed_post_state(&bal, 1, &empty_pre_state()).unwrap();
    assert!(state.accounts.is_empty());
    assert!(state.storages.is_empty());
}
```

**Step 3: Update test_bal_with_balance_change**

Replace the test:

```rust
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
```

**Step 4: Update test_bal_with_storage_change**

Replace the test:

```rust
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
```

**Step 5: Run all bal_state tests**

Run: `cargo test -p reth-stateless bal_state -- --nocapture`
Expected: All tests pass

**Step 6: Commit**

```bash
git add crates/stateless/src/subblock/bal_state.rs
git commit -m "test(stateless): update existing tests to use MockPreState"
```

---

## Task 7: Implement Trait for StatelessSparseTrie

**Files:**
- Modify: `crates/stateless/src/trie.rs:130-154`

**Step 1: Add import**

Add to imports at top of file (after line 6, near other alloy imports):

```rust
use crate::subblock::PreStateAccountProvider;
```

**Step 2: Add trait implementation**

Add after line 153 (after the `StatelessTrie` impl block ends with `}`):

```rust
impl PreStateAccountProvider for StatelessSparseTrie {
    type Error = crate::validation::StatelessValidationError;

    fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error> {
        self.account(address).map_err(|e| {
            crate::validation::StatelessValidationError::WitnessIncomplete {
                message: e.to_string(),
            }
        })
    }
}
```

**Step 3: Add error variant to StatelessValidationError**

Modify `crates/stateless/src/validation.rs`. Add after line 98 (after `SignerRecovery` variant):

```rust
    /// Error when witness is incomplete for required account lookup.
    #[error("witness incomplete: {message}")]
    WitnessIncomplete {
        /// Description of what was missing.
        message: String,
    },
```

**Step 4: Verify it compiles**

Run: `cargo check -p reth-stateless`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add crates/stateless/src/trie.rs crates/stateless/src/validation.rs
git commit -m "feat(stateless): implement PreStateAccountProvider for StatelessSparseTrie"
```

---

## Task 8: Update Aggregator Call Site

**Files:**
- Modify: `crates/stateless/src/subblock/aggregator.rs:125`

**Step 1: Update the call**

Replace line 125:

```rust
    let hashed_post_state = bal_to_hashed_post_state(&bal, final_bal_index, &trie)?;
```

**Step 2: Verify it compiles**

Run: `cargo check -p reth-stateless`
Expected: Compiles successfully

**Step 3: Run all tests**

Run: `cargo test -p reth-stateless`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/stateless/src/subblock/aggregator.rs
git commit -m "fix(stateless): pass trie to bal_to_hashed_post_state in aggregator"
```

---

## Task 9: Update Module Re-exports

**Files:**
- Modify: `crates/stateless/src/subblock/mod.rs:14`

**Step 1: Export the trait**

Replace line 14:

```rust
pub use bal_state::{bal_to_hashed_post_state, PreStateAccountProvider};
```

**Step 2: Verify it compiles**

Run: `cargo check -p reth-stateless`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add crates/stateless/src/subblock/mod.rs
git commit -m "feat(stateless): export PreStateAccountProvider from subblock module"
```

---

## Task 10: Final Verification

**Step 1: Run full test suite**

Run: `cargo test -p reth-stateless`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy -p reth-stateless --all-features -- -D warnings`
Expected: No warnings

**Step 3: Run formatter**

Run: `cargo +nightly fmt --all`
Expected: Code formatted

**Step 4: Final commit if any formatting changes**

```bash
git add -A
git commit -m "chore(stateless): format code"
```

---

## Summary

After completing all tasks, you will have:

1. A `PreStateAccountProvider` trait in `bal_state.rs`
2. `StatelessSparseTrie` implementing the trait
3. `bal_to_hashed_post_state` using the provider for fallback values
4. Updated aggregator passing the trie to the function
5. Tests verifying the pre-state fallback behavior
6. New `WitnessIncomplete` error variant for incomplete witness errors
