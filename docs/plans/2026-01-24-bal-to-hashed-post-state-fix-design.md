# Fix `bal_to_hashed_post_state` Pre-State Fallback

## Problem

The `bal_to_hashed_post_state` function in `crates/stateless/src/subblock/bal_state.rs` uses default values (0, ZERO, None) for account fields not present in the BAL at the queried index. This corrupts accounts that only had partial changes.

**Example bug scenario:**
- Pre-state: Account has `nonce=5`, `balance=100`
- BAL: Only `balance` changed to `200`
- Current result: `nonce=0` (wrong), `balance=200` (correct)
- Expected result: `nonce=5` (from pre-state), `balance=200` (from BAL)

This produces incorrect `HashedPostState` values, leading to wrong state root computation.

## Solution

Pass a pre-state account provider to `bal_to_hashed_post_state` and query it for fallback values when BAL fields are missing.

## Design

### New Trait

```rust
// crates/stateless/src/subblock/bal_state.rs

/// Provider for pre-state account data during BAL conversion.
pub trait PreStateAccountProvider {
    type Error;

    /// Returns the pre-state account for the given address.
    ///
    /// - `Ok(Some(account))` - account exists in pre-state
    /// - `Ok(None)` - account proven to not exist (new account)
    /// - `Err(...)` - witness incomplete, cannot determine pre-state
    fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error>;
}
```

### Updated Function Signature

```rust
// Before
pub fn bal_to_hashed_post_state(bal: &Bal, bal_index: u64) -> HashedPostState

// After
pub fn bal_to_hashed_post_state<P>(
    bal: &Bal,
    bal_index: u64,
    pre_state: &P,
) -> Result<HashedPostState, P::Error>
where
    P: PreStateAccountProvider,
```

### Implementation Logic

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
                if a.code_hash == KECCAK_EMPTY { None } else { Some(a.code_hash) }
            })
        }),
    };
    accounts.insert(hashed_address, Some(account));
}
```

### Trait Implementation for StatelessSparseTrie

```rust
// crates/stateless/src/trie.rs

impl PreStateAccountProvider for StatelessSparseTrie {
    type Error = StatelessValidationError;

    fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error> {
        self.account(address)
            .map_err(|_| StatelessValidationError::WitnessIncomplete)
    }
}
```

Note: May need to add `WitnessIncomplete` variant to `StatelessValidationError` or use existing error variant.

### Call Site Update

```rust
// crates/stateless/src/subblock/aggregator.rs, line 125

// Before
let hashed_post_state = bal_to_hashed_post_state(&bal, final_bal_index);

// After
let hashed_post_state = bal_to_hashed_post_state(&bal, final_bal_index, &trie)?;
```

### Test Mock

```rust
#[cfg(test)]
struct MockPreState {
    accounts: alloc::collections::BTreeMap<Address, TrieAccount>,
}

#[cfg(test)]
impl PreStateAccountProvider for MockPreState {
    type Error = core::convert::Infallible;

    fn account(&self, address: Address) -> Result<Option<TrieAccount>, Self::Error> {
        Ok(self.accounts.get(&address).copied())
    }
}
```

### New Test Case

```rust
#[test]
fn test_bal_partial_change_uses_prestate() {
    let address = Address::repeat_byte(0x01);

    // Pre-state: account with nonce=5, balance=100
    let pre_account = TrieAccount {
        nonce: 5,
        balance: U256::from(100),
        storage_root: EMPTY_ROOT_HASH,
        code_hash: KECCAK_EMPTY,
    };

    let mut mock = MockPreState { accounts: Default::default() };
    mock.accounts.insert(address, pre_account);

    // BAL: only balance changed to 200
    let mut bal = Bal::new();
    let mut account_bal = AccountBal::default();
    account_bal.account_info.balance.force_update(0, U256::from(200));
    bal.accounts.insert(address, account_bal);

    let state = bal_to_hashed_post_state(&bal, 1, &mock).unwrap();

    let hashed_address = keccak256(address);
    let account = state.accounts.get(&hashed_address).unwrap().unwrap();

    // Balance from BAL, nonce from pre-state
    assert_eq!(account.balance, U256::from(200));
    assert_eq!(account.nonce, 5);
}
```

## Files Changed

| File | Change |
|------|--------|
| `crates/stateless/src/subblock/bal_state.rs` | Add trait, update function |
| `crates/stateless/src/trie.rs` | Implement trait for `StatelessSparseTrie` |
| `crates/stateless/src/subblock/aggregator.rs` | Update call site |
| `crates/stateless/src/subblock/mod.rs` | Re-export `PreStateAccountProvider` |
| `crates/stateless/src/validation.rs` | Possibly add error variant |

## Error Semantics

- **Witness incomplete**: If BAL references an account not provable in the witness, this is an invalid witness error
- **New account**: `Ok(None)` from provider means account doesn't exist in pre-state, use defaults (0, ZERO)
- **Existing account**: `Ok(Some(account))` provides fallback values for unchanged fields

## Comparison with engine/tree Implementation

The `crates/engine/tree/src/tree/payload_processor/bal.rs` version correctly handles this by querying an `AccountReader` provider:

```rust
let existing_account = provider.basic_account(&address)?;
let balance = balance.unwrap_or_else(|| {
    existing_account.as_ref().map(|acc| acc.balance).unwrap_or(U256::ZERO)
});
```

This fix aligns the stateless crate with that pattern.
