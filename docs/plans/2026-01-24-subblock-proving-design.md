# Subblock Proving Design

## Overview

Extend the `reth-stateless` crate to support **subblock proving** - splitting block validation into parallelizable pieces using EIP-7928 Block Access Lists (BALs).

### Key Concepts

- **Worker guest program**: Executes a range of transactions `[A, B)` within a block
- **Master/Aggregator guest program**: Verifies worker proofs and runs pre/post-block logic
- **BAL fast-forwarding**: Workers receive the full `ExecutionWitness` and use BAL to fast-forward state to their starting tx index, avoiding intermediate state root computation

## Data Structures

### SubblockInput

Input to the worker guest program:

```rust
pub struct SubblockInput {
    /// The full block (header + body with ALL transactions)
    pub block: Block,
    /// ExecutionWitness for the entire block (pre-state)
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block
    pub bal: BlockAccessList,
    /// Transaction range to execute: [start_tx_index, end_tx_index)
    pub tx_range: Range<usize>,
    /// Chain config for fork rules
    pub chain_config: ChainConfig,
    /// Whether this is the first subblock (runs pre-block logic)
    pub is_first: bool,
    /// Whether this is the last subblock (runs post-block logic)
    pub is_last: bool,
}
```

### SubblockOutput

Output committed by the worker (lightweight - no intermediate state roots):

```rust
pub struct SubblockOutput {
    /// Receipts for txs in this range
    pub receipts: Vec<Receipt>,
    /// Logs bloom for this range
    pub logs_bloom: Bloom,
    /// EIP-7685 requests from this range
    pub requests: Vec<Request>,
    /// Cumulative gas used at end of range
    pub cumulative_gas_used: u64,
}
```

### AggregationInput

Input to the master/aggregator guest program:

```rust
pub struct AggregationInput {
    /// The full block being validated
    pub block: Block,
    /// ExecutionWitness for the entire block
    pub witness: ExecutionWitness,
    /// Block Access List for the entire block
    pub bal: BlockAccessList,
    /// Chain config for fork rules
    pub chain_config: ChainConfig,
    /// Subblock outputs (in order), verified by ZK proofs
    pub subblock_outputs: Vec<SubblockOutput>,
    /// The tx ranges each subblock covered (for verification)
    pub tx_ranges: Vec<Range<usize>>,
}
```

## Worker Execution Flow

```rust
pub fn subblock_validation<ChainSpec, E>(
    input: SubblockInput,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<SubblockOutput, SubblockValidationError>
```

### Steps

1. **Build the database layer:**
   - Create `StatelessSparseTrie` from `ExecutionWitness` (verifies pre-state root)
   - Create `WitnessDatabase` from the trie + bytecodes + ancestor hashes
   - Wrap with revm's `BalDatabase`, set `bal_index = tx_range.start`

2. **Pre-block logic (if `is_first`):**
   - Apply beacon block root (EIP-4788)
   - Apply blockhashes contract update (EIP-2935)
   - Bump `bal_index` after pre-block system calls

3. **Execute transactions in range:**
   ```rust
   for tx_index in tx_range {
       let tx = &block.body.transactions[tx_index];
       let result = executor.execute_transaction(tx)?;
       receipts.push(result.receipt);
       logs_bloom.accrue_bloom(&result.receipt.bloom);
       cumulative_gas_used = result.receipt.cumulative_gas_used;
       db.bump_bal_index();
   }
   ```

4. **Post-block logic (if `is_last`):**
   - Process withdrawals (Shanghai+)
   - Collect requests (EIP-7685)

5. **Return `SubblockOutput`**

## Aggregation Validation Flow

```rust
pub fn aggregation_validation<ChainSpec, E>(
    input: AggregationInput,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<B256, AggregationValidationError>
```

### Steps

1. **Verify ranges are complete:**
   - Ranges must be contiguous
   - Start at 0, end at `block.body.transactions.len()`

2. **Run pre-block logic** (beacon block root, etc.)

3. **Verify gas chaining:**
   - `subblock[n+1]` starting gas == `subblock[n].cumulative_gas_used`

4. **Combine outputs:**
   - Merge receipts in order
   - Accrue logs blooms
   - Collect all requests

5. **Run post-block validation:**
   - `validate_block_post_execution` (receipts root, gas used, requests)

6. **Compute final state root:**
   - Apply full BAL to witness
   - Verify matches `block.state_root`

7. **Return block hash**

## Final State Root Computation

The master computes the final state root without re-executing transactions:

```rust
fn compute_final_state_root(
    witness: &ExecutionWitness,
    bal: &BlockAccessList,
    parent_state_root: B256,
    num_transactions: usize,
) -> Result<B256, StatelessValidationError> {
    // 1. Build trie from witness (pre-state)
    let (mut trie, _bytecode) = StatelessSparseTrie::new(witness, parent_state_root)?;

    // 2. Convert BAL to HashedPostState at final index
    let hashed_post_state = bal_to_hashed_post_state(bal, num_transactions + 1);

    // 3. Calculate state root
    trie.calculate_state_root(hashed_post_state)
}
```

The `bal_to_hashed_post_state` helper:
- Iterates over all accounts in BAL
- Gets final values of nonce/balance/code at end-of-block index
- Gets final storage values
- Builds `HashedPostState` representing full diff from pre-state to post-state

## Module Structure

```
crates/stateless/src/
├── lib.rs                    # Add re-exports for subblock types
├── validation.rs             # Existing stateless_validation (unchanged)
├── trie.rs                   # Existing StatelessTrie (reused)
├── witness_db.rs             # Existing WitnessDatabase (reused)
├── subblock/
│   ├── mod.rs                # Module exports
│   ├── types.rs              # SubblockInput, SubblockOutput, AggregationInput
│   ├── worker.rs             # subblock_validation function
│   ├── aggregator.rs         # aggregation_validation function
│   └── bal_state.rs          # bal_to_hashed_post_state helper
```

## Public API

```rust
// lib.rs additions
pub mod subblock;
pub use subblock::{
    SubblockInput, SubblockOutput, AggregationInput,
    subblock_validation, aggregation_validation,
};
```

## Dependencies

New dependencies for the stateless crate:
- `alloy-eip7928` - BAL types (`BlockAccessList`, `AccountChanges`, etc.)
- `revm-database-interface` - `BalDatabase`, `BalState` for BAL-aware database wrapper

## Key Design Decisions

1. **No intermediate state roots**: Workers don't compute state roots; master computes final state root once from BAL
2. **Caller-defined tx ranges**: Host/prover decides how to split transactions for load balancing
3. **Full witness to all workers**: Each worker gets the complete `ExecutionWitness` and uses BAL to fast-forward
4. **Extend existing crate**: New functionality lives in `crates/stateless/src/subblock/` module
5. **Reuse existing infrastructure**: Leverages `StatelessSparseTrie`, `WitnessDatabase`, `calculate_state_root`
