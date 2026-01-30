# Subblock Proving for Parallelized Block Validation

This document describes the subblock proving architecture in `reth-stateless`, which enables parallelized block validation using EIP-7928 Block Access Lists (BALs).

## Overview

Traditional block validation executes all transactions sequentially, which limits parallelization opportunities. The subblock module splits a block into independent "subblocks" - ranges of transactions that can be validated concurrently using BAL fast-forwarding.

Each subblock:
- Executes only its assigned transaction range
- Uses the BAL to read pre-state values without re-executing prior transactions
- Produces receipts with LOCAL cumulative gas (starting from 0)
- Validates that execution matches the provided BAL

An aggregator then combines all subblock outputs, adjusts gas values to global positions, and computes the final state root.

## Architecture

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                   Block + Witness + BAL                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│   Worker 1    │       │   Worker 2    │       │   Worker N    │
│ range [0,k)   │       │ range [k,m)   │       │ range [m,n+2) │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│SubblockOutput │       │SubblockOutput │       │SubblockOutput │
│ - receipts    │       │ - receipts    │       │ - receipts    │
│ - bloom       │       │ - bloom       │       │ - bloom       │
│ - requests    │       │ - requests    │       │ - requests    │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │      Aggregator       │
                    │ - Verify ranges       │
                    │ - Adjust gas          │
                    │ - Combine blooms      │
                    │ - Compute state root  │
                    │ - Validate post-state │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │     Block Hash        │
                    └───────────────────────┘
```

### Components

| Component | File | Purpose |
|-----------|------|---------|
| Worker | `worker.rs` | Executes transaction range, produces `SubblockOutput` |
| Aggregator | `aggregator.rs` | Combines outputs, validates state root |
| BAL Witness DB | `bal_witness_db.rs` | Database layer with BAL fast-forwarding |
| BAL Validation | `bal_validation.rs` | Verifies built BAL matches provided BAL |
| BAL State | `bal_state.rs` | Converts BAL to `HashedPostState` |
| Execution Context | `execution.rs` | Creates position-specific execution contexts |
| Types | `types.rs` | `SubblockInput`, `SubblockOutput`, `AggregationInput` |
| Errors | `error.rs` | Error types with detailed mismatch info |

## Worker (`subblock_validation`)

The worker executes a subset of transactions using BAL fast-forwarding.

### Input Processing

`SubblockInput` contains:
- Full block (header + all transactions)
- `ExecutionWitness` (pre-state sparse trie)
- BAL for the entire block
- BAL range to execute (e.g., `[3, 7)`)
- Chain config

### BAL Range to Transaction Indices

BAL indices map to block execution phases:

```
For a block with N transactions:

BAL Index:  0      1      2      ...    N      N+1
            │      │      │             │      │
            ▼      ▼      ▼             ▼      ▼
          ┌────┬──────┬──────┬───────┬──────┬────────┐
          │Pre-│ TX 0 │ TX 1 │  ...  │TX N-1│ Post-  │
          │exec│      │      │       │      │ exec   │
          └────┴──────┴──────┴───────┴──────┴────────┘

Full range: [0, N+2)
```

Conversion formula:
```
tx_start = bal_range.start == 0 ? 0 : bal_range.start - 1
tx_end = min(bal_range.end - 1, tx_count)
```

### Subblock Position Flags

The `is_first` and `is_last` flags determine what extra processing occurs:

| Flag | Condition | Effect |
|------|-----------|--------|
| `is_first` | `bal_range.start == 0` | Runs pre-execution (beacon root, blockhashes) |
| `is_last` | `bal_range.end > tx_count` | Processes withdrawals |

Possible positions:
- **First only**: `[0, k)` where `k <= tx_count`
- **Last only**: `[m, N+2)` where `m > 0`
- **Both (single subblock)**: `[0, N+2)`
- **Neither (middle)**: `[k, m)` where `0 < k < m <= tx_count`

### BAL Fast-Forwarding

`BalWitnessDatabase` enables reading state at any BAL index:

```
┌─────────────────────────────────────────┐
│  Database Request (address, slot, etc.) │
└──────────────────┬──────────────────────┘
                   │
       ┌───────────▼───────────┐
       │  Check BalState       │
       │  (fast-forward view)  │
       └───────────┬───────────┘
                   │
          Has value at bal_index?
         /                      \
       Yes                       No
         │                        │
  Return BAL value         Query StatelessTrie
                            (pre-state)
```

### BAL Building and Validation

During execution:
1. The EVM's BAL builder records all state changes
2. After execution, `validate_subblock_bal` compares built BAL against provided BAL
3. Only changes within `bal_range` are validated

## Aggregator (`aggregation_validation`)

The aggregator combines verified subblock outputs and validates the final state.

### Range Verification

Ranges must be:
1. **Complete**: Cover `[0, tx_count + 2)`
2. **Contiguous**: `ranges[i].end == ranges[i+1].start`
3. **Start at zero**: `ranges[0].start == 0`

Example valid ranges for 10 transactions:
```
[0, 4), [4, 8), [8, 12)  ✓ Complete and contiguous
[0, 12)                  ✓ Single range covering all
[1, 6), [6, 12)          ✗ Doesn't start at 0
[0, 3), [4, 12)          ✗ Gap between 3 and 4
[0, 8)                   ✗ Incomplete (missing 8..12)
```

### Gas Adjustment (Local to Global)

Each subblock produces receipts with LOCAL cumulative gas (starting from 0). The aggregator adjusts to GLOBAL cumulative gas:

```
Subblock 1: range [0, 3)        Subblock 2: range [3, 7)
├─ tx0: local_gas = 21000       ├─ tx3: local_gas = 30000
├─ tx1: local_gas = 42000       ├─ tx4: local_gas = 51000
└─ tx2: local_gas = 63000       └─ (ends)

After aggregation:
├─ tx0: global_gas = 21000      (offset 0 + 21000)
├─ tx1: global_gas = 42000      (offset 0 + 42000)
├─ tx2: global_gas = 63000      (offset 0 + 63000)
├─ tx3: global_gas = 93000      (offset 63000 + 30000)
└─ tx4: global_gas = 114000     (offset 63000 + 51000)

Offset for subblock N = last cumulative gas of subblock N-1
```

### Post-State Root Validation

After combining outputs, the aggregator:

1. Converts the BAL to `HashedPostState` at `bal_index = tx_count + 2`
2. Updates the sparse trie with state changes
3. Computes the state root
4. Compares against the block header's `state_root`

If the computed root doesn't match, the block is invalid.

### BAL Hash Verification (EIP-7928, Amsterdam)

For post-Amsterdam blocks, the aggregator also verifies:
```
compute_block_access_list_hash(bal) == block.header.block_access_list_hash
```

## Key Concepts

### EIP-7928 BAL Index Semantics

Every operation in a block is assigned a BAL index:

| Index | Operation | Description |
|-------|-----------|-------------|
| 0 | Pre-execution | Beacon root deposit, blockhashes system call |
| 1 | Transaction 0 | First transaction |
| 2 | Transaction 1 | Second transaction |
| ... | ... | ... |
| N | Transaction N-1 | Last transaction |
| N+1 | Post-execution | Withdrawals processing |

Full BAL range for a block: `[0, tx_count + 2)`

### BalWrites Index Semantics

`BalWrites::get(i)` returns the value **visible at the START of index i**, which is the state **AFTER** a write at index `i-1`:

```
Time/Index:  0     1     2     3     4
             │     │     │     │     │
Value:      [?]   [A]   [A]   [B]   [B]
                   ▲           ▲
                   │           │
            Write A at 0   Write B at 2

get(0) = None     (no prior state)
get(1) = Some(A)  (visible after write at 0)
get(2) = Some(A)  (unchanged, still A)
get(3) = Some(B)  (visible after write at 2)
get(4) = Some(B)  (unchanged, still B)
```

This is why validation checks `get(index + 1)` for a change recorded at `index`.

### Pre/Post Execution Handling

| Position | Pre-execution | Post-execution |
|----------|---------------|----------------|
| First (`is_first=true`) | Beacon root, blockhashes | - |
| Last (`is_last=true`) | - | Withdrawals |
| Single (both) | Beacon root, blockhashes | Withdrawals |
| Middle (neither) | - | - |

## Integration with Stateless Validation

The subblock module complements the single-threaded `stateless_validation`:

- **Single-threaded**: `stateless_validation` executes the entire block sequentially
- **Parallel**: Subblock validation splits work across workers, then aggregates

Both produce the same result for valid blocks. Subblock validation enables:
- Parallel proving for ZK systems
- Distributed validation across multiple machines
- Faster block validation on multi-core systems

## See Also

- [EIP-7928: Block-level Access Lists](https://eips.ethereum.org/EIPS/eip-7928)
- [Stateless validation module](../src/validation.rs)
- [`SubblockInput`](../src/subblock/types.rs)
- [`subblock_validation`](../src/subblock/worker.rs)
- [`aggregation_validation`](../src/subblock/aggregator.rs)
