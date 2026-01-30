//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using [EIP-7928] Block Access Lists (BALs).
//!
//! # Architecture
//!
//! The module follows a two-phase design:
//!
//! 1. **Worker Phase** ([`subblock_validation`]): Multiple workers execute disjoint
//!    transaction ranges in parallel using BAL fast-forwarding
//! 2. **Aggregation Phase** ([`aggregation_validation`]): A single aggregator combines
//!    worker outputs, validates the post-state root, and produces the block hash
//!
//! # BAL Index Semantics (EIP-7928)
//!
//! BAL indices map to block execution phases:
//!
//! | Index | Operation |
//! |-------|-----------|
//! | `0` | Pre-execution (beacon root, blockhashes) |
//! | `1..N` | Transactions (tx `i-1` at index `i`) |
//! | `N+1` | Post-execution (withdrawals) |
//!
//! For a block with N transactions, the full BAL range is `[0, N+2)`.
//!
//! # Example
//!
//! ```ignore
//! // Split a block with 100 transactions into 4 subblocks
//! let subblock_ranges = [0..27, 27..52, 52..77, 77..102];
//!
//! // Execute subblocks in parallel (each produces SubblockOutput)
//! let outputs: Vec<SubblockOutput> = subblock_ranges
//!     .par_iter()
//!     .map(|range| {
//!         subblock_validation(SubblockInput {
//!             block: block.clone(),
//!             witness: witness.clone(),
//!             bal: bal.clone(),
//!             bal_range: range.clone(),
//!             chain_config,
//!         }, public_keys, chain_spec, evm_config)
//!     })
//!     .collect::<Result<_, _>>()?;
//!
//! // Aggregate results and compute final state root
//! let block_hash = aggregation_validation(AggregationInput {
//!     block,
//!     witness,
//!     bal,
//!     chain_config,
//!     subblock_outputs: outputs,
//!     bal_ranges: subblock_ranges.to_vec(),
//! }, public_keys, chain_spec)?;
//! ```
//!
//! # Key Concepts
//!
//! - **BAL Fast-Forwarding**: Reading state at any transaction index using the BAL,
//!   without re-executing prior transactions
//! - **Local vs Global Gas**: Subblocks track LOCAL cumulative gas (starting from 0);
//!   the aggregator adjusts to GLOBAL cumulative gas when combining outputs
//! - **Pre/Post Execution**: Only the first subblock runs pre-execution system calls;
//!   only the last subblock processes withdrawals
//!
//! # See Also
//!
//! - [EIP-7928]: Block-level Access Lists specification
//! - [`crate::validation::stateless_validation`]: Single-threaded stateless validation
//! - [Architecture documentation](../docs/subblock.md)
//!
//! [EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928

mod aggregator;
mod bal_state;
mod bal_validation;
mod bal_witness_db;
mod error;
mod execution;
mod types;
mod worker;

pub use aggregator::aggregation_validation;
pub use bal_state::{bal_to_hashed_post_state, PreStateAccountProvider};
pub use error::{AggregationValidationError, SubblockValidationError};
pub use execution::create_subblock_execution_ctx;
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
pub use worker::subblock_validation;

use bal_validation::validate_subblock_bal;
pub(crate) use bal_witness_db::BalWitnessDatabase;
