//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod aggregator;
mod bal_state;
mod bal_witness_db;
mod error;
mod types;
mod worker;

pub use aggregator::aggregation_validation;
pub use bal_state::bal_to_hashed_post_state;
pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
pub use worker::subblock_validation;

pub(crate) use bal_witness_db::BalWitnessDatabase;
