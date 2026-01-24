//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod error;
mod types;

pub use error::{AggregationValidationError, SubblockValidationError};
pub use types::{AggregationInput, SubblockInput, SubblockOutput};
