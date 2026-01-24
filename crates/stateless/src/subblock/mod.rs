//! Subblock proving module for parallelized block validation.
//!
//! This module provides types and functions for splitting block validation into
//! parallelizable pieces using EIP-7928 Block Access Lists (BALs).

mod types;

pub use types::{AggregationInput, SubblockInput, SubblockOutput};
