//! Provides types and functions for stateless execution and validation of Ethereum blocks.
//!
//! This crate enables the verification of block execution without requiring access to a
//! full node's persistent database. Instead, it relies on pre-generated "witness" data
//! that proves the specific state accessed during the block's execution.
//!
//! # Key Components
//!
//! * `WitnessDatabase`: An implementation of [`reth_revm::Database`] that uses a
//!   [`reth_trie_sparse::SparseStateTrie`] populated from witness data, along with provided
//!   bytecode and ancestor block hashes, to serve state reads during execution.
//! * `stateless_validation`: The core function that orchestrates the stateless validation process.
//!   It takes a block, its execution witness, ancestor headers, and chain specification, then
//!   performs:
//!     1. Witness verification against the parent block's state root.
//!     2. Block execution using the `WitnessDatabase`.
//!     3. Post-execution consensus checks.
//!     4. Post-state root calculation and comparison against the block header.
//!
//! # Usage
//!
//! The primary entry point is typically the `validation::stateless_validation` function. Callers
//! need to provide the block to be validated along with accurately generated `ExecutionWitness`
//! data corresponding to that block's execution trace and the necessary Headers of ancestor
//! blocks.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![no_std]

extern crate alloc;

mod recover_block;
/// Sparse trie implementation for stateless validation
pub mod trie;

pub mod flat_witness;

use alloy_genesis::ChainConfig;
#[doc(inline)]
pub use recover_block::UncompressedPublicKey;
#[doc(inline)]
pub use trie::StatelessTrie;
#[doc(inline)]
pub use validation::stateless_validation_with_trie;

pub use alloy_genesis::Genesis;

/// Implementation of stateless validation
pub mod validation;
pub(crate) mod witness_db;

#[doc(inline)]
pub use alloy_rpc_types_debug::ExecutionWitness;

use reth_ethereum_primitives::Block;

use crate::flat_witness::{FlatExecutionWitness, PrePostStateWitness};

/// `StatelessInput` is a convenience structure for serializing the input needed
/// for the stateless validation function.
pub type StatelessInput = GenericStatelessInput<ExecutionWitness>;

/// `StatelessExecutionInput` is a convenience structure for serializing the input needed
/// for an execution-only stateless validation function.
pub type StatelessExecutionInput = GenericStatelessInput<FlatExecutionWitness>;

/// `StatelessInputPrePostState` is a convenience structure for serializing the input needed
/// for a pre and post state validation.
pub type StatelessInputPrePostState = GenericStatelessInput<PrePostStateWitness>;

/// Generic structure for stateless validation input.
#[serde_with::serde_as]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct GenericStatelessInput<Witness> {
    /// The block being executed in the stateless validation function
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<reth_ethereum_primitives::TransactionSigned, alloy_consensus::Header>"
    )]
    pub block: Block,
    /// `FlatExecutionWitness` for the stateless validation function
    pub witness: Witness,
    /// Chain configuration for the stateless validation function
    #[serde_as(as = "alloy_genesis::serde_bincode_compat::ChainConfig<'_>")]
    pub chain_config: ChainConfig,
}

/// Tracks the amount of cycles a region of code takes up
/// in a zkvm environment and is no-op otherwise.
#[macro_export]
macro_rules! track_cycles {
    ($name:expr, $body:expr) => {{
        #[cfg(target_os = "zkvm")]
        {
            // tracing::info!("cycle-tracker-report-start: {}", $name);
            let result = $body;
            // tracing::info!("cycle-tracker-report-end: {}", $name);
            result
        }

        #[cfg(not(target_os = "zkvm"))]
        $body
    }};
}
