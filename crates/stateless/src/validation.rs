use crate::{
    flat_witness::FlatExecutionWitness,
    recover_block::{recover_block_with_public_keys, UncompressedPublicKey},
    track_cycles,
    trie::{StatelessSparseTrie, StatelessTrie},
    witness_db::WitnessDatabase,
    ExecutionWitness,
};
use alloc::{
    collections::BTreeMap,
    fmt::Debug,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::{keccak256, map::HashMap, Bytes, B256, U256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{Consensus, HeaderValidator};
use reth_errors::ConsensusError;
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_execution_types::FlatPreState;
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use reth_revm::{
    db::{AccountState, Cache},
    Database,
};
use reth_trie_common::{HashedPostState, KeccakKeyHasher};

/// BLOCKHASH ancestor lookup window limit per EVM (number of most recent blocks accessible).
const BLOCKHASH_ANCESTOR_LIMIT: usize = 256;

/// Errors that can occur during stateless validation.
#[derive(Debug, thiserror::Error)]
pub enum StatelessValidationError {
    /// Error when the number of ancestor headers exceeds the limit.
    #[error("ancestor header count ({count}) exceeds limit ({limit})")]
    AncestorHeaderLimitExceeded {
        /// The number of headers provided.
        count: usize,
        /// The limit.
        limit: usize,
    },

    /// Error when the ancestor headers do not form a contiguous chain.
    #[error("invalid ancestor chain")]
    InvalidAncestorChain,

    /// Error when revealing the witness data failed.
    #[error("failed to reveal witness data for pre-state root {pre_state_root}")]
    WitnessRevealFailed {
        /// The pre-state root used for verification.
        pre_state_root: B256,
    },

    /// Error during stateless block execution.
    #[error("stateless block execution failed")]
    StatelessExecutionFailed(String),

    /// Error during consensus validation of the block.
    #[error("consensus validation failed: {0}")]
    ConsensusValidationFailed(#[from] ConsensusError),

    /// Error during stateless state root calculation.
    #[error("stateless state root calculation failed")]
    StatelessStateRootCalculationFailed,

    /// Error calculating the pre-state root from the witness data.
    #[error("stateless pre-state root calculation failed")]
    StatelessPreStateRootCalculationFailed,

    /// Error when required ancestor headers are missing (e.g., parent header for pre-state root).
    #[error("missing required ancestor headers")]
    MissingAncestorHeader,

    /// Error when deserializing ancestor headers
    #[error("could not deserialize ancestor headers")]
    HeaderDeserializationFailed,

    /// Error when the computed state root does not match the one in the block header.
    #[error("mismatched post-state root: {got}\n {expected}")]
    PostStateRootMismatch {
        /// The computed post-state root
        got: B256,
        /// The expected post-state root; in the block header
        expected: B256,
    },

    /// Error when the computed pre-state root does not match the expected one.
    #[error("mismatched pre-state root: {got} \n {expected}")]
    PreStateRootMismatch {
        /// The computed pre-state root
        got: B256,
        /// The expected pre-state root from the previous block
        expected: B256,
    },

    /// Error during signer recovery.
    #[error("signer recovery failed")]
    SignerRecovery,

    /// Error when signature has non-normalized s value in homestead block.
    #[error("signature s value not normalized for homestead block")]
    HomesteadSignatureNotNormalized,

    /// Custom error.
    #[error("{0}")]
    Custom(&'static str),

    /// Error validating the flatdb against the sparse trie witness.
    #[error("flatdb and sparse trie validation mismatch")]
    FlatdbSparseTrieMismatch,

    /// Error when a block hash in flatdb does not match the expected ancestor hash.
    #[error("flatdb ancestor hash not found in witness for block {block_number}: got {got}, expected {expected:?}")]
    FlatdbAncestorHashNotFound {
        /// The block number being checked.
        block_number: u64,
        /// The block hash from flatdb.
        got: B256,
        /// The expected block hash from the witness.
        expected: Option<B256>,
    },

    /// Error when flatdb bytecode hash does not match the computed hash.
    #[error("flatdb bytecode hash mismatch: computed {got}, expected {expected}")]
    FlatdbBytecodeHashMismatch {
        /// The computed hash from the bytecode.
        got: B256,
        /// The expected code hash from flatdb.
        expected: B256,
    },

    /// Error when flatdb account state does not match the trie witness.
    #[error("flatdb account state mismatch with trie witness for address {address}")]
    FlatdbAccountStateMismatch {
        /// The address of the account with mismatched state.
        address: alloy_primitives::Address,
    },

    /// Error when flatdb storage slot state does not match the trie witness.
    #[error("flatdb storage slot state mismatch with trie witness for address {address}")]
    FlatdbStorageSlotStateMismatch {
        /// The address of the account with mismatched state.
        address: alloy_primitives::Address,
        /// The storage slot with mismatched state.
        slot: alloy_primitives::U256,
    },

    /// Error getting account from the witness database.
    #[error("getting account from witness database")]
    GetAccountFromWitnessDatabase,

    /// Error getting storage slot from the witness database.
    #[error("getting storage slot from witness database")]
    GetStorageSlotFromWitnessDatabase,
}

/// Performs stateless validation of a block using the provided witness data.
///
/// This function attempts to fully validate a given `current_block` statelessly, ie without access
/// to a persistent database.
/// It relies entirely on the `witness` data and `ancestor_headers`
/// provided alongside the block.
///
/// The witness data is validated in the following way:
///
/// 1. **Ancestor Header Verification:** Checks if the `ancestor_headers` are present, form a
///    contiguous chain back from `current_block`'s parent, and do not exceed the `BLOCKHASH` opcode
///    limit using `compute_ancestor_hashes`. We must have at least one ancestor header, even if the
///    `BLOCKHASH` opcode is not used because we need the state root of the previous block to verify
///    the pre state reads.
///
/// 2. **Pre-State Verification:** Retrieves the expected `pre_state_root` from the parent header
///    from `ancestor_headers`. Verifies the provided [`ExecutionWitness`] against the
///    `pre_state_root`.
///
/// 3. **Chain Verification:** The code currently does not verify the [`EthChainSpec`] and expects a
///    higher level function to assert that this is correct by, for example, asserting that it is
///    equal to the Ethereum Mainnet `ChainSpec` or asserting against the genesis hash that this
///    `ChainSpec` defines.
///
/// High Level Overview of functionality:
///
/// - Verify all state accesses against a trusted pre-state root
/// - Put all state accesses into an in-memory database
/// - Use the in-memory database to execute the block
/// - Validate the output of block execution (e.g. receipts, logs, requests)
/// - Compute the post-state root using the state-diff from block execution
/// - Check that the post-state root is the state root in the block.
///
/// If all steps succeed the function returns `Some` containing the hash of the validated
/// `current_block`.
pub fn stateless_validation<ChainSpec, E>(
    current_block: Block,
    public_keys: Vec<UncompressedPublicKey>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<B256, StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    let (hash, _) = stateless_validation_with_trie::<StatelessSparseTrie, ChainSpec, E>(
        current_block,
        public_keys,
        witness,
        chain_spec,
        evm_config,
    )?;
    Ok(hash)
}

/// Performs stateless validation of a block using a custom `StatelessTrie` implementation.
///
/// This is a generic version of `stateless_validation` that allows users to provide their own
/// implementation of the `StatelessTrie` for custom trie backends or optimizations.
///
/// See `stateless_validation` for detailed documentation of the validation process.
pub fn stateless_validation_with_trie<T, ChainSpec, E>(
    current_block: Block,
    public_keys: Vec<UncompressedPublicKey>,
    witness: ExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<(B256, HashedPostState), StatelessValidationError>
where
    T: StatelessTrie,
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    let ExecutionContext { block, parent, ancestor_hashes } = prepare_execution_context(
        current_block,
        public_keys,
        &witness.headers,
        chain_spec.clone(),
    )?;

    // Verify that the pre-state reads are correct
    let (mut trie, bytecode) =
        track_cycles!("verify_witness", T::new(&witness, parent.state_root)?);
    let db = WitnessDatabase::new(&trie, bytecode, ancestor_hashes);

    let hashed_post_state =
        stateless_validation_execution(&block, &parent, chain_spec, evm_config, db)?;

    // Compute and check the post state root
    track_cycles!("post_state_compute", {
        let state_root = trie.calculate_state_root(hashed_post_state.clone())?;
        if state_root != block.state_root {
            return Err(StatelessValidationError::PostStateRootMismatch {
                got: state_root,
                expected: block.state_root,
            });
        }
    });

    // Return block hash
    Ok((block.hash_slow(), hashed_post_state))
}

/// Performs stateless validation of a block using a flatdb execution witness.
pub fn stateless_validation_with_flatdb<ChainSpec, E>(
    current_block: Block,
    public_keys: Vec<UncompressedPublicKey>,
    witness: FlatExecutionWitness,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
) -> Result<(B256, HashedPostState), StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    let recovered_block = recover_block_with_public_keys(current_block, public_keys, &*chain_spec)?;

    let hash = keccak256(&witness.parent_header);
    let parent_header = alloy_rlp::decode_exact::<Header>(&witness.parent_header)
        .map(|h| SealedHeader::new(h, hash))
        .map_err(|_| StatelessValidationError::HeaderDeserializationFailed)?;
    let db = witness.create_db();

    let hashed_post_state = stateless_validation_execution(
        &recovered_block,
        &parent_header,
        chain_spec,
        evm_config,
        db,
    )?;

    Ok((recovered_block.hash_slow(), hashed_post_state))
}

/// Executes the block statelessly with a provided `Database` and performs post-execution
/// validation.
fn stateless_validation_execution<DB: reth_evm::Database, ChainSpec, E>(
    current_block: &RecoveredBlock<Block>,
    parent: &SealedHeader,
    chain_spec: Arc<ChainSpec>,
    evm_config: E,
    db: DB,
) -> Result<HashedPostState, StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
    E: ConfigureEvm<Primitives = EthPrimitives> + Clone + 'static,
{
    // Validate block against pre-execution consensus rules
    validate_block_consensus(chain_spec.clone(), current_block, parent)?;

    // Execute the block
    let executor = evm_config.executor(db);
    let output = track_cycles!(
        "block_execution",
        executor
            .execute(current_block)
            .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?
    );

    // Post validation checks
    validate_block_post_execution(current_block, &chain_spec, &output.receipts, &output.requests)
        .map_err(StatelessValidationError::ConsensusValidationFailed)?;

    Ok(HashedPostState::from_bundle_state::<KeccakKeyHasher>(&output.state.state))
}

/// Cross-validates flatdb state against a cryptographically verified sparse trie witness.
///
/// Flatdb provides optimized flat storage for EVM execution, but lacks cryptographic
/// verification. This function ensures flatdb was correctly constructed by checking that:
/// - Block hashes match between flatdb and the verified trie witness
/// - Contract bytecode hashes are correct
/// - Account state matches the sparse trie (witness may contain extra accounts; that's ok)
/// - Post-state root computed from flatdb matches the block header
///
/// Returns block hash if all validations pass.
pub fn stateless_validation_flatdb_storage_check<T>(
    current_block: Block,
    trie_witness: ExecutionWitness,
    flatdb_pre_state: FlatPreState,
    block_hashes: BTreeMap<U256, B256>,
    flatdb_post_state: HashedPostState,
) -> Result<B256, StatelessValidationError>
where
    T: StatelessTrie,
{
    let sealed_block = reth_primitives_traits::Block::seal_slow(current_block);
    let (parent, ancestor_hashes) =
        parse_and_validate_ancestor_chain(&sealed_block, &trie_witness.headers)?;

    // Verify that the flatdb block hashes map was correctly constructed.
    track_cycles!("verify_flatdb_block_hashes", {
        for (block_num, block_hash) in block_hashes {
            let block_num = block_num.try_into().unwrap();
            match ancestor_hashes.get(&block_num) {
                Some(expected_hash) if *expected_hash == block_hash => {}
                _ => {
                    return Err(StatelessValidationError::FlatdbAncestorHashNotFound {
                        block_number: block_num,
                        got: block_hash,
                        expected: ancestor_hashes.get(&block_num).copied(),
                    })
                }
            }
        }
    });

    // Verify that the contract code hashed map was correctly constructed.
    track_cycles!("verify_flatdb_bytecodes", {
        for (expected_codehash, flatdb_code) in &flatdb_pre_state.contracts {
            let got_codehash = keccak256(flatdb_code);
            if got_codehash != *expected_codehash {
                return Err(StatelessValidationError::FlatdbBytecodeHashMismatch {
                    got: got_codehash,
                    expected: *expected_codehash,
                });
            }
        }
    });

    // Verify the trie witness so we have a cryptographically verified state to compare against.
    let (mut trie, _) =
        track_cycles!("verify_trie_witness", T::new(&trie_witness, parent.state_root)?);

    // Verify that all accounts in flatdb pre-state match those in the trie witness.
    track_cycles!("verify_flatdb_state_against_trie", {
        // For bytecodes we pass Default::default() since the WitnessDatabase won't be used for
        // checking bytecode. We already did it above by checking that the flatdb bytecodes
        // hashes match. If the flatdb accounts contains an account with a code_hash not
        // present in the bytecode map, then the execution would have failed since
        // the code would be missing.
        let mut db = WitnessDatabase::new(&trie, Default::default(), ancestor_hashes);
        for (address, flatdb_account) in flatdb_pre_state.accounts {
            let trie_account = db
                .basic(address)
                .map_err(|_| StatelessValidationError::GetAccountFromWitnessDatabase)?;
            let flatdb_account_info = (flatdb_account.account_state != AccountState::NotExisting)
                .then_some(flatdb_account.info);

            if trie_account != flatdb_account_info {
                return Err(StatelessValidationError::FlatdbAccountStateMismatch { address });
            }
            for (slot, value) in flatdb_account.storage {
                let trie_value = db
                    .storage(address, slot)
                    .map_err(|_| StatelessValidationError::GetStorageSlotFromWitnessDatabase)?;
                if trie_value != value {
                    return Err(StatelessValidationError::FlatdbStorageSlotStateMismatch {
                        address,
                        slot,
                    });
                }
            }
        }
    });

    // Compute and check the post state root using the provided post-state from the execution using
    // flatdb state.
    track_cycles!("post_state_compute", {
        let state_root = trie.calculate_state_root(flatdb_post_state)?;
        if state_root != sealed_block.state_root {
            return Err(StatelessValidationError::PostStateRootMismatch {
                got: state_root,
                expected: sealed_block.state_root,
            });
        }
    });

    Ok(sealed_block.hash())
}

/// Execution context prepared from witness data for stateless block validation.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// The current block being validated, with transaction signers recovered from signatures.
    pub block: RecoveredBlock<Block>,
    /// The immediate parent header, containing the pre-state root required for witness
    /// verification.
    pub parent: SealedHeader,
    /// Map of ancestor block numbers to their hashes, used for BLOCKHASH opcode lookups.
    /// Limited to 256 most recent blocks per EVM specification.
    pub ancestor_hashes: BTreeMap<u64, B256>,
}

/// Extracts and validates the core witness components required for stateless execution.
///
/// This function prepares three essential components from raw witness data:
/// 1. **Recovered Block**: Validates and recovers transaction signers using provided public keys
/// 2. **Parent Header**: The immediate ancestor header containing the pre-state root
/// 3. **Ancestor Hashes**: Block hash map for BLOCKHASH opcode support (up to 256 blocks)
///
/// The ancestor headers must form a contiguous chain leading to `current_block`'s parent.
/// At least one ancestor header (the parent) is required for pre-state root verification.
pub fn prepare_execution_context<ChainSpec>(
    current_block: Block,
    public_keys: Vec<UncompressedPublicKey>,
    headers: &[Bytes],
    chain_spec: Arc<ChainSpec>,
) -> Result<ExecutionContext, StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
{
    let block = recover_block_with_public_keys(current_block, public_keys, &*chain_spec)?;
    let (parent, ancestor_hashes) = parse_and_validate_ancestor_chain(&block, headers)?;

    Ok(ExecutionContext { block, parent, ancestor_hashes })
}

/// Deserializes, validates, and extracts ancestor headers from raw witness data.
pub fn parse_and_validate_ancestor_chain(
    current_block: &SealedBlock<Block>,
    headers: &[Bytes],
) -> Result<(SealedHeader, BTreeMap<u64, B256>), StatelessValidationError> {
    let mut ancestor_headers: Vec<_> = headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes)
                .map(|h| SealedHeader::new(h, hash))
                .map_err(|_| StatelessValidationError::HeaderDeserializationFailed)
        })
        .collect::<Result<_, _>>()?;
    // Sort the headers by their block number to ensure that they are in
    // ascending order.
    ancestor_headers.sort_by_key(|header| header.number());

    // Enforce BLOCKHASH ancestor headers limit (256 most recent blocks)
    let count = ancestor_headers.len();
    if count > BLOCKHASH_ANCESTOR_LIMIT {
        return Err(StatelessValidationError::AncestorHeaderLimitExceeded {
            count,
            limit: BLOCKHASH_ANCESTOR_LIMIT,
        });
    }

    // Check that the ancestor headers form a contiguous chain and are not just random headers.
    let ancestor_hashes = compute_ancestor_hashes(current_block, &ancestor_headers)?;

    // There should be at least one ancestor header.
    // The edge case here would be the genesis block, but we do not create proofs for the genesis
    // block.
    let parent = match ancestor_headers.last() {
        Some(prev_header) => prev_header,
        None => return Err(StatelessValidationError::MissingAncestorHeader),
    };

    Ok((parent.clone(), ancestor_hashes))
}

/// Performs consensus validation checks on a block without execution or state validation.
///
/// This function validates a block against Ethereum consensus rules by:
///
/// 1. **Header Validation:** Validates the sealed header against protocol specifications,
///    including:
///    - Gas limit checks
///    - Base fee validation for EIP-1559
///    - Withdrawals root validation for Shanghai fork
///    - Blob-related fields validation for Cancun fork
///
/// 2. **Pre-Execution Validation:** Validates block structure, transaction format, signature
///    validity, and other pre-execution requirements.
///
/// This function acts as a preliminary validation before executing and validating the state
/// transition function.
fn validate_block_consensus<ChainSpec>(
    chain_spec: Arc<ChainSpec>,
    block: &RecoveredBlock<Block>,
    parent: &SealedHeader<Header>,
) -> Result<(), StatelessValidationError>
where
    ChainSpec: Send + Sync + EthChainSpec<Header = Header> + EthereumHardforks + Debug,
{
    let consensus = EthBeaconConsensus::new(chain_spec);

    consensus.validate_header(block.sealed_header())?;
    consensus.validate_header_against_parent(block.sealed_header(), parent)?;

    consensus.validate_block_pre_execution(block)?;

    Ok(())
}

/// Verifies the contiguity, number of ancestor headers and extracts their hashes.
///
/// This function is used to prepare the data required for the `BLOCKHASH`
/// opcode in a stateless execution context.
///
/// It verifies that the provided `ancestor_headers` form a valid, unbroken chain leading back from
///    the parent of the `current_block`.
///
/// Note: This function becomes obsolete if EIP-2935 is implemented.
/// Note: The headers are assumed to be in ascending order.
///
/// If both checks pass, it returns a [`BTreeMap`] mapping the block number of each
/// ancestor header to its corresponding block hash.
fn compute_ancestor_hashes(
    current_block: &SealedBlock<Block>,
    ancestor_headers: &[SealedHeader],
) -> Result<BTreeMap<u64, B256>, StatelessValidationError> {
    let mut ancestor_hashes = BTreeMap::new();

    let mut child_header = current_block.sealed_header();

    // Next verify that headers supplied are contiguous
    for parent_header in ancestor_headers.iter().rev() {
        let parent_hash = child_header.parent_hash();
        ancestor_hashes.insert(parent_header.number, parent_hash);

        if parent_hash != parent_header.hash() {
            return Err(StatelessValidationError::InvalidAncestorChain); // Blocks must be contiguous
        }

        if parent_header.number + 1 != child_header.number {
            return Err(StatelessValidationError::InvalidAncestorChain); // Header number should be
                                                                        // contiguous
        }

        child_header = parent_header
    }

    Ok(ancestor_hashes)
}
