#![warn(unused_crate_dependencies)]

use core::panic;
use std::sync::Arc;

use alloy_primitives::{keccak256, Bytes, U256};
use alloy_rlp::Encodable;
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    evm::{
        primitives::{execute::Executor, ConfigureEvm},
        revm::{database::StateProviderDatabase, db::AccountState, State},
        EthEvmConfig,
    },
    network::types::BlockHashOrNumber,
    node::EthereumNode,
    primitives::AlloyBlockHeader,
    provider::{providers::ReadOnlyConfig, BlockReader},
    TransactionSigned,
};
use reth_execution_types::witness::FlatWitnessRecord;
use reth_stateless::{flat_witness::FlatExecutionWitness, UncompressedPublicKey};
use reth_storage_api::HeaderProvider;
use revm::Database;

fn main() -> eyre::Result<()> {
    let datadir = std::env::var("RETH_DATADIR")?;
    let chain_spec = Arc::new(ChainSpecBuilder::mainnet().build());
    let factory = EthereumNode::provider_factory_builder()
        .open_read_only(chain_spec.clone(), ReadOnlyConfig::from_datadir(datadir))?;

    let provider = factory.provider()?;

    let block = provider
        .recovered_block(BlockHashOrNumber::Number(23175588), Default::default())
        .unwrap()
        .unwrap();

    let state_provider = provider.history_by_block_hash(block.parent_hash()).unwrap();

    let block_number = block.header().number();
    println!("Executing block number: {block_number}");

    let evm_config = EthEvmConfig::new(chain_spec.clone());
    let db = StateProviderDatabase::new(state_provider);
    let block_executor = evm_config.executor(db);

    let mut witness_record = FlatWitnessRecord::default();
    let mut lowest_block_number = Default::default();

    let _ = block_executor
        .execute_with_state_closure(&block, |statedb: &State<_>| {
            witness_record.record_executed_state(statedb);
            lowest_block_number = statedb.block_hashes.keys().next().copied()
        })
        .unwrap();

    let state_provider = provider.history_by_block_hash(block.parent_hash()).unwrap();
    let pre_state = state_provider.flat_witness(witness_record).unwrap();

    let smallest = match lowest_block_number {
        Some(smallest) => smallest,
        None => {
            // Return only the parent header, if there were no calls to the
            // BLOCKHASH opcode.
            block_number.saturating_sub(1)
        }
    };

    let range = smallest..block_number;

    let headers: Vec<Bytes> = provider
        .headers_range(range.clone())
        .unwrap()
        .into_iter()
        .map(|header| {
            let mut serialized_header = Vec::new();
            header.encode(&mut serialized_header);
            serialized_header.into()
        })
        .collect();

    let block_hashes =
        headers.iter().zip(range).map(|(bytes, num)| (U256::from(num), keccak256(bytes))).collect();

    let parent = headers.last().unwrap().clone();
    let flat_witness = FlatExecutionWitness::new(pre_state, block_hashes, parent);

    let mut db = StateProviderDatabase::new(state_provider);
    for (address, flatdb_account) in flat_witness.state.accounts.iter() {
        let trie_account = db.basic(*address).unwrap();
        let flatdb_account_info = (flatdb_account.account_state != AccountState::NotExisting)
            .then_some(flatdb_account.clone().info);

        if trie_account != flatdb_account_info {
            panic!(
                "Mismatch in account info for address {:?}: trie={:?}, flatdb={:?}",
                address, trie_account, flatdb_account_info
            );
        }

        for (slot, value) in flatdb_account.storage.iter() {
            let trie_value = db.storage(*address, *slot).unwrap();
            if trie_value != *value {
                panic!(
                    "Mismatch in storage for address {:?} at slot {:?}: trie={:?}, flatdb={:?}",
                    address, slot, trie_value, value
                );
            }
        }
    }

    let public_keys = recover_signers(block.body().transactions())
        .expect("Failed to recover public keys from transaction signatures");

    reth_stateless::stateless_validation_with_flatdb(
        block.into_block(),
        public_keys,
        flat_witness,
        chain_spec,
        evm_config,
    )
    .unwrap();

    Ok(())
}

fn recover_signers<'a, I>(txs: I) -> Result<Vec<UncompressedPublicKey>, Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = &'a TransactionSigned>,
{
    txs.into_iter()
        .enumerate()
        .map(|(i, tx)| {
            tx.signature()
                .recover_from_prehash(&tx.signature_hash())
                .map(|keys| {
                    UncompressedPublicKey(
                        keys.to_encoded_point(false).as_bytes().try_into().unwrap(),
                    )
                })
                .map_err(|e| format!("failed to recover signature for tx #{i}: {e}").into())
        })
        .collect::<Result<Vec<UncompressedPublicKey>, _>>()
}
