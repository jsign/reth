#![allow(missing_docs)]

use alloy_primitives::{map::HashMap, Address, Bytes, B256, U256};
use reth_revm::{
    db::{Cache, DbAccount},
    state::Bytecode,
};
use serde_with::{DeserializeAs, SerializeAs};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheBincode {
    pub accounts: HashMap<Address, DbAccount>,
    pub contracts: HashMap<B256, Bytes>,
    pub block_hashes: HashMap<U256, B256>,
}

impl SerializeAs<Cache> for CacheBincode {
    fn serialize_as<S>(source: &Cache, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::Serialize;
        let cache_bincode = Self {
            accounts: source.accounts.clone(),
            contracts: source.contracts.iter().map(|(k, v)| (*k, v.original_bytes())).collect(),
            block_hashes: source.block_hashes.clone(),
        };
        cache_bincode.serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, Cache> for CacheBincode {
    fn deserialize_as<D>(deserializer: D) -> Result<Cache, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;
        let cache_bincode = Self::deserialize(deserializer)?;
        Ok(Cache {
            accounts: cache_bincode.accounts,
            contracts: cache_bincode
                .contracts
                .into_iter()
                .map(|(k, v)| (k, Bytecode::new_raw(v)))
                .collect(),
            logs: Default::default(),
            block_hashes: cache_bincode.block_hashes,
        })
    }
}
