//! Print archive tip and approximate block numbers for common time windows.
//!
//! Opens the datadir read-only, reads the tip block number, and estimates blocks for
//! 1 week / 1 month / 3 months / 6 months / 1 year ago assuming a 12 s block time.

use reth_chainspec::MAINNET;
use reth_ethereum::node::EthereumNode;
use reth_provider::{providers::ReadOnlyConfig, BlockNumReader};
use reth_tasks::Runtime;
use std::path::PathBuf;

const SECS_PER_BLOCK: u64 = 12;
const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// Configuration for the `info` subcommand.
#[derive(Debug, Clone)]
pub struct InfoConfig {
    pub datadir: PathBuf,
}

/// Reads the tip and prints approximate block numbers for common time windows.
pub fn run(config: InfoConfig) -> eyre::Result<()> {
    let runtime = Runtime::test();
    let provider_factory = EthereumNode::provider_factory_builder().open_read_only(
        MAINNET.clone(),
        ReadOnlyConfig::from_datadir(&config.datadir).disable_long_read_transaction_safety(),
        runtime,
    )?;
    let tip = provider_factory.provider()?.best_block_number()?;

    println!("latest_block: {tip}");

    let windows: &[(&str, u64)] = &[
        ("1 day", SECS_PER_DAY),
        ("1 week", 7 * SECS_PER_DAY),
        ("1 month", 30 * SECS_PER_DAY),
        ("3 months", 90 * SECS_PER_DAY),
        ("6 months", 180 * SECS_PER_DAY),
        ("1 year", 365 * SECS_PER_DAY),
    ];

    for (label, delta_secs) in windows {
        let blocks_back = delta_secs / SECS_PER_BLOCK;
        let block = tip.saturating_sub(blocks_back);
        println!("{label:>9} ago: block~={block} (~{blocks_back} blocks back @ 12s/block)");
    }

    Ok(())
}
