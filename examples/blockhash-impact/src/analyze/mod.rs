//! Offline analysis of blockhash-impact parquet outputs.
//!
//! Reads two parquet files (canonical and EIP-7709 simulation), joins by
//! `(block_number, tx_hash, event_index)`, and prints a BLOCKHASH usage report. See [`report`] for
//! the report shape and what each section means.

mod parquet_reader;
mod report;

pub use parquet_reader::read_rows;
pub use report::{
    build_report, print_report, Report, RepricingSplit, TopEntry, TopSection, WindowSplit,
};

use eyre::Context as _;
use std::path::PathBuf;

/// Configuration for the analyze subcommand.
#[derive(Debug, Clone)]
pub struct AnalyzeConfig {
    /// Parquet produced by a canonical scan (no `--simulate-eip7709`).
    pub canonical: PathBuf,
    /// Parquet produced by `scan --simulate-eip7709`.
    pub eip7709: PathBuf,
    /// How many entries to include in each top-N listing.
    pub top_n: usize,
}

/// Reads, joins, and prints the report. Returns the joined row count.
pub fn run(config: AnalyzeConfig) -> eyre::Result<usize> {
    let canonical = read_rows(&config.canonical)
        .wrap_err_with(|| format!("failed to read canonical parquet at {:?}", config.canonical))?;
    let eip7709 = read_rows(&config.eip7709)
        .wrap_err_with(|| format!("failed to read EIP-7709 parquet at {:?}", config.eip7709))?;

    eprintln!(
        "loaded canonical={} rows ({:?}), eip7709={} rows ({:?})",
        canonical.len(),
        config.canonical,
        eip7709.len(),
        config.eip7709,
    );

    let report = build_report(&canonical, &eip7709, config.top_n);
    print_report(&report);
    Ok(report.joined_rows)
}
