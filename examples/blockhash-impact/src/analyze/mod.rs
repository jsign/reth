//! Offline analysis of blockhash-impact parquet outputs.
//!
//! Reads the paired dataset directory emitted by `scan`.

mod parquet_reader;
mod report;

pub use parquet_reader::{read_rows, read_transactions};
pub use report::{
    build_dataset_report, build_report, print_report, AffectedContract, ImpactSummary, Report,
    RepricingSplit, TopEntry, TopSection, WindowSplit,
};

use eyre::Context as _;
use std::path::PathBuf;

/// Configuration for the analyze subcommand.
#[derive(Debug, Clone)]
pub struct AnalyzeConfig {
    pub input: PathBuf,
    /// How many entries to include in each top-N listing.
    pub top_n: usize,
}

/// Reads, joins, and prints the report. Returns the joined row count.
pub fn run(config: AnalyzeConfig) -> eyre::Result<usize> {
    let events_path = config.input.join("events.parquet");
    let transactions_path = config.input.join("transactions.parquet");
    let manifest_path = config.input.join("manifest.json");
    let manifest: crate::scan::Manifest = serde_json::from_slice(
        &reth_fs_util::read(&manifest_path)
            .wrap_err_with(|| format!("failed to read manifest at {manifest_path:?}"))?,
    )?;
    eyre::ensure!(manifest.complete, "dataset manifest reports incomplete coverage");
    eyre::ensure!(
        manifest.schema_version == 2,
        "unsupported dataset schema version {}",
        manifest.schema_version
    );
    eyre::ensure!(
        manifest.eip_revision == crate::eip7709::EIP7709_REVISION,
        "dataset targets EIP-7709 revision {}, expected {}",
        manifest.eip_revision,
        crate::eip7709::EIP7709_REVISION,
    );

    let events = read_rows(&events_path)
        .wrap_err_with(|| format!("failed to read events parquet at {events_path:?}"))?;
    let transactions = read_transactions(&transactions_path).wrap_err_with(|| {
        format!("failed to read transactions parquet at {transactions_path:?}")
    })?;
    eyre::ensure!(
        events.len() as u64 == manifest.blockhash_events,
        "event count does not match manifest: parquet={} manifest={}",
        events.len(),
        manifest.blockhash_events,
    );
    eyre::ensure!(
        transactions.len() as u64 == manifest.affected_transactions,
        "affected transaction count does not match manifest: parquet={} manifest={}",
        transactions.len(),
        manifest.affected_transactions,
    );
    let simulation_errors =
        transactions.iter().filter(|tx| tx.simulation_error.is_some()).count() as u64;
    eyre::ensure!(
        simulation_errors == manifest.simulation_errors,
        "simulation error count does not match manifest: parquet={simulation_errors} manifest={}",
        manifest.simulation_errors,
    );

    eprintln!(
        "loaded events={} affected_transactions={} blocks={}..={} verification={}",
        events.len(),
        transactions.len(),
        manifest.resolved_from,
        manifest.resolved_to,
        manifest.verification_status,
    );

    let report = build_dataset_report(&events, &transactions, config.top_n);
    print_report(&report);
    Ok(report.joined_rows)
}
