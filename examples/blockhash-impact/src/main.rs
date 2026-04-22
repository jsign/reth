use clap::Parser;
use example_blockhash_impact::{scan_archive, ScanConfig};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Replay a canonical mainnet archive range and export executed BLOCKHASH events")]
struct Cli {
    /// Path to the canonical mainnet archive datadir.
    #[arg(long)]
    datadir: PathBuf,

    /// First block to scan, inclusive.
    #[arg(long)]
    from: u64,

    /// Last block to scan, inclusive.
    #[arg(long)]
    to: u64,

    /// Output parquet path.
    #[arg(long)]
    output: PathBuf,

    /// Number of worker threads. Defaults to the number of available CPUs.
    #[arg(long)]
    jobs: Option<usize>,

    /// Number of blocks each worker claims at a time.
    #[arg(long, default_value_t = 2_000)]
    blocks_per_chunk: u64,

    /// Number of rows a worker buffers before flushing to the writer thread.
    #[arg(long, default_value_t = 10_000)]
    flush_rows: usize,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let summary = scan_archive(ScanConfig {
        datadir: cli.datadir,
        from: cli.from,
        to: cli.to,
        output: cli.output,
        jobs: cli.jobs,
        blocks_per_chunk: cli.blocks_per_chunk,
        flush_rows: cli.flush_rows,
    })?;

    println!(
        "Scanned blocks {}..={} in {:.2?} ({:.2} blocks/s)",
        summary.resolved_from,
        summary.resolved_to,
        summary.elapsed,
        summary.blocks_per_second()
    );
    println!(
        "blocks_scanned={} txs_scanned={} txs_with_blockhash={} blockhash_events={}",
        summary.blocks_scanned,
        summary.txs_scanned,
        summary.txs_with_blockhash,
        summary.blockhash_events
    );
    println!(
        "min_gas_before={} output={}",
        summary
            .min_observed_gas_before
            .map_or_else(|| "n/a".to_string(), |value| value.to_string()),
        summary.output.display()
    );

    Ok(())
}
