use clap::{Parser, Subcommand};
use example_blockhash_impact::{
    analyze::{self, AnalyzeConfig},
    info::{self, InfoConfig},
    scan_archive, ScanConfig,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Replay a canonical mainnet archive range and analyze BLOCKHASH usage \
             under both the canonical and EIP-7709 cost models")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Replay a block range and emit paired EIP-7709 impact datasets.
    Scan(ScanArgs),
    /// Read a scan output directory and print the gas and breakage report.
    Analyze(AnalyzeArgs),
    /// Print the latest available block and approximate blocks 1w/1m/3m/6m/1y ago.
    Info(InfoArgs),
}

#[derive(Debug, Parser)]
struct InfoArgs {
    /// Path to the canonical mainnet archive datadir. Opened read-only.
    #[arg(long)]
    datadir: PathBuf,
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// Path to the canonical mainnet archive datadir. Opened read-only.
    #[arg(long)]
    datadir: PathBuf,

    /// First block to scan, inclusive.
    #[arg(long)]
    from: u64,

    /// Last block to scan, inclusive.
    #[arg(long)]
    to: u64,

    /// Output directory for events.parquet, transactions.parquet, and manifest.json.
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

    /// Verify replayed execution against canonical block outputs and state roots.
    ///
    /// This is significantly slower and uses more memory per worker.
    #[arg(long)]
    verify_execution: bool,
}

#[derive(Debug, Parser)]
struct AnalyzeArgs {
    /// Directory produced by `scan`.
    #[arg(long)]
    input: PathBuf,

    /// How many entries to print per top-N category.
    #[arg(long, default_value_t = 20)]
    top_n: usize,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Analyze(args) => run_analyze(args),
        Command::Info(args) => run_info(args),
    }
}

fn run_info(args: InfoArgs) -> eyre::Result<()> {
    info::run(InfoConfig { datadir: args.datadir })
}

fn run_scan(args: ScanArgs) -> eyre::Result<()> {
    let summary = scan_archive(ScanConfig {
        datadir: args.datadir,
        from: args.from,
        to: args.to,
        output: args.output,
        jobs: args.jobs,
        blocks_per_chunk: args.blocks_per_chunk,
        flush_rows: args.flush_rows,
        verify_execution: args.verify_execution,
    })?;

    println!(
        "Scanned blocks {}..={} in {:.2?} ({:.2} blocks/s)",
        summary.resolved_from,
        summary.resolved_to,
        summary.elapsed,
        summary.blocks_per_second()
    );
    println!(
        "blocks_scanned={} txs_scanned={} txs_with_blockhash={} blockhash_events={} simulation_errors={}",
        summary.blocks_scanned,
        summary.txs_scanned,
        summary.txs_with_blockhash,
        summary.blockhash_events,
        summary.simulation_errors,
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

fn run_analyze(args: AnalyzeArgs) -> eyre::Result<()> {
    analyze::run(AnalyzeConfig { input: args.input, top_n: args.top_n })?;
    Ok(())
}
