use clap::{Parser, Subcommand};
use example_blockhash_impact::{
    analyze::{self, AnalyzeConfig},
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
    /// Replay a block range and emit one parquet row per executed BLOCKHASH event.
    Scan(ScanArgs),
    /// Read a canonical and an EIP-7709 parquet and print the UX-impact report.
    Analyze(AnalyzeArgs),
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

    /// Verify replayed execution against canonical block outputs and state roots.
    ///
    /// This is significantly slower and uses more memory per worker.
    #[arg(long)]
    verify_execution: bool,

    /// Inject EIP-7709 SLOAD-equivalent gas at every BLOCKHASH and trigger OOG cascading when a
    /// frame can't afford it. Mutually exclusive with `--verify-execution` because injection
    /// diverges canonical state and breaks state-root validation.
    #[arg(long)]
    simulate_eip7709: bool,
}

#[derive(Debug, Parser)]
struct AnalyzeArgs {
    /// Parquet produced by a canonical scan (no `--simulate-eip7709`).
    #[arg(long)]
    canonical: PathBuf,

    /// Parquet produced by `scan --simulate-eip7709`.
    #[arg(long)]
    eip7709: PathBuf,

    /// How many entries to print per top-N category.
    #[arg(long, default_value_t = 20)]
    top_n: usize,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Analyze(args) => run_analyze(args),
    }
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
        simulate_eip7709: args.simulate_eip7709,
    })?;

    println!(
        "Scanned blocks {}..={} in {:.2?} ({:.2} blocks/s)",
        summary.resolved_from,
        summary.resolved_to,
        summary.elapsed,
        summary.blocks_per_second()
    );
    println!(
        "blocks_scanned={} txs_scanned={} txs_with_blockhash={} blockhash_events={} chunks_aborted={}",
        summary.blocks_scanned,
        summary.txs_scanned,
        summary.txs_with_blockhash,
        summary.blockhash_events,
        summary.chunks_aborted,
    );
    if summary.chunks_aborted > 0 {
        println!(
            "warning: {} chunk(s) were abandoned mid-execution due to EIP-7709 state divergence; \
             the parquet covers a sparse subset of the requested range",
            summary.chunks_aborted,
        );
    }
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
    analyze::run(AnalyzeConfig {
        canonical: args.canonical,
        eip7709: args.eip7709,
        top_n: args.top_n,
    })?;
    Ok(())
}
