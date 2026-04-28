//! Scanner orchestration: replays a canonical mainnet block range across a worker pool, runs the
//! [`crate::inspector::BlockhashImpactInspector`] on every BLOCKHASH event, and streams rows to
//! the parquet writer thread.

use alloy_consensus::BlockHeader;
use alloy_evm::{
    block::{BlockExecutor, TxResult},
    Evm,
};
use eyre::{Context as _, ContextCompat as _};
use reth_chainspec::{EthereumHardforks, MAINNET};
use reth_ethereum::{evm::EthEvmConfig, node::EthereumNode};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::ConfigureEvm;
use reth_provider::{providers::ReadOnlyConfig, BlockNumReader, BlockReader, ChainSpecProvider};
use reth_revm::{
    database::StateProviderDatabase,
    db::State,
    revm::{self as revm},
};
use reth_storage_api::{HashedPostStateProvider, StateRootProvider};
use reth_tasks::Runtime;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    inspector::BlockhashImpactInspector,
    parquet_writer::{row_schema, write_rows},
    progress::report_progress,
    row::{transaction_metadata, BlockExecutionContext, BlockhashRow},
};

/// Scanner configuration.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub datadir: PathBuf,
    pub from: u64,
    pub to: u64,
    pub output: PathBuf,
    pub jobs: Option<usize>,
    pub blocks_per_chunk: u64,
    pub flush_rows: usize,
    pub verify_execution: bool,
    /// When true, inject EIP-7709 SLOAD-equivalent gas at every BLOCKHASH step. Mutually
    /// exclusive with `verify_execution` because gas injection diverges canonical state.
    pub simulate_eip7709: bool,
}

/// Runtime summary emitted after a completed scan.
#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub resolved_from: u64,
    pub resolved_to: u64,
    pub blocks_scanned: u64,
    pub txs_scanned: u64,
    pub txs_with_blockhash: u64,
    pub blockhash_events: u64,
    pub min_observed_gas_before: Option<u64>,
    /// Chunks abandoned mid-execution under `--simulate-eip7709`. Their remaining blocks are
    /// missing from the parquet output and analysis should treat the file as a sparse subset.
    pub chunks_aborted: u64,
    pub elapsed: Duration,
    pub output: PathBuf,
}

impl ScanSummary {
    pub fn blocks_per_second(&self) -> f64 {
        if self.elapsed.is_zero() {
            return self.blocks_scanned as f64;
        }

        self.blocks_scanned as f64 / self.elapsed.as_secs_f64()
    }
}

pub fn scan_archive(config: ScanConfig) -> eyre::Result<ScanSummary> {
    validate_config(&config)?;

    let runtime = Runtime::test();
    let provider_factory = EthereumNode::provider_factory_builder().open_read_only(
        MAINNET.clone(),
        ReadOnlyConfig::from_datadir(&config.datadir).disable_long_read_transaction_safety(),
        runtime,
    )?;

    let best_block = provider_factory.provider()?.best_block_number()?;
    let resolved_from = config.from.max(1);
    let resolved_to = config.to.min(best_block);
    if resolved_from > resolved_to {
        eyre::bail!(
            "resolved block range is empty: from={} to={} best_block={best_block}",
            resolved_from,
            resolved_to
        );
    }

    let jobs = config
        .jobs
        .unwrap_or_else(|| thread::available_parallelism().map(|value| value.get()).unwrap_or(1));
    let next_block = Arc::new(AtomicU64::new(resolved_from));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (row_tx, row_rx) = mpsc::channel::<Vec<BlockhashRow>>();
    let output = config.output.clone();
    let schema = Arc::new(row_schema());

    let writer_handle = thread::Builder::new()
        .name("blockhash-impact-writer".to_string())
        .spawn({
            let schema = Arc::clone(&schema);
            move || write_rows(output, schema, row_rx)
        })
        .wrap_err("failed to spawn parquet writer thread")?;

    let started_at = Instant::now();
    let total_blocks = resolved_to - resolved_from + 1;
    let blocks_completed = Arc::new(AtomicU64::new(0));
    let progress_done = Arc::new(AtomicBool::new(false));

    eprintln!(
        "scanning blocks {resolved_from}..={resolved_to} ({total_blocks} blocks) with {jobs} workers, chunk={} blocks",
        config.blocks_per_chunk,
    );

    let progress_handle = thread::Builder::new()
        .name("blockhash-impact-progress".to_string())
        .spawn({
            let blocks_completed = Arc::clone(&blocks_completed);
            let progress_done = Arc::clone(&progress_done);
            move || {
                report_progress(total_blocks, blocks_completed, progress_done, started_at);
            }
        })
        .wrap_err("failed to spawn progress reporter thread")?;

    let mut worker_handles = Vec::with_capacity(jobs);
    for worker_index in 0..jobs {
        let provider_factory = provider_factory.clone();
        let evm_config = EthEvmConfig::new(provider_factory.chain_spec().clone());
        let next_block = Arc::clone(&next_block);
        let cancelled = Arc::clone(&cancelled);
        let row_tx = row_tx.clone();
        let blocks_per_chunk = config.blocks_per_chunk;
        let flush_rows = config.flush_rows;
        let blocks_completed = Arc::clone(&blocks_completed);

        worker_handles.push(
            thread::Builder::new()
                .name(format!("blockhash-impact-worker-{worker_index}"))
                .spawn(move || {
                    let mut stats = WorkerStats::default();
                    let mut buffered_rows = Vec::with_capacity(flush_rows.max(1));

                    'chunks: loop {
                        if cancelled.load(Ordering::Relaxed) {
                            break;
                        }

                        let chunk_start = next_block.fetch_add(blocks_per_chunk, Ordering::Relaxed);
                        if chunk_start > resolved_to {
                            break;
                        }
                        let chunk_end = chunk_start
                            .saturating_add(blocks_per_chunk.saturating_sub(1))
                            .min(resolved_to);

                        let expected_blocks = (chunk_end - chunk_start + 1) as usize;
                        let blocks = provider_factory.recovered_block_range(chunk_start..=chunk_end)?;
                        if blocks.len() != expected_blocks {
                            eyre::bail!(
                                "missing canonical blocks in range {chunk_start}..={chunk_end}: expected {expected_blocks}, got {}",
                                blocks.len()
                            );
                        }

                        let parent_block = chunk_start
                            .checked_sub(1)
                            .wrap_err("cannot initialize chunk state before genesis")?;
                        let state_provider = provider_factory.history_by_block_number(parent_block)?;
                        let mut db_builder =
                            State::builder().with_database(StateProviderDatabase::new(state_provider));
                        if config.verify_execution {
                            // Track cumulative bundle updates only when verification needs
                            // canonical state-root checks.
                            db_builder = db_builder.with_bundle_update();
                        }
                        let mut db = db_builder.build();

                        for block in blocks {
                            if cancelled.load(Ordering::Relaxed) {
                                break;
                            }

                            let block_context = BlockExecutionContext {
                                block_number: block.number(),
                                block_hash: block.hash(),
                            };

                            // Per-block scratch state. Rows and stat deltas land in `stats` /
                            // `buffered_rows` only on success — under `--simulate-eip7709`, state
                            // divergence can cause a tx mid-block to fail with e.g. block-budget
                            // overflow, in which case we discard this block's data and abandon the
                            // rest of the chunk (db is dirty after a partial block).
                            let mut block_rows: Vec<BlockhashRow> = Vec::new();
                            let mut block_txs_scanned: u64 = 0;
                            let mut block_txs_with_blockhash: u64 = 0;

                            let block_result: eyre::Result<()> = (|| {
                                // Scope the executor so its `&mut db` borrow ends before the
                                // optional verify branch needs `&mut db`.
                                let execution_result = {
                                    let evm_env = evm_config.evm_env(block.header()).expect(
                                        "ethereum evm environment construction is infallible",
                                    );
                                    let execution_ctx = evm_config
                                        .context_for_block(block.sealed_block())
                                        .expect(
                                            "ethereum block execution context construction is infallible",
                                        );
                                    let evm = evm_config.evm_with_env_and_inspector(
                                        &mut db,
                                        evm_env,
                                        BlockhashImpactInspector::new(config.simulate_eip7709),
                                    );
                                    let mut executor =
                                        evm_config.create_executor(evm, execution_ctx);

                                    executor.apply_pre_execution_changes().wrap_err_with(|| {
                                        format!(
                                            "failed to apply pre-execution changes for block {}",
                                            block.number()
                                        )
                                    })?;

                                    for (tx_index, tx) in
                                        block.clone_transactions_recovered().enumerate()
                                    {
                                        block_txs_scanned += 1;
                                        let tx_index = tx_index as u64;
                                        let tx_metadata = transaction_metadata(tx_index, &tx);
                                        let tx_result = executor
                                            .execute_transaction_without_commit(tx)
                                            .wrap_err_with(|| {
                                                format!(
                                                    "failed to execute transaction {tx_index} in block {}",
                                                    block.number()
                                                )
                                            })?;

                                        // Replace the inspector with a fresh one carrying the
                                        // same injection flag so each tx gets isolated trace rows
                                        // and a fresh per-tx warmth set, while block state still
                                        // advances normally.
                                        let rows = std::mem::replace(
                                            executor.evm_mut().inspector_mut(),
                                            BlockhashImpactInspector::new(config.simulate_eip7709),
                                        )
                                        .into_rows(
                                            block_context,
                                            tx_metadata,
                                            &tx_result.result().result,
                                        );

                                        if !rows.is_empty() {
                                            block_txs_with_blockhash += 1;
                                            block_rows.extend(rows);
                                        }

                                        executor.commit_transaction(tx_result).wrap_err_with(
                                            || {
                                                format!(
                                                    "failed to commit transaction {tx_index} in block {}",
                                                    block.number()
                                                )
                                            },
                                        )?;
                                    }

                                    executor.apply_post_execution_changes().wrap_err_with(|| {
                                        format!(
                                            "failed to apply post-execution changes for block {}",
                                            block.number()
                                        )
                                    })?
                                };

                                if config.verify_execution {
                                    db.merge_transitions(
                                        revm::database::states::bundle_state::BundleRetention::PlainState,
                                    );
                                    verify_block_execution(
                                        &block,
                                        evm_config.chain_spec().as_ref(),
                                        db.database.as_ref(),
                                        &db.bundle_state,
                                        &execution_result,
                                    )?;
                                }

                                Ok(())
                            })();

                            match block_result {
                                Ok(()) => {
                                    stats.blocks_scanned += 1;
                                    stats.txs_scanned += block_txs_scanned;
                                    stats.txs_with_blockhash += block_txs_with_blockhash;
                                    stats.record_rows(&block_rows);
                                    buffered_rows.extend(block_rows);
                                    if buffered_rows.len() >= flush_rows {
                                        row_tx
                                            .send(std::mem::take(&mut buffered_rows))
                                            .wrap_err("failed to send row batch to writer")?;
                                    }
                                    blocks_completed.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(err) if config.simulate_eip7709 => {
                                    eprintln!(
                                        "[simulate-eip7709] aborting chunk {chunk_start}..={chunk_end} at block {} due to state divergence: {err:#}",
                                        block.number()
                                    );
                                    stats.chunks_aborted += 1;
                                    continue 'chunks;
                                }
                                Err(err) => return Err(err),
                            }
                        }
                    }

                    if !buffered_rows.is_empty() {
                        row_tx
                            .send(buffered_rows)
                            .wrap_err("failed to flush final row batch to writer")?;
                    }

                    Ok::<_, eyre::Report>(stats)
                })
                .wrap_err_with(|| format!("failed to spawn worker thread {worker_index}"))?,
        );
    }
    drop(row_tx);

    let mut first_error = None;
    let mut aggregate = WorkerStats::default();
    for handle in worker_handles {
        match handle.join() {
            Ok(Ok(stats)) => aggregate.merge(stats),
            Ok(Err(err)) => {
                cancelled.store(true, Ordering::Relaxed);
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(_) => {
                cancelled.store(true, Ordering::Relaxed);
                if first_error.is_none() {
                    first_error = Some(eyre::eyre!("worker thread panicked"));
                }
            }
        }
    }

    progress_done.store(true, Ordering::Relaxed);
    progress_handle.thread().unpark();
    if progress_handle.join().is_err() && first_error.is_none() {
        first_error = Some(eyre::eyre!("progress reporter thread panicked"));
    }

    let writer_result = match writer_handle.join() {
        Ok(result) => result,
        Err(_) => Err(eyre::eyre!("writer thread panicked")),
    };

    if let Some(err) = first_error {
        let _ = writer_result;
        return Err(err);
    }

    writer_result?;

    Ok(ScanSummary {
        resolved_from,
        resolved_to,
        blocks_scanned: aggregate.blocks_scanned,
        txs_scanned: aggregate.txs_scanned,
        txs_with_blockhash: aggregate.txs_with_blockhash,
        blockhash_events: aggregate.blockhash_events,
        min_observed_gas_before: aggregate.min_observed_gas_before,
        chunks_aborted: aggregate.chunks_aborted,
        elapsed: started_at.elapsed(),
        output: config.output,
    })
}

fn validate_config(config: &ScanConfig) -> eyre::Result<()> {
    if config.blocks_per_chunk == 0 {
        eyre::bail!("--blocks-per-chunk must be greater than zero");
    }
    if config.flush_rows == 0 {
        eyre::bail!("--flush-rows must be greater than zero");
    }
    if config.jobs == Some(0) {
        eyre::bail!("--jobs must be greater than zero");
    }
    if config.from > config.to {
        eyre::bail!("--from ({}) is greater than --to ({})", config.from, config.to);
    }
    if config.simulate_eip7709 && config.verify_execution {
        eyre::bail!(
            "--simulate-eip7709 cannot be combined with --verify-execution: \
             gas injection diverges canonical state, which breaks state-root validation"
        );
    }

    Ok(())
}

fn verify_block_execution<B, R, ChainSpec, StateProvider>(
    block: &reth_primitives_traits::RecoveredBlock<B>,
    chain_spec: &ChainSpec,
    state_provider: &StateProvider,
    bundle_state: &reth_revm::db::BundleState,
    execution_result: &alloy_evm::block::BlockExecutionResult<R>,
) -> eyre::Result<()>
where
    B: reth_primitives_traits::Block,
    R: reth_primitives_traits::Receipt,
    ChainSpec: EthereumHardforks,
    StateProvider: HashedPostStateProvider + StateRootProvider,
{
    validate_block_post_execution(block, chain_spec, execution_result, None).wrap_err_with(
        || {
            format!(
                "replayed execution result mismatched canonical header for block {}",
                block.number()
            )
        },
    )?;

    let expected_blob_gas_used = block.header().blob_gas_used().unwrap_or_default();
    eyre::ensure!(
        execution_result.blob_gas_used == expected_blob_gas_used,
        "blob gas used mismatch for block {}: got {}, expected {}",
        block.number(),
        execution_result.blob_gas_used,
        expected_blob_gas_used,
    );

    let state_root = state_provider
        .state_root(state_provider.hashed_post_state(bundle_state))
        .wrap_err_with(|| format!("failed to compute state root for block {}", block.number()))?;
    eyre::ensure!(
        state_root == block.header().state_root(),
        "state root mismatch for block {}: got {:?}, expected {:?}",
        block.number(),
        state_root,
        block.header().state_root(),
    );

    Ok(())
}

#[derive(Debug, Clone, Default)]
struct WorkerStats {
    blocks_scanned: u64,
    txs_scanned: u64,
    txs_with_blockhash: u64,
    blockhash_events: u64,
    min_observed_gas_before: Option<u64>,
    /// Chunks abandoned mid-execution under `--simulate-eip7709` because state divergence caused
    /// a tx to fail (e.g. block-budget overflow). The remaining blocks in those chunks are
    /// missing from the parquet output.
    chunks_aborted: u64,
}

impl WorkerStats {
    fn record_rows(&mut self, rows: &[BlockhashRow]) {
        self.blockhash_events += rows.len() as u64;
        let batch_min = rows.iter().map(|row| row.gas_before).min();
        self.min_observed_gas_before = match (self.min_observed_gas_before, batch_min) {
            (Some(current), Some(batch_min)) => Some(current.min(batch_min)),
            (None, Some(batch_min)) => Some(batch_min),
            (current, None) => current,
        };
    }

    fn merge(&mut self, other: Self) {
        self.blocks_scanned += other.blocks_scanned;
        self.txs_scanned += other.txs_scanned;
        self.txs_with_blockhash += other.txs_with_blockhash;
        self.blockhash_events += other.blockhash_events;
        self.chunks_aborted += other.chunks_aborted;
        self.min_observed_gas_before =
            match (self.min_observed_gas_before, other.min_observed_gas_before) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None,
            };
    }
}
