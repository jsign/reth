use alloy_consensus::{
    transaction::{Recovered, TxHashRef},
    BlockHeader, Transaction,
};
use alloy_evm::{
    block::{BlockExecutor, TxResult},
    Evm,
};
use alloy_primitives::{Address, B256};
use arrow::{
    array::{
        ArrayRef, BooleanArray, Int64Array, RecordBatch, StringArray, UInt32Array, UInt64Array,
        UInt8Array,
    },
    datatypes::{DataType, Field, Schema},
};
use eyre::{Context as _, ContextCompat};
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};
use reth_chainspec::{EthereumHardforks, MAINNET};
use reth_ethereum::{evm::EthEvmConfig, node::EthereumNode};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::ConfigureEvm;
use reth_fs_util as fs;
use reth_provider::{providers::ReadOnlyConfig, BlockNumReader, BlockReader, ChainSpecProvider};
use reth_revm::{
    database::StateProviderDatabase,
    db::State,
    revm::{
        self as revm,
        bytecode::opcode,
        context_interface::ContextTr,
        inspector::Inspector,
        interpreter::{
            interpreter_types::{InputsTr, Jumps},
            CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, CreateScheme,
            Interpreter,
        },
    },
};
use reth_storage_api::{HashedPostStateProvider, StateRootProvider};
use reth_tasks::Runtime;
use std::{
    fmt,
    fs::File,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

const CURRENT_BLOCKHASH_COST: u64 = 20;

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

#[derive(Debug, Clone, Copy)]
pub struct BlockExecutionContext {
    pub block_number: u64,
    pub block_hash: B256,
}

#[derive(Debug, Clone)]
pub struct TxExecutionMetadata {
    pub tx_index: u64,
    pub tx_hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub tx_type: u8,
    pub gas_limit: u64,
}

#[derive(Debug, Clone)]
pub struct BlockhashRow {
    pub block_number: u64,
    pub block_hash: String,
    pub tx_index: u64,
    pub tx_hash: String,
    pub tx_from: String,
    pub tx_to: Option<String>,
    pub tx_nonce: u64,
    pub tx_type: u8,
    pub tx_gas_limit: u64,
    pub tx_gas_used: u64,
    pub tx_status: String,
    pub event_index: u64,
    pub frame_id: u64,
    pub parent_frame_id: Option<u64>,
    pub frame_depth: u32,
    pub frame_kind: String,
    pub frame_caller: String,
    pub frame_target: Option<String>,
    pub frame_code_address: Option<String>,
    pub frame_gas_limit: u64,
    pub frame_is_static: bool,
    pub frame_end_status: Option<String>,
    pub pc: u64,
    pub requested_block_number: Option<u64>,
    pub requested_block_delta: Option<i64>,
    pub gas_before: u64,
    pub gas_after: u64,
    pub observed_gas_cost: u64,
    pub extra_gas_headroom: i64,
}

#[derive(Debug, Clone, Default)]
pub struct BlockhashImpactInspector {
    next_frame_id: u64,
    next_event_index: u64,
    frame_stack: Vec<u64>,
    frames: Vec<FrameRecord>,
    events: Vec<BlockhashEventRecord>,
    pending_blockhash: Option<PendingBlockhash>,
}

impl BlockhashImpactInspector {
    pub fn into_rows<H>(
        mut self,
        block: BlockExecutionContext,
        tx: TxExecutionMetadata,
        result: &revm::context::result::ExecutionResult<H>,
    ) -> Vec<BlockhashRow>
    where
        H: fmt::Debug,
    {
        if self.events.is_empty() {
            return Vec::new();
        }

        self.enrich_root_frame(&tx, result);
        let tx_status = format_tx_status(result);
        let tx_gas_used = result.tx_gas_used();

        self.events
            .into_iter()
            .map(|event| {
                let frame = self
                    .frames
                    .iter()
                    .find(|frame| frame.id == event.frame_id)
                    .expect("event frame is tracked");

                BlockhashRow {
                    block_number: block.block_number,
                    block_hash: hex(block.block_hash),
                    tx_index: tx.tx_index,
                    tx_hash: hex(tx.tx_hash),
                    tx_from: hex(tx.from),
                    tx_to: tx.to.map(hex),
                    tx_nonce: tx.nonce,
                    tx_type: tx.tx_type,
                    tx_gas_limit: tx.gas_limit,
                    tx_gas_used,
                    tx_status: tx_status.clone(),
                    event_index: event.event_index,
                    frame_id: frame.id,
                    parent_frame_id: frame.parent_frame_id,
                    frame_depth: frame.depth,
                    frame_kind: frame.kind.as_str().to_string(),
                    frame_caller: hex(frame.caller),
                    frame_target: frame.target.map(hex),
                    frame_code_address: frame.code_address.map(hex),
                    frame_gas_limit: frame.gas_limit,
                    frame_is_static: frame.is_static,
                    frame_end_status: frame.end_status.clone(),
                    pc: event.pc,
                    requested_block_number: event.requested_block_number,
                    requested_block_delta: event
                        .requested_block_number
                        .and_then(|requested| block_number_delta(block.block_number, requested)),
                    gas_before: event.gas_before,
                    gas_after: event.gas_after,
                    observed_gas_cost: event.observed_gas_cost,
                    extra_gas_headroom: gas_headroom(event.gas_before),
                }
            })
            .collect()
    }

    fn enrich_root_frame<H>(
        &mut self,
        tx: &TxExecutionMetadata,
        result: &revm::context::result::ExecutionResult<H>,
    ) where
        H: fmt::Debug,
    {
        let Some(root_frame) = self.frames.iter_mut().find(|frame| frame.parent_frame_id.is_none())
        else {
            return;
        };

        root_frame.caller = tx.from;
        root_frame.gas_limit = tx.gas_limit;
        root_frame.is_static = false;
        root_frame.depth = 0;
        root_frame.kind = if tx.to.is_some() { FrameKind::TxCall } else { FrameKind::TxCreate };
        root_frame.target = tx.to.or_else(|| result.created_address());
        root_frame.code_address = root_frame.target;
        root_frame.end_status = Some(format_tx_status(result));
    }

    fn push_frame(
        &mut self,
        kind: FrameKind,
        caller: Address,
        target: Option<Address>,
        code_address: Option<Address>,
        gas_limit: u64,
        is_static: bool,
    ) {
        let frame_id = self.next_frame_id;
        self.next_frame_id += 1;

        let parent_frame_id = self.frame_stack.last().copied();
        let depth = self.frame_stack.len() as u32;
        self.frames.push(FrameRecord {
            id: frame_id,
            parent_frame_id,
            depth,
            kind,
            caller,
            target,
            code_address,
            gas_limit,
            is_static,
            end_status: None,
        });
        self.frame_stack.push(frame_id);
    }

    fn pop_frame_with_status(&mut self, status: String) {
        if let Some(frame_id) = self.frame_stack.pop() &&
            let Some(frame) = self.frames.iter_mut().find(|frame| frame.id == frame_id)
        {
            frame.end_status = Some(status);
        }
    }
}

impl<CTX> Inspector<CTX> for BlockhashImpactInspector
where
    CTX: ContextTr,
{
    fn initialize_interp(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        if !self.frame_stack.is_empty() || !self.frames.is_empty() {
            return;
        }

        let target = Some(interp.input.target_address());
        let code_address = interp.input.bytecode_address().copied();
        let kind = if code_address.is_some() { FrameKind::TxCall } else { FrameKind::TxCreate };
        self.push_frame(
            kind,
            interp.input.caller_address(),
            target,
            code_address,
            interp.gas.remaining(),
            interp.runtime_flag.is_static,
        );
    }

    fn step(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        if interp.bytecode.opcode() != opcode::BLOCKHASH {
            return;
        }

        let Some(frame_id) = self.frame_stack.last().copied() else {
            return;
        };

        let requested_block_number =
            interp.stack.peek(0).ok().and_then(|number| u64::try_from(number).ok());

        self.pending_blockhash = Some(PendingBlockhash {
            frame_id,
            event_index: self.next_event_index,
            pc: interp.bytecode.pc() as u64,
            requested_block_number,
            gas_before: interp.gas.remaining(),
        });
        self.next_event_index += 1;
    }

    fn step_end(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        let Some(pending) = self.pending_blockhash.take() else {
            return;
        };

        let gas_after = interp.gas.remaining();
        self.events.push(BlockhashEventRecord {
            frame_id: pending.frame_id,
            event_index: pending.event_index,
            pc: pending.pc,
            requested_block_number: pending.requested_block_number,
            gas_before: pending.gas_before,
            gas_after,
            observed_gas_cost: pending.gas_before.saturating_sub(gas_after),
        });
    }

    fn call(&mut self, _context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if self.frame_stack.is_empty() {
            return None;
        }

        let kind = match inputs.scheme {
            CallScheme::Call => FrameKind::Call,
            CallScheme::CallCode => FrameKind::CallCode,
            CallScheme::DelegateCall => FrameKind::DelegateCall,
            CallScheme::StaticCall => FrameKind::StaticCall,
        };

        self.push_frame(
            kind,
            inputs.caller,
            Some(inputs.target_address),
            Some(inputs.bytecode_address),
            inputs.gas_limit,
            inputs.is_static,
        );
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.pop_frame_with_status(format!("{:?}", outcome.instruction_result()));
    }

    fn create(&mut self, _context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        if self.frame_stack.is_empty() {
            return None;
        }

        let kind = match inputs.scheme() {
            CreateScheme::Create => FrameKind::Create,
            CreateScheme::Create2 { .. } => FrameKind::Create2,
            CreateScheme::Custom { .. } => FrameKind::Create,
        };

        self.push_frame(kind, inputs.caller(), None, None, inputs.gas_limit(), false);
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if let Some(frame_id) = self.frame_stack.last().copied() &&
            let Some(frame) = self.frames.iter_mut().find(|frame| frame.id == frame_id)
        {
            frame.target = outcome.address;
            frame.code_address = outcome.address;
        }
        self.pop_frame_with_status(format!("{:?}", outcome.instruction_result()));
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

                    loop {
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

                            stats.blocks_scanned += 1;
                            let block_context = BlockExecutionContext {
                                block_number: block.number(),
                                block_hash: block.hash(),
                            };
                            let evm_env = evm_config
                                .evm_env(block.header())
                                .expect("ethereum evm environment construction is infallible");
                            let execution_ctx = evm_config
                                .context_for_block(block.sealed_block())
                                .expect("ethereum block execution context construction is infallible");
                            let evm = evm_config.evm_with_env_and_inspector(
                                &mut db,
                                evm_env,
                                BlockhashImpactInspector::default(),
                            );
                            let mut executor = evm_config.create_executor(evm, execution_ctx);

                            executor.apply_pre_execution_changes().wrap_err_with(|| {
                                format!(
                                    "failed to apply pre-execution changes for block {}",
                                    block.number()
                                )
                            })?;

                            for (tx_index, tx) in block.clone_transactions_recovered().enumerate() {
                                stats.txs_scanned += 1;
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

                                // Reset the inspector before committing so each transaction gets
                                // isolated trace rows while block state still advances normally.
                                let rows = std::mem::take(executor.evm_mut().inspector_mut())
                                    .into_rows(
                                        block_context,
                                        tx_metadata,
                                        &tx_result.result().result,
                                    );

                                if !rows.is_empty() {
                                    stats.txs_with_blockhash += 1;
                                    stats.record_rows(&rows);
                                    buffered_rows.extend(rows);
                                    if buffered_rows.len() >= flush_rows {
                                        row_tx
                                            .send(std::mem::take(&mut buffered_rows))
                                            .wrap_err("failed to send row batch to writer")?;
                                    }
                                }

                                executor.commit_transaction(tx_result).wrap_err_with(|| {
                                    format!(
                                        "failed to commit transaction {tx_index} in block {}",
                                        block.number()
                                    )
                                })?;
                            }

                            let execution_result =
                                executor.apply_post_execution_changes().wrap_err_with(|| {
                                    format!(
                                        "failed to apply post-execution changes for block {}",
                                        block.number()
                                    )
                                })?;

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

                            blocks_completed.fetch_add(1, Ordering::Relaxed);
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
        elapsed: started_at.elapsed(),
        output: config.output,
    })
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

fn write_rows(
    output: PathBuf,
    schema: Arc<Schema>,
    row_rx: mpsc::Receiver<Vec<BlockhashRow>>,
) -> eyre::Result<()> {
    if let Some(parent) = output.parent() &&
        !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(&output)
        .map_err(|err| reth_fs_util::FsPathError::create_file(err, &output))
        .wrap_err("failed to create parquet output file")?;
    let writer_properties =
        WriterProperties::builder().set_compression(Compression::SNAPPY).build();
    let mut writer = ArrowWriter::try_new(file, Arc::clone(&schema), Some(writer_properties))
        .wrap_err("failed to create parquet writer")?;

    for rows in row_rx {
        if rows.is_empty() {
            continue;
        }

        let batch = rows_to_record_batch(rows, Arc::clone(&schema))?;
        writer.write(&batch).wrap_err("failed to append parquet record batch")?;
    }

    writer.close().wrap_err("failed to finalize parquet file")?;
    Ok(())
}

fn report_progress(
    total_blocks: u64,
    blocks_completed: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
    started_at: Instant,
) {
    const TICK: Duration = Duration::from_secs(2);

    let mut last_tick = started_at;
    let mut last_completed: u64 = 0;

    loop {
        let stopping = done.load(Ordering::Relaxed);
        let now = Instant::now();
        let current = blocks_completed.load(Ordering::Relaxed);

        let tick_secs = now.saturating_duration_since(last_tick).as_secs_f64().max(1e-6);
        let overall_secs = now.saturating_duration_since(started_at).as_secs_f64().max(1e-6);
        let instant_rate = current.saturating_sub(last_completed) as f64 / tick_secs;
        let overall_rate = current as f64 / overall_secs;
        let rate_for_eta = if instant_rate > 0.0 { instant_rate } else { overall_rate };

        let remaining = total_blocks.saturating_sub(current);
        let eta = if rate_for_eta > 0.0 { Some(remaining as f64 / rate_for_eta) } else { None };
        let pct =
            if total_blocks == 0 { 100.0 } else { (current as f64 / total_blocks as f64) * 100.0 };

        eprintln!(
            "[progress] {}/{} ({:.2}%) | {} blk/s (avg {}) | elapsed {} | ETA {}",
            current,
            total_blocks,
            pct,
            format_rate(instant_rate),
            format_rate(overall_rate),
            format_hms(overall_secs),
            eta.map(format_hms).unwrap_or_else(|| "?".to_string()),
        );

        if stopping {
            return;
        }

        last_tick = now;
        last_completed = current;

        thread::park_timeout(TICK);
    }
}

fn format_rate(rate: f64) -> String {
    if !rate.is_finite() || rate < 0.0 {
        return "?".to_string();
    }
    if rate >= 100.0 {
        format!("{rate:.0}")
    } else if rate >= 10.0 {
        format!("{rate:.1}")
    } else {
        format!("{rate:.2}")
    }
}

fn format_hms(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "?".to_string();
    }
    let total = secs.min(u64::MAX as f64 / 2.0) as u64;
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    if days > 0 {
        format!("{days}d{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
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

    Ok(())
}

fn transaction_metadata<T>(tx_index: u64, tx: &Recovered<T>) -> TxExecutionMetadata
where
    T: Transaction + TxHashRef,
{
    TxExecutionMetadata {
        tx_index,
        tx_hash: *tx.tx_hash(),
        from: tx.signer(),
        to: tx.to(),
        nonce: tx.nonce(),
        tx_type: tx.ty(),
        gas_limit: tx.gas_limit(),
    }
}

fn row_schema() -> Schema {
    Schema::new(vec![
        Field::new("block_number", DataType::UInt64, false),
        Field::new("block_hash", DataType::Utf8, false),
        Field::new("tx_index", DataType::UInt64, false),
        Field::new("tx_hash", DataType::Utf8, false),
        Field::new("tx_from", DataType::Utf8, false),
        Field::new("tx_to", DataType::Utf8, true),
        Field::new("tx_nonce", DataType::UInt64, false),
        Field::new("tx_type", DataType::UInt8, false),
        Field::new("tx_gas_limit", DataType::UInt64, false),
        Field::new("tx_gas_used", DataType::UInt64, false),
        Field::new("tx_status", DataType::Utf8, false),
        Field::new("event_index", DataType::UInt64, false),
        Field::new("frame_id", DataType::UInt64, false),
        Field::new("parent_frame_id", DataType::UInt64, true),
        Field::new("frame_depth", DataType::UInt32, false),
        Field::new("frame_kind", DataType::Utf8, false),
        Field::new("frame_caller", DataType::Utf8, false),
        Field::new("frame_target", DataType::Utf8, true),
        Field::new("frame_code_address", DataType::Utf8, true),
        Field::new("frame_gas_limit", DataType::UInt64, false),
        Field::new("frame_is_static", DataType::Boolean, false),
        Field::new("frame_end_status", DataType::Utf8, true),
        Field::new("pc", DataType::UInt64, false),
        Field::new("requested_block_number", DataType::UInt64, true),
        Field::new("requested_block_delta", DataType::Int64, true),
        Field::new("gas_before", DataType::UInt64, false),
        Field::new("gas_after", DataType::UInt64, false),
        Field::new("observed_gas_cost", DataType::UInt64, false),
        Field::new("extra_gas_headroom", DataType::Int64, false),
    ])
}

fn rows_to_record_batch(rows: Vec<BlockhashRow>, schema: Arc<Schema>) -> eyre::Result<RecordBatch> {
    let capacity = rows.len();
    let mut block_number = Vec::with_capacity(capacity);
    let mut block_hash = Vec::with_capacity(capacity);
    let mut tx_index = Vec::with_capacity(capacity);
    let mut tx_hash = Vec::with_capacity(capacity);
    let mut tx_from = Vec::with_capacity(capacity);
    let mut tx_to = Vec::with_capacity(capacity);
    let mut tx_nonce = Vec::with_capacity(capacity);
    let mut tx_type = Vec::with_capacity(capacity);
    let mut tx_gas_limit = Vec::with_capacity(capacity);
    let mut tx_gas_used = Vec::with_capacity(capacity);
    let mut tx_status = Vec::with_capacity(capacity);
    let mut event_index = Vec::with_capacity(capacity);
    let mut frame_id = Vec::with_capacity(capacity);
    let mut parent_frame_id = Vec::with_capacity(capacity);
    let mut frame_depth = Vec::with_capacity(capacity);
    let mut frame_kind = Vec::with_capacity(capacity);
    let mut frame_caller = Vec::with_capacity(capacity);
    let mut frame_target = Vec::with_capacity(capacity);
    let mut frame_code_address = Vec::with_capacity(capacity);
    let mut frame_gas_limit = Vec::with_capacity(capacity);
    let mut frame_is_static = Vec::with_capacity(capacity);
    let mut frame_end_status = Vec::with_capacity(capacity);
    let mut pc = Vec::with_capacity(capacity);
    let mut requested_block_number = Vec::with_capacity(capacity);
    let mut requested_block_delta = Vec::with_capacity(capacity);
    let mut gas_before = Vec::with_capacity(capacity);
    let mut gas_after = Vec::with_capacity(capacity);
    let mut observed_gas_cost = Vec::with_capacity(capacity);
    let mut extra_gas_headroom = Vec::with_capacity(capacity);

    for row in rows {
        block_number.push(row.block_number);
        block_hash.push(row.block_hash);
        tx_index.push(row.tx_index);
        tx_hash.push(row.tx_hash);
        tx_from.push(row.tx_from);
        tx_to.push(row.tx_to);
        tx_nonce.push(row.tx_nonce);
        tx_type.push(row.tx_type);
        tx_gas_limit.push(row.tx_gas_limit);
        tx_gas_used.push(row.tx_gas_used);
        tx_status.push(row.tx_status);
        event_index.push(row.event_index);
        frame_id.push(row.frame_id);
        parent_frame_id.push(row.parent_frame_id);
        frame_depth.push(row.frame_depth);
        frame_kind.push(row.frame_kind);
        frame_caller.push(row.frame_caller);
        frame_target.push(row.frame_target);
        frame_code_address.push(row.frame_code_address);
        frame_gas_limit.push(row.frame_gas_limit);
        frame_is_static.push(row.frame_is_static);
        frame_end_status.push(row.frame_end_status);
        pc.push(row.pc);
        requested_block_number.push(row.requested_block_number);
        requested_block_delta.push(row.requested_block_delta);
        gas_before.push(row.gas_before);
        gas_after.push(row.gas_after);
        observed_gas_cost.push(row.observed_gas_cost);
        extra_gas_headroom.push(row.extra_gas_headroom);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from(block_number)),
        Arc::new(StringArray::from(block_hash)),
        Arc::new(UInt64Array::from(tx_index)),
        Arc::new(StringArray::from(tx_hash)),
        Arc::new(StringArray::from(tx_from)),
        Arc::new(StringArray::from(tx_to)),
        Arc::new(UInt64Array::from(tx_nonce)),
        Arc::new(UInt8Array::from(tx_type)),
        Arc::new(UInt64Array::from(tx_gas_limit)),
        Arc::new(UInt64Array::from(tx_gas_used)),
        Arc::new(StringArray::from(tx_status)),
        Arc::new(UInt64Array::from(event_index)),
        Arc::new(UInt64Array::from(frame_id)),
        Arc::new(UInt64Array::from(parent_frame_id)),
        Arc::new(UInt32Array::from(frame_depth)),
        Arc::new(StringArray::from(frame_kind)),
        Arc::new(StringArray::from(frame_caller)),
        Arc::new(StringArray::from(frame_target)),
        Arc::new(StringArray::from(frame_code_address)),
        Arc::new(UInt64Array::from(frame_gas_limit)),
        Arc::new(BooleanArray::from(frame_is_static)),
        Arc::new(StringArray::from(frame_end_status)),
        Arc::new(UInt64Array::from(pc)),
        Arc::new(UInt64Array::from(requested_block_number)),
        Arc::new(Int64Array::from(requested_block_delta)),
        Arc::new(UInt64Array::from(gas_before)),
        Arc::new(UInt64Array::from(gas_after)),
        Arc::new(UInt64Array::from(observed_gas_cost)),
        Arc::new(Int64Array::from(extra_gas_headroom)),
    ];

    RecordBatch::try_new(schema, columns).wrap_err("failed to assemble arrow record batch")
}

fn format_tx_status<H>(result: &revm::context::result::ExecutionResult<H>) -> String
where
    H: fmt::Debug,
{
    match result {
        revm::context::result::ExecutionResult::Success { reason, .. } => {
            format!("Success({reason:?})")
        }
        revm::context::result::ExecutionResult::Revert { .. } => "Revert".to_string(),
        revm::context::result::ExecutionResult::Halt { reason, .. } => {
            format!("Halt({reason:?})")
        }
    }
}

fn block_number_delta(block_number: u64, requested_block_number: u64) -> Option<i64> {
    let block_number = i64::try_from(block_number).ok()?;
    let requested_block_number = i64::try_from(requested_block_number).ok()?;
    Some(block_number - requested_block_number)
}

fn gas_headroom(gas_before: u64) -> i64 {
    i64::try_from(gas_before).unwrap_or(i64::MAX) - CURRENT_BLOCKHASH_COST as i64
}

fn hex<T: fmt::LowerHex>(value: T) -> String {
    format!("{value:#x}")
}

#[derive(Debug, Clone)]
struct FrameRecord {
    id: u64,
    parent_frame_id: Option<u64>,
    depth: u32,
    kind: FrameKind,
    caller: Address,
    target: Option<Address>,
    code_address: Option<Address>,
    gas_limit: u64,
    is_static: bool,
    end_status: Option<String>,
}

#[derive(Debug, Clone)]
struct BlockhashEventRecord {
    frame_id: u64,
    event_index: u64,
    pc: u64,
    requested_block_number: Option<u64>,
    gas_before: u64,
    gas_after: u64,
    observed_gas_cost: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingBlockhash {
    frame_id: u64,
    event_index: u64,
    pc: u64,
    requested_block_number: Option<u64>,
    gas_before: u64,
}

#[derive(Debug, Clone, Copy)]
enum FrameKind {
    TxCall,
    TxCreate,
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    Create,
    Create2,
}

impl FrameKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TxCall => "tx_call",
            Self::TxCreate => "tx_create",
            Self::Call => "call",
            Self::CallCode => "callcode",
            Self::DelegateCall => "delegatecall",
            Self::StaticCall => "staticcall",
            Self::Create => "create",
            Self::Create2 => "create2",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct WorkerStats {
    blocks_scanned: u64,
    txs_scanned: u64,
    txs_with_blockhash: u64,
    blockhash_events: u64,
    min_observed_gas_before: Option<u64>,
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
        self.min_observed_gas_before =
            match (self.min_observed_gas_before, other.min_observed_gas_before) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None,
            };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, U256};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use reth_revm::{
        revm::{
            bytecode::Bytecode,
            database::{BenchmarkDB, CacheDB, EmptyDB, BENCH_CALLER, BENCH_TARGET},
            primitives::{Bytes, TxKind},
            state::AccountInfo,
            Context, MainBuilder,
        },
        InspectEvm, MainContext,
    };
    use tempfile::tempdir;

    const TEST_BLOCK_NUMBER: u64 = 100;
    const TEST_GAS_LIMIT: u64 = 100_000;
    const TEST_TX_TYPE: u8 = 0;

    #[test]
    fn root_blockhash_event_is_recorded() {
        let inspector_result = run_call_contract(
            vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP],
            TEST_BLOCK_NUMBER,
        );
        let rows = inspector_result.rows;

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pc, 2);
        assert_eq!(rows[0].requested_block_number, Some(1));
        assert!(rows[0].gas_before > 0);
        assert_eq!(rows[0].frame_depth, 0);
        assert_eq!(rows[0].frame_kind, "tx_call");
    }

    #[test]
    fn nested_call_frame_metadata_is_recorded() {
        let callee_address = address!("1000000000000000000000000000000000000001");
        let callee_code = vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP];
        let caller_code = call_contract_bytecode(callee_address);
        let inspector_result =
            run_nested_call(caller_code, callee_address, callee_code, TEST_BLOCK_NUMBER);
        let rows = inspector_result.rows;

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].frame_depth, 1);
        assert_eq!(rows[0].parent_frame_id, Some(0));
        assert_eq!(rows[0].frame_kind, "call");
    }

    #[test]
    fn reverted_inner_frame_still_emits_rows() {
        let callee_address = address!("1000000000000000000000000000000000000002");
        let callee_code = vec![
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::REVERT,
        ];
        let caller_code = call_contract_bytecode(callee_address);
        let inspector_result =
            run_nested_call(caller_code, callee_address, callee_code, TEST_BLOCK_NUMBER);
        let rows = inspector_result.rows;

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].frame_end_status.as_deref(), Some("Revert"));
        assert!(rows[0].tx_status.starts_with("Success("));
    }

    #[test]
    fn create_and_create2_frames_capture_constructor_blockhash() {
        let init_code = constructor_with_blockhash();

        let create_rows = run_call_contract(
            create_wrapper_bytecode(opcode::CREATE, &init_code),
            TEST_BLOCK_NUMBER,
        )
        .rows;
        assert_eq!(create_rows.len(), 1);
        assert_eq!(create_rows[0].frame_kind, "create");
        assert_eq!(create_rows[0].frame_depth, 1);

        let create2_rows = run_call_contract(
            create_wrapper_bytecode(opcode::CREATE2, &init_code),
            TEST_BLOCK_NUMBER,
        )
        .rows;
        assert_eq!(create2_rows.len(), 1);
        assert_eq!(create2_rows[0].frame_kind, "create2");
        assert_eq!(create2_rows[0].frame_depth, 1);
    }

    #[test]
    fn current_block_request_is_still_recorded() {
        let inspector_result = run_call_contract(
            vec![opcode::PUSH1, TEST_BLOCK_NUMBER as u8, opcode::BLOCKHASH, opcode::STOP],
            TEST_BLOCK_NUMBER,
        );
        let rows = inspector_result.rows;

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requested_block_number, Some(TEST_BLOCK_NUMBER));
        assert_eq!(rows[0].requested_block_delta, Some(0));
    }

    #[test]
    fn parquet_writer_roundtrip_preserves_schema_and_row_count() -> eyre::Result<()> {
        let tempdir = tempdir()?;
        let output = tempdir.path().join("blockhash.parquet");
        let schema = Arc::new(row_schema());
        let (tx, rx) = mpsc::channel();
        tx.send(vec![sample_row(0, 42), sample_row(1, 84)])?;
        drop(tx);

        write_rows(output.clone(), Arc::clone(&schema), rx)?;

        let file = File::open(&output)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let schema_read = builder.schema().clone();
        let reader = builder.build()?;
        let batches: Vec<RecordBatch> = reader.collect::<Result<_, _>>()?;
        let row_count: usize = batches.iter().map(RecordBatch::num_rows).sum();

        assert_eq!(row_count, 2);
        assert_eq!(schema_read.fields().len(), schema.fields().len());

        Ok(())
    }

    struct InspectorRun {
        rows: Vec<BlockhashRow>,
    }

    fn run_call_contract(code: Vec<u8>, block_number: u64) -> InspectorRun {
        let bytecode = Bytecode::new_raw(Bytes::from(code));
        let context = Context::mainnet()
            .modify_block_chained(|block| block.number = U256::from(block_number))
            .with_db(BenchmarkDB::new_bytecode(bytecode));
        let mut evm = context.build_mainnet_with_inspector(BlockhashImpactInspector::default());
        let result = evm
            .inspect_one_tx(
                revm::context::TxEnv::builder()
                    .caller(BENCH_CALLER)
                    .kind(TxKind::Call(BENCH_TARGET))
                    .gas_limit(TEST_GAS_LIMIT)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        InspectorRun {
            rows: evm.inspector.into_rows(
                BlockExecutionContext { block_number, block_hash: B256::repeat_byte(0x22) },
                TxExecutionMetadata {
                    tx_index: 0,
                    tx_hash: B256::repeat_byte(0x11),
                    from: BENCH_CALLER,
                    to: Some(BENCH_TARGET),
                    nonce: 0,
                    tx_type: TEST_TX_TYPE,
                    gas_limit: TEST_GAS_LIMIT,
                },
                &result,
            ),
        }
    }

    fn run_nested_call(
        caller_code: Vec<u8>,
        callee_address: Address,
        callee_code: Vec<u8>,
        block_number: u64,
    ) -> InspectorRun {
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            BENCH_CALLER,
            AccountInfo { balance: U256::from(10_000_000_000u64), nonce: 0, ..Default::default() },
        );
        db.insert_account_info(
            BENCH_TARGET,
            AccountInfo {
                balance: U256::from(1_000_000_000u64),
                nonce: 0,
                code_hash: alloy_primitives::keccak256(&caller_code),
                code: Some(Bytecode::new_raw(Bytes::from(caller_code))),
                ..Default::default()
            },
        );
        db.insert_account_info(
            callee_address,
            AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: alloy_primitives::keccak256(&callee_code),
                code: Some(Bytecode::new_raw(Bytes::from(callee_code))),
                ..Default::default()
            },
        );

        let context = Context::mainnet()
            .modify_block_chained(|block| block.number = U256::from(block_number))
            .with_db(db);
        let mut evm = context.build_mainnet_with_inspector(BlockhashImpactInspector::default());
        let result = evm
            .inspect_one_tx(
                revm::context::TxEnv::builder()
                    .caller(BENCH_CALLER)
                    .kind(TxKind::Call(BENCH_TARGET))
                    .gas_limit(TEST_GAS_LIMIT)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        InspectorRun {
            rows: evm.inspector.into_rows(
                BlockExecutionContext { block_number, block_hash: B256::repeat_byte(0x33) },
                TxExecutionMetadata {
                    tx_index: 0,
                    tx_hash: B256::repeat_byte(0x44),
                    from: BENCH_CALLER,
                    to: Some(BENCH_TARGET),
                    nonce: 0,
                    tx_type: TEST_TX_TYPE,
                    gas_limit: TEST_GAS_LIMIT,
                },
                &result,
            ),
        }
    }

    fn call_contract_bytecode(callee_address: Address) -> Vec<u8> {
        let mut bytecode = vec![
            opcode::PUSH1,
            0x20,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::PUSH20,
        ];
        bytecode.extend_from_slice(callee_address.as_slice());
        bytecode.extend_from_slice(&[opcode::PUSH2, 0xff, 0xff, opcode::CALL, opcode::STOP]);
        bytecode
    }

    fn constructor_with_blockhash() -> Vec<u8> {
        vec![
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::POP,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::RETURN,
        ]
    }

    fn create_wrapper_bytecode(create_opcode: u8, init_code: &[u8]) -> Vec<u8> {
        let init_len = init_code.len() as u8;
        let code_offset = if create_opcode == opcode::CREATE { 0x0f } else { 0x11 };

        let mut bytecode = vec![
            opcode::PUSH1,
            init_len,
            opcode::PUSH1,
            code_offset,
            opcode::PUSH1,
            0x00,
            opcode::CODECOPY,
        ];

        if create_opcode == opcode::CREATE2 {
            bytecode.extend_from_slice(&[opcode::PUSH1, 0x01]);
        }

        bytecode.extend_from_slice(&[
            opcode::PUSH1,
            init_len,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            create_opcode,
            opcode::STOP,
        ]);
        bytecode.extend_from_slice(init_code);
        bytecode
    }

    fn sample_row(event_index: u64, gas_before: u64) -> BlockhashRow {
        BlockhashRow {
            block_number: 12,
            block_hash: hex(B256::repeat_byte(0xaa)),
            tx_index: 1,
            tx_hash: hex(B256::repeat_byte(0xbb)),
            tx_from: hex(address!("1000000000000000000000000000000000000000")),
            tx_to: Some(hex(address!("2000000000000000000000000000000000000000"))),
            tx_nonce: 3,
            tx_type: TEST_TX_TYPE,
            tx_gas_limit: 21_000,
            tx_gas_used: 20_000,
            tx_status: "Success(Stop)".to_string(),
            event_index,
            frame_id: 0,
            parent_frame_id: None,
            frame_depth: 0,
            frame_kind: "tx_call".to_string(),
            frame_caller: hex(address!("1000000000000000000000000000000000000000")),
            frame_target: Some(hex(address!("2000000000000000000000000000000000000000"))),
            frame_code_address: Some(hex(address!("2000000000000000000000000000000000000000"))),
            frame_gas_limit: 21_000,
            frame_is_static: false,
            frame_end_status: Some("Success(Stop)".to_string()),
            pc: 2,
            requested_block_number: Some(1),
            requested_block_delta: Some(11),
            gas_before,
            gas_after: gas_before.saturating_sub(CURRENT_BLOCKHASH_COST),
            observed_gas_cost: CURRENT_BLOCKHASH_COST,
            extra_gas_headroom: gas_headroom(gas_before),
        }
    }
}
