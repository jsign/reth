//! Loads a blockhash-impact parquet back into [`BlockhashRow`]s. BLOCKHASH events are sparse on
//! mainnet, so the reader collects everything into memory in one pass.

use arrow::{
    array::{Array, BooleanArray, Int64Array, StringArray, UInt32Array, UInt64Array, UInt8Array},
    record_batch::RecordBatch,
};
use eyre::ContextCompat as _;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::{fs::File, path::Path};

use crate::row::{BlockhashRow, TransactionImpactRow};

/// Reads every column we need out of a blockhash-impact parquet file. Loads everything into memory
/// — BLOCKHASH events are sparse on mainnet, so this is fine in practice.
pub fn read_rows(path: &Path) -> eyre::Result<Vec<BlockhashRow>> {
    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;
    let mut rows = Vec::new();
    for batch in reader {
        let batch = batch?;
        let len = batch.num_rows();

        let block_number = u64_col(&batch, "block_number")?;
        let block_hash = str_col(&batch, "block_hash")?;
        let tx_index = u64_col(&batch, "tx_index")?;
        let tx_hash = str_col(&batch, "tx_hash")?;
        let tx_from = str_col(&batch, "tx_from")?;
        let tx_to = opt_str_col(&batch, "tx_to")?;
        let tx_nonce = u64_col(&batch, "tx_nonce")?;
        let tx_type = u8_col(&batch, "tx_type")?;
        let tx_gas_limit = u64_col(&batch, "tx_gas_limit")?;
        let tx_gas_used = u64_col(&batch, "tx_gas_used")?;
        let tx_status = str_col(&batch, "tx_status")?;
        let event_index = u64_col(&batch, "event_index")?;
        let frame_id = u64_col(&batch, "frame_id")?;
        let frame_path = str_col(&batch, "frame_path")?;
        let parent_frame_id = opt_u64_col(&batch, "parent_frame_id")?;
        let frame_depth = u32_col(&batch, "frame_depth")?;
        let frame_kind = str_col(&batch, "frame_kind")?;
        let frame_caller = str_col(&batch, "frame_caller")?;
        let frame_target = opt_str_col(&batch, "frame_target")?;
        let frame_code_address = opt_str_col(&batch, "frame_code_address")?;
        let frame_gas_limit = u64_col(&batch, "frame_gas_limit")?;
        let frame_is_static = bool_col(&batch, "frame_is_static")?;
        let frame_end_status = opt_str_col(&batch, "frame_end_status")?;
        let pc = u64_col(&batch, "pc")?;
        let pc_occurrence = u32_col(&batch, "pc_occurrence")?;
        let requested_block_number = opt_u64_col(&batch, "requested_block_number")?;
        let requested_block_delta = opt_i64_col(&batch, "requested_block_delta")?;
        let gas_before = u64_col(&batch, "gas_before")?;
        let gas_after = u64_col(&batch, "gas_after")?;
        let observed_gas_cost = u64_col(&batch, "observed_gas_cost")?;
        let extra_gas_headroom = i64_col(&batch, "extra_gas_headroom")?;
        let slot_index = opt_u64_col(&batch, "slot_index")?;
        let is_in_window = bool_col(&batch, "is_in_window")?;
        let slot_warmth_class = str_col(&batch, "slot_warmth_class")?;
        let eip7709_extra_cost = u64_col(&batch, "eip7709_extra_cost")?;
        let eip7709_new_cost = u64_col(&batch, "eip7709_new_cost")?;
        let eip7709_new_headroom = i64_col(&batch, "eip7709_new_headroom")?;
        let eip7709_would_oog_frame = bool_col(&batch, "eip7709_would_oog_frame")?;
        let simulation_matched = bool_col(&batch, "simulation_matched")?;
        let simulation_event_index = opt_u64_col(&batch, "simulation_event_index")?;
        let simulation_gas_before = opt_u64_col(&batch, "simulation_gas_before")?;
        let simulation_gas_after = opt_u64_col(&batch, "simulation_gas_after")?;
        let simulation_observed_gas_cost = opt_u64_col(&batch, "simulation_observed_gas_cost")?;
        let simulation_frame_end_status = opt_str_col(&batch, "simulation_frame_end_status")?;

        for i in 0..len {
            rows.push(BlockhashRow {
                block_number: block_number.value(i),
                block_hash: block_hash.value(i).to_string(),
                tx_index: tx_index.value(i),
                tx_hash: tx_hash.value(i).to_string(),
                tx_from: tx_from.value(i).to_string(),
                tx_to: opt_str_at(tx_to, i),
                tx_nonce: tx_nonce.value(i),
                tx_type: tx_type.value(i),
                tx_gas_limit: tx_gas_limit.value(i),
                tx_gas_used: tx_gas_used.value(i),
                tx_status: tx_status.value(i).to_string(),
                event_index: event_index.value(i),
                frame_id: frame_id.value(i),
                frame_path: frame_path.value(i).to_string(),
                parent_frame_id: opt_u64_at(parent_frame_id, i),
                frame_depth: frame_depth.value(i),
                frame_kind: frame_kind.value(i).to_string(),
                frame_caller: frame_caller.value(i).to_string(),
                frame_target: opt_str_at(frame_target, i),
                frame_code_address: opt_str_at(frame_code_address, i),
                frame_gas_limit: frame_gas_limit.value(i),
                frame_is_static: frame_is_static.value(i),
                frame_end_status: opt_str_at(frame_end_status, i),
                pc: pc.value(i),
                pc_occurrence: pc_occurrence.value(i),
                requested_block_number: opt_u64_at(requested_block_number, i),
                requested_block_delta: opt_i64_at(requested_block_delta, i),
                gas_before: gas_before.value(i),
                gas_after: gas_after.value(i),
                observed_gas_cost: observed_gas_cost.value(i),
                extra_gas_headroom: extra_gas_headroom.value(i),
                slot_index: opt_u64_at(slot_index, i),
                is_in_window: is_in_window.value(i),
                slot_warmth_class: slot_warmth_class.value(i).to_string(),
                eip7709_extra_cost: eip7709_extra_cost.value(i),
                eip7709_new_cost: eip7709_new_cost.value(i),
                eip7709_new_headroom: eip7709_new_headroom.value(i),
                eip7709_would_oog_frame: eip7709_would_oog_frame.value(i),
                simulation_matched: simulation_matched.value(i),
                simulation_event_index: opt_u64_at(simulation_event_index, i),
                simulation_gas_before: opt_u64_at(simulation_gas_before, i),
                simulation_gas_after: opt_u64_at(simulation_gas_after, i),
                simulation_observed_gas_cost: opt_u64_at(simulation_observed_gas_cost, i),
                simulation_frame_end_status: opt_str_at(simulation_frame_end_status, i),
            });
        }
    }
    Ok(rows)
}

pub fn read_transactions(path: &Path) -> eyre::Result<Vec<TransactionImpactRow>> {
    let file = File::open(path)?;
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
    let mut rows = Vec::new();
    for batch in reader {
        let batch = batch?;
        let block_number = u64_col(&batch, "block_number")?;
        let block_hash = str_col(&batch, "block_hash")?;
        let tx_index = u64_col(&batch, "tx_index")?;
        let tx_hash = str_col(&batch, "tx_hash")?;
        let tx_from = str_col(&batch, "tx_from")?;
        let tx_to = opt_str_col(&batch, "tx_to")?;
        let canonical_gas_used = u64_col(&batch, "canonical_gas_used")?;
        let simulated_gas_used = opt_u64_col(&batch, "simulated_gas_used")?;
        let gas_delta = opt_i64_col(&batch, "gas_delta")?;
        let canonical_status = str_col(&batch, "canonical_status")?;
        let simulated_status = opt_str_col(&batch, "simulated_status")?;
        let classification = str_col(&batch, "classification")?;
        let status_changed = bool_col(&batch, "status_changed")?;
        let output_changed = bool_col(&batch, "output_changed")?;
        let logs_changed = bool_col(&batch, "logs_changed")?;
        let created_address_changed = bool_col(&batch, "created_address_changed")?;
        let state_changed = bool_col(&batch, "state_changed")?;
        let trace_diverged = bool_col(&batch, "trace_diverged")?;
        let internal_breakage = bool_col(&batch, "internal_breakage")?;
        let new_tx_oog = bool_col(&batch, "new_tx_oog")?;
        let canonical_event_count = u64_col(&batch, "canonical_event_count")?;
        let simulated_event_count = opt_u64_col(&batch, "simulated_event_count")?;
        let unmatched_canonical_events = u64_col(&batch, "unmatched_canonical_events")?;
        let unmatched_simulation_events = u64_col(&batch, "unmatched_simulation_events")?;
        let simulation_error = opt_str_col(&batch, "simulation_error")?;

        for i in 0..batch.num_rows() {
            rows.push(TransactionImpactRow {
                block_number: block_number.value(i),
                block_hash: block_hash.value(i).to_string(),
                tx_index: tx_index.value(i),
                tx_hash: tx_hash.value(i).to_string(),
                tx_from: tx_from.value(i).to_string(),
                tx_to: opt_str_at(tx_to, i),
                canonical_gas_used: canonical_gas_used.value(i),
                simulated_gas_used: opt_u64_at(simulated_gas_used, i),
                gas_delta: opt_i64_at(gas_delta, i),
                canonical_status: canonical_status.value(i).to_string(),
                simulated_status: opt_str_at(simulated_status, i),
                classification: classification.value(i).to_string(),
                status_changed: status_changed.value(i),
                output_changed: output_changed.value(i),
                logs_changed: logs_changed.value(i),
                created_address_changed: created_address_changed.value(i),
                state_changed: state_changed.value(i),
                trace_diverged: trace_diverged.value(i),
                internal_breakage: internal_breakage.value(i),
                new_tx_oog: new_tx_oog.value(i),
                canonical_event_count: canonical_event_count.value(i),
                simulated_event_count: opt_u64_at(simulated_event_count, i),
                unmatched_canonical_events: unmatched_canonical_events.value(i),
                unmatched_simulation_events: unmatched_simulation_events.value(i),
                simulation_error: opt_str_at(simulation_error, i),
            });
        }
    }
    Ok(rows)
}

fn u64_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a UInt64Array> {
    batch
        .column_by_name(name)
        .wrap_err_with(|| format!("missing column: {name}"))?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .wrap_err_with(|| format!("column {name} is not UInt64"))
}

fn opt_u64_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a UInt64Array> {
    u64_col(batch, name)
}

fn opt_u64_at(arr: &UInt64Array, i: usize) -> Option<u64> {
    if arr.is_null(i) {
        None
    } else {
        Some(arr.value(i))
    }
}

fn i64_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a Int64Array> {
    batch
        .column_by_name(name)
        .wrap_err_with(|| format!("missing column: {name}"))?
        .as_any()
        .downcast_ref::<Int64Array>()
        .wrap_err_with(|| format!("column {name} is not Int64"))
}

fn opt_i64_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a Int64Array> {
    i64_col(batch, name)
}

fn opt_i64_at(arr: &Int64Array, i: usize) -> Option<i64> {
    if arr.is_null(i) {
        None
    } else {
        Some(arr.value(i))
    }
}

fn u32_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a UInt32Array> {
    batch
        .column_by_name(name)
        .wrap_err_with(|| format!("missing column: {name}"))?
        .as_any()
        .downcast_ref::<UInt32Array>()
        .wrap_err_with(|| format!("column {name} is not UInt32"))
}

fn u8_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a UInt8Array> {
    batch
        .column_by_name(name)
        .wrap_err_with(|| format!("missing column: {name}"))?
        .as_any()
        .downcast_ref::<UInt8Array>()
        .wrap_err_with(|| format!("column {name} is not UInt8"))
}

fn bool_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a BooleanArray> {
    batch
        .column_by_name(name)
        .wrap_err_with(|| format!("missing column: {name}"))?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .wrap_err_with(|| format!("column {name} is not Boolean"))
}

fn str_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a StringArray> {
    batch
        .column_by_name(name)
        .wrap_err_with(|| format!("missing column: {name}"))?
        .as_any()
        .downcast_ref::<StringArray>()
        .wrap_err_with(|| format!("column {name} is not Utf8"))
}

fn opt_str_col<'a>(batch: &'a RecordBatch, name: &str) -> eyre::Result<&'a StringArray> {
    str_col(batch, name)
}

fn opt_str_at(arr: &StringArray, i: usize) -> Option<String> {
    if arr.is_null(i) {
        None
    } else {
        Some(arr.value(i).to_string())
    }
}
