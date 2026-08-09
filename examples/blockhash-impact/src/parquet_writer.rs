//! Parquet sink for the scanner: schema definition, row → arrow batch conversion, and the writer
//! thread that drains the worker channel.

use arrow::{
    array::{
        ArrayRef, BooleanArray, Int64Array, RecordBatch, StringArray, UInt32Array, UInt64Array,
        UInt8Array,
    },
    datatypes::{DataType, Field, Schema},
};
use eyre::Context as _;
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};
use reth_fs_util as fs;
use std::{
    fs::File,
    path::PathBuf,
    sync::{mpsc, Arc},
};

use crate::row::{BlockhashRow, TransactionImpactRow};

pub(crate) struct OutputBatch {
    pub events: Vec<BlockhashRow>,
    pub transactions: Vec<TransactionImpactRow>,
}

pub(crate) fn row_schema() -> Schema {
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
        Field::new("frame_path", DataType::Utf8, false),
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
        Field::new("pc_occurrence", DataType::UInt32, false),
        Field::new("requested_block_number", DataType::UInt64, true),
        Field::new("requested_block_delta", DataType::Int64, true),
        Field::new("gas_before", DataType::UInt64, false),
        Field::new("gas_after", DataType::UInt64, false),
        Field::new("observed_gas_cost", DataType::UInt64, false),
        Field::new("extra_gas_headroom", DataType::Int64, false),
        Field::new("slot_index", DataType::UInt64, true),
        Field::new("is_in_window", DataType::Boolean, false),
        Field::new("slot_warmth_class", DataType::Utf8, false),
        Field::new("eip7709_extra_cost", DataType::UInt64, false),
        Field::new("eip7709_new_cost", DataType::UInt64, false),
        Field::new("eip7709_new_headroom", DataType::Int64, false),
        Field::new("eip7709_would_oog_frame", DataType::Boolean, false),
        Field::new("simulation_matched", DataType::Boolean, false),
        Field::new("simulation_event_index", DataType::UInt64, true),
        Field::new("simulation_gas_before", DataType::UInt64, true),
        Field::new("simulation_gas_after", DataType::UInt64, true),
        Field::new("simulation_observed_gas_cost", DataType::UInt64, true),
        Field::new("simulation_frame_end_status", DataType::Utf8, true),
    ])
}

pub(crate) fn transaction_schema() -> Schema {
    Schema::new(vec![
        Field::new("block_number", DataType::UInt64, false),
        Field::new("block_hash", DataType::Utf8, false),
        Field::new("tx_index", DataType::UInt64, false),
        Field::new("tx_hash", DataType::Utf8, false),
        Field::new("tx_from", DataType::Utf8, false),
        Field::new("tx_to", DataType::Utf8, true),
        Field::new("canonical_gas_used", DataType::UInt64, false),
        Field::new("simulated_gas_used", DataType::UInt64, true),
        Field::new("gas_delta", DataType::Int64, true),
        Field::new("canonical_status", DataType::Utf8, false),
        Field::new("simulated_status", DataType::Utf8, true),
        Field::new("classification", DataType::Utf8, false),
        Field::new("status_changed", DataType::Boolean, false),
        Field::new("output_changed", DataType::Boolean, false),
        Field::new("logs_changed", DataType::Boolean, false),
        Field::new("created_address_changed", DataType::Boolean, false),
        Field::new("state_changed", DataType::Boolean, false),
        Field::new("trace_diverged", DataType::Boolean, false),
        Field::new("internal_breakage", DataType::Boolean, false),
        Field::new("new_tx_oog", DataType::Boolean, false),
        Field::new("canonical_event_count", DataType::UInt64, false),
        Field::new("simulated_event_count", DataType::UInt64, true),
        Field::new("unmatched_canonical_events", DataType::UInt64, false),
        Field::new("unmatched_simulation_events", DataType::UInt64, false),
        Field::new("simulation_error", DataType::Utf8, true),
    ])
}

pub(crate) fn rows_to_record_batch(
    rows: Vec<BlockhashRow>,
    schema: Arc<Schema>,
) -> eyre::Result<RecordBatch> {
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
    let mut frame_path = Vec::with_capacity(capacity);
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
    let mut pc_occurrence = Vec::with_capacity(capacity);
    let mut requested_block_number = Vec::with_capacity(capacity);
    let mut requested_block_delta = Vec::with_capacity(capacity);
    let mut gas_before = Vec::with_capacity(capacity);
    let mut gas_after = Vec::with_capacity(capacity);
    let mut observed_gas_cost = Vec::with_capacity(capacity);
    let mut extra_gas_headroom = Vec::with_capacity(capacity);
    let mut slot_index = Vec::with_capacity(capacity);
    let mut is_in_window = Vec::with_capacity(capacity);
    let mut slot_warmth_class = Vec::with_capacity(capacity);
    let mut eip7709_extra_cost = Vec::with_capacity(capacity);
    let mut eip7709_new_cost = Vec::with_capacity(capacity);
    let mut eip7709_new_headroom = Vec::with_capacity(capacity);
    let mut eip7709_would_oog_frame = Vec::with_capacity(capacity);
    let mut simulation_matched = Vec::with_capacity(capacity);
    let mut simulation_event_index = Vec::with_capacity(capacity);
    let mut simulation_gas_before = Vec::with_capacity(capacity);
    let mut simulation_gas_after = Vec::with_capacity(capacity);
    let mut simulation_observed_gas_cost = Vec::with_capacity(capacity);
    let mut simulation_frame_end_status = Vec::with_capacity(capacity);

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
        frame_path.push(row.frame_path);
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
        pc_occurrence.push(row.pc_occurrence);
        requested_block_number.push(row.requested_block_number);
        requested_block_delta.push(row.requested_block_delta);
        gas_before.push(row.gas_before);
        gas_after.push(row.gas_after);
        observed_gas_cost.push(row.observed_gas_cost);
        extra_gas_headroom.push(row.extra_gas_headroom);
        slot_index.push(row.slot_index);
        is_in_window.push(row.is_in_window);
        slot_warmth_class.push(row.slot_warmth_class);
        eip7709_extra_cost.push(row.eip7709_extra_cost);
        eip7709_new_cost.push(row.eip7709_new_cost);
        eip7709_new_headroom.push(row.eip7709_new_headroom);
        eip7709_would_oog_frame.push(row.eip7709_would_oog_frame);
        simulation_matched.push(row.simulation_matched);
        simulation_event_index.push(row.simulation_event_index);
        simulation_gas_before.push(row.simulation_gas_before);
        simulation_gas_after.push(row.simulation_gas_after);
        simulation_observed_gas_cost.push(row.simulation_observed_gas_cost);
        simulation_frame_end_status.push(row.simulation_frame_end_status);
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
        Arc::new(StringArray::from(frame_path)),
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
        Arc::new(UInt32Array::from(pc_occurrence)),
        Arc::new(UInt64Array::from(requested_block_number)),
        Arc::new(Int64Array::from(requested_block_delta)),
        Arc::new(UInt64Array::from(gas_before)),
        Arc::new(UInt64Array::from(gas_after)),
        Arc::new(UInt64Array::from(observed_gas_cost)),
        Arc::new(Int64Array::from(extra_gas_headroom)),
        Arc::new(UInt64Array::from(slot_index)),
        Arc::new(BooleanArray::from(is_in_window)),
        Arc::new(StringArray::from(slot_warmth_class)),
        Arc::new(UInt64Array::from(eip7709_extra_cost)),
        Arc::new(UInt64Array::from(eip7709_new_cost)),
        Arc::new(Int64Array::from(eip7709_new_headroom)),
        Arc::new(BooleanArray::from(eip7709_would_oog_frame)),
        Arc::new(BooleanArray::from(simulation_matched)),
        Arc::new(UInt64Array::from(simulation_event_index)),
        Arc::new(UInt64Array::from(simulation_gas_before)),
        Arc::new(UInt64Array::from(simulation_gas_after)),
        Arc::new(UInt64Array::from(simulation_observed_gas_cost)),
        Arc::new(StringArray::from(simulation_frame_end_status)),
    ];

    RecordBatch::try_new(schema, columns).wrap_err("failed to assemble arrow record batch")
}

pub(crate) fn transactions_to_record_batch(
    rows: Vec<TransactionImpactRow>,
    schema: Arc<Schema>,
) -> eyre::Result<RecordBatch> {
    let mut block_number = Vec::with_capacity(rows.len());
    let mut block_hash = Vec::with_capacity(rows.len());
    let mut tx_index = Vec::with_capacity(rows.len());
    let mut tx_hash = Vec::with_capacity(rows.len());
    let mut tx_from = Vec::with_capacity(rows.len());
    let mut tx_to = Vec::with_capacity(rows.len());
    let mut canonical_gas_used = Vec::with_capacity(rows.len());
    let mut simulated_gas_used = Vec::with_capacity(rows.len());
    let mut gas_delta = Vec::with_capacity(rows.len());
    let mut canonical_status = Vec::with_capacity(rows.len());
    let mut simulated_status = Vec::with_capacity(rows.len());
    let mut classification = Vec::with_capacity(rows.len());
    let mut status_changed = Vec::with_capacity(rows.len());
    let mut output_changed = Vec::with_capacity(rows.len());
    let mut logs_changed = Vec::with_capacity(rows.len());
    let mut created_address_changed = Vec::with_capacity(rows.len());
    let mut state_changed = Vec::with_capacity(rows.len());
    let mut trace_diverged = Vec::with_capacity(rows.len());
    let mut internal_breakage = Vec::with_capacity(rows.len());
    let mut new_tx_oog = Vec::with_capacity(rows.len());
    let mut canonical_event_count = Vec::with_capacity(rows.len());
    let mut simulated_event_count = Vec::with_capacity(rows.len());
    let mut unmatched_canonical_events = Vec::with_capacity(rows.len());
    let mut unmatched_simulation_events = Vec::with_capacity(rows.len());
    let mut simulation_error = Vec::with_capacity(rows.len());

    for row in rows {
        block_number.push(row.block_number);
        block_hash.push(row.block_hash);
        tx_index.push(row.tx_index);
        tx_hash.push(row.tx_hash);
        tx_from.push(row.tx_from);
        tx_to.push(row.tx_to);
        canonical_gas_used.push(row.canonical_gas_used);
        simulated_gas_used.push(row.simulated_gas_used);
        gas_delta.push(row.gas_delta);
        canonical_status.push(row.canonical_status);
        simulated_status.push(row.simulated_status);
        classification.push(row.classification);
        status_changed.push(row.status_changed);
        output_changed.push(row.output_changed);
        logs_changed.push(row.logs_changed);
        created_address_changed.push(row.created_address_changed);
        state_changed.push(row.state_changed);
        trace_diverged.push(row.trace_diverged);
        internal_breakage.push(row.internal_breakage);
        new_tx_oog.push(row.new_tx_oog);
        canonical_event_count.push(row.canonical_event_count);
        simulated_event_count.push(row.simulated_event_count);
        unmatched_canonical_events.push(row.unmatched_canonical_events);
        unmatched_simulation_events.push(row.unmatched_simulation_events);
        simulation_error.push(row.simulation_error);
    }

    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(UInt64Array::from(block_number)),
            Arc::new(StringArray::from(block_hash)),
            Arc::new(UInt64Array::from(tx_index)),
            Arc::new(StringArray::from(tx_hash)),
            Arc::new(StringArray::from(tx_from)),
            Arc::new(StringArray::from(tx_to)),
            Arc::new(UInt64Array::from(canonical_gas_used)),
            Arc::new(UInt64Array::from(simulated_gas_used)),
            Arc::new(Int64Array::from(gas_delta)),
            Arc::new(StringArray::from(canonical_status)),
            Arc::new(StringArray::from(simulated_status)),
            Arc::new(StringArray::from(classification)),
            Arc::new(BooleanArray::from(status_changed)),
            Arc::new(BooleanArray::from(output_changed)),
            Arc::new(BooleanArray::from(logs_changed)),
            Arc::new(BooleanArray::from(created_address_changed)),
            Arc::new(BooleanArray::from(state_changed)),
            Arc::new(BooleanArray::from(trace_diverged)),
            Arc::new(BooleanArray::from(internal_breakage)),
            Arc::new(BooleanArray::from(new_tx_oog)),
            Arc::new(UInt64Array::from(canonical_event_count)),
            Arc::new(UInt64Array::from(simulated_event_count)),
            Arc::new(UInt64Array::from(unmatched_canonical_events)),
            Arc::new(UInt64Array::from(unmatched_simulation_events)),
            Arc::new(StringArray::from(simulation_error)),
        ],
    )
    .wrap_err("failed to assemble transaction impact record batch")
}

pub(crate) fn write_datasets(
    output: PathBuf,
    event_schema: Arc<Schema>,
    transaction_schema: Arc<Schema>,
    row_rx: mpsc::Receiver<OutputBatch>,
) -> eyre::Result<()> {
    fs::create_dir_all(&output)?;
    let events_path = output.join("events.parquet");
    let transactions_path = output.join("transactions.parquet");
    let events_file = File::create(&events_path)
        .map_err(|err| reth_fs_util::FsPathError::create_file(err, &events_path))
        .wrap_err("failed to create events parquet")?;
    let transactions_file = File::create(&transactions_path)
        .map_err(|err| reth_fs_util::FsPathError::create_file(err, &transactions_path))
        .wrap_err("failed to create transactions parquet")?;
    let writer_properties =
        WriterProperties::builder().set_compression(Compression::SNAPPY).build();
    let mut event_writer = ArrowWriter::try_new(
        events_file,
        Arc::clone(&event_schema),
        Some(writer_properties.clone()),
    )
    .wrap_err("failed to create events parquet writer")?;
    let mut transaction_writer = ArrowWriter::try_new(
        transactions_file,
        Arc::clone(&transaction_schema),
        Some(writer_properties),
    )
    .wrap_err("failed to create transactions parquet writer")?;

    for batch in row_rx {
        if !batch.events.is_empty() {
            event_writer
                .write(&rows_to_record_batch(batch.events, Arc::clone(&event_schema))?)
                .wrap_err("failed to append events parquet batch")?;
        }
        if !batch.transactions.is_empty() {
            transaction_writer
                .write(&transactions_to_record_batch(
                    batch.transactions,
                    Arc::clone(&transaction_schema),
                )?)
                .wrap_err("failed to append transactions parquet batch")?;
        }
    }

    event_writer.close().wrap_err("failed to finalize events parquet")?;
    transaction_writer.close().wrap_err("failed to finalize transactions parquet")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eip7709::{slot_index as eip7709_slot_index, WarmthClass},
        row::{gas_headroom, hex, CURRENT_BLOCKHASH_COST},
    };
    use alloy_primitives::{address, B256};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use tempfile::tempdir;

    const TEST_TX_TYPE: u8 = 0;

    #[test]
    fn parquet_writer_roundtrip_preserves_schema_and_row_count() -> eyre::Result<()> {
        let tempdir = tempdir()?;
        let output = tempdir.path().join("dataset");
        let schema = Arc::new(row_schema());
        let tx_schema = Arc::new(transaction_schema());
        let (tx, rx) = mpsc::channel();
        tx.send(OutputBatch {
            events: vec![sample_row(0, 42), sample_row(1, 84)],
            transactions: vec![sample_transaction()],
        })?;
        drop(tx);

        write_datasets(output.clone(), Arc::clone(&schema), tx_schema, rx)?;

        let file = File::open(output.join("events.parquet"))?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let schema_read = builder.schema().clone();
        let reader = builder.build()?;
        let batches: Vec<RecordBatch> = reader.collect::<Result<_, _>>()?;
        let row_count: usize = batches.iter().map(RecordBatch::num_rows).sum();

        assert_eq!(row_count, 2);
        assert_eq!(schema_read.fields().len(), schema.fields().len());

        let file = File::open(output.join("transactions.parquet"))?;
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
        let transaction_count: usize =
            reader.collect::<Result<Vec<_>, _>>()?.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(transaction_count, 1);

        let events = crate::analyze::read_rows(&output.join("events.parquet"))?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_index, 1);
        assert_eq!(events[1].gas_before, 84);
        let transactions = crate::analyze::read_transactions(&output.join("transactions.parquet"))?;
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].classification, "gas_only");

        Ok(())
    }

    fn sample_row(event_index: u64, gas_before: u64) -> BlockhashRow {
        let warmth = WarmthClass::Cold;
        let new_cost = warmth.total_cost();
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
            frame_path: "0".to_string(),
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
            pc_occurrence: 0,
            requested_block_number: Some(1),
            requested_block_delta: Some(11),
            gas_before,
            gas_after: gas_before.saturating_sub(CURRENT_BLOCKHASH_COST),
            observed_gas_cost: CURRENT_BLOCKHASH_COST,
            extra_gas_headroom: gas_headroom(gas_before),
            slot_index: Some(eip7709_slot_index(1)),
            is_in_window: true,
            slot_warmth_class: warmth.as_str().to_string(),
            eip7709_extra_cost: warmth.extra_cost(),
            eip7709_new_cost: new_cost,
            eip7709_new_headroom: i64::try_from(gas_before).unwrap_or(i64::MAX) - new_cost as i64,
            eip7709_would_oog_frame: gas_before < new_cost,
            simulation_matched: true,
            simulation_event_index: Some(event_index),
            simulation_gas_before: Some(gas_before),
            simulation_gas_after: Some(gas_before.saturating_sub(new_cost)),
            simulation_observed_gas_cost: Some(new_cost),
            simulation_frame_end_status: Some("Success(Stop)".to_string()),
        }
    }

    fn sample_transaction() -> TransactionImpactRow {
        TransactionImpactRow {
            block_number: 12,
            block_hash: hex(B256::repeat_byte(0xaa)),
            tx_index: 1,
            tx_hash: hex(B256::repeat_byte(0xbb)),
            tx_from: hex(address!("1000000000000000000000000000000000000000")),
            tx_to: Some(hex(address!("2000000000000000000000000000000000000000"))),
            canonical_gas_used: 20_000,
            simulated_gas_used: Some(22_100),
            gas_delta: Some(2_100),
            canonical_status: "Success(Stop)".to_string(),
            simulated_status: Some("Success(Stop)".to_string()),
            classification: "gas_only".to_string(),
            status_changed: false,
            output_changed: false,
            logs_changed: false,
            created_address_changed: false,
            state_changed: false,
            trace_diverged: false,
            internal_breakage: false,
            new_tx_oog: false,
            canonical_event_count: 1,
            simulated_event_count: Some(1),
            unmatched_canonical_events: 0,
            unmatched_simulation_events: 0,
            simulation_error: None,
        }
    }
}
