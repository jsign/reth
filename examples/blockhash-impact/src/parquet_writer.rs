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

use crate::row::BlockhashRow;

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
        Field::new("slot_index", DataType::UInt64, true),
        Field::new("is_in_window", DataType::Boolean, false),
        Field::new("slot_warmth_class", DataType::Utf8, false),
        Field::new("eip7709_extra_cost", DataType::UInt64, false),
        Field::new("eip7709_new_cost", DataType::UInt64, false),
        Field::new("eip7709_new_headroom", DataType::Int64, false),
        Field::new("eip7709_would_oog_frame", DataType::Boolean, false),
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
    let mut slot_index = Vec::with_capacity(capacity);
    let mut is_in_window = Vec::with_capacity(capacity);
    let mut slot_warmth_class = Vec::with_capacity(capacity);
    let mut eip7709_extra_cost = Vec::with_capacity(capacity);
    let mut eip7709_new_cost = Vec::with_capacity(capacity);
    let mut eip7709_new_headroom = Vec::with_capacity(capacity);
    let mut eip7709_would_oog_frame = Vec::with_capacity(capacity);

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
        slot_index.push(row.slot_index);
        is_in_window.push(row.is_in_window);
        slot_warmth_class.push(row.slot_warmth_class);
        eip7709_extra_cost.push(row.eip7709_extra_cost);
        eip7709_new_cost.push(row.eip7709_new_cost);
        eip7709_new_headroom.push(row.eip7709_new_headroom);
        eip7709_would_oog_frame.push(row.eip7709_would_oog_frame);
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
        Arc::new(UInt64Array::from(slot_index)),
        Arc::new(BooleanArray::from(is_in_window)),
        Arc::new(StringArray::from(slot_warmth_class)),
        Arc::new(UInt64Array::from(eip7709_extra_cost)),
        Arc::new(UInt64Array::from(eip7709_new_cost)),
        Arc::new(Int64Array::from(eip7709_new_headroom)),
        Arc::new(BooleanArray::from(eip7709_would_oog_frame)),
    ];

    RecordBatch::try_new(schema, columns).wrap_err("failed to assemble arrow record batch")
}

pub(crate) fn write_rows(
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
            slot_index: Some(eip7709_slot_index(1)),
            is_in_window: true,
            slot_warmth_class: warmth.as_str().to_string(),
            eip7709_extra_cost: warmth.extra_cost(),
            eip7709_new_cost: new_cost,
            eip7709_new_headroom: i64::try_from(gas_before).unwrap_or(i64::MAX) - new_cost as i64,
            eip7709_would_oog_frame: gas_before < new_cost,
        }
    }
}
