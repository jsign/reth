//! Replays a canonical mainnet archive range and records every BLOCKHASH execution event under
//! both the canonical and EIP-7709 cost models. See the `scan` and `analyze` modules for the
//! producer/consumer halves of the pipeline.

pub mod analyze;
pub mod eip7709;
pub mod info;

mod inspector;
mod parquet_writer;
mod progress;
mod row;
mod scan;

pub use inspector::BlockhashImpactInspector;
pub use row::{BlockExecutionContext, BlockhashRow, TxExecutionMetadata};
pub use scan::{scan_archive, ScanConfig, ScanSummary};
