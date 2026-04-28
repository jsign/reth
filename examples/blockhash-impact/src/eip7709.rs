//! Constants and helpers for [EIP-7709] simulation.
//!
//! [EIP-7709]: https://eips.ethereum.org/EIPS/eip-7709

use alloy_primitives::{address, Address};

/// EIP-2935 history storage system contract.
pub const HISTORY_STORAGE_ADDRESS: Address = address!("0000F90827F1C53a10cb7A02335B175320002935");

/// Ring-buffer length of the EIP-2935 history contract; slot index is `arg % HISTORY_SERVE_WINDOW`.
pub const HISTORY_SERVE_WINDOW: u64 = 8192;

/// BLOCKHASH continues to expose only the 256 most-recent block hashes (delta in `[1, 256]`).
pub const BLOCKHASH_VISIBLE_WINDOW: u64 = 256;

/// Pre-EIP-7709 flat gas cost of BLOCKHASH (still charged by revm's instruction table).
pub const BASE_BLOCKHASH_COST: u64 = 20;

/// EIP-2929 cold SLOAD cost charged on the first read of a given slot in a transaction.
pub const COLD_SLOAD_COST: u64 = 2100;

/// EIP-2929 warm SLOAD cost charged on subsequent reads of the same slot in a transaction.
pub const WARM_SLOAD_COST: u64 = 100;

/// Slot identifier within the EIP-2935 ring buffer for the requested block number.
#[inline]
pub fn slot_index(requested_block_number: u64) -> u64 {
    requested_block_number % HISTORY_SERVE_WINDOW
}

/// Whether the requested block number falls inside the BLOCKHASH visible window — only
/// in-window calls trigger the SLOAD charge.
#[inline]
pub fn is_in_window(delta: i64) -> bool {
    (1..=BLOCKHASH_VISIBLE_WINDOW as i64).contains(&delta)
}

/// Classification of a BLOCKHASH execution under the EIP-7709 cost model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmthClass {
    /// Slot was cold under EIP-2929 access-list semantics (first read in this tx).
    Cold,
    /// Slot was warm — already touched earlier in this tx.
    Warm,
    /// Requested block is outside the BLOCKHASH visible window; no SLOAD is performed.
    OutOfWindow,
    /// Warmth could not be determined for this scan (canonical scan with `--simulate-eip7709` off
    /// does not consult the journal); treated as unclassified for analytics.
    Unknown,
}

impl WarmthClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::OutOfWindow => "out_of_window",
            Self::Unknown => "unknown",
        }
    }

    /// Extra gas charged on top of [`BASE_BLOCKHASH_COST`] for this classification.
    pub const fn extra_cost(self) -> u64 {
        match self {
            Self::Cold => COLD_SLOAD_COST,
            Self::Warm => WARM_SLOAD_COST,
            Self::OutOfWindow | Self::Unknown => 0,
        }
    }

    /// Total per-event cost under EIP-7709 for this classification.
    pub const fn total_cost(self) -> u64 {
        BASE_BLOCKHASH_COST + self.extra_cost()
    }
}
