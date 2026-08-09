//! Constants and the revm opcode override used for the EIP-7709 simulation.

use alloy_eips::eip2935::HISTORY_SERVE_WINDOW as EIP2935_HISTORY_SERVE_WINDOW;
pub use alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS;
use alloy_evm::{eth::EthEvmContext, Database};
use alloy_primitives::U256;
use reth_revm::revm::{
    bytecode::opcode,
    context_interface::{
        journaled_state::{account::JournaledAccountTr, JournalTr},
        ContextTr,
    },
    inspector::Inspector,
    interpreter::{
        interpreter::EthInterpreter,
        interpreter_types::{InterpreterTypes, StackTr},
        Host, Instruction, InstructionContext,
    },
};
use std::cell::Cell;

/// The exact draft analyzed by this tool.
pub const EIP7709_REVISION: &str = "069a8398a85408250107d4cb08f09e33d42e3d58";

/// Ring-buffer length of the EIP-2935 history contract.
pub const HISTORY_SERVE_WINDOW: u64 = EIP2935_HISTORY_SERVE_WINDOW as u64;

/// BLOCKHASH continues to expose only the 256 most-recent block hashes.
pub const BLOCKHASH_VISIBLE_WINDOW: u64 = 256;

/// Pre-EIP-7709 flat gas cost of BLOCKHASH, retained by EIP-7709.
pub const BASE_BLOCKHASH_COST: u64 = 20;

/// Berlin and later cold SLOAD cost.
pub const COLD_SLOAD_COST: u64 = 2100;

/// Berlin and later warm SLOAD cost.
pub const WARM_SLOAD_COST: u64 = 100;

thread_local! {
    /// The opcode override is permanently installed in each worker EVM. This per-thread switch
    /// makes the first execution canonical and the paired execution theoretical without rebuilding
    /// the block executor or sharing state between worker threads.
    static EIP7709_ENABLED: Cell<bool> = const { Cell::new(false) };
    static LAST_ACCESS: Cell<Option<WarmthClass>> = const { Cell::new(None) };
}

/// Execute a closure with the theoretical opcode semantics enabled on this worker thread.
pub fn with_eip7709_enabled<T>(f: impl FnOnce() -> T) -> T {
    EIP7709_ENABLED.with(|enabled| {
        let previous = enabled.replace(true);
        struct Reset<'a>(&'a Cell<bool>, bool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(self.1);
            }
        }
        let _reset = Reset(enabled, previous);
        f()
    })
}

pub(crate) fn eip7709_enabled() -> bool {
    EIP7709_ENABLED.get()
}

pub(crate) fn clear_last_access() {
    LAST_ACCESS.set(None);
}

pub(crate) fn take_last_access() -> Option<WarmthClass> {
    LAST_ACCESS.take()
}

/// Installs the EIP-aware BLOCKHASH implementation while leaving it disabled by default.
pub fn install_eip7709_instruction<DB, I, P>(
    evm: alloy_evm::eth::EthEvm<DB, I, P>,
) -> alloy_evm::eth::EthEvm<DB, I, P>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
{
    let mut inner = evm.into_inner();
    inner.instruction.insert_instruction(
        opcode::BLOCKHASH,
        Instruction::new(
            eip7709_blockhash::<EthInterpreter, EthEvmContext<DB>>,
            BASE_BLOCKHASH_COST,
        ),
    );
    alloy_evm::eth::EthEvm::new(inner, true)
}

/// Installs the override on a raw revm mainnet EVM (used by focused execution tests).
pub fn install_eip7709_instruction_raw<CTX, I>(
    mut evm: reth_revm::revm::handler::MainnetEvm<CTX, I>,
) -> reth_revm::revm::handler::MainnetEvm<CTX, I>
where
    CTX: ContextTr,
{
    evm.instruction.insert_instruction(
        opcode::BLOCKHASH,
        Instruction::new(eip7709_blockhash::<EthInterpreter, CTX>, BASE_BLOCKHASH_COST),
    );
    evm
}

/// Slot identifier within the EIP-2935 ring buffer for the requested block number.
#[inline]
pub fn slot_index(requested_block_number: u64) -> u64 {
    requested_block_number % HISTORY_SERVE_WINDOW
}

/// Whether the requested block number falls inside the BLOCKHASH visible window.
#[inline]
pub fn is_in_window(delta: i64) -> bool {
    (1..=BLOCKHASH_VISIBLE_WINDOW as i64).contains(&delta)
}

/// Classification of a BLOCKHASH execution under EIP-2929 journal semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmthClass {
    Cold,
    Warm,
    OutOfWindow,
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

    pub const fn extra_cost(self) -> u64 {
        match self {
            Self::Cold => COLD_SLOAD_COST,
            Self::Warm => WARM_SLOAD_COST,
            Self::OutOfWindow | Self::Unknown => 0,
        }
    }

    pub const fn total_cost(self) -> u64 {
        BASE_BLOCKHASH_COST + self.extra_cost()
    }
}

fn eip7709_blockhash<WIRE, CTX>(context: InstructionContext<'_, CTX, WIRE>)
where
    WIRE: InterpreterTypes,
    CTX: ContextTr,
{
    if context.interpreter.stack.len() < 1 {
        context.interpreter.halt_underflow();
        return;
    }
    // SAFETY: the length check above guarantees the top item exists.
    let ([], number) = unsafe { context.interpreter.stack.popn_top::<0>().unwrap_unchecked() };

    let requested_number = *number;
    let block_number = context.host.block_number();
    let Some(diff) = block_number.checked_sub(requested_number) else {
        LAST_ACCESS.set(Some(WarmthClass::OutOfWindow));
        *number = U256::ZERO;
        return;
    };

    let diff = u64::try_from(diff).unwrap_or(u64::MAX);
    if diff == 0 || diff > BLOCKHASH_VISIBLE_WINDOW {
        LAST_ACCESS.set(Some(WarmthClass::OutOfWindow));
        *number = U256::ZERO;
        return;
    }

    if eip7709_enabled() {
        let requested =
            u64::try_from(requested_number).expect("an in-window block number always fits in u64");
        let key = U256::from(slot_index(requested));

        // Loading the remote account is an implementation detail of accessing its storage. Undo
        // any newly introduced address warmth: EIP-7709 charges and warms the storage key exactly
        // like SLOAD, but it does not add an EXTCODE/BALANCE-style address access.
        if let Err(err) = prepare_history_account(context.host) {
            *context.host.error() = Err(err.into());
            return context.interpreter.halt_fatal();
        }

        let cold_cost = context.host.gas_params().cold_storage_cost();
        let warm_cost = context.host.gas_params().warm_storage_read_cost();
        let skip_cold = context.interpreter.gas.remaining() < cold_cost;
        let storage = context.host.sload_skip_cold_load(HISTORY_STORAGE_ADDRESS, key, skip_cold);
        let warmth = match storage {
            Ok(storage) => {
                if storage.is_cold {
                    WarmthClass::Cold
                } else {
                    WarmthClass::Warm
                }
            }
            Err(reth_revm::revm::context_interface::host::LoadError::ColdLoadSkipped) => {
                LAST_ACCESS.set(Some(WarmthClass::Cold));
                return context.interpreter.halt_oog();
            }
            Err(reth_revm::revm::context_interface::host::LoadError::DBError) => {
                return context.interpreter.halt_fatal();
            }
        };
        LAST_ACCESS.set(Some(warmth));
        let cost = if warmth == WarmthClass::Cold { cold_cost } else { warm_cost };
        if !context.interpreter.gas.record_regular_cost(cost) {
            return context.interpreter.halt_oog();
        }
    } else {
        LAST_ACCESS.set(Some(WarmthClass::Unknown));
    }

    let requested = u64::try_from(requested_number).expect("an in-window block number fits u64");
    let Some(hash) = context.host.block_hash(requested) else {
        return context.interpreter.halt_fatal();
    };
    *number = U256::from_be_bytes(hash.0);
}

fn prepare_history_account<CTX>(
    context: &mut CTX,
) -> Result<(), <CTX::Db as reth_revm::revm::database_interface::Database>::Error>
where
    CTX: ContextTr,
{
    let mut account_load = context.journal_mut().load_account_mut(HISTORY_STORAGE_ADDRESS)?;
    if account_load.is_cold {
        account_load.data.unsafe_mark_cold();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip2935_ring_boundaries_are_exact() {
        assert_eq!(HISTORY_SERVE_WINDOW, 8191);
        assert_eq!(slot_index(8190), 8190);
        assert_eq!(slot_index(8191), 0);
        assert_eq!(slot_index(8192), 1);
    }

    #[test]
    fn visible_window_boundaries_are_exact() {
        assert!(!is_in_window(0));
        assert!(is_in_window(1));
        assert!(is_in_window(256));
        assert!(!is_in_window(257));
    }
}
