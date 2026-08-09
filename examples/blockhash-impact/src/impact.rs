//! Normalized comparison of canonical and theoretical transaction execution.

use alloy_primitives::{Address, U256};
use reth_revm::revm::{
    context::result::ResultAndState,
    state::{Account, EvmState},
};
use std::{collections::HashMap, fmt};

use crate::row::{
    format_tx_status, hex, BlockExecutionContext, BlockhashRow, TransactionImpactRow,
    TxExecutionMetadata,
};

/// Pair event rows using coordinates that remain stable across control-flow divergence.
pub(crate) fn pair_event_rows(
    canonical: &mut [BlockhashRow],
    simulated: &[BlockhashRow],
) -> (u64, u64) {
    let mut simulation_index: HashMap<EventKey, &BlockhashRow> =
        simulated.iter().map(|row| (EventKey::new(row), row)).collect();
    let mut unmatched_canonical = 0;
    for row in canonical {
        if let Some(simulated) = simulation_index.remove(&EventKey::new(row)) {
            row.attach_simulation(simulated);
        } else {
            unmatched_canonical += 1;
        }
    }
    (unmatched_canonical, simulation_index.len() as u64)
}

pub(crate) fn compare_transaction<H>(
    block: BlockExecutionContext,
    tx: &TxExecutionMetadata,
    canonical: &ResultAndState<H>,
    simulated: Result<&ResultAndState<H>, &str>,
    trace: TraceComparison<'_>,
) -> TransactionImpactRow
where
    H: Clone + fmt::Debug + PartialEq + Eq,
{
    let TraceComparison {
        canonical_rows,
        simulated_rows,
        unmatched_canonical_events,
        unmatched_simulation_events,
    } = trace;
    let canonical_status = format_tx_status(&canonical.result);
    let base = TransactionImpactRow {
        block_number: block.block_number,
        block_hash: hex(block.block_hash),
        tx_index: tx.tx_index,
        tx_hash: hex(tx.tx_hash),
        tx_from: hex(tx.from),
        tx_to: tx.to.map(hex),
        canonical_gas_used: canonical.result.tx_gas_used(),
        simulated_gas_used: None,
        gas_delta: None,
        canonical_status,
        simulated_status: None,
        classification: "simulation_error".to_string(),
        status_changed: false,
        output_changed: false,
        logs_changed: false,
        created_address_changed: false,
        state_changed: false,
        trace_diverged: unmatched_canonical_events > 0 || unmatched_simulation_events > 0,
        internal_breakage: false,
        new_tx_oog: false,
        canonical_event_count: canonical_rows.len() as u64,
        simulated_event_count: None,
        unmatched_canonical_events,
        unmatched_simulation_events,
        simulation_error: None,
    };

    let simulated = match simulated {
        Ok(simulated) => simulated,
        Err(error) => {
            return TransactionImpactRow { simulation_error: Some(error.to_string()), ..base }
        }
    };

    let simulated_status = format_tx_status(&simulated.result);
    let status_changed = base.canonical_status != simulated_status;
    let output_changed = canonical.result.output() != simulated.result.output();
    let logs_changed = canonical.result.logs() != simulated.result.logs();
    let created_address_changed =
        canonical.result.created_address() != simulated.result.created_address();
    let state_changed =
        normalized_state(&canonical.state, block, tx, canonical.result.tx_gas_used()) !=
            normalized_state(&simulated.state, block, tx, simulated.result.tx_gas_used());
    let observable_change =
        status_changed || output_changed || logs_changed || created_address_changed;
    let frame_status_changed = canonical_rows.iter().any(|canonical_event| {
        canonical_event.simulation_matched &&
            canonical_event.frame_end_status != canonical_event.simulation_frame_end_status
    });
    let internal_breakage = base.trace_diverged || frame_status_changed;
    let gas_delta = signed_delta(simulated.result.tx_gas_used(), canonical.result.tx_gas_used());
    let classification = if state_changed {
        "state_change"
    } else if observable_change {
        "observable_change"
    } else if internal_breakage {
        "internal_breakage"
    } else if gas_delta != 0 {
        "gas_only"
    } else {
        "unaffected"
    };
    let new_tx_oog = !is_oog(&base.canonical_status) && is_oog(&simulated_status);

    TransactionImpactRow {
        simulated_gas_used: Some(simulated.result.tx_gas_used()),
        gas_delta: Some(gas_delta),
        simulated_status: Some(simulated_status),
        classification: classification.to_string(),
        status_changed,
        output_changed,
        logs_changed,
        created_address_changed,
        state_changed,
        internal_breakage,
        new_tx_oog,
        simulated_event_count: Some(simulated_rows.len() as u64),
        ..base
    }
}

pub(crate) struct TraceComparison<'a> {
    pub canonical_rows: &'a [BlockhashRow],
    pub simulated_rows: &'a [BlockhashRow],
    pub unmatched_canonical_events: u64,
    pub unmatched_simulation_events: u64,
}

fn signed_delta(left: u64, right: u64) -> i64 {
    let delta = i128::from(left) - i128::from(right);
    i64::try_from(delta).unwrap_or(if delta.is_negative() { i64::MIN } else { i64::MAX })
}

fn is_oog(status: &str) -> bool {
    status.contains("OutOfGas") || status.contains("OutOfGasError")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAccount {
    address: Address,
    balance: U256,
    nonce: u64,
    code_hash: alloy_primitives::B256,
    created: bool,
    selfdestructed: bool,
    loaded_as_not_existing: bool,
    storage: Vec<(U256, U256)>,
}

fn normalized_state(
    state: &EvmState,
    block: BlockExecutionContext,
    tx: &TxExecutionMetadata,
    gas_used: u64,
) -> Vec<NormalizedAccount> {
    let mut accounts = state
        .iter()
        .filter_map(|(address, account)| normalize_account(*address, account, block, tx, gas_used))
        .collect::<Vec<_>>();
    accounts.sort_unstable_by_key(|account| account.address);
    accounts
}

fn normalize_account(
    address: Address,
    account: &Account,
    block: BlockExecutionContext,
    tx: &TxExecutionMetadata,
    gas_used: u64,
) -> Option<NormalizedAccount> {
    let mut storage = account
        .changed_storage_slots()
        .map(|(key, slot)| (*key, slot.present_value))
        .collect::<Vec<_>>();
    storage.sort_unstable_by_key(|(key, _)| *key);

    let has_persistent_effect = account.is_touched() ||
        account.is_created() ||
        account.is_selfdestructed() ||
        account.info.balance != account.original_info.balance ||
        account.info.nonce != account.original_info.nonce ||
        account.info.code_hash != account.original_info.code_hash ||
        !storage.is_empty();
    if !has_persistent_effect {
        return None;
    }

    let gas_used = U256::from(gas_used);
    let mut balance = account.info.balance;
    if address == tx.from {
        balance =
            balance.saturating_add(gas_used.saturating_mul(U256::from(tx.effective_gas_price)));
    }
    if address == block.beneficiary {
        balance =
            balance.saturating_sub(gas_used.saturating_mul(U256::from(tx.priority_fee_per_gas)));
    }

    Some(NormalizedAccount {
        address,
        balance,
        nonce: account.info.nonce,
        code_hash: account.info.code_hash,
        created: account.is_created(),
        selfdestructed: account.is_selfdestructed(),
        loaded_as_not_existing: account.is_loaded_as_not_existing(),
        storage,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EventKey {
    frame_path: String,
    code_address: Option<String>,
    pc: u64,
    occurrence: u32,
}

impl EventKey {
    fn new(row: &BlockhashRow) -> Self {
        Self {
            frame_path: row.frame_path.clone(),
            code_address: row.frame_code_address.clone(),
            pc: row.pc,
            occurrence: row.pc_occurrence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use reth_revm::revm::{
        context::result::{ExecutionResult, HaltReason, Output, ResultGas, SuccessReason},
        state::{AccountInfo, EvmStorageSlot},
    };

    #[test]
    fn read_only_loaded_account_is_not_persistent() {
        let address = Address::repeat_byte(0x11);
        let account = Account::from(AccountInfo::default());
        let mut state = EvmState::default();
        state.insert(address, account);
        assert!(normalized_state(&state, block(), &tx(), 21_000).is_empty());
    }

    #[test]
    fn changed_storage_is_persistent() {
        let address = Address::repeat_byte(0x11);
        let mut account = Account::from(AccountInfo::default());
        account
            .storage
            .insert(U256::ZERO, EvmStorageSlot::new_changed(U256::ZERO, U256::from(1), 0));
        let mut state = EvmState::default();
        state.insert(address, account);
        assert_eq!(normalized_state(&state, block(), &tx(), 21_000).len(), 1);
    }

    #[test]
    fn fee_balance_normalization_distinguishes_gas_from_real_transfers() {
        let canonical = success_result(21_000, Bytes::new(), fee_state(21_000, 0));
        let simulated = success_result(23_100, Bytes::new(), fee_state(23_100, 0));
        let impact = compare(&canonical, &simulated);
        assert_eq!(impact.classification, "gas_only");
        assert!(!impact.state_changed);

        let simulated_transfer = success_result(23_100, Bytes::new(), fee_state(23_100, 7));
        let impact = compare(&canonical, &simulated_transfer);
        assert_eq!(impact.classification, "state_change");
        assert!(impact.state_changed);
    }

    #[test]
    fn successful_output_change_is_observable_without_oog() {
        let canonical = success_result(21_020, Bytes::from_static(&[1]), EvmState::default());
        let simulated = success_result(23_120, Bytes::from_static(&[2]), EvmState::default());
        let impact = compare(&canonical, &simulated);
        assert_eq!(impact.classification, "observable_change");
        assert!(impact.output_changed);
        assert!(!impact.status_changed);
    }

    #[test]
    fn trace_divergence_is_internal_breakage_when_effects_match() {
        let canonical = success_result(21_020, Bytes::new(), EvmState::default());
        let simulated = success_result(23_120, Bytes::new(), EvmState::default());
        let impact = compare_transaction(
            block(),
            &tx(),
            &canonical,
            Ok(&simulated),
            TraceComparison {
                canonical_rows: &[],
                simulated_rows: &[],
                unmatched_canonical_events: 1,
                unmatched_simulation_events: 0,
            },
        );

        assert_eq!(impact.classification, "internal_breakage");
        assert!(impact.trace_diverged);
        assert!(impact.internal_breakage);
    }

    fn compare(
        canonical: &ResultAndState<HaltReason>,
        simulated: &ResultAndState<HaltReason>,
    ) -> TransactionImpactRow {
        compare_transaction(
            block(),
            &tx(),
            canonical,
            Ok(simulated),
            TraceComparison {
                canonical_rows: &[],
                simulated_rows: &[],
                unmatched_canonical_events: 0,
                unmatched_simulation_events: 0,
            },
        )
    }

    fn success_result(gas_used: u64, output: Bytes, state: EvmState) -> ResultAndState<HaltReason> {
        ResultAndState::new(
            ExecutionResult::Success {
                reason: SuccessReason::Return,
                gas: ResultGas::default().with_total_gas_spent(gas_used),
                logs: Vec::new(),
                output: Output::Call(output),
            },
            state,
        )
    }

    fn fee_state(gas_used: u64, semantic_transfer: u64) -> EvmState {
        let metadata = tx();
        let context = block();
        let sender_pre = U256::from(1_000_000_000u64);
        let beneficiary_pre = U256::from(1_000u64);
        let gas = U256::from(gas_used);
        let transfer = U256::from(semantic_transfer);

        let mut sender =
            Account::from(AccountInfo { balance: sender_pre, nonce: 0, ..Default::default() });
        sender.info.balance =
            sender_pre - gas * U256::from(metadata.effective_gas_price) - transfer;
        sender.info.nonce = 1;
        sender.mark_touch();

        let mut beneficiary =
            Account::from(AccountInfo { balance: beneficiary_pre, ..Default::default() });
        beneficiary.info.balance =
            beneficiary_pre + gas * U256::from(metadata.priority_fee_per_gas) + transfer;
        beneficiary.mark_touch();

        let mut state = EvmState::default();
        state.insert(metadata.from, sender);
        state.insert(context.beneficiary, beneficiary);
        state
    }

    fn block() -> BlockExecutionContext {
        BlockExecutionContext {
            block_number: 1,
            block_hash: Default::default(),
            beneficiary: Address::repeat_byte(0x22),
            base_fee: 10,
        }
    }

    fn tx() -> TxExecutionMetadata {
        TxExecutionMetadata {
            tx_index: 0,
            tx_hash: Default::default(),
            from: Address::repeat_byte(0x33),
            to: Some(Address::repeat_byte(0x44)),
            nonce: 0,
            tx_type: 0,
            gas_limit: 100_000,
            effective_gas_price: 12,
            priority_fee_per_gas: 2,
        }
    }
}
