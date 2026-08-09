//! revm `Inspector` that records every BLOCKHASH execution event.
//!
//! Gas injection lives in the opcode implementation in [`crate::eip7709`]. Keeping the inspector
//! observational is important: storage warmth and rollback are owned by revm's journal.

use alloy_primitives::Address;
use reth_revm::revm::{
    self as revm,
    bytecode::opcode,
    context_interface::ContextTr,
    inspector::Inspector,
    interpreter::{
        interpreter_types::{InputsTr, Jumps},
        CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, CreateScheme,
        Interpreter,
    },
};
use std::{collections::HashMap, fmt};

use crate::{
    eip7709::{
        clear_last_access, eip7709_enabled, is_in_window as eip7709_is_in_window,
        slot_index as eip7709_slot_index, take_last_access, WarmthClass,
    },
    row::{
        block_number_delta, format_tx_status, gas_headroom, hex, BlockExecutionContext,
        BlockhashRow, FrameKind, TxExecutionMetadata,
    },
};

#[derive(Debug, Clone, Default)]
pub struct BlockhashImpactInspector {
    next_frame_id: u64,
    next_event_index: u64,
    frame_stack: Vec<u64>,
    frames: Vec<FrameRecord>,
    events: Vec<BlockhashEventRecord>,
    pending_blockhash: Option<PendingBlockhash>,
    pc_occurrences: HashMap<(u64, u64), u32>,
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
        self.finalize_aborted_pending();
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

                let eip7709_extra_cost = event.warmth_class.extra_cost();
                let eip7709_new_cost = event.warmth_class.total_cost();
                let eip7709_new_headroom =
                    i64::try_from(event.gas_before).unwrap_or(i64::MAX) - eip7709_new_cost as i64;
                let eip7709_would_oog_frame = event.gas_before < eip7709_new_cost;

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
                    frame_path: frame.path.clone(),
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
                    pc_occurrence: event.pc_occurrence,
                    requested_block_number: event.requested_block_number,
                    requested_block_delta: event.requested_block_delta,
                    gas_before: event.gas_before,
                    gas_after: event.gas_after,
                    observed_gas_cost: event.observed_gas_cost,
                    extra_gas_headroom: gas_headroom(event.gas_before),
                    slot_index: event.slot_index,
                    is_in_window: event.is_in_window,
                    slot_warmth_class: event.warmth_class.as_str().to_string(),
                    eip7709_extra_cost,
                    eip7709_new_cost,
                    eip7709_new_headroom,
                    eip7709_would_oog_frame,
                    simulation_matched: false,
                    simulation_event_index: None,
                    simulation_gas_before: None,
                    simulation_gas_after: None,
                    simulation_observed_gas_cost: None,
                    simulation_frame_end_status: None,
                }
            })
            .collect()
    }

    fn finalize_aborted_pending(&mut self) {
        let Some(pending) = self.pending_blockhash.take() else {
            return;
        };
        let warmth_class = take_last_access().unwrap_or(pending.warmth_class);
        self.events.push(BlockhashEventRecord {
            frame_id: pending.frame_id,
            event_index: pending.event_index,
            pc: pending.pc,
            pc_occurrence: pending.pc_occurrence,
            requested_block_number: pending.requested_block_number,
            requested_block_delta: pending.requested_block_delta,
            slot_index: pending.slot_index,
            is_in_window: pending.is_in_window,
            warmth_class,
            gas_before: pending.gas_before,
            gas_after: 0,
            observed_gas_cost: pending.gas_before,
        });
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
        let path = if let Some(parent_id) = parent_frame_id {
            let parent = self
                .frames
                .iter_mut()
                .find(|frame| frame.id == parent_id)
                .expect("parent frame is tracked");
            let child = parent.next_child_index;
            parent.next_child_index += 1;
            format!("{}.{}", parent.path, child)
        } else {
            "0".to_string()
        };
        self.frames.push(FrameRecord {
            id: frame_id,
            path,
            parent_frame_id,
            depth,
            kind,
            caller,
            target,
            code_address,
            gas_limit,
            is_static,
            end_status: None,
            next_child_index: 0,
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

    fn step(&mut self, interp: &mut Interpreter, context: &mut CTX) {
        if interp.bytecode.opcode() != opcode::BLOCKHASH {
            return;
        }

        let Some(frame_id) = self.frame_stack.last().copied() else {
            return;
        };

        let requested_block_number =
            interp.stack.peek(0).ok().and_then(|number| u64::try_from(number).ok());
        let block_number = u64::try_from(context.block_number()).unwrap_or(u64::MAX);
        let requested_block_delta = requested_block_number
            .and_then(|requested| block_number_delta(block_number, requested));
        let in_window = requested_block_delta.is_some_and(eip7709_is_in_window);
        let slot = requested_block_number.map(eip7709_slot_index);

        // The opcode records the actual journal access result after this callback. Canonical
        // execution keeps in-window warmth unknown because it performs no storage access.
        let warmth_class = if in_window { WarmthClass::Unknown } else { WarmthClass::OutOfWindow };

        let gas_before = interp.gas.remaining();
        let event_index = self.next_event_index;
        self.next_event_index += 1;
        let pc = interp.bytecode.pc() as u64;
        let occurrence = self.pc_occurrences.entry((frame_id, pc)).or_default();
        let pc_occurrence = *occurrence;
        *occurrence += 1;
        clear_last_access();

        self.pending_blockhash = Some(PendingBlockhash {
            frame_id,
            event_index,
            pc,
            pc_occurrence,
            requested_block_number,
            requested_block_delta,
            slot_index: slot,
            is_in_window: in_window,
            warmth_class,
            gas_before,
        });
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
            requested_block_delta: pending.requested_block_delta,
            slot_index: pending.slot_index,
            is_in_window: pending.is_in_window,
            pc_occurrence: pending.pc_occurrence,
            warmth_class: if eip7709_enabled() {
                take_last_access().unwrap_or(pending.warmth_class)
            } else {
                pending.warmth_class
            },
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

#[derive(Debug, Clone)]
struct FrameRecord {
    id: u64,
    path: String,
    parent_frame_id: Option<u64>,
    depth: u32,
    kind: FrameKind,
    caller: Address,
    target: Option<Address>,
    code_address: Option<Address>,
    gas_limit: u64,
    is_static: bool,
    end_status: Option<String>,
    next_child_index: u32,
}

#[derive(Debug, Clone)]
struct BlockhashEventRecord {
    frame_id: u64,
    event_index: u64,
    pc: u64,
    pc_occurrence: u32,
    requested_block_number: Option<u64>,
    requested_block_delta: Option<i64>,
    slot_index: Option<u64>,
    is_in_window: bool,
    warmth_class: WarmthClass,
    gas_before: u64,
    gas_after: u64,
    observed_gas_cost: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingBlockhash {
    frame_id: u64,
    event_index: u64,
    pc: u64,
    pc_occurrence: u32,
    requested_block_number: Option<u64>,
    requested_block_delta: Option<i64>,
    slot_index: Option<u64>,
    is_in_window: bool,
    warmth_class: WarmthClass,
    gas_before: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip7709::{
        install_eip7709_instruction_raw, with_eip7709_enabled, BASE_BLOCKHASH_COST,
        HISTORY_STORAGE_ADDRESS,
    };
    use alloy_primitives::{address, B256, U256};
    use reth_revm::{
        revm::{
            bytecode::Bytecode,
            context_interface::transaction::{AccessList, AccessListItem},
            database::{BenchmarkDB, CacheDB, EmptyDB, BENCH_CALLER, BENCH_TARGET},
            primitives::{Bytes, TxKind},
            state::AccountInfo,
            Context, MainBuilder,
        },
        InspectEvm, MainContext,
    };

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
    fn eip7709_classification_in_window_is_cold_then_warm_in_same_tx() {
        // Two BLOCKHASH calls in the same tx with the same arg → first cold, second warm.
        // BLOCKHASH(1); POP; BLOCKHASH(1); STOP
        let code = vec![
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::POP,
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::STOP,
        ];
        let rows =
            run_call_contract_with(code.clone(), TEST_BLOCK_NUMBER, true, TEST_GAS_LIMIT).rows;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].slot_warmth_class, "cold");
        assert_eq!(rows[1].slot_warmth_class, "warm");
        assert!(rows[0].is_in_window);
        assert_eq!(rows[0].slot_index, Some(1));
        assert_eq!(rows[0].eip7709_extra_cost, 2100);
        assert_eq!(rows[1].eip7709_extra_cost, 100);
        assert_eq!(rows[0].eip7709_new_cost, 2120);
        assert_eq!(rows[1].eip7709_new_cost, 120);
    }

    #[test]
    fn eip7709_out_of_window_charges_only_base() {
        // BLOCKHASH(block.number) → delta = 0 → out_of_window → no SLOAD charge.
        let code = vec![opcode::PUSH1, TEST_BLOCK_NUMBER as u8, opcode::BLOCKHASH, opcode::STOP];
        let rows = run_call_contract(code, TEST_BLOCK_NUMBER).rows;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].slot_warmth_class, "out_of_window");
        assert!(!rows[0].is_in_window);
        assert_eq!(rows[0].eip7709_extra_cost, 0);
        assert_eq!(rows[0].eip7709_new_cost, BASE_BLOCKHASH_COST);
    }

    #[test]
    fn eip7709_out_of_window_access_does_not_warm_its_slot() {
        // At block 8200, requests 1 and 8192 map to slot 1. Only 8192 is in the 256-block window,
        // so the earlier out-of-window request must leave the shared slot cold.
        let code = vec![
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::POP,
            opcode::PUSH2,
            0x20,
            0x00,
            opcode::BLOCKHASH,
            opcode::STOP,
        ];
        let rows = run_call_contract_with(code, 8_200, true, TEST_GAS_LIMIT).rows;

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].slot_index, Some(1));
        assert_eq!(rows[0].slot_warmth_class, "out_of_window");
        assert_eq!(rows[1].slot_index, Some(1));
        assert_eq!(rows[1].slot_warmth_class, "cold");
    }

    #[test]
    fn eip7709_simulate_oog_halts_the_tx() {
        // Tight gas budget: tx pays the 21k intrinsic + a few opcodes; not enough for the cold
        // SLOAD charge. With injection on, the call must Halt(OutOfGas).
        let code = vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP];
        // 21_000 intrinsic + 3 (PUSH1) + 20 (BLOCKHASH) + 0 (STOP) = 21_023; with injection of
        // 2100 extra the tx needs 23_123 and we only give 22_500.
        let rows = run_call_contract_with(code, TEST_BLOCK_NUMBER, true, 22_500).rows;
        // The event is still recorded (we capture pending_blockhash before halting).
        assert_eq!(rows.len(), 1);
        assert!(rows[0].tx_status.starts_with("Halt("), "got tx_status={}", rows[0].tx_status);
        assert!(rows[0].eip7709_would_oog_frame);
    }

    #[test]
    fn eip7709_simulate_succeeds_when_budget_is_sufficient() {
        let code = vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP];
        let rows = run_call_contract_with(code, TEST_BLOCK_NUMBER, true, TEST_GAS_LIMIT).rows;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].tx_status.starts_with("Success("));
        // With injection, observed_gas_cost should reflect 20 + 2100.
        assert_eq!(rows[0].observed_gas_cost, 2120);
        assert!(!rows[0].eip7709_would_oog_frame);
    }

    #[test]
    fn access_list_prewarms_the_history_slot() {
        let code = vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP];
        let access_list = AccessList(vec![AccessListItem {
            address: HISTORY_STORAGE_ADDRESS,
            storage_keys: vec![B256::from(U256::from(1).to_be_bytes())],
        }]);
        let rows = run_call_contract_with_access_list(
            code,
            TEST_BLOCK_NUMBER,
            true,
            TEST_GAS_LIMIT,
            Some(access_list),
        )
        .rows;

        assert_eq!(rows[0].slot_warmth_class, "warm");
        assert_eq!(rows[0].observed_gas_cost, 120);
    }

    #[test]
    fn successful_and_reverted_calls_follow_journal_warmth() {
        let callee = address!("1000000000000000000000000000000000000010");
        let successful_callee =
            vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::POP, opcode::STOP];
        let mut caller = call_contract_bytecode(callee);
        caller.pop();
        caller.extend_from_slice(&[opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP]);
        let successful = run_nested_call_with_mode(
            caller.clone(),
            callee,
            successful_callee,
            TEST_BLOCK_NUMBER,
            true,
        )
        .rows;
        assert_eq!(successful.len(), 2);
        assert_eq!(successful[0].slot_warmth_class, "cold");
        assert_eq!(successful[1].slot_warmth_class, "warm");

        let reverted_callee = vec![
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::REVERT,
        ];
        let reverted =
            run_nested_call_with_mode(caller, callee, reverted_callee, TEST_BLOCK_NUMBER, true)
                .rows;
        assert_eq!(reverted.len(), 2);
        assert_eq!(reverted[0].slot_warmth_class, "cold");
        assert_eq!(reverted[1].slot_warmth_class, "cold");
    }

    #[test]
    fn direct_history_contract_sload_prewarms_blockhash() {
        let history_code =
            vec![opcode::PUSH1, 0x00, opcode::CALLDATALOAD, opcode::SLOAD, opcode::STOP];
        let caller_code = call_history_then_blockhash_bytecode();
        let rows = run_nested_call_with_mode(
            caller_code,
            HISTORY_STORAGE_ADDRESS,
            history_code,
            TEST_BLOCK_NUMBER,
            true,
        )
        .rows;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].slot_warmth_class, "warm");
        assert_eq!(rows[0].observed_gas_cost, 120);
    }

    #[test]
    fn gas_after_blockhash_can_change_successful_output() {
        let code = vec![
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::POP,
            opcode::GAS,
            opcode::PUSH1,
            0x00,
            opcode::MSTORE,
            opcode::PUSH1,
            0x20,
            opcode::PUSH1,
            0x00,
            opcode::RETURN,
        ];
        let canonical =
            run_call_contract_with(code.clone(), TEST_BLOCK_NUMBER, false, TEST_GAS_LIMIT);
        let simulated = run_call_contract_with(code, TEST_BLOCK_NUMBER, true, TEST_GAS_LIMIT);

        assert!(canonical.result.result.is_success());
        assert!(simulated.result.result.is_success());
        assert_ne!(canonical.result.result.output(), simulated.result.result.output());
        let impact = compare_runs(canonical, &simulated);
        assert_eq!(impact.classification, "observable_change");
        assert!(impact.output_changed);
        assert!(!impact.state_changed);
    }

    #[test]
    fn ordinary_repricing_is_gas_only_and_history_read_is_not_state() {
        let code = vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP];
        let canonical =
            run_call_contract_with(code.clone(), TEST_BLOCK_NUMBER, false, TEST_GAS_LIMIT);
        let simulated = run_call_contract_with(code, TEST_BLOCK_NUMBER, true, TEST_GAS_LIMIT);
        let impact = compare_runs(canonical, &simulated);

        assert_eq!(impact.classification, "gas_only");
        assert_eq!(impact.gas_delta, Some(2_100));
        assert!(!impact.output_changed);
        assert!(!impact.state_changed);
    }

    fn compare_runs(
        mut canonical: InspectorRun,
        simulated: &InspectorRun,
    ) -> crate::row::TransactionImpactRow {
        let (unmatched_canonical, unmatched_simulation) =
            crate::impact::pair_event_rows(&mut canonical.rows, &simulated.rows);
        let block = BlockExecutionContext {
            block_number: TEST_BLOCK_NUMBER,
            block_hash: B256::repeat_byte(0x22),
            beneficiary: Address::ZERO,
            base_fee: 0,
        };
        let tx = TxExecutionMetadata {
            tx_index: 0,
            tx_hash: B256::repeat_byte(0x11),
            from: BENCH_CALLER,
            to: Some(BENCH_TARGET),
            nonce: 0,
            tx_type: TEST_TX_TYPE,
            gas_limit: TEST_GAS_LIMIT,
            effective_gas_price: 0,
            priority_fee_per_gas: 0,
        };
        crate::impact::compare_transaction(
            block,
            &tx,
            &canonical.result,
            Ok(&simulated.result),
            crate::impact::TraceComparison {
                canonical_rows: &canonical.rows,
                simulated_rows: &simulated.rows,
                unmatched_canonical_events: unmatched_canonical,
                unmatched_simulation_events: unmatched_simulation,
            },
        )
    }

    #[test]
    fn caught_inner_oog_keeps_the_transaction_successful() {
        let callee = address!("1000000000000000000000000000000000000011");
        let callee_code = vec![opcode::PUSH1, 0x01, opcode::BLOCKHASH, opcode::STOP];
        let mut caller_code = call_contract_bytecode(callee);
        let gas_immediate = caller_code.len() - 4;
        caller_code[gas_immediate] = 0x01;
        caller_code[gas_immediate + 1] = 0xf4;

        let rows =
            run_nested_call_with_mode(caller_code, callee, callee_code, TEST_BLOCK_NUMBER, true)
                .rows;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].tx_status.starts_with("Success("));
        assert!(rows[0]
            .frame_end_status
            .as_deref()
            .is_some_and(|status| status.starts_with("OutOfGas")));
    }

    pub(super) struct InspectorRun {
        pub rows: Vec<BlockhashRow>,
        pub result: revm::context::result::ResultAndState,
    }

    fn run_call_contract(code: Vec<u8>, block_number: u64) -> InspectorRun {
        run_call_contract_with(code, block_number, false, TEST_GAS_LIMIT)
    }

    fn run_call_contract_with(
        code: Vec<u8>,
        block_number: u64,
        inject_eip7709: bool,
        gas_limit: u64,
    ) -> InspectorRun {
        run_call_contract_with_access_list(code, block_number, inject_eip7709, gas_limit, None)
    }

    fn run_call_contract_with_access_list(
        code: Vec<u8>,
        block_number: u64,
        inject_eip7709: bool,
        gas_limit: u64,
        access_list: Option<AccessList>,
    ) -> InspectorRun {
        let bytecode = Bytecode::new_raw(Bytes::from(code));
        let context = Context::mainnet()
            .modify_block_chained(|block| block.number = U256::from(block_number))
            .with_db(BenchmarkDB::new_bytecode(bytecode));
        let evm = context.build_mainnet_with_inspector(BlockhashImpactInspector::default());
        let mut evm = install_eip7709_instruction_raw(evm);
        let mut tx = revm::context::TxEnv::builder()
            .caller(BENCH_CALLER)
            .kind(TxKind::Call(BENCH_TARGET))
            .gas_limit(gas_limit);
        if let Some(access_list) = access_list {
            tx = tx.access_list(access_list);
        }
        let tx = tx.build().unwrap();
        let execute = || evm.inspect_tx(tx);
        let result =
            if inject_eip7709 { with_eip7709_enabled(execute) } else { execute() }.unwrap();

        let rows = evm.inspector.into_rows(
            BlockExecutionContext {
                block_number,
                block_hash: B256::repeat_byte(0x22),
                beneficiary: Address::ZERO,
                base_fee: 0,
            },
            TxExecutionMetadata {
                tx_index: 0,
                tx_hash: B256::repeat_byte(0x11),
                from: BENCH_CALLER,
                to: Some(BENCH_TARGET),
                nonce: 0,
                tx_type: TEST_TX_TYPE,
                gas_limit,
                effective_gas_price: 0,
                priority_fee_per_gas: 0,
            },
            &result.result,
        );
        InspectorRun { rows, result }
    }

    fn run_nested_call(
        caller_code: Vec<u8>,
        callee_address: Address,
        callee_code: Vec<u8>,
        block_number: u64,
    ) -> InspectorRun {
        run_nested_call_with_mode(caller_code, callee_address, callee_code, block_number, false)
    }

    fn run_nested_call_with_mode(
        caller_code: Vec<u8>,
        callee_address: Address,
        callee_code: Vec<u8>,
        block_number: u64,
        inject_eip7709: bool,
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
        let evm = context.build_mainnet_with_inspector(BlockhashImpactInspector::default());
        let mut evm = install_eip7709_instruction_raw(evm);
        let mut execute = || {
            evm.inspect_tx(
                revm::context::TxEnv::builder()
                    .caller(BENCH_CALLER)
                    .kind(TxKind::Call(BENCH_TARGET))
                    .gas_limit(TEST_GAS_LIMIT)
                    .build()
                    .unwrap(),
            )
        };
        let result =
            if inject_eip7709 { with_eip7709_enabled(execute) } else { execute() }.unwrap();

        let rows = evm.inspector.into_rows(
            BlockExecutionContext {
                block_number,
                block_hash: B256::repeat_byte(0x33),
                beneficiary: Address::ZERO,
                base_fee: 0,
            },
            TxExecutionMetadata {
                tx_index: 0,
                tx_hash: B256::repeat_byte(0x44),
                from: BENCH_CALLER,
                to: Some(BENCH_TARGET),
                nonce: 0,
                tx_type: TEST_TX_TYPE,
                gas_limit: TEST_GAS_LIMIT,
                effective_gas_price: 0,
                priority_fee_per_gas: 0,
            },
            &result.result,
        );
        InspectorRun { rows, result }
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

    fn call_history_then_blockhash_bytecode() -> Vec<u8> {
        let mut bytecode = vec![
            opcode::PUSH1,
            0x01,
            opcode::PUSH1,
            0x00,
            opcode::MSTORE,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x00,
            opcode::PUSH1,
            0x20,
            opcode::PUSH1,
            0x00,
            opcode::PUSH20,
        ];
        bytecode.extend_from_slice(HISTORY_STORAGE_ADDRESS.as_slice());
        bytecode.extend_from_slice(&[
            opcode::PUSH2,
            0xff,
            0xff,
            opcode::STATICCALL,
            opcode::POP,
            opcode::PUSH1,
            0x01,
            opcode::BLOCKHASH,
            opcode::STOP,
        ]);
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
}
