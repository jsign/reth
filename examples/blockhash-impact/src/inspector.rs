//! revm `Inspector` that records every BLOCKHASH execution event.
//!
//! Two modes:
//! - Observation: `inject_eip7709 == false` records canonical execution and only annotates rows
//!   with the EIP-7709 classification (cold/warm/out-of-window/unknown).
//! - Simulation: `inject_eip7709 == true` charges EIP-7709 SLOAD-equivalent gas on every in-window
//!   BLOCKHASH and triggers OOG via `Interpreter::halt_oog` when a frame can't afford it, letting
//!   revm unwind canonically.

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
use std::{collections::HashSet, fmt};

use crate::{
    eip7709::{
        is_in_window as eip7709_is_in_window, slot_index as eip7709_slot_index, WarmthClass,
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
    /// When true, charges EIP-7709 SLOAD-equivalent gas at every BLOCKHASH and triggers OOG via
    /// `Interpreter::halt_oog` on insufficient gas; otherwise observation-only.
    inject_eip7709: bool,
    /// Per-tx slot warmth simulation. When `inject_eip7709` is on, this mirrors the journal's
    /// access list (we still use `ctx.sload` for the authoritative `is_cold`); when off, this is
    /// the only warmth source. Reset every tx via [`Self::reset_for_next_tx`].
    warmth_set: HashSet<u64>,
}

impl BlockhashImpactInspector {
    /// Constructs an inspector. `inject_eip7709 == true` simulates the new BLOCKHASH cost model in
    /// revm; `false` records canonical execution and only annotates rows with classification.
    pub fn new(inject_eip7709: bool) -> Self {
        Self { inject_eip7709, ..Self::default() }
    }

    /// Whether this inspector charges EIP-7709 SLOAD gas during execution.
    pub fn inject_eip7709(&self) -> bool {
        self.inject_eip7709
    }

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

        // Classify slot warmth via a per-tx `HashSet`. We don't consult `ctx.sload` because the
        // host trait's `sload` requires the account to be already loaded (it returns
        // `ColdLoadSkipped` otherwise), and `HISTORY_STORAGE_ADDRESS` is never touched by any
        // canonical user-code instruction — so the simulation matches what an EIP-7709-aware EVM
        // would observe.
        let warmth_class = if !in_window {
            WarmthClass::OutOfWindow
        } else if let Some(slot) = slot {
            if self.warmth_set.insert(slot) {
                WarmthClass::Cold
            } else {
                WarmthClass::Warm
            }
        } else {
            WarmthClass::Unknown
        };

        let gas_before = interp.gas.remaining();
        let event_index = self.next_event_index;
        self.next_event_index += 1;
        let pc = interp.bytecode.pc() as u64;

        // EIP-7709 charges `BASE + SLOAD-equivalent`. revm's instruction table charges the BASE
        // (20) inside `Interpreter::step` AFTER this hook runs, so we only need to inject the
        // SLOAD-equivalent extra here. If the frame can't afford it, halt with OOG and let revm
        // unwind the call frame canonically. Note: when `halt_oog` is called the inspector loop
        // breaks BEFORE `step_end` fires, so we must push the event row here directly.
        if self.inject_eip7709 {
            let extra = warmth_class.extra_cost();
            if extra > 0 && !interp.gas.record_regular_cost(extra) {
                interp.halt_oog();
                self.events.push(BlockhashEventRecord {
                    frame_id,
                    event_index,
                    pc,
                    requested_block_number,
                    requested_block_delta,
                    slot_index: slot,
                    is_in_window: in_window,
                    warmth_class,
                    gas_before,
                    gas_after: 0,
                    observed_gas_cost: gas_before,
                });
                return;
            }
        }

        self.pending_blockhash = Some(PendingBlockhash {
            frame_id,
            event_index,
            pc,
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
            warmth_class: pending.warmth_class,
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
    use crate::eip7709::BASE_BLOCKHASH_COST;
    use alloy_primitives::{address, B256, U256};
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
        // Without injection: classification still computed via per-tx HashSet.
        let rows = run_call_contract(code.clone(), TEST_BLOCK_NUMBER).rows;
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

    pub(super) struct InspectorRun {
        pub rows: Vec<BlockhashRow>,
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
        let bytecode = Bytecode::new_raw(Bytes::from(code));
        let context = Context::mainnet()
            .modify_block_chained(|block| block.number = U256::from(block_number))
            .with_db(BenchmarkDB::new_bytecode(bytecode));
        let mut evm =
            context.build_mainnet_with_inspector(BlockhashImpactInspector::new(inject_eip7709));
        let result = evm
            .inspect_one_tx(
                revm::context::TxEnv::builder()
                    .caller(BENCH_CALLER)
                    .kind(TxKind::Call(BENCH_TARGET))
                    .gas_limit(gas_limit)
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
                    gas_limit,
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
}
