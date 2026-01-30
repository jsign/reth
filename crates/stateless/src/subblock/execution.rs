//! Partial block execution utilities for subblock validation.
//!
//! Creates execution contexts customized for subblock position.
//!
//! # Subblock Positions
//!
//! A subblock's position determines which extra processing occurs:
//!
//! | Position | `is_first` | `is_last` | Pre-execution | Post-execution |
//! |----------|------------|-----------|---------------|----------------|
//! | First    | `true`     | `false`   | Beacon root, blockhashes | - |
//! | Middle   | `false`    | `false`   | - | - |
//! | Last     | `false`    | `true`    | - | Withdrawals |
//! | Single   | `true`     | `true`    | Beacon root, blockhashes | Withdrawals |
//!
//! # Flag Derivation from BAL Range
//!
//! - `is_first = bal_range.start == 0` (includes pre-execution at index 0)
//! - `is_last = bal_range.end > tx_count` (includes post-execution at index N+1)

use alloc::borrow::Cow;
use alloy_consensus::BlockHeader;
use alloy_evm::eth::EthBlockExecutionCtx;
use reth_ethereum_primitives::Block;
use reth_primitives_traits::RecoveredBlock;

/// Creates an execution context customized for subblock position.
///
/// - First subblock (`is_first=true`): Includes `parent_beacon_block_root` for pre-execution
/// - Last subblock (`is_last=true`): Includes `withdrawals` for post-execution
/// - Middle subblocks: Neither pre nor post execution
pub fn create_subblock_execution_ctx<'a>(
    block: &'a RecoveredBlock<Block>,
    is_last: bool,
) -> EthBlockExecutionCtx<'a> {
    EthBlockExecutionCtx {
        tx_count_hint: Some(block.transaction_count()),
        parent_hash: block.header().parent_hash(),
        // Always pass the actual value - only used if apply_pre_execution_changes() is called
        parent_beacon_block_root: block.header().parent_beacon_block_root(),
        ommers: &block.body().ommers,
        // Only last subblock processes withdrawals in finish()
        withdrawals: if is_last {
            block.body().withdrawals.as_ref().map(Cow::Borrowed)
        } else {
            None
        },
        extra_data: block.header().extra_data().clone(),
        slot_number: block.header().slot_number(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_consensus::Header;
    use alloy_primitives::{Bytes as PrimitiveBytes, B256};
    use reth_ethereum_primitives::{Block, BlockBody};
    use reth_primitives_traits::RecoveredBlock;

    fn mock_recovered_block(with_withdrawals: bool) -> RecoveredBlock<Block> {
        let header = Header {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::repeat_byte(0x42)),
            extra_data: PrimitiveBytes::from_static(b"test"),
            ..Default::default()
        };
        let withdrawals = if with_withdrawals { Some(vec![].into()) } else { None };
        let body = BlockBody { transactions: vec![], ommers: vec![], withdrawals };
        let block = Block { header, body };
        RecoveredBlock::new_unhashed(block, vec![])
    }

    #[test]
    fn test_first_subblock_ctx_has_beacon_root() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, false);

        assert!(ctx.parent_beacon_block_root.is_some());
        assert!(ctx.withdrawals.is_none()); // Not last
    }

    #[test]
    fn test_last_subblock_ctx_has_withdrawals() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, true);

        assert!(ctx.withdrawals.is_some());
    }

    #[test]
    fn test_middle_subblock_ctx_has_neither() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, false);

        assert!(ctx.withdrawals.is_none());
    }

    #[test]
    fn test_single_subblock_ctx_has_both() {
        let block = mock_recovered_block(true);
        let ctx = create_subblock_execution_ctx(&block, true);

        assert!(ctx.parent_beacon_block_root.is_some());
        assert!(ctx.withdrawals.is_some());
    }
}
