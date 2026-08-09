//! Joins canonical and EIP-7709 row sets and produces a usage-focused BLOCKHASH report.
//!
//! Canonical rows define the set of real BLOCKHASH usages. EIP-7709 rows are joined only to
//! identify simulation outcome changes.

use std::collections::{HashMap, HashSet};

use crate::row::BlockhashRow;

#[derive(Debug, Default)]
pub struct Report {
    pub total_usages: u64,
    pub txs_with_blockhash: u64,
    pub joined_rows: usize,
    pub canonical_only_rows: usize,
    pub eip7709_only_rows: usize,
    pub window_split: WindowSplit,
    pub repricing_split: RepricingSplit,
    pub top_senders: TopSection,
    pub top_tx_recipients: TopSection,
    pub top_contracts: TopSection,
    pub top_code_addresses: TopSection,
}

#[derive(Debug, Default)]
pub struct WindowSplit {
    pub in_window: u64,
    pub out_of_window: u64,
}

#[derive(Debug, Default)]
pub struct RepricingSplit {
    pub cold: u64,
    pub warm: u64,
    pub out_of_window: u64,
    pub unknown: u64,
}

#[derive(Debug, Default)]
pub struct TopSection {
    pub total_usages: u64,
    pub entries: Vec<TopEntry>,
}

#[derive(Debug, Clone)]
pub struct TopEntry {
    pub key: String,
    pub usages: u64,
    pub usage_pct: f64,
    pub immediate_oog: u64,
    pub immediate_oog_pct: f64,
    pub simulation_tx_oog: u64,
    pub simulation_tx_oog_pct: f64,
    pub joined_usages: u64,
    pub simulation_frame_oog: u64,
    pub simulation_frame_oog_pct: f64,
    pub sample_tx_hash: String,
}

/// Build the full report. `canonical` and `eip7709` are joined by
/// `(block_number, tx_hash, event_index)`; rows present on only one side are counted for
/// transparency. Primary usage totals are always derived from canonical rows.
pub fn build_report(canonical: &[BlockhashRow], eip7709: &[BlockhashRow], top_n: usize) -> Report {
    let mut report = Report { total_usages: canonical.len() as u64, ..Report::default() };

    let eip7709_index: HashMap<RowKey<'_>, &BlockhashRow> =
        eip7709.iter().map(|row| (RowKey::new(row), row)).collect();
    let canonical_keys: HashSet<RowKey<'_>> = canonical.iter().map(RowKey::new).collect();
    let mut tx_status_by_key: HashMap<TxKey<'_>, &str> = HashMap::new();
    for row in eip7709 {
        tx_status_by_key.insert(TxKey::new(row), row.tx_status.as_str());
    }

    let mut txs_with_blockhash: HashSet<TxKey<'_>> = HashSet::new();
    let mut by_sender: HashMap<String, TopAgg> = HashMap::new();
    let mut by_tx_recipient: HashMap<String, TopAgg> = HashMap::new();
    let mut by_contract: HashMap<String, TopAgg> = HashMap::new();
    let mut by_code_address: HashMap<String, TopAgg> = HashMap::new();

    for row in canonical {
        let tx_key = TxKey::new(row);
        txs_with_blockhash.insert(tx_key);

        if row.is_in_window {
            report.window_split.in_window += 1;
        } else {
            report.window_split.out_of_window += 1;
        }

        match row.slot_warmth_class.as_str() {
            "cold" => report.repricing_split.cold += 1,
            "warm" => report.repricing_split.warm += 1,
            "out_of_window" => report.repricing_split.out_of_window += 1,
            _ => report.repricing_split.unknown += 1,
        }

        let eip7709_match = eip7709_index.get(&RowKey::new(row)).copied();
        if eip7709_match.is_some() {
            report.joined_rows += 1;
        } else {
            report.canonical_only_rows += 1;
        }

        let simulation_tx_oog = !is_tx_oog(&row.tx_status) &&
            tx_status_by_key.get(&tx_key).is_some_and(|status| is_tx_oog(status));
        let simulation_frame_oog = eip7709_match.is_some_and(|eip7709_row| {
            !is_frame_oog(row.frame_end_status.as_deref()) &&
                is_frame_oog(eip7709_row.frame_end_status.as_deref())
        });
        let joined = eip7709_match.is_some();

        record_usage(
            &mut by_sender,
            row.tx_from.clone(),
            row,
            joined,
            simulation_tx_oog,
            simulation_frame_oog,
        );
        if let Some(tx_to) = &row.tx_to {
            record_usage(
                &mut by_tx_recipient,
                tx_to.clone(),
                row,
                joined,
                simulation_tx_oog,
                simulation_frame_oog,
            );
        }
        if let Some(target) = &row.frame_target {
            record_usage(
                &mut by_contract,
                target.clone(),
                row,
                joined,
                simulation_tx_oog,
                simulation_frame_oog,
            );
        }
        if let Some(code_address) = &row.frame_code_address {
            record_usage(
                &mut by_code_address,
                code_address.clone(),
                row,
                joined,
                simulation_tx_oog,
                simulation_frame_oog,
            );
        }
    }

    report.txs_with_blockhash = txs_with_blockhash.len() as u64;
    report.eip7709_only_rows =
        eip7709.iter().filter(|row| !canonical_keys.contains(&RowKey::new(row))).count();
    report.top_senders = top_section(by_sender, top_n);
    report.top_tx_recipients = top_section(by_tx_recipient, top_n);
    report.top_contracts = top_section(by_contract, top_n);
    report.top_code_addresses = top_section(by_code_address, top_n);

    report
}

pub fn print_report(report: &Report) {
    println!("=== EIP-7709 BLOCKHASH Usage Report ===");
    println!(
        "joined rows: {} | canonical-only: {} | eip7709-only: {}\n",
        report.joined_rows, report.canonical_only_rows, report.eip7709_only_rows
    );

    println!("--- 1. Usage Summary ---");
    println!(
        "  transactions with BLOCKHASH: {}\n  BLOCKHASH usages:            {}",
        report.txs_with_blockhash, report.total_usages
    );
    println!(
        "  window:\n    in-window:     {} ({:.2}% of all)\n    out-of-window: {} ({:.2}% of all)",
        report.window_split.in_window,
        pct(report.window_split.in_window, report.total_usages),
        report.window_split.out_of_window,
        pct(report.window_split.out_of_window, report.total_usages),
    );
    println!(
        "  repriced in-window usages:\n    cold:    {} ({:.2}% of in-window, {:.2}% of all)\n    warm:    {} ({:.2}% of in-window, {:.2}% of all)\n    unknown: {} ({:.2}% of all)",
        report.repricing_split.cold,
        pct(report.repricing_split.cold, report.window_split.in_window),
        pct(report.repricing_split.cold, report.total_usages),
        report.repricing_split.warm,
        pct(report.repricing_split.warm, report.window_split.in_window),
        pct(report.repricing_split.warm, report.total_usages),
        report.repricing_split.unknown,
        pct(report.repricing_split.unknown, report.total_usages),
    );
    println!();

    println!("--- 2. Top BLOCKHASH Users ---");
    print_top("senders (tx_from)", &report.top_senders);
    print_top("tx recipients (tx_to)", &report.top_tx_recipients);
    print_top("contracts (frame_target)", &report.top_contracts);
    print_top("code addresses (frame_code_address)", &report.top_code_addresses);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RowKey<'a> {
    block_number: u64,
    tx_hash: &'a str,
    event_index: u64,
}

impl<'a> RowKey<'a> {
    fn new(row: &'a BlockhashRow) -> Self {
        Self {
            block_number: row.block_number,
            tx_hash: row.tx_hash.as_str(),
            event_index: row.event_index,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TxKey<'a> {
    block_number: u64,
    tx_hash: &'a str,
}

impl<'a> TxKey<'a> {
    fn new(row: &'a BlockhashRow) -> Self {
        Self { block_number: row.block_number, tx_hash: row.tx_hash.as_str() }
    }
}

#[derive(Debug, Default, Clone)]
struct TopAgg {
    usages: u64,
    immediate_oog: u64,
    simulation_tx_oog: u64,
    joined_usages: u64,
    simulation_frame_oog: u64,
    sample_tx_hash: Option<String>,
}

fn record_usage(
    map: &mut HashMap<String, TopAgg>,
    key: String,
    row: &BlockhashRow,
    joined: bool,
    simulation_tx_oog: bool,
    simulation_frame_oog: bool,
) {
    let entry = map.entry(key).or_default();
    entry.usages += 1;
    entry.immediate_oog += u64::from(row.eip7709_would_oog_frame);
    entry.simulation_tx_oog += u64::from(simulation_tx_oog);
    entry.joined_usages += u64::from(joined);
    entry.simulation_frame_oog += u64::from(simulation_frame_oog);
    if entry.sample_tx_hash.is_none() {
        entry.sample_tx_hash = Some(row.tx_hash.clone());
    }
}

fn top_section(map: HashMap<String, TopAgg>, top_n: usize) -> TopSection {
    let total_usages = map.values().map(|entry| entry.usages).sum();
    let mut entries: Vec<TopEntry> = map
        .into_iter()
        .map(|(key, entry)| TopEntry {
            key,
            usages: entry.usages,
            usage_pct: pct(entry.usages, total_usages),
            immediate_oog: entry.immediate_oog,
            immediate_oog_pct: pct(entry.immediate_oog, entry.usages),
            simulation_tx_oog: entry.simulation_tx_oog,
            simulation_tx_oog_pct: pct(entry.simulation_tx_oog, entry.usages),
            joined_usages: entry.joined_usages,
            simulation_frame_oog: entry.simulation_frame_oog,
            simulation_frame_oog_pct: pct(entry.simulation_frame_oog, entry.joined_usages),
            sample_tx_hash: entry.sample_tx_hash.unwrap_or_default(),
        })
        .collect();

    entries.sort_by(|a, b| {
        b.usages
            .cmp(&a.usages)
            .then(b.immediate_oog.cmp(&a.immediate_oog))
            .then(b.simulation_tx_oog.cmp(&a.simulation_tx_oog))
            .then(b.simulation_frame_oog.cmp(&a.simulation_frame_oog))
            .then(a.key.cmp(&b.key))
    });
    entries.truncate(top_n);

    TopSection { total_usages, entries }
}

fn is_tx_oog(status: &str) -> bool {
    status.starts_with("Halt(OutOfGas")
}

fn is_frame_oog(status: Option<&str>) -> bool {
    status
        .is_some_and(|status| status.starts_with("OutOfGas") || status.starts_with("Halt(OutOfGas"))
}

fn pct(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}

fn print_top(label: &str, section: &TopSection) {
    println!("  by {label} (total_usages={}):", section.total_usages);
    if section.entries.is_empty() {
        println!("    (none)");
        return;
    }

    for entry in &section.entries {
        println!(
            "    {} usages={} ({:.2}%) immediate_oog={} ({:.2}%) simulation_tx_oog={} ({:.2}%) simulation_frame_oog={}/{} ({:.2}%) sample_tx={}",
            entry.key,
            entry.usages,
            entry.usage_pct,
            entry.immediate_oog,
            entry.immediate_oog_pct,
            entry.simulation_tx_oog,
            entry.simulation_tx_oog_pct,
            entry.simulation_frame_oog,
            entry.joined_usages,
            entry.simulation_frame_oog_pct,
            entry.sample_tx_hash,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_counts_distinct_txs_and_usage_percentages_from_canonical_rows() {
        let canonical = vec![
            row(1, "tx1", 0).with_warmth("cold").with_in_window(true),
            row(1, "tx1", 1).with_warmth("warm").with_in_window(true),
            row(1, "tx2", 0).with_warmth("out_of_window").with_in_window(false),
            row(1, "tx3", 0).with_warmth("unknown").with_in_window(false),
        ];

        let report = build_report(&canonical, &[], 10);

        assert_eq!(report.total_usages, 4);
        assert_eq!(report.txs_with_blockhash, 3);
        assert_eq!(report.window_split.in_window, 2);
        assert_eq!(report.window_split.out_of_window, 2);
        assert_eq!(report.repricing_split.cold, 1);
        assert_eq!(report.repricing_split.warm, 1);
        assert_eq!(report.repricing_split.out_of_window, 1);
        assert_eq!(report.repricing_split.unknown, 1);
    }

    #[test]
    fn top_sections_sort_by_usage_and_use_section_denominators() {
        let canonical = vec![
            row(1, "tx1", 0).with_sender("alice").with_tx_to(Some("recipient-a")),
            row(1, "tx1", 1).with_sender("alice").with_tx_to(Some("recipient-a")),
            row(1, "tx2", 0).with_sender("bob").with_tx_to(Some("recipient-b")),
            row(1, "tx3", 0).with_sender("carol").with_tx_to(None),
        ];

        let report = build_report(&canonical, &[], 2);

        assert_eq!(report.top_senders.total_usages, 4);
        assert_eq!(report.top_senders.entries.len(), 2);
        assert_eq!(report.top_senders.entries[0].key, "alice");
        assert_eq!(report.top_senders.entries[0].usages, 2);
        assert_eq!(report.top_senders.entries[0].usage_pct, 50.0);
        assert_eq!(report.top_senders.entries[1].key, "bob");

        assert_eq!(report.top_tx_recipients.total_usages, 3);
        assert_eq!(report.top_tx_recipients.entries.len(), 2);
        assert_eq!(report.top_tx_recipients.entries[0].key, "recipient-a");
        assert_eq!(report.top_tx_recipients.entries[0].usages, 2);
        assert_eq!(report.top_tx_recipients.entries[0].usage_pct, 200.0 / 3.0);
    }

    #[test]
    fn optional_top_sections_exclude_missing_keys() {
        let canonical = vec![
            row(1, "tx1", 0).with_frame_target(Some("target-a")).with_code_address(Some("code-a")),
            row(1, "tx2", 0).with_frame_target(None).with_code_address(Some("code-a")),
            row(1, "tx3", 0).with_frame_target(Some("target-b")).with_code_address(None),
        ];

        let report = build_report(&canonical, &[], 10);

        assert_eq!(report.top_contracts.total_usages, 2);
        assert_eq!(report.top_contracts.entries.len(), 2);
        assert!(report.top_contracts.entries.iter().any(|entry| entry.key == "target-a"));
        assert!(report.top_contracts.entries.iter().any(|entry| entry.key == "target-b"));

        assert_eq!(report.top_code_addresses.total_usages, 2);
        assert_eq!(report.top_code_addresses.entries.len(), 1);
        assert_eq!(report.top_code_addresses.entries[0].key, "code-a");
        assert_eq!(report.top_code_addresses.entries[0].usages, 2);
    }

    #[test]
    fn top_entries_count_immediate_and_simulation_oog() {
        let canonical = vec![
            row(1, "tx1", 0)
                .with_sender("alice")
                .with_would_oog(true)
                .with_frame_status(Some("Continue")),
            row(1, "tx1", 1).with_sender("alice").with_frame_status(Some("Stop")),
            row(1, "tx2", 0)
                .with_sender("alice")
                .with_tx_status("Halt(OutOfGas)")
                .with_frame_status(Some("OutOfGas")),
            row(1, "tx3", 0).with_sender("bob"),
        ];
        let eip7709 = vec![
            row(1, "tx1", 0)
                .with_sender("alice")
                .with_tx_status("Halt(OutOfGas)")
                .with_frame_status(Some("Halt(OutOfGas)")),
            row(1, "tx1", 1)
                .with_sender("alice")
                .with_tx_status("Halt(OutOfGas)")
                .with_frame_status(Some("Stop")),
            row(1, "tx2", 0)
                .with_sender("alice")
                .with_tx_status("Halt(OutOfGas)")
                .with_frame_status(Some("OutOfGas")),
        ];

        let report = build_report(&canonical, &eip7709, 10);
        let alice = &report.top_senders.entries[0];

        assert_eq!(report.joined_rows, 3);
        assert_eq!(report.canonical_only_rows, 1);
        assert_eq!(alice.key, "alice");
        assert_eq!(alice.usages, 3);
        assert_eq!(alice.immediate_oog, 1);
        assert_eq!(alice.immediate_oog_pct, 100.0 / 3.0);
        assert_eq!(alice.simulation_tx_oog, 2);
        assert_eq!(alice.simulation_tx_oog_pct, 200.0 / 3.0);
        assert_eq!(alice.joined_usages, 3);
        assert_eq!(alice.simulation_frame_oog, 1);
        assert_eq!(alice.simulation_frame_oog_pct, 100.0 / 3.0);
    }

    #[test]
    fn canonical_only_rows_count_for_usage_but_not_joined_frame_oog() {
        let canonical = vec![
            row(1, "tx1", 0).with_sender("alice").with_frame_status(Some("Stop")),
            row(1, "tx1", 1).with_sender("alice").with_frame_status(Some("Stop")),
        ];
        let eip7709 = vec![
            row(1, "tx1", 0)
                .with_sender("alice")
                .with_tx_status("Halt(OutOfGas)")
                .with_frame_status(Some("OutOfGas")),
            row(1, "tx-extra", 0),
        ];

        let report = build_report(&canonical, &eip7709, 10);
        let alice = &report.top_senders.entries[0];

        assert_eq!(report.total_usages, 2);
        assert_eq!(report.joined_rows, 1);
        assert_eq!(report.canonical_only_rows, 1);
        assert_eq!(report.eip7709_only_rows, 1);
        assert_eq!(alice.usages, 2);
        assert_eq!(alice.simulation_tx_oog, 2);
        assert_eq!(alice.joined_usages, 1);
        assert_eq!(alice.simulation_frame_oog, 1);
        assert_eq!(alice.simulation_frame_oog_pct, 100.0);
    }

    trait RowExt {
        fn with_sender(self, sender: &str) -> Self;
        fn with_tx_to(self, tx_to: Option<&str>) -> Self;
        fn with_tx_status(self, status: &str) -> Self;
        fn with_frame_target(self, target: Option<&str>) -> Self;
        fn with_code_address(self, code_address: Option<&str>) -> Self;
        fn with_frame_status(self, status: Option<&str>) -> Self;
        fn with_in_window(self, is_in_window: bool) -> Self;
        fn with_warmth(self, warmth: &str) -> Self;
        fn with_would_oog(self, would_oog: bool) -> Self;
    }

    impl RowExt for BlockhashRow {
        fn with_sender(mut self, sender: &str) -> Self {
            self.tx_from = sender.to_string();
            self
        }

        fn with_tx_to(mut self, tx_to: Option<&str>) -> Self {
            self.tx_to = tx_to.map(str::to_string);
            self
        }

        fn with_tx_status(mut self, status: &str) -> Self {
            self.tx_status = status.to_string();
            self
        }

        fn with_frame_target(mut self, target: Option<&str>) -> Self {
            self.frame_target = target.map(str::to_string);
            self
        }

        fn with_code_address(mut self, code_address: Option<&str>) -> Self {
            self.frame_code_address = code_address.map(str::to_string);
            self
        }

        fn with_frame_status(mut self, status: Option<&str>) -> Self {
            self.frame_end_status = status.map(str::to_string);
            self
        }

        fn with_in_window(mut self, is_in_window: bool) -> Self {
            self.is_in_window = is_in_window;
            self
        }

        fn with_warmth(mut self, warmth: &str) -> Self {
            self.slot_warmth_class = warmth.to_string();
            self
        }

        fn with_would_oog(mut self, would_oog: bool) -> Self {
            self.eip7709_would_oog_frame = would_oog;
            self
        }
    }

    fn row(block_number: u64, tx_hash: &str, event_index: u64) -> BlockhashRow {
        BlockhashRow {
            block_number,
            block_hash: format!("block-{block_number}"),
            tx_index: 0,
            tx_hash: tx_hash.to_string(),
            tx_from: "sender".to_string(),
            tx_to: Some("tx-to".to_string()),
            tx_nonce: 0,
            tx_type: 0,
            tx_gas_limit: 100_000,
            tx_gas_used: 21_000,
            tx_status: "Success(Stop)".to_string(),
            event_index,
            frame_id: event_index,
            parent_frame_id: None,
            frame_depth: 0,
            frame_kind: "tx_call".to_string(),
            frame_caller: "sender".to_string(),
            frame_target: Some("target".to_string()),
            frame_code_address: Some("code".to_string()),
            frame_gas_limit: 100_000,
            frame_is_static: false,
            frame_end_status: Some("Stop".to_string()),
            pc: 0,
            requested_block_number: Some(1),
            requested_block_delta: Some(1),
            gas_before: 100_000,
            gas_after: 99_980,
            observed_gas_cost: 20,
            extra_gas_headroom: 99_980,
            slot_index: Some(1),
            is_in_window: true,
            slot_warmth_class: "cold".to_string(),
            eip7709_extra_cost: 2_100,
            eip7709_new_cost: 2_120,
            eip7709_new_headroom: 97_880,
            eip7709_would_oog_frame: false,
        }
    }
}
