//! Joins canonical and EIP-7709 row sets and produces the printable UX-impact report covering:
//!
//! 1. Cold/warm/out-of-window split (+ per-tx repeat-slot histogram).
//! 2. Frame-level OOG: which frames flip `Success`/`Revert` → `Halt(OutOfGas)`.
//! 3. Tx-level outcome impact: status flips, gas-used premium percentiles, gas-limit overruns.
//! 4. Top affected senders / contracts / code_addresses.
//! 5. Block-level aggregates.

use std::collections::{BTreeMap, HashMap};

use crate::row::BlockhashRow;

#[derive(Debug, Default)]
pub struct Report {
    pub joined_rows: usize,
    pub canonical_only_rows: usize,
    pub eip7709_only_rows: usize,
    pub by_class: ClassSplit,
    pub repeat_slot_histogram: BTreeMap<u32, u64>,
    pub frame_status_changed: u64,
    pub frame_to_oog: u64,
    pub frame_kind_oog: BTreeMap<String, u64>,
    pub near_edge_frames: u64,
    pub tx_status_flipped: u64,
    pub tx_status_oog: u64,
    pub tx_gas_premium_percentiles: GasPercentiles,
    pub tx_over_gas_limit: u64,
    pub top_senders: Vec<TopEntry>,
    pub top_targets: Vec<TopEntry>,
    pub top_code_addresses: Vec<TopEntry>,
    pub blocks_with_failures: u64,
    pub block_max_premium: Option<(u64, u64)>,
    pub block_premium_p50: u64,
    pub block_premium_p95: u64,
    pub block_premium_max: u64,
}

#[derive(Debug, Default)]
pub struct ClassSplit {
    pub total: u64,
    pub cold: u64,
    pub warm: u64,
    pub out_of_window: u64,
    pub unknown: u64,
    pub avg_extra_cold: u64,
    pub avg_extra_warm: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct GasPercentiles {
    pub count: u64,
    pub p50: i64,
    pub p95: i64,
    pub p99: i64,
    pub max: i64,
}

#[derive(Debug, Clone)]
pub struct TopEntry {
    pub key: String,
    pub oog_frames: u64,
    pub total_premium: u64,
    pub sample_tx_hash: String,
}

/// Build the full report. `canonical` and `eip7709` are joined by
/// `(block_number, tx_hash, event_index)`; rows present on only one side are counted but
/// otherwise skipped.
pub fn build_report(canonical: &[BlockhashRow], eip7709: &[BlockhashRow], top_n: usize) -> Report {
    let mut report = Report::default();

    let canonical_index: HashMap<(u64, &str, u64), &BlockhashRow> = canonical
        .iter()
        .map(|row| ((row.block_number, row.tx_hash.as_str(), row.event_index), row))
        .collect();
    let mut matched: HashMap<(u64, String, u64), bool> = HashMap::with_capacity(canonical.len());

    // Per-tx aggregates so the tx-level stats use one entry per unique tx, not per event.
    let mut per_tx: HashMap<(u64, String), TxAgg> = HashMap::new();
    let mut per_block: HashMap<u64, u64> = HashMap::new();
    let mut per_block_failures: HashMap<u64, bool> = HashMap::new();
    let mut by_sender: HashMap<String, AggrEntry> = HashMap::new();
    let mut by_target: HashMap<String, AggrEntry> = HashMap::new();
    let mut by_code: HashMap<String, AggrEntry> = HashMap::new();

    let mut cold_cost_total: u64 = 0;
    let mut warm_cost_total: u64 = 0;

    for ev in eip7709 {
        let key = (ev.block_number, ev.tx_hash.as_str(), ev.event_index);
        let canonical_match = canonical_index.get(&key).copied();
        if canonical_match.is_some() {
            matched.insert((ev.block_number, ev.tx_hash.clone(), ev.event_index), true);
            report.joined_rows += 1;
        } else {
            report.eip7709_only_rows += 1;
        }

        report.by_class.total += 1;
        match ev.slot_warmth_class.as_str() {
            "cold" => {
                report.by_class.cold += 1;
                cold_cost_total += ev.eip7709_extra_cost;
            }
            "warm" => {
                report.by_class.warm += 1;
                warm_cost_total += ev.eip7709_extra_cost;
            }
            "out_of_window" => report.by_class.out_of_window += 1,
            _ => report.by_class.unknown += 1,
        }

        // Track block-level premium and failure presence.
        *per_block.entry(ev.block_number).or_default() += ev.eip7709_extra_cost;
        let tx_oog = ev.tx_status.starts_with("Halt(") && !canonical_status_oog(canonical_match);
        if tx_oog {
            per_block_failures.entry(ev.block_number).or_insert(true);
        }

        // Frame-level OOG diff (canonical vs eip7709).
        if let Some(canonical_row) = canonical_match {
            if let (Some(canonical_status), Some(eip_status)) =
                (&canonical_row.frame_end_status, &ev.frame_end_status) &&
                canonical_status != eip_status
            {
                report.frame_status_changed += 1;
                if eip_status.starts_with("OutOfGas") || eip_status == "OutOfGas" {
                    report.frame_to_oog += 1;
                    *report.frame_kind_oog.entry(ev.frame_kind.clone()).or_default() += 1;
                    record_top(
                        &mut by_sender,
                        ev.tx_from.clone(),
                        ev.eip7709_extra_cost,
                        &ev.tx_hash,
                    );
                    if let Some(target) = ev.frame_target.clone() {
                        record_top(&mut by_target, target, ev.eip7709_extra_cost, &ev.tx_hash);
                    }
                    if let Some(code) = ev.frame_code_address.clone() {
                        record_top(&mut by_code, code, ev.eip7709_extra_cost, &ev.tx_hash);
                    }
                }
            }
            if (BASE..BASE + 2100).contains(&canonical_row.gas_before) {
                report.near_edge_frames += 1;
            }
        }

        // Per-tx aggregates (any event in the tx contributes; sums per-tx).
        let tx_key = (ev.block_number, ev.tx_hash.clone());
        let agg = per_tx.entry(tx_key).or_insert_with(|| TxAgg {
            tx_gas_used_canonical: 0,
            tx_gas_used_eip7709: ev.tx_gas_used,
            tx_gas_limit: ev.tx_gas_limit,
            tx_status_canonical: None,
            tx_status_eip7709: ev.tx_status.clone(),
        });
        agg.tx_gas_used_eip7709 = ev.tx_gas_used;
        agg.tx_status_eip7709 = ev.tx_status.clone();
        agg.tx_gas_limit = ev.tx_gas_limit;
        if let Some(canonical_row) = canonical_match {
            agg.tx_gas_used_canonical = canonical_row.tx_gas_used;
            agg.tx_status_canonical = Some(canonical_row.tx_status.clone());
        }
    }

    // Canonical rows that didn't match anything in eip7709 (i.e. event no longer executed
    // because a parent OOG'd). Count these for transparency.
    for ev in canonical {
        if !matched.contains_key(&(ev.block_number, ev.tx_hash.clone(), ev.event_index)) {
            report.canonical_only_rows += 1;
        }
    }

    if let Some(avg) = cold_cost_total.checked_div(report.by_class.cold) {
        report.by_class.avg_extra_cold = avg;
    }
    if let Some(avg) = warm_cost_total.checked_div(report.by_class.warm) {
        report.by_class.avg_extra_warm = avg;
    }

    // Repeat-slot-per-tx histogram: count how many distinct slot_indexes are touched ≥2× in a tx.
    {
        let mut slot_count_by_tx: HashMap<(u64, String, u64), u32> = HashMap::new();
        for ev in eip7709 {
            if !ev.is_in_window {
                continue;
            }
            let Some(slot) = ev.slot_index else { continue };
            *slot_count_by_tx.entry((ev.block_number, ev.tx_hash.clone(), slot)).or_default() += 1;
        }
        for &count in slot_count_by_tx.values() {
            *report.repeat_slot_histogram.entry(count).or_default() += 1;
        }
    }

    // Tx-level stats.
    let mut premiums: Vec<i64> = Vec::with_capacity(per_tx.len());
    for agg in per_tx.values() {
        let canonical_status = agg.tx_status_canonical.as_deref().unwrap_or("");
        if !canonical_status.is_empty() && canonical_status != agg.tx_status_eip7709 {
            report.tx_status_flipped += 1;
            if !canonical_status.starts_with("Halt(") && agg.tx_status_eip7709.starts_with("Halt(")
            {
                report.tx_status_oog += 1;
            }
        }
        let premium = agg.tx_gas_used_eip7709 as i64 - agg.tx_gas_used_canonical as i64;
        premiums.push(premium);
        if agg.tx_gas_used_eip7709 > agg.tx_gas_limit {
            report.tx_over_gas_limit += 1;
        }
    }
    report.tx_gas_premium_percentiles = percentiles(&mut premiums);

    report.blocks_with_failures = per_block_failures.len() as u64;
    report.block_max_premium = per_block.iter().max_by_key(|&(_, v)| *v).map(|(&k, &v)| (k, v));
    let mut block_premiums: Vec<i64> = per_block.values().map(|&v| v as i64).collect();
    let block_pct = percentiles(&mut block_premiums);
    report.block_premium_p50 = block_pct.p50.max(0) as u64;
    report.block_premium_p95 = block_pct.p95.max(0) as u64;
    report.block_premium_max = block_pct.max.max(0) as u64;

    report.top_senders = top_n_entries(&by_sender, top_n);
    report.top_targets = top_n_entries(&by_target, top_n);
    report.top_code_addresses = top_n_entries(&by_code, top_n);

    report
}

pub fn print_report(report: &Report) {
    println!("=== EIP-7709 UX Impact Report ===");
    println!(
        "joined rows: {} | canonical-only: {} | eip7709-only: {}\n",
        report.joined_rows, report.canonical_only_rows, report.eip7709_only_rows
    );

    println!("--- 1. Cold/Warm/Out-of-Window Split ---");
    let total = report.by_class.total.max(1);
    println!(
        "  total events: {}\n  cold:          {} ({:.2}%)  avg extra: {} gas\n  warm:          {} ({:.2}%)  avg extra: {} gas\n  out_of_window: {} ({:.2}%)\n  unknown:       {} ({:.2}%)",
        report.by_class.total,
        report.by_class.cold,
        report.by_class.cold as f64 * 100.0 / total as f64,
        report.by_class.avg_extra_cold,
        report.by_class.warm,
        report.by_class.warm as f64 * 100.0 / total as f64,
        report.by_class.avg_extra_warm,
        report.by_class.out_of_window,
        report.by_class.out_of_window as f64 * 100.0 / total as f64,
        report.by_class.unknown,
        report.by_class.unknown as f64 * 100.0 / total as f64,
    );
    println!("  per-tx repeat-slot histogram (touches per slot):");
    for (touches, count) in &report.repeat_slot_histogram {
        println!("    {touches}× : {count} (slot, tx) pairs");
    }
    println!();

    println!("--- 2. Frame-Level OOG ---");
    println!(
        "  frame end_status flipped: {}\n  → Halt(OutOfGas):        {}\n  near-edge frames (canonical gas_before in [20, 2120)): {}",
        report.frame_status_changed, report.frame_to_oog, report.near_edge_frames
    );
    println!("  flips → OOG by frame_kind:");
    for (kind, count) in &report.frame_kind_oog {
        println!("    {kind:>14}: {count}");
    }
    println!();

    println!("--- 3. Tx-Level Outcome Impact ---");
    let p = &report.tx_gas_premium_percentiles;
    println!(
        "  tx status flipped:       {}\n  tx status → Halt(OutOfGas): {}\n  tx_gas_used_eip7709 > tx_gas_limit: {}\n  tx-gas-used premium percentiles (n={}): p50={} p95={} p99={} max={}",
        report.tx_status_flipped,
        report.tx_status_oog,
        report.tx_over_gas_limit,
        p.count,
        p.p50,
        p.p95,
        p.p99,
        p.max,
    );
    println!();

    println!("--- 4. Top Affected ---");
    print_top("senders (tx_from)", &report.top_senders);
    print_top("targets (frame_target)", &report.top_targets);
    print_top("code addresses (frame_code_address)", &report.top_code_addresses);
    println!();

    println!("--- 5. Block-Level Aggregates ---");
    println!(
        "  blocks with ≥1 newly-failing tx: {}\n  per-block extra-gas premium: p50={} p95={} max={}",
        report.blocks_with_failures,
        report.block_premium_p50,
        report.block_premium_p95,
        report.block_premium_max,
    );
    if let Some((block, premium)) = report.block_max_premium {
        println!("  worst-case block: #{block} extra_gas_premium={premium}");
    }
}

const BASE: u64 = 20;

#[derive(Debug)]
struct TxAgg {
    tx_gas_used_canonical: u64,
    tx_gas_used_eip7709: u64,
    tx_gas_limit: u64,
    tx_status_canonical: Option<String>,
    tx_status_eip7709: String,
}

#[derive(Debug, Default, Clone)]
struct AggrEntry {
    oog_frames: u64,
    total_premium: u64,
    sample_tx_hash: Option<String>,
}

fn record_top(
    map: &mut HashMap<String, AggrEntry>,
    key: String,
    premium: u64,
    sample_tx_hash: &str,
) {
    let entry = map.entry(key).or_default();
    entry.oog_frames += 1;
    entry.total_premium += premium;
    if entry.sample_tx_hash.is_none() {
        entry.sample_tx_hash = Some(sample_tx_hash.to_string());
    }
}

fn top_n_entries(map: &HashMap<String, AggrEntry>, top_n: usize) -> Vec<TopEntry> {
    let mut vec: Vec<TopEntry> = map
        .iter()
        .map(|(k, v)| TopEntry {
            key: k.clone(),
            oog_frames: v.oog_frames,
            total_premium: v.total_premium,
            sample_tx_hash: v.sample_tx_hash.clone().unwrap_or_default(),
        })
        .collect();
    vec.sort_by(|a, b| b.oog_frames.cmp(&a.oog_frames).then(b.total_premium.cmp(&a.total_premium)));
    vec.truncate(top_n);
    vec
}

fn percentiles(values: &mut [i64]) -> GasPercentiles {
    if values.is_empty() {
        return GasPercentiles::default();
    }
    values.sort_unstable();
    let count = values.len();
    let pick = |q: f64| -> i64 {
        let idx = ((count as f64 - 1.0) * q).round() as usize;
        values[idx]
    };
    GasPercentiles {
        count: count as u64,
        p50: pick(0.50),
        p95: pick(0.95),
        p99: pick(0.99),
        max: *values.last().unwrap(),
    }
}

fn canonical_status_oog(row: Option<&BlockhashRow>) -> bool {
    row.is_some_and(|r| r.tx_status.starts_with("Halt("))
}

fn print_top(label: &str, entries: &[TopEntry]) {
    println!("  by {label}:");
    if entries.is_empty() {
        println!("    (none)");
        return;
    }
    for entry in entries {
        println!(
            "    {} oog_frames={} total_premium={} sample_tx={}",
            entry.key, entry.oog_frames, entry.total_premium, entry.sample_tx_hash
        );
    }
}
