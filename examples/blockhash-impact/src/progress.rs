//! Worker-pool progress reporter that prints throughput and ETA on a 2-second tick.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub(crate) fn report_progress(
    total_blocks: u64,
    blocks_completed: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
    started_at: Instant,
) {
    const TICK: Duration = Duration::from_secs(2);

    let mut last_tick = started_at;
    let mut last_completed: u64 = 0;

    loop {
        let stopping = done.load(Ordering::Relaxed);
        let now = Instant::now();
        let current = blocks_completed.load(Ordering::Relaxed);

        let tick_secs = now.saturating_duration_since(last_tick).as_secs_f64().max(1e-6);
        let overall_secs = now.saturating_duration_since(started_at).as_secs_f64().max(1e-6);
        let instant_rate = current.saturating_sub(last_completed) as f64 / tick_secs;
        let overall_rate = current as f64 / overall_secs;
        let rate_for_eta = if instant_rate > 0.0 { instant_rate } else { overall_rate };

        let remaining = total_blocks.saturating_sub(current);
        let eta = if rate_for_eta > 0.0 { Some(remaining as f64 / rate_for_eta) } else { None };
        let pct =
            if total_blocks == 0 { 100.0 } else { (current as f64 / total_blocks as f64) * 100.0 };

        eprintln!(
            "[progress] {}/{} ({:.2}%) | {} blk/s (avg {}) | elapsed {} | ETA {}",
            current,
            total_blocks,
            pct,
            format_rate(instant_rate),
            format_rate(overall_rate),
            format_hms(overall_secs),
            eta.map(format_hms).unwrap_or_else(|| "?".to_string()),
        );

        if stopping {
            return;
        }

        last_tick = now;
        last_completed = current;

        thread::park_timeout(TICK);
    }
}

fn format_rate(rate: f64) -> String {
    if !rate.is_finite() || rate < 0.0 {
        return "?".to_string();
    }
    if rate >= 100.0 {
        format!("{rate:.0}")
    } else if rate >= 10.0 {
        format!("{rate:.1}")
    } else {
        format!("{rate:.2}")
    }
}

fn format_hms(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "?".to_string();
    }
    let total = secs.min(u64::MAX as f64 / 2.0) as u64;
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    if days > 0 {
        format!("{days}d{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}
