use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use common::{
    EventHeader, EVENT_ANTI_DETACH, EVENT_BYTECODE_WIPED, EVENT_CONTAINER_PROBE, EVENT_MEMFD_STAGED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 11: Anti-Detach Self-Defense
// ──────────────────────────────────────────────

const BPF_PROG_DETACH: u32 = 9;
const BPF_OBJ_UNPIN: u32 = 19;
const BPF_LINK_DETACH: u32 = 34;

#[aya_ebpf::macros::tracepoint]
pub fn shadow_anti_detach(ctx: aya_ebpf::programs::TracePointContext) -> u32 {
    try_anti_detach(&ctx).unwrap_or_default()
}

fn try_anti_detach(ctx: &aya_ebpf::programs::TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_DETACH && cmd != BPF_OBJ_UNPIN && cmd != BPF_LINK_DETACH {
        return Ok(0);
    }

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    let event = EventHeader {
        event_type: EVENT_ANTI_DETACH,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 17: Memory-Only Payload Staging
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_memfd_create_enter(ctx: ProbeContext) -> u32 {
    try_memfd_create_enter(&ctx).unwrap_or_default()
}

fn try_memfd_create_enter(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let flags: u32 = unsafe { ctx.arg(1).ok_or(1i64)? };
    let mctx = MemfdCtx { flags, _pad: 0 };
    unsafe { MEMFD_ARGS.insert(&pid_tgid, &mctx, 0)? };

    Ok(0)
}

#[kretprobe]
pub fn shadow_memfd_create_exit(ctx: RetProbeContext) -> u32 {
    try_memfd_create_exit(&ctx).unwrap_or_default()
}

fn try_memfd_create_exit(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if unsafe { MEMFD_ARGS.get(&pid_tgid) }.is_none() {
        return Ok(0);
    }
    unsafe { MEMFD_ARGS.remove(&pid_tgid)? };

    let ret: i64 = ctx.ret().ok_or(1i64)?;
    if ret < 0 {
        return Ok(0);
    }

    let ts = unsafe { bpf_ktime_get_ns() };
    unsafe { MEMFD_TRACKER.insert(&pid, &ts, 0)? };

    Ok(0)
}

#[kprobe]
pub fn shadow_execveat_enter(ctx: ProbeContext) -> u32 {
    try_execveat_enter(&ctx).unwrap_or_default()
}

fn try_execveat_enter(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let ts = match unsafe { MEMFD_TRACKER.get(&pid) } {
        Some(&t) => t,
        None => return Ok(0),
    };

    let flags: u32 = unsafe { ctx.arg(4).ok_or(1i64)? };
    if flags & 0x1000 == 0 {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    if now.saturating_sub(ts) > 60_000_000_000 {
        unsafe { MEMFD_TRACKER.remove(&pid)? };
        return Ok(0);
    }

    let event = EventHeader {
        event_type: EVENT_MEMFD_STAGED,
        pid,
        timestamp_ns: now,
        context: flags as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 19: Anti-Forensics Bytecode Wipe
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_wipe_check(ctx: ProbeContext) -> u32 {
    try_wipe_check(&ctx).unwrap_or_default()
}

fn try_wipe_check(_ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            let pid_tgid = bpf_get_current_pid_tgid();
            let event = EventHeader {
                event_type: EVENT_BYTECODE_WIPED,
                pid: (pid_tgid >> 32) as u32,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 1,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }
    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 23: Container Escape Probes
// ──────────────────────────────────────────────

const CLONE_NEWNS: u64 = 0x00020000;
const CLONE_NEWUSER: u64 = 0x10000000;

#[kprobe]
pub fn shadow_unshare_enter(ctx: ProbeContext) -> u32 {
    try_unshare_enter(&ctx).unwrap_or_default()
}

fn try_unshare_enter(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let flags: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if flags & (CLONE_NEWNS | CLONE_NEWUSER) == 0 {
        return Ok(0);
    }

    let result = common::ContainerProbeResult {
        pid,
        in_container: 1,
        ns_type: if flags & CLONE_NEWUSER != 0 { 1 } else { 2 },
        _pad: [0u8; 2],
        ns_ino: flags,
    };
    unsafe {
        if let Some(ptr) = CONTAINER_STATE.get_ptr_mut(0) {
            *ptr = result;
        }
    }

    let event = EventHeader {
        event_type: EVENT_CONTAINER_PROBE,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: flags,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

#[kprobe]
pub fn shadow_commit_creds(ctx: ProbeContext) -> u32 {
    try_commit_creds(&ctx).unwrap_or_default()
}

fn try_commit_creds(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let cred_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    let uid: u32 = unsafe { bpf_probe_read_kernel((cred_ptr + 4) as *const u32)? };

    if uid == 0 {
        let event = EventHeader {
            event_type: EVENT_CONTAINER_PROBE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: 0,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
