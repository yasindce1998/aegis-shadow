#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
};
use common::{
    DefenseAlert, LatencyBaseline, ALERT_BYTECODE_TAMPER, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS,
    ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_LATENCY,
};

// ──────────────────────────────────────────────
// BPF Maps
// ──────────────────────────────────────────────

#[map]
static DEFENSE_ALERTS: PerfEventArray<DefenseAlert> = PerfEventArray::new(0);

#[map]
static SYSCALL_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[map]
static LATENCY_BASELINE: HashMap<u32, LatencyBaseline> = HashMap::with_max_entries(512, 0);

/// Tracks PIDs that have created BPF maps (to distinguish known vs ghost).
/// Key: pid (u32). Value: creation count (u32).
#[map]
static KNOWN_MAP_IDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Stores bytecode hashes of BPF programs loaded by each PID.
/// Key: pid (u32). Value: last bytecode hash (u64).
#[map]
static PROG_BYTECODE_HASHES: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// Tracks kprobe/tracepoint attachment counts per target hash.
/// Key: cmd hash (u64). Value: attachment count (u32).
#[map]
static KPROBE_ATTACH_COUNTS: HashMap<u64, u32> = HashMap::with_max_entries(512, 0);

// ──────────────────────────────────────────────
// MODULE 1: Ghost Map Detection
// ──────────────────────────────────────────────

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_DELETE: u32 = 2;

#[tracepoint]
pub fn detect_ghost_map(ctx: TracePointContext) -> u32 {
    try_detect_ghost_map(&ctx).unwrap_or_default()
}

fn try_detect_ghost_map(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_MAP_CREATE && cmd != BPF_MAP_DELETE {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if cmd == BPF_MAP_CREATE {
        // Track this PID as a known map creator
        let count = unsafe { KNOWN_MAP_IDS.get(&pid) }.copied().unwrap_or(0);
        let _ = KNOWN_MAP_IDS.insert(&pid, &(count + 1), 0);

        let alert = DefenseAlert {
            alert_type: ALERT_GHOST_MAP,
            severity: 2,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cmd as u64,
            details: [0u8; 16],
        };
        DEFENSE_ALERTS.output(ctx, &alert, 0);
    } else if cmd == BPF_MAP_DELETE {
        // If deleting from a PID we haven't seen create maps, higher severity
        let severity = if unsafe { KNOWN_MAP_IDS.get(&pid) }.is_none() {
            4 // CRITICAL — unknown PID deleting maps
        } else {
            2
        };

        let alert = DefenseAlert {
            alert_type: ALERT_GHOST_MAP,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cmd as u64,
            details: [0u8; 16],
        };
        DEFENSE_ALERTS.output(ctx, &alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 2: Syscall Latency Monitoring
// ──────────────────────────────────────────────

#[tracepoint]
pub fn monitor_syscall_enter(ctx: TracePointContext) -> u32 {
    try_monitor_syscall_enter(&ctx).unwrap_or_default()
}

fn try_monitor_syscall_enter(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ts = unsafe { bpf_ktime_get_ns() };

    let _ = SYSCALL_ENTRY_TS.insert(&pid_tgid, &ts, 0);

    Ok(0)
}

#[tracepoint]
pub fn monitor_syscall_exit(ctx: TracePointContext) -> u32 {
    try_monitor_syscall_exit(&ctx).unwrap_or_default()
}

fn try_monitor_syscall_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let entry_ts = match unsafe { SYSCALL_ENTRY_TS.get(&pid_tgid) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };
    let _ = SYSCALL_ENTRY_TS.remove(&pid_tgid);

    let exit_ts = unsafe { bpf_ktime_get_ns() };
    let latency_ns = exit_ts.saturating_sub(entry_ts);

    let syscall_nr: u32 = unsafe { ctx.read_at(8).unwrap_or(0) };

    if let Some(baseline) = unsafe { LATENCY_BASELINE.get(&syscall_nr) } {
        let baseline_avg = baseline.avg_latency_ns;
        let threshold = baseline_avg + (baseline_avg / 2);

        if latency_ns > threshold {
            let pid = (pid_tgid >> 32) as u32;
            let mut details = [0u8; 16];
            let latency_bytes = latency_ns.to_le_bytes();
            details[0..8].copy_from_slice(&latency_bytes);

            let alert = DefenseAlert {
                alert_type: ALERT_SYSCALL_LATENCY,
                severity: 2,
                pid,
                _pad: 0,
                timestamp_ns: exit_ts,
                context: syscall_nr as u64,
                details,
            };

            DEFENSE_ALERTS.output(ctx, &alert, 0);
        }
    } else {
        let entry = LatencyBaseline {
            avg_latency_ns: latency_ns,
            sample_count: 1,
            _pad: 0,
        };
        let _ = LATENCY_BASELINE.insert(&syscall_nr, &entry, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 3: Bytecode Integrity Checking
// ──────────────────────────────────────────────

const BPF_PROG_LOAD: u32 = 5;

#[tracepoint]
pub fn check_bytecode_integrity(ctx: TracePointContext) -> u32 {
    try_check_bytecode_integrity(&ctx).unwrap_or_default()
}

fn try_check_bytecode_integrity(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_LOAD {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Hash the command metadata as a fingerprint for this load
    let cmd_bytes = cmd.to_le_bytes();
    let hash = fnv1a_hash(&cmd_bytes);

    let severity = if let Some(prev_hash) = unsafe { PROG_BYTECODE_HASHES.get(&pid) } {
        if *prev_hash != hash {
            4 // CRITICAL — same PID loading different bytecode (possible tampering)
        } else {
            2
        }
    } else {
        3 // HIGH — new program load
    };

    let _ = PROG_BYTECODE_HASHES.insert(&pid, &hash, 0);

    let mut details = [0u8; 16];
    details[0..8].copy_from_slice(&hash.to_le_bytes());

    let alert = DefenseAlert {
        alert_type: ALERT_BYTECODE_TAMPER,
        severity,
        pid,
        _pad: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
        details,
    };

    DEFENSE_ALERTS.output(ctx, &alert, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 4: Hidden Process Detection
// ──────────────────────────────────────────────

#[kprobe]
pub fn detect_hidden_process(ctx: ProbeContext) -> u32 {
    try_detect_hidden_process(&ctx).unwrap_or_default()
}

fn try_detect_hidden_process(ctx: &ProbeContext) -> Result<u32, i64> {
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let count: u64 = ctx.arg(2).ok_or(2i64)?;

    if buf_ptr == 0 || count == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if count < 1024 {
        let alert = DefenseAlert {
            alert_type: ALERT_HIDDEN_PROCESS,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: count,
            details: [0u8; 16],
        };

        DEFENSE_ALERTS.output(ctx, &alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 5: Suspicious Hook Detection
// ──────────────────────────────────────────────

const BPF_PROG_ATTACH: u32 = 8;
const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;

#[tracepoint]
pub fn detect_suspicious_hook(ctx: TracePointContext) -> u32 {
    try_detect_suspicious_hook(&ctx).unwrap_or_default()
}

fn try_detect_suspicious_hook(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_ATTACH && cmd != BPF_RAW_TRACEPOINT_OPEN {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Track attachment count per command type
    let key = cmd as u64 | ((pid as u64) << 32);
    let count = unsafe { KPROBE_ATTACH_COUNTS.get(&key) }
        .copied()
        .unwrap_or(0);
    let new_count = count + 1;
    let _ = KPROBE_ATTACH_COUNTS.insert(&key, &new_count, 0);

    // Escalate severity when same PID attaches many hooks
    let severity = if new_count > 3 { 4 } else { 3 };

    let mut details = [0u8; 16];
    details[0..4].copy_from_slice(&new_count.to_le_bytes());

    let alert = DefenseAlert {
        alert_type: ALERT_SUSPICIOUS_HOOK,
        severity,
        pid,
        _pad: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
        details,
    };

    DEFENSE_ALERTS.output(ctx, &alert, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// Helper: FNV-1a Hash
// ──────────────────────────────────────────────

#[inline(always)]
fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    let mut i = 0usize;

    while i < data.len() && i < 1024 {
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }

    hash
}

// ──────────────────────────────────────────────
// Panic Handler
// ──────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
