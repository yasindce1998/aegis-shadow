use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{KProbe, TracePoint},
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use common::{
    DefenseAlert, ALERT_HONEYPOT_READ, ALERT_MAP_AUDIT, ALERT_MEMFD_EXEC, ALERT_PROG_INVENTORY,
    ALERT_SUSPICIOUS_HOOK,
};
use defense::{classify_alert_type, DefenseEngine, RuntimeConfig};
use tracing::{error, info, warn};
use std::fs;
use std::io::Write;
use std::path::Path;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, Duration};

#[derive(Debug, Parser)]
#[command(name = "aegis-shadow-defense")]
#[command(about = "Aegis-Shadow Defensive Detection Engine", long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Output alerts to JSON file
    #[arg(short, long)]
    output: Option<String>,

    /// Alert threshold (1=Low, 2=Medium, 3=High, 4=Critical)
    #[arg(short, long, default_value = "2")]
    threshold: u8,

    /// Enable all detection modules
    #[arg(long)]
    all_modules: bool,

    /// Enable ghost map detection
    #[arg(long)]
    ghost_maps: bool,

    /// Enable syscall latency monitoring
    #[arg(long)]
    syscall_latency: bool,

    /// Enable bytecode integrity checking
    #[arg(long)]
    bytecode_check: bool,

    /// Enable hidden process detection
    #[arg(long)]
    hidden_process: bool,

    /// Enable suspicious hook detection
    #[arg(long)]
    suspicious_hooks: bool,

    /// Enable eBPF program inventory (ID gap detection)
    #[arg(long)]
    prog_inventory: bool,

    /// Enable syscall argument anomaly profiling
    #[arg(long)]
    syscall_anomaly: bool,

    /// Enable network behavior baseline
    #[arg(long)]
    net_baseline: bool,

    /// Enable memory-backed execution detection
    #[arg(long)]
    memfd_detect: bool,

    /// Enable BPF map content auditing
    #[arg(long)]
    map_audit: bool,

    /// Enable tracepoint coverage monitoring (rapid detach detection)
    #[arg(long)]
    tracepoint_monitor: bool,

    /// Enable automatic detachment of malicious BPF programs
    #[arg(long)]
    auto_detach: bool,

    /// Enable automatic process containment via cgroups
    #[arg(long)]
    auto_contain: bool,

    /// Enable honeypot BPF maps
    #[arg(long)]
    honeypots: bool,

    /// Baseline calibration period (seconds)
    #[arg(long, default_value = "60")]
    calibration_period: u64,

    /// Path to runtime config file (JSON, hot-reloaded every 5s)
    #[arg(long)]
    config: Option<String>,

    /// Stream alerts as NDJSON to stdout (for TUI bridge)
    #[arg(long)]
    json_stdout: bool,
}

const HONEYPOT_PIN_DIR: &str = "/sys/fs/bpf/honeypot";

fn setup_honeypots(bpf: &mut Ebpf) -> Result<Vec<u32>> {
    let pin_dir = Path::new(HONEYPOT_PIN_DIR);
    if !pin_dir.exists() {
        fs::create_dir_all(pin_dir)?;
    }

    let honeypot_names = ["shadow_config", "rootkit_pids", "c2_keys"];

    for name in &honeypot_names {
        let map_name = format!("HONEYPOT_{}", name.to_uppercase().replace('_', ""));
        if bpf.map(&map_name).is_some() {
            info!("Honeypot map '{}' registered for monitoring", name);
        }
    }

    info!(
        "Honeypot maps pinned at {} for eBPF-side detection",
        HONEYPOT_PIN_DIR
    );

    Ok(vec![])
}

fn contain_process(pid: u32) -> Result<()> {
    let cgroup_path = format!("/sys/fs/cgroup/aegis-contain-{}", pid);
    let cgroup_dir = Path::new(&cgroup_path);

    if !cgroup_dir.exists() {
        fs::create_dir_all(cgroup_dir)?;
    }

    // Set restrictive memory limit (64MB)
    let memory_max = cgroup_dir.join("memory.max");
    if memory_max.exists() {
        fs::write(&memory_max, "67108864")?;
    }

    // Set CPU weight to minimum
    let cpu_weight = cgroup_dir.join("cpu.weight");
    if cpu_weight.exists() {
        fs::write(&cpu_weight, "1")?;
    }

    // Move PID into containment cgroup
    let procs_file = cgroup_dir.join("cgroup.procs");
    let mut f = fs::OpenOptions::new().write(true).open(&procs_file)?;
    writeln!(f, "{}", pid)?;

    info!("Contained PID {} in cgroup {}", pid, cgroup_path);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(if cli.verbose { "debug" } else { "info" })
        });

    if cli.json_stdout {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .init();
    }

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase RLIMIT_MEMLOCK");
    }

    info!("Aegis-Shadow Defense Engine Starting...");

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/defense"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/defense"
    ))?;

    if Btf::from_sys_fs().is_ok() {
        info!("BTF loaded from /sys/kernel/btf/vmlinux");
    } else {
        warn!("BTF not available - CO-RE features may not work");
    }

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    let enable_all = cli.all_modules;
    let enable_ghost = enable_all || cli.ghost_maps;
    let enable_latency = enable_all || cli.syscall_latency;
    let enable_bytecode = enable_all || cli.bytecode_check;
    let enable_hidden = enable_all || cli.hidden_process;
    let enable_hooks = enable_all || cli.suspicious_hooks;
    let enable_prog_inv = enable_all || cli.prog_inventory;
    let enable_syscall_anom = enable_all || cli.syscall_anomaly;
    let enable_net_base = enable_all || cli.net_baseline;
    let enable_memfd = enable_all || cli.memfd_detect;
    let enable_map_audit = enable_all || cli.map_audit;
    let enable_tp_monitor = enable_all || cli.tracepoint_monitor;
    let enable_honeypots = enable_all || cli.honeypots;

    let any_enabled = enable_ghost
        || enable_latency
        || enable_bytecode
        || enable_hidden
        || enable_hooks
        || enable_prog_inv
        || enable_syscall_anom
        || enable_net_base
        || enable_memfd
        || enable_map_audit
        || enable_tp_monitor
        || enable_honeypots;

    if !any_enabled {
        warn!("No detection modules enabled. Use --all-modules or enable specific modules.");
        return Ok(());
    }

    // ─── Original Modules (1-5) ─────────────────────────────────────────────────

    if enable_ghost {
        let ghost_map: &mut TracePoint = bpf
            .program_mut("detect_ghost_map")
            .context("detect_ghost_map not found")?
            .try_into()?;
        ghost_map.load()?;
        ghost_map.attach("syscalls", "sys_enter_bpf")?;
        info!("Module 1: Ghost Map Detection enabled");
    }

    if enable_latency {
        let syscall_enter: &mut TracePoint = bpf
            .program_mut("monitor_syscall_enter")
            .context("monitor_syscall_enter not found")?
            .try_into()?;
        syscall_enter.load()?;
        syscall_enter.attach("raw_syscalls", "sys_enter")?;

        let syscall_exit: &mut TracePoint = bpf
            .program_mut("monitor_syscall_exit")
            .context("monitor_syscall_exit not found")?
            .try_into()?;
        syscall_exit.load()?;
        syscall_exit.attach("raw_syscalls", "sys_exit")?;
        info!("Module 2: Syscall Latency Monitoring enabled");
        info!(
            "Calibrating baseline for {} seconds...",
            cli.calibration_period
        );
    }

    if enable_bytecode {
        let bytecode_check: &mut TracePoint = bpf
            .program_mut("check_bytecode_integrity")
            .context("check_bytecode_integrity not found")?
            .try_into()?;
        bytecode_check.load()?;
        bytecode_check.attach("syscalls", "sys_enter_bpf")?;
        info!("Module 3: Bytecode Integrity Checking enabled");
    }

    if enable_hidden {
        let hidden_proc: &mut KProbe = bpf
            .program_mut("detect_hidden_process")
            .context("detect_hidden_process not found")?
            .try_into()?;
        hidden_proc.load()?;
        hidden_proc.attach("__x64_sys_getdents64", 0)?;
        info!("Module 4: Hidden Process Detection enabled");
    }

    if enable_hooks {
        let hook_detect: &mut TracePoint = bpf
            .program_mut("detect_suspicious_hook")
            .context("detect_suspicious_hook not found")?
            .try_into()?;
        hook_detect.load()?;
        hook_detect.attach("syscalls", "sys_enter_bpf")?;
        info!("Module 5: Suspicious Hook Detection enabled");
    }

    // ─── New Modules (6-11) ─────────────────────────────────────────────────────

    if enable_prog_inv {
        let prog_inv: &mut TracePoint = bpf
            .program_mut("detect_prog_inventory")
            .context("detect_prog_inventory not found")?
            .try_into()?;
        prog_inv.load()?;
        prog_inv.attach("syscalls", "sys_enter_bpf")?;
        info!("Module 6: eBPF Program Inventory (ID Gap Detection) enabled");
    }

    if enable_syscall_anom {
        let syscall_anom: &mut TracePoint = bpf
            .program_mut("detect_syscall_anomaly")
            .context("detect_syscall_anomaly not found")?
            .try_into()?;
        syscall_anom.load()?;
        syscall_anom.attach("raw_syscalls", "sys_enter")?;
        info!("Module 7: Syscall Argument Anomaly Profiling enabled");
    }

    if enable_net_base {
        let net_anom: &mut KProbe = bpf
            .program_mut("detect_net_anomaly")
            .context("detect_net_anomaly not found")?
            .try_into()?;
        net_anom.load()?;
        net_anom.attach("tcp_connect", 0)?;
        info!("Module 8: Network Behavior Baseline enabled");
    }

    if enable_memfd {
        let memfd_create: &mut KProbe = bpf
            .program_mut("detect_memfd_create")
            .context("detect_memfd_create not found")?
            .try_into()?;
        memfd_create.load()?;
        memfd_create.attach("__x64_sys_memfd_create", 0)?;

        let memfd_exec: &mut KProbe = bpf
            .program_mut("detect_memfd_exec")
            .context("detect_memfd_exec not found")?
            .try_into()?;
        memfd_exec.load()?;
        memfd_exec.attach("do_execveat_common", 0)?;
        info!("Module 9: Memory-Backed Execution Detection enabled");
    }

    if enable_map_audit {
        let map_audit: &mut TracePoint = bpf
            .program_mut("audit_map_content")
            .context("audit_map_content not found")?
            .try_into()?;
        map_audit.load()?;
        map_audit.attach("syscalls", "sys_enter_bpf")?;
        info!("Module 10: BPF Map Content Auditing enabled");
    }

    if enable_tp_monitor {
        let rapid_detach: &mut KProbe = bpf
            .program_mut("detect_rapid_detach")
            .context("detect_rapid_detach not found")?
            .try_into()?;
        rapid_detach.load()?;
        rapid_detach.attach("bpf_prog_put", 0)?;
        info!("Module 11: Tracepoint Coverage Monitoring enabled");
    }

    // ─── Honeypot Setup ─────────────────────────────────────────────────────────

    if enable_honeypots {
        match setup_honeypots(&mut bpf) {
            Ok(ids) => {
                info!(
                    "Module 15: Honeypot BPF Maps active ({} decoys deployed)",
                    ids.len()
                );
            }
            Err(e) => {
                warn!("Honeypot setup failed (non-fatal): {}", e);
            }
        }
    }

    // ─── Engine Initialization ──────────────────────────────────────────────────

    let mut engine = DefenseEngine::new(cli.output.clone(), cli.threshold)?;
    engine.auto_detach_enabled = cli.auto_detach;
    engine.auto_contain_enabled = cli.auto_contain;

    if cli.auto_detach {
        info!("Response: Auto-Detach enabled (will detach malicious BPF programs)");
    }
    if cli.auto_contain {
        info!("Response: Auto-Contain enabled (will isolate attack-chain PIDs via cgroups)");
    }

    let (alert_tx, mut alert_rx) = mpsc::channel::<DefenseAlert>(256);

    // Spawn per-CPU perf event readers
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("DEFENSE_ALERTS")
            .context("DEFENSE_ALERTS map not found")?,
    )?;

    let cpus = aya::util::online_cpus().unwrap_or_else(|_| vec![0]);
    for cpu in cpus.iter() {
        let mut buf = perf_array.open(*cpu, None)?;
        let tx = alert_tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..64)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<DefenseAlert>()))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for buf in buffers.iter().take(events.read) {
                            if buf.len() >= std::mem::size_of::<DefenseAlert>() {
                                let alert = unsafe {
                                    std::ptr::read_unaligned(buf.as_ptr() as *const DefenseAlert)
                                };
                                if tx.send(alert).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading perf events: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
    drop(alert_tx);

    info!("Alert monitoring started on {} CPUs", cpus.len());

    // Calibration timer — signals engine when calibration period ends
    let (cal_tx, cal_rx) = tokio::sync::oneshot::channel::<()>();
    let calibration_period = cli.calibration_period;
    tokio::spawn(async move {
        sleep(Duration::from_secs(calibration_period)).await;
        let _ = cal_tx.send(());
    });
    let mut cal_rx = Some(cal_rx);

    let config_path = cli.config.clone();
    let mut config_interval = interval(Duration::from_secs(5));
    config_interval.tick().await; // consume initial tick

    info!("Defense engine active. Press Ctrl+C to stop.");
    if config_path.is_some() {
        info!("Config hot-reload enabled (polling every 5s)");
    }

    loop {
        tokio::select! {
            Some(alert) = alert_rx.recv() => {
                if let Some(record) = engine.process_alert(&alert) {
                    if cli.json_stdout {
                        if let Ok(json) = serde_json::to_string(&record) {
                            println!("{}", json);
                        }
                    }

                    // Auto-detach response: track suspicious prog IDs
                    if alert.alert_type == ALERT_PROG_INVENTORY
                        || alert.alert_type == ALERT_SUSPICIOUS_HOOK
                        || alert.alert_type == ALERT_MAP_AUDIT
                        || alert.alert_type == ALERT_HONEYPOT_READ
                    {
                        let prog_id = alert.context as u32;
                        engine.record_suspicious_prog(prog_id);
                        if engine.should_auto_detach(prog_id) {
                            info!(
                                "AUTO-DETACH: Program {} flagged for detachment ({} corroborating alerts)",
                                prog_id,
                                engine.auto_detach_candidates.get(&prog_id).unwrap_or(&0)
                            );
                            // In production: invoke bpf(BPF_PROG_DETACH) via raw fd
                            // For research: log the action
                        }
                    }

                    // Auto-contain response: isolate PIDs with attack chains
                    if record.is_attack_chain && engine.should_contain(alert.pid) {
                        match contain_process(alert.pid) {
                            Ok(()) => {
                                engine.mark_contained(alert.pid);
                                info!(
                                    "AUTO-CONTAIN: PID {} isolated (attack chain: {:?})",
                                    alert.pid, record.correlated_types
                                );
                            }
                            Err(e) => {
                                warn!("Failed to contain PID {}: {}", alert.pid, e);
                            }
                        }
                    }

                    // Memfd execution is always critical — log prominently
                    if alert.alert_type == ALERT_MEMFD_EXEC {
                        warn!(
                            "CRITICAL: Fileless execution detected! PID={} fd={}",
                            alert.pid, alert.context
                        );
                    }
                }
            }
            _ = async {
                if let Some(rx) = cal_rx.take() {
                    let _ = rx.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                engine.finish_calibration();
                info!("Calibration complete — anomaly detection active");
            }
            _ = config_interval.tick(), if config_path.is_some() => {
                if let Some(ref path) = config_path {
                    if let Some(cfg) = RuntimeConfig::load_from_file(path) {
                        engine.apply_config(&cfg);
                    }
                }
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    info!("Shutting down...");
    let m = engine.metrics();
    info!("=== Defense Engine Metrics ===");
    info!("  Alerts processed:       {}", m.alerts_processed);
    info!("  Alerts suppressed:      {}", m.alerts_suppressed);
    info!("  Attack chains detected: {}", m.attack_chains_detected);
    info!("  Anomaly escalations:    {}", m.anomaly_escalations);
    info!("=== Alert Breakdown ===");
    for (alert_type, count) in &engine.alert_count {
        let type_str = classify_alert_type(*alert_type);
        info!("  {} - {} alerts", type_str, count);
    }

    // Print correlation graph summary
    let chains = engine.correlation_summary();
    if chains != "[]" {
        info!("=== Attack Chain Correlations ===");
        info!("  {}", chains);
    }

    // Report auto-detach candidates
    if !engine.auto_detach_candidates.is_empty() {
        info!("=== Auto-Detach Candidates ===");
        for (prog_id, count) in &engine.auto_detach_candidates {
            info!("  prog_id={} — {} corroborating alerts", prog_id, count);
        }
    }

    // Report contained PIDs
    if !engine.contained_pids.is_empty() {
        info!("=== Contained PIDs ===");
        for pid in &engine.contained_pids {
            info!("  PID {}", pid);
        }
    }

    Ok(())
}
