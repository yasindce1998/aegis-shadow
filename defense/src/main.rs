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
use common::DefenseAlert;
use defense::DefenseEngine;
use log::{error, info, warn};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

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

    /// Baseline calibration period (seconds)
    #[arg(long, default_value = "60")]
    calibration_period: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }),
    )
    .init();

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

    if !enable_all
        && !enable_ghost
        && !enable_latency
        && !enable_bytecode
        && !enable_hidden
        && !enable_hooks
    {
        warn!("No detection modules enabled. Use --all-modules or enable specific modules.");
        return Ok(());
    }

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

    let mut engine = DefenseEngine::new(cli.output.clone(), cli.threshold)?;

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
                        for i in 0..events.read {
                            if buffers[i].len() >= std::mem::size_of::<DefenseAlert>() {
                                let alert = unsafe {
                                    std::ptr::read_unaligned(
                                        buffers[i].as_ptr() as *const DefenseAlert
                                    )
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

    info!("Defense engine active. Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            Some(alert) = alert_rx.recv() => {
                engine.process_alert(&alert);
            }
            _ = async {
                if let Some(rx) = cal_rx.take() {
                    let _ = rx.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                engine.finish_calibration();
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    info!("Shutting down...");
    info!("Total alerts processed: {}", engine.total_alerts());
    for (alert_type, count) in &engine.alert_count {
        let type_str = defense::classify_alert_type(*alert_type);
        info!("  {} - {} alerts", type_str, count);
    }

    Ok(())
}
