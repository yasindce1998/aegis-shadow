use common::{
    ALERT_AUTO_DETACH, ALERT_BYTECODE_TAMPER, ALERT_CONTAINMENT, ALERT_CROSS_REFERENCE,
    ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS, ALERT_HONEYPOT_READ, ALERT_HW_PERF_COUNTER,
    ALERT_MAP_AUDIT, ALERT_MEMFD_EXEC, ALERT_MEMORY_FORENSICS, ALERT_NET_BASELINE,
    ALERT_PROG_INVENTORY, ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_ANOMALY, ALERT_SYSCALL_LATENCY,
    ALERT_TRACEPOINT_GAP, ALERT_VERIFIER_ANALYSIS, EVENT_ACTIVITY_THROTTLED, EVENT_ANTI_DETACH,
    EVENT_ARP_POISONED, EVENT_AUDIT_KILLED, EVENT_BEHAVIOR_PROFILED, EVENT_BGP_HIJACK,
    EVENT_BINARY_PATCHED_INFLIGHT, EVENT_BPF_ITER_ABUSED, EVENT_BPF_LINK_PINNED,
    EVENT_BPF_PROG_DETECTED, EVENT_BYTECODE_MORPHED, EVENT_CGROUP_BPF_INJECT, EVENT_CGROUP_PERSIST,
    EVENT_CONTAINER_LATERAL, EVENT_CONTAINER_PROBE, EVENT_COREDUMP_SUPPRESSED, EVENT_DEADMAN_ARMED,
    EVENT_DMA_STASH, EVENT_DNS_EXFIL, EVENT_DOH_C2_ESTABLISHED, EVENT_DR_BREAKPOINT,
    EVENT_FILE_OBFUSCATED, EVENT_FTRACE_BLINDED, EVENT_FTRACE_SELF_HIDDEN,
    EVENT_HEARTBEAT_RECEIVED, EVENT_HYPERVISOR_BLINDSPOT, EVENT_HYPERVISOR_DETECTED,
    EVENT_HYPERVISOR_FINGERPRINT, EVENT_IDT_HOOKED, EVENT_INITRAMFS_IMPLANT,
    EVENT_INITRAMFS_LOADER, EVENT_INODE_SLACK_HIDE, EVENT_INTEGRITY_BYPASSED, EVENT_IPV6_EXT_ABUSE,
    EVENT_ISN_COVERT, EVENT_JOURNAL_MANIPULATED, EVENT_KPROBE_DETECTED, EVENT_LIVEPATCH_ABUSED,
    EVENT_LIVE_MIGRATION_DETECTED, EVENT_LSM_HOOK_SUBVERTED, EVENT_MODSIGN_BYPASS,
    EVENT_MODULE_PARAM_INJECT, EVENT_NAMESPACE_ESCAPE, EVENT_NIC_EXFIL,
    EVENT_NORM_DEVIATION_AVOIDED, EVENT_OBFUSCATED_PIN, EVENT_OPAQUE_PREDICATE,
    EVENT_PACKET_INTERCEPTED, EVENT_PATTERN_ROTATED, EVENT_PCIE_TLP_SIGNAL,
    EVENT_PHANTOM_CONN_ESTABLISHED, EVENT_PHANTOM_DATA_XFER, EVENT_PHANTOM_SYN_ACK,
    EVENT_PKG_MANAGER_HOOKED, EVENT_PMC_COVERT, EVENT_PORT_KNOCK_AUTH, EVENT_PROC_DEEP_SPOOF,
    EVENT_PROC_HIDDEN, EVENT_PROG_ARRAY_HIJACKED, EVENT_RAW_SOCKET_C2, EVENT_SCORCHED_EARTH,
    EVENT_SHM_COVERT_MSG, EVENT_TAILCALL_INJECTED, EVENT_TAIL_CALL_CHAIN,
    EVENT_TASK_STRUCT_PATCHED, EVENT_TC_TRAFFIC_INJECTED, EVENT_TIMESTOMPED, EVENT_TRAFFIC_SHAPED,
    EVENT_TSC_SIDECHAN, EVENT_UFFD_INJECTION, EVENT_VDSO_HOOKED,
};
use defense::{format_alert_details, make_defense_alert, make_latency_alert, DefenseEngine};
use integration_tests::{
    assert_classifies_to, make_event, make_event_at, TEST_PID, TEST_PID_2, TEST_PID_3,
    TEST_TIMESTAMP,
};
use offense::{classify_event, make_rootkit_config, EventClassification};

// ═══════════════════════════════════════════════════════════════════
// Original scenarios (preserved)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_offense_hide_pid_triggers_defense_alert() {
    let offense_event = make_event(EVENT_PROC_HIDDEN, 1337, 0);
    let classification = classify_event(&offense_event);
    assert_eq!(
        classification,
        EventClassification::ProcessHidden { pid: 1337 }
    );

    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let defense_alert = make_defense_alert(ALERT_HIDDEN_PROCESS, 4, 1337, 1_000_100, 0);
    let record = engine.process_alert(&defense_alert).unwrap();

    assert_eq!(record.alert_type, "Hidden Process Detected");
    assert_eq!(record.severity, "CRITICAL");
    assert_eq!(record.pid, 1337);
}

#[test]
fn test_offense_bpf_load_triggers_ghost_map_detection() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let ghost_alerts: Vec<_> = (0..5)
        .map(|i| make_defense_alert(ALERT_GHOST_MAP, 3, 1337, i * 1000, i as u64))
        .collect();

    for alert in &ghost_alerts {
        let record = engine.process_alert(alert).unwrap();
        assert_eq!(record.alert_type, "Ghost Map Detected");
    }

    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 5);
}

#[test]
fn test_offense_syscall_hook_causes_latency_spike() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let baseline_latency_ns: u64 = 500;
    let hooked_latency_ns: u64 = 50_000;

    let latency_alert = make_latency_alert(1337, 2_000_000, 217, hooked_latency_ns);
    let record = engine.process_alert(&latency_alert).unwrap();

    assert_eq!(record.alert_type, "Syscall Latency Anomaly");
    assert!(record.details.contains("50000ns"));

    assert!(hooked_latency_ns > baseline_latency_ns * 13 / 10);
}

#[test]
fn test_offense_bytecode_tamper_detected() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let tamper_alert = make_defense_alert(ALERT_BYTECODE_TAMPER, 4, 1337, 3_000_000, 0xDEAD);
    let record = engine.process_alert(&tamper_alert).unwrap();

    assert_eq!(record.alert_type, "Bytecode Tampering");
    assert_eq!(record.severity, "CRITICAL");
    assert!(record.details.contains("57005"));
}

#[test]
fn test_offense_hook_install_detected() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let hook_alert = make_defense_alert(ALERT_SUSPICIOUS_HOOK, 3, 1337, 4_000_000, 5);
    let record = engine.process_alert(&hook_alert).unwrap();

    assert_eq!(record.alert_type, "Suspicious Hook Detected");
    assert_eq!(record.severity, "HIGH");
}

#[test]
fn test_full_attack_chain_detection() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let offense_pid = 1337u32;

    let offense_events = vec![
        make_event_at(EVENT_PROC_HIDDEN, offense_pid, 0, 100),
        make_event_at(EVENT_PACKET_INTERCEPTED, 1, 53, 200),
        make_event_at(EVENT_FILE_OBFUSCATED, offense_pid, 12345, 300),
        make_event_at(EVENT_ANTI_DETACH, offense_pid, 2, 400),
        make_event_at(EVENT_TIMESTOMPED, offense_pid, 67890, 500),
        make_event_at(EVENT_DNS_EXFIL, offense_pid, 1, 600),
    ];

    for event in &offense_events {
        let _class = classify_event(event);
    }

    let defense_alerts = vec![
        make_defense_alert(ALERT_GHOST_MAP, 3, offense_pid, 150, 0),
        make_defense_alert(ALERT_SUSPICIOUS_HOOK, 3, offense_pid, 250, 0),
        make_latency_alert(offense_pid, 350, 78, 100_000),
        make_defense_alert(ALERT_HIDDEN_PROCESS, 4, offense_pid, 450, 0),
        make_defense_alert(ALERT_BYTECODE_TAMPER, 4, offense_pid, 550, 0),
    ];

    let mut records = Vec::new();
    for alert in &defense_alerts {
        if let Some(record) = engine.process_alert(alert) {
            records.push(record);
        }
    }

    assert_eq!(records.len(), 5);
    assert_eq!(engine.total_alerts(), 5);

    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 1);
    assert_eq!(engine.alerts_by_type(ALERT_SUSPICIOUS_HOOK), 1);
    assert_eq!(engine.alerts_by_type(ALERT_SYSCALL_LATENCY), 1);
    assert_eq!(engine.alerts_by_type(ALERT_HIDDEN_PROCESS), 1);
    assert_eq!(engine.alerts_by_type(ALERT_BYTECODE_TAMPER), 1);
}

#[test]
fn test_high_threshold_misses_subtle_attacks() {
    let mut sensitive_engine = DefenseEngine::new(None, 1).unwrap();
    let mut standard_engine = DefenseEngine::new(None, 2).unwrap();
    let mut strict_engine = DefenseEngine::new(None, 4).unwrap();

    let subtle_attack = make_defense_alert(ALERT_GHOST_MAP, 1, 1337, 1000, 0);
    let moderate_attack = make_defense_alert(ALERT_SYSCALL_LATENCY, 2, 1337, 2000, 0);
    let obvious_attack = make_defense_alert(ALERT_HIDDEN_PROCESS, 4, 1337, 3000, 0);

    assert!(sensitive_engine.process_alert(&subtle_attack).is_some());
    assert!(standard_engine.process_alert(&subtle_attack).is_none());
    assert!(strict_engine.process_alert(&subtle_attack).is_none());

    assert!(sensitive_engine.process_alert(&moderate_attack).is_some());
    assert!(standard_engine.process_alert(&moderate_attack).is_some());
    assert!(strict_engine.process_alert(&moderate_attack).is_none());

    assert!(sensitive_engine.process_alert(&obvious_attack).is_some());
    assert!(standard_engine.process_alert(&obvious_attack).is_some());
    assert!(strict_engine.process_alert(&obvious_attack).is_some());
}

#[test]
fn test_rootkit_config_all_features_active() {
    let config = make_rootkit_config(1337);

    assert_eq!(config.hide_procs, 1);
    assert_eq!(config.net_stealth, 1);
    assert_eq!(config.file_obfuscate, 1);
    assert_eq!(config.mute_telemetry, 1);

    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let expected_detections = vec![
        (ALERT_HIDDEN_PROCESS, "hide_procs"),
        (ALERT_GHOST_MAP, "net_stealth BPF maps"),
        (ALERT_SUSPICIOUS_HOOK, "file_obfuscate hooks"),
        (ALERT_BYTECODE_TAMPER, "mute_telemetry tampering"),
    ];

    for (alert_type, _feature) in &expected_detections {
        let alert = make_defense_alert(*alert_type, 3, config.self_pid, 1000, 0);
        assert!(
            engine.process_alert(&alert).is_some(),
            "Defense should detect activity from feature"
        );
    }

    assert_eq!(engine.total_alerts(), expected_detections.len() as u64);
}

#[test]
fn test_rapid_fire_alerts_all_processed() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    for i in 0..100 {
        let alert = make_defense_alert(ALERT_GHOST_MAP, 2, 1337, i as u64, i as u64);
        engine.process_alert(&alert);
    }

    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 100);
}

#[test]
fn test_multiple_attackers() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let attacker_pids = [1001u32, 2002, 3003, 4004];

    for &pid in &attacker_pids {
        engine.process_alert(&make_defense_alert(ALERT_HIDDEN_PROCESS, 4, pid, 1000, 0));
        engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, pid, 2000, 0));
    }

    assert_eq!(engine.alerts_by_type(ALERT_HIDDEN_PROCESS), 4);
    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 4);
    assert_eq!(engine.total_alerts(), 8);
}

// ═══════════════════════════════════════════════════════════════════
// Advanced event classification (events 25-88) through offense→defense pipeline
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_kernel_evasion_events_classify_correctly() {
    assert_classifies_to(EVENT_KPROBE_DETECTED, "KprobeDetected");
    assert_classifies_to(EVENT_TAIL_CALL_CHAIN, "TailCallChain");
    assert_classifies_to(EVENT_FTRACE_BLINDED, "FtraceBlinded");
    assert_classifies_to(EVENT_BPF_ITER_ABUSED, "BpfIterAbused");
}

#[test]
fn test_memory_process_events_classify_correctly() {
    assert_classifies_to(EVENT_VDSO_HOOKED, "VdsoHooked");
    assert_classifies_to(EVENT_SHM_COVERT_MSG, "ShmCovertMsg");
    assert_classifies_to(EVENT_UFFD_INJECTION, "UffdInjection");
    assert_classifies_to(EVENT_COREDUMP_SUPPRESSED, "CoredumpSuppressed");
}

#[test]
fn test_network_covert_events_classify_correctly() {
    assert_classifies_to(EVENT_ISN_COVERT, "IsnCovert");
    assert_classifies_to(EVENT_IPV6_EXT_ABUSE, "Ipv6ExtAbuse");
    assert_classifies_to(EVENT_ARP_POISONED, "ArpPoisoned");
    assert_classifies_to(EVENT_PORT_KNOCK_AUTH, "PortKnockAuth");
    assert_classifies_to(EVENT_BGP_HIJACK, "BgpHijack");
}

#[test]
fn test_hardware_events_classify_correctly() {
    assert_classifies_to(EVENT_DR_BREAKPOINT, "DrBreakpoint");
    assert_classifies_to(EVENT_PMC_COVERT, "PmcCovert");
    assert_classifies_to(EVENT_TSC_SIDECHAN, "TscSidechan");
}

#[test]
fn test_anti_forensics_events_classify_correctly() {
    assert_classifies_to(EVENT_AUDIT_KILLED, "AuditKilled");
    assert_classifies_to(EVENT_INODE_SLACK_HIDE, "InodeSlackHide");
    assert_classifies_to(EVENT_JOURNAL_MANIPULATED, "JournalManipulated");
    assert_classifies_to(EVENT_PROC_DEEP_SPOOF, "ProcDeepSpoof");
}

#[test]
fn test_advanced_persistence_events_classify_correctly() {
    assert_classifies_to(EVENT_INITRAMFS_IMPLANT, "InitramfsImplant");
    assert_classifies_to(EVENT_MODSIGN_BYPASS, "ModsignBypass");
    assert_classifies_to(EVENT_BPF_LINK_PINNED, "BpfLinkPinned");
}

#[test]
fn test_hypervisor_evasion_events_classify_correctly() {
    assert_classifies_to(EVENT_HYPERVISOR_DETECTED, "HypervisorDetected");
    assert_classifies_to(EVENT_HYPERVISOR_FINGERPRINT, "HypervisorFingerprint");
    assert_classifies_to(EVENT_HYPERVISOR_BLINDSPOT, "HypervisorBlindspot");
    assert_classifies_to(EVENT_LIVE_MIGRATION_DETECTED, "LiveMigrationDetected");
}

#[test]
fn test_polymorphic_events_classify_correctly() {
    assert_classifies_to(EVENT_BYTECODE_MORPHED, "BytecodeMorphed");
    assert_classifies_to(EVENT_PATTERN_ROTATED, "PatternRotated");
    assert_classifies_to(EVENT_OPAQUE_PREDICATE, "OpaquePredicate");
}

#[test]
fn test_phantom_network_events_classify_correctly() {
    assert_classifies_to(EVENT_PHANTOM_SYN_ACK, "PhantomSynAck");
    assert_classifies_to(EVENT_PHANTOM_CONN_ESTABLISHED, "PhantomConnEstablished");
    assert_classifies_to(EVENT_PHANTOM_DATA_XFER, "PhantomDataXfer");
}

#[test]
fn test_container_lateral_events_classify_correctly() {
    assert_classifies_to(EVENT_CGROUP_BPF_INJECT, "CgroupBpfInject");
    assert_classifies_to(EVENT_CONTAINER_LATERAL, "ContainerLateral");
    assert_classifies_to(EVENT_NAMESPACE_ESCAPE, "NamespaceEscape");
}

#[test]
fn test_dma_covert_events_classify_correctly() {
    assert_classifies_to(EVENT_DMA_STASH, "DmaStash");
    assert_classifies_to(EVENT_PCIE_TLP_SIGNAL, "PcieTlpSignal");
    assert_classifies_to(EVENT_NIC_EXFIL, "NicExfil");
}

#[test]
fn test_behavioral_ai_events_classify_correctly() {
    assert_classifies_to(EVENT_BEHAVIOR_PROFILED, "BehaviorProfiled");
    assert_classifies_to(EVENT_ACTIVITY_THROTTLED, "ActivityThrottled");
    assert_classifies_to(EVENT_NORM_DEVIATION_AVOIDED, "NormDeviationAvoided");
}

#[test]
fn test_supply_chain_events_classify_correctly() {
    assert_classifies_to(EVENT_PKG_MANAGER_HOOKED, "PkgManagerHooked");
    assert_classifies_to(EVENT_BINARY_PATCHED_INFLIGHT, "BinaryPatchedInflight");
    assert_classifies_to(EVENT_INTEGRITY_BYPASSED, "IntegrityBypassed");
}

#[test]
fn test_dead_mans_switch_events_classify_correctly() {
    assert_classifies_to(EVENT_HEARTBEAT_RECEIVED, "HeartbeatReceived");
    assert_classifies_to(EVENT_DEADMAN_ARMED, "DeadmanArmed");
    assert_classifies_to(EVENT_SCORCHED_EARTH, "ScorchedEarth");
}

#[test]
fn test_bpf_parasitism_events_classify_correctly() {
    assert_classifies_to(EVENT_BPF_PROG_DETECTED, "BpfProgDetected");
    assert_classifies_to(EVENT_TAILCALL_INJECTED, "TailcallInjected");
    assert_classifies_to(EVENT_PROG_ARRAY_HIJACKED, "ProgArrayHijacked");
}

#[test]
fn test_advanced_rootkit_events_classify_correctly() {
    assert_classifies_to(EVENT_TASK_STRUCT_PATCHED, "TaskStructPatched");
    assert_classifies_to(EVENT_LSM_HOOK_SUBVERTED, "LsmHookSubverted");
    assert_classifies_to(EVENT_IDT_HOOKED, "IdtHooked");
    assert_classifies_to(EVENT_FTRACE_SELF_HIDDEN, "FtraceSelfHidden");
    assert_classifies_to(EVENT_LIVEPATCH_ABUSED, "LivepatchAbused");
}

#[test]
fn test_network_stealth_events_classify_correctly() {
    assert_classifies_to(EVENT_RAW_SOCKET_C2, "RawSocketC2");
    assert_classifies_to(EVENT_TC_TRAFFIC_INJECTED, "TcTrafficInjected");
    assert_classifies_to(EVENT_DOH_C2_ESTABLISHED, "DohC2Established");
    assert_classifies_to(EVENT_TRAFFIC_SHAPED, "TrafficShaped");
}

#[test]
fn test_advanced_persistence_v2_events_classify_correctly() {
    assert_classifies_to(EVENT_OBFUSCATED_PIN, "ObfuscatedPin");
    assert_classifies_to(EVENT_CGROUP_PERSIST, "CgroupPersist");
    assert_classifies_to(EVENT_MODULE_PARAM_INJECT, "ModuleParamInject");
    assert_classifies_to(EVENT_INITRAMFS_LOADER, "InitramfsLoader");
}

// ═══════════════════════════════════════════════════════════════════
// Defense engine processing alerts 6-18
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_defense_alert_prog_inventory() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_PROG_INVENTORY, 3, TEST_PID, TEST_TIMESTAMP, 10);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Program Inventory Gap");
    assert_eq!(record.severity, "HIGH");
    assert!(record.details.contains("prog_count=10"));
}

#[test]
fn test_defense_alert_syscall_anomaly() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_SYSCALL_ANOMALY, 3, TEST_PID, TEST_TIMESTAMP, 59);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Syscall Argument Anomaly");
    assert!(record.details.contains("syscall=59"));
}

#[test]
fn test_defense_alert_net_baseline() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_NET_BASELINE, 2, TEST_PID, TEST_TIMESTAMP, 65536);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Network Behavior Anomaly");
    assert!(record.details.contains("bytes=65536"));
}

#[test]
fn test_defense_alert_memfd_exec() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_MEMFD_EXEC, 4, TEST_PID, TEST_TIMESTAMP, 3);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Memory-Backed Execution");
    assert_eq!(record.severity, "CRITICAL");
    assert!(record.details.contains("fd=3"));
}

#[test]
fn test_defense_alert_map_audit() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_MAP_AUDIT, 3, TEST_PID, TEST_TIMESTAMP, 77);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "BPF Map C2 Signature");
    assert!(record.details.contains("map_id=77"));
}

#[test]
fn test_defense_alert_tracepoint_gap() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_TRACEPOINT_GAP, 3, TEST_PID, TEST_TIMESTAMP, 500);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Rapid BPF Detach");
    assert!(record.details.contains("gap_ms=500"));
}

#[test]
fn test_defense_alert_auto_detach() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_AUTO_DETACH, 2, TEST_PID, TEST_TIMESTAMP, 42);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Auto-Detach Triggered");
    assert!(record.details.contains("prog_id=42"));
}

#[test]
fn test_defense_alert_containment() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_CONTAINMENT, 4, TEST_PID, TEST_TIMESTAMP, 9999);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Process Contained");
    assert_eq!(record.severity, "CRITICAL");
    assert!(record.details.contains("target_pid=9999"));
}

#[test]
fn test_defense_alert_honeypot_read() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_HONEYPOT_READ, 3, TEST_PID, TEST_TIMESTAMP, 88);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Honeypot Map Accessed");
    assert!(record.details.contains("map_id=88"));
}

#[test]
fn test_defense_alert_cross_reference() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_CROSS_REFERENCE, 3, TEST_PID, TEST_TIMESTAMP, 7);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Cross-Reference Anomaly");
    assert!(record.details.contains("discrepancy=7"));
}

#[test]
fn test_defense_alert_hw_perf_counter() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_HW_PERF_COUNTER, 2, TEST_PID, TEST_TIMESTAMP, 3);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "HW Perf Counter Deviation");
    assert!(record.details.contains("counter=3"));
}

#[test]
fn test_defense_alert_verifier_analysis() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_VERIFIER_ANALYSIS, 3, TEST_PID, TEST_TIMESTAMP, 101);
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Suspicious BPF Program");
    assert!(record.details.contains("prog_id=101"));
}

#[test]
fn test_defense_alert_memory_forensics() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(
        ALERT_MEMORY_FORENSICS,
        4,
        TEST_PID,
        TEST_TIMESTAMP,
        0xFFFF_0000,
    );
    let record = engine.process_alert(&alert).unwrap();

    assert_eq!(record.alert_type, "Kernel Data Tampering");
    assert_eq!(record.severity, "CRITICAL");
    assert!(record.details.contains("region=0xffff0000"));
}

// ═══════════════════════════════════════════════════════════════════
// Attack chain detection with advanced alert types
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_advanced_attack_chain_hypervisor_evasion() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let events = vec![
        make_event(EVENT_HYPERVISOR_DETECTED, TEST_PID, 1),
        make_event(EVENT_HYPERVISOR_FINGERPRINT, TEST_PID, 0xCAFE),
        make_event(EVENT_HYPERVISOR_BLINDSPOT, TEST_PID, 5000),
        make_event(EVENT_LIVE_MIGRATION_DETECTED, TEST_PID, 100),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let alerts = vec![
        make_defense_alert(ALERT_HW_PERF_COUNTER, 2, TEST_PID, 100, 1),
        make_defense_alert(ALERT_VERIFIER_ANALYSIS, 3, TEST_PID, 200, 42),
        make_defense_alert(ALERT_MEMORY_FORENSICS, 4, TEST_PID, 300, 0xDEAD),
    ];

    for alert in &alerts {
        engine.process_alert(alert);
    }

    assert_eq!(engine.total_alerts(), 3);
    assert_eq!(engine.alerts_by_type(ALERT_HW_PERF_COUNTER), 1);
    assert_eq!(engine.alerts_by_type(ALERT_VERIFIER_ANALYSIS), 1);
    assert_eq!(engine.alerts_by_type(ALERT_MEMORY_FORENSICS), 1);
}

#[test]
fn test_advanced_attack_chain_container_escape() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let events = vec![
        make_event(EVENT_CGROUP_BPF_INJECT, TEST_PID, 0x100),
        make_event(EVENT_CONTAINER_LATERAL, TEST_PID, 0x200),
        make_event(EVENT_NAMESPACE_ESCAPE, TEST_PID, 0x300),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let alerts = vec![
        make_defense_alert(ALERT_PROG_INVENTORY, 3, TEST_PID, 100, 5),
        make_defense_alert(ALERT_HONEYPOT_READ, 3, TEST_PID, 200, 10),
        make_defense_alert(ALERT_CONTAINMENT, 4, TEST_PID, 300, TEST_PID as u64),
    ];

    let mut records = Vec::new();
    for alert in &alerts {
        if let Some(record) = engine.process_alert(alert) {
            records.push(record);
        }
    }

    assert_eq!(records.len(), 3);
    assert_eq!(records[2].alert_type, "Process Contained");
    assert_eq!(records[2].severity, "CRITICAL");
}

#[test]
fn test_advanced_attack_chain_supply_chain_persistence() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let events = vec![
        make_event(EVENT_PKG_MANAGER_HOOKED, TEST_PID, 0xABC),
        make_event(EVENT_BINARY_PATCHED_INFLIGHT, TEST_PID, 12345),
        make_event(EVENT_INTEGRITY_BYPASSED, TEST_PID, 99),
        make_event(EVENT_BPF_LINK_PINNED, TEST_PID, 7),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let alerts = vec![
        make_defense_alert(ALERT_MAP_AUDIT, 3, TEST_PID, 100, 5),
        make_defense_alert(ALERT_CROSS_REFERENCE, 3, TEST_PID, 200, 2),
        make_defense_alert(ALERT_BYTECODE_TAMPER, 4, TEST_PID, 300, 0xBEEF),
    ];

    for alert in &alerts {
        engine.process_alert(alert);
    }

    assert_eq!(engine.total_alerts(), 3);
    assert_eq!(engine.pid_distinct_types(TEST_PID), 3);
}

#[test]
fn test_advanced_attack_chain_dead_mans_switch() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let events = vec![
        make_event(EVENT_HEARTBEAT_RECEIVED, TEST_PID, 60),
        make_event(EVENT_DEADMAN_ARMED, TEST_PID, 300),
        make_event(EVENT_SCORCHED_EARTH, TEST_PID, 15),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let alerts = vec![
        make_defense_alert(ALERT_TRACEPOINT_GAP, 3, TEST_PID, 100, 1000),
        make_defense_alert(ALERT_AUTO_DETACH, 3, TEST_PID, 200, 55),
        make_defense_alert(ALERT_HIDDEN_PROCESS, 4, TEST_PID, 300, 0),
    ];

    for alert in &alerts {
        engine.process_alert(alert);
    }

    assert_eq!(engine.total_alerts(), 3);
}

#[test]
fn test_advanced_attack_chain_bpf_parasitism() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let events = vec![
        make_event(EVENT_BPF_PROG_DETECTED, TEST_PID, 100),
        make_event(EVENT_TAILCALL_INJECTED, TEST_PID, 5),
        make_event(EVENT_PROG_ARRAY_HIJACKED, TEST_PID, 3),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let alerts = vec![
        make_defense_alert(ALERT_PROG_INVENTORY, 3, TEST_PID, 100, 12),
        make_defense_alert(ALERT_MAP_AUDIT, 3, TEST_PID, 200, 5),
        make_defense_alert(ALERT_VERIFIER_ANALYSIS, 3, TEST_PID, 300, 100),
        make_defense_alert(ALERT_BYTECODE_TAMPER, 4, TEST_PID, 400, 0xFACE),
    ];

    for alert in &alerts {
        engine.process_alert(alert);
    }

    assert_eq!(engine.total_alerts(), 4);
    assert_eq!(engine.pid_distinct_types(TEST_PID), 4);
}

// ═══════════════════════════════════════════════════════════════════
// Correlation and multi-PID advanced scenarios
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_multi_pid_advanced_events_correlated() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let pid_a_events = vec![
        make_event(EVENT_KPROBE_DETECTED, TEST_PID, 0x1000),
        make_event(EVENT_FTRACE_BLINDED, TEST_PID, 0x2000),
        make_event(EVENT_TAIL_CALL_CHAIN, TEST_PID, 5),
    ];

    let pid_b_events = vec![
        make_event(EVENT_NAMESPACE_ESCAPE, TEST_PID_2, 0x100),
        make_event(EVENT_CONTAINER_LATERAL, TEST_PID_2, 0x200),
    ];

    for event in pid_a_events.iter().chain(pid_b_events.iter()) {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let alerts = vec![
        make_defense_alert(ALERT_SUSPICIOUS_HOOK, 3, TEST_PID, 100, 0),
        make_defense_alert(ALERT_BYTECODE_TAMPER, 4, TEST_PID, 200, 0),
        make_defense_alert(ALERT_PROG_INVENTORY, 3, TEST_PID_2, 300, 8),
        make_defense_alert(ALERT_CONTAINMENT, 4, TEST_PID_2, 400, TEST_PID_2 as u64),
    ];

    for alert in &alerts {
        engine.process_alert(alert);
    }

    assert_eq!(engine.total_alerts(), 4);
    assert_eq!(engine.pid_distinct_types(TEST_PID), 2);
    assert_eq!(engine.pid_distinct_types(TEST_PID_2), 2);
}

#[test]
fn test_polymorphic_engine_evading_detection() {
    let events = vec![
        make_event(EVENT_BYTECODE_MORPHED, TEST_PID, 1),
        make_event(EVENT_PATTERN_ROTATED, TEST_PID, 0xABCD),
        make_event(EVENT_OPAQUE_PREDICATE, TEST_PID, 7),
    ];

    let classifications: Vec<_> = events.iter().map(|e| classify_event(e)).collect();
    assert_eq!(
        classifications[0],
        EventClassification::BytecodeMorphed {
            pid: TEST_PID,
            gen_id: 1
        }
    );
    assert_eq!(
        classifications[1],
        EventClassification::PatternRotated {
            pid: TEST_PID,
            pattern_hash: 0xABCD
        }
    );
    assert_eq!(
        classifications[2],
        EventClassification::OpaquePredicate {
            pid: TEST_PID,
            predicate_id: 7
        }
    );
}

#[test]
fn test_phantom_network_stack_full_lifecycle() {
    let events = vec![
        make_event(EVENT_PHANTOM_SYN_ACK, TEST_PID, 8080),
        make_event(EVENT_PHANTOM_CONN_ESTABLISHED, TEST_PID, 1),
        make_event(EVENT_PHANTOM_DATA_XFER, TEST_PID, 4096),
    ];

    let classifications: Vec<_> = events.iter().map(|e| classify_event(e)).collect();
    assert_eq!(
        classifications[0],
        EventClassification::PhantomSynAck {
            pid: TEST_PID,
            port: 8080
        }
    );
    assert_eq!(
        classifications[1],
        EventClassification::PhantomConnEstablished {
            pid: TEST_PID,
            conn_id: 1
        }
    );
    assert_eq!(
        classifications[2],
        EventClassification::PhantomDataXfer {
            pid: TEST_PID,
            bytes: 4096
        }
    );
}

#[test]
fn test_dma_exfiltration_chain() {
    let events = vec![
        make_event(EVENT_DMA_STASH, TEST_PID, 0x1_0000_0000),
        make_event(EVENT_PCIE_TLP_SIGNAL, TEST_PID, 0x1234),
        make_event(EVENT_NIC_EXFIL, TEST_PID, 65536),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let alerts = vec![
        make_defense_alert(ALERT_NET_BASELINE, 3, TEST_PID, 100, 65536),
        make_defense_alert(ALERT_MEMFD_EXEC, 4, TEST_PID, 200, 5),
        make_defense_alert(ALERT_MEMORY_FORENSICS, 4, TEST_PID, 300, 0x1_0000),
    ];

    for alert in &alerts {
        engine.process_alert(alert);
    }

    assert_eq!(engine.total_alerts(), 3);
    assert_eq!(engine.pid_distinct_types(TEST_PID), 3);
}

#[test]
fn test_rootkit_advanced_techniques_chain() {
    let events = vec![
        make_event(EVENT_TASK_STRUCT_PATCHED, TEST_PID, 0x400),
        make_event(EVENT_LSM_HOOK_SUBVERTED, TEST_PID, 5),
        make_event(EVENT_IDT_HOOKED, TEST_PID, 0x80),
        make_event(EVENT_FTRACE_SELF_HIDDEN, TEST_PID, 99),
        make_event(EVENT_LIVEPATCH_ABUSED, TEST_PID, 0xDEAD_BEEF),
    ];

    let classifications: Vec<_> = events.iter().map(|e| classify_event(e)).collect();
    assert_eq!(
        classifications[0],
        EventClassification::TaskStructPatched {
            pid: TEST_PID,
            field_offset: 0x400
        }
    );
    assert_eq!(
        classifications[1],
        EventClassification::LsmHookSubverted {
            pid: TEST_PID,
            hook_id: 5
        }
    );
    assert_eq!(
        classifications[2],
        EventClassification::IdtHooked {
            pid: TEST_PID,
            vector: 0x80
        }
    );
    assert_eq!(
        classifications[3],
        EventClassification::FtraceSelfHidden {
            pid: TEST_PID,
            prog_id: 99
        }
    );
    assert_eq!(
        classifications[4],
        EventClassification::LivepatchAbused {
            pid: TEST_PID,
            target_addr: 0xDEAD_BEEF
        }
    );
}

#[test]
fn test_network_stealth_c2_setup() {
    let events = vec![
        make_event(EVENT_RAW_SOCKET_C2, TEST_PID, 443),
        make_event(EVENT_DOH_C2_ESTABLISHED, TEST_PID, 0xABCD),
        make_event(EVENT_TC_TRAFFIC_INJECTED, TEST_PID, 1500),
        make_event(EVENT_TRAFFIC_SHAPED, TEST_PID, 1024),
    ];

    for event in &events {
        let class = classify_event(event);
        assert!(!matches!(class, EventClassification::Unknown { .. }));
    }

    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    engine.process_alert(&make_defense_alert(
        ALERT_NET_BASELINE,
        3,
        TEST_PID,
        100,
        1500,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_SUSPICIOUS_HOOK,
        3,
        TEST_PID,
        200,
        0,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_SYSCALL_ANOMALY,
        3,
        TEST_PID,
        300,
        41,
    ));

    assert_eq!(engine.total_alerts(), 3);
    assert_eq!(engine.pid_distinct_types(TEST_PID), 3);
}

#[test]
fn test_behavioral_ai_camouflage_detection() {
    let events = vec![
        make_event(EVENT_BEHAVIOR_PROFILED, TEST_PID, 1),
        make_event(EVENT_ACTIVITY_THROTTLED, TEST_PID, 100),
        make_event(EVENT_NORM_DEVIATION_AVOIDED, TEST_PID, 5),
    ];

    let classifications: Vec<_> = events.iter().map(|e| classify_event(e)).collect();
    assert_eq!(
        classifications[0],
        EventClassification::BehaviorProfiled {
            pid: TEST_PID,
            profile_id: 1
        }
    );
    assert_eq!(
        classifications[1],
        EventClassification::ActivityThrottled {
            pid: TEST_PID,
            rate: 100
        }
    );
    assert_eq!(
        classifications[2],
        EventClassification::NormDeviationAvoided {
            pid: TEST_PID,
            margin: 5
        }
    );
}

#[test]
fn test_three_attacker_advanced_scenario() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let attacker_a = TEST_PID;
    let attacker_b = TEST_PID_2;
    let attacker_c = TEST_PID_3;

    let events = vec![
        make_event(EVENT_KPROBE_DETECTED, attacker_a, 0x1000),
        make_event(EVENT_NAMESPACE_ESCAPE, attacker_b, 0x100),
        make_event(EVENT_SCORCHED_EARTH, attacker_c, 10),
    ];

    for event in &events {
        assert!(!matches!(
            classify_event(event),
            EventClassification::Unknown { .. }
        ));
    }

    engine.process_alert(&make_defense_alert(
        ALERT_SUSPICIOUS_HOOK,
        3,
        attacker_a,
        100,
        0,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_BYTECODE_TAMPER,
        4,
        attacker_a,
        200,
        0,
    ));

    engine.process_alert(&make_defense_alert(
        ALERT_CONTAINMENT,
        4,
        attacker_b,
        300,
        attacker_b as u64,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_PROG_INVENTORY,
        3,
        attacker_b,
        400,
        3,
    ));

    engine.process_alert(&make_defense_alert(
        ALERT_MEMORY_FORENSICS,
        4,
        attacker_c,
        500,
        0xDEAD,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_AUTO_DETACH,
        3,
        attacker_c,
        600,
        77,
    ));

    assert_eq!(engine.total_alerts(), 6);
    assert_eq!(engine.pid_distinct_types(attacker_a), 2);
    assert_eq!(engine.pid_distinct_types(attacker_b), 2);
    assert_eq!(engine.pid_distinct_types(attacker_c), 2);
}

#[test]
fn test_format_alert_details_advanced_types() {
    let alert_prog = make_defense_alert(ALERT_PROG_INVENTORY, 3, TEST_PID, 100, 10);
    assert_eq!(
        format_alert_details(&alert_prog),
        "prog_count=10, expected=0"
    );

    let alert_net = make_defense_alert(ALERT_NET_BASELINE, 2, TEST_PID, 200, 65536);
    assert_eq!(format_alert_details(&alert_net), "bytes=65536, threshold=0");

    let alert_honeypot = make_defense_alert(ALERT_HONEYPOT_READ, 3, TEST_PID, 300, 88);
    assert_eq!(
        format_alert_details(&alert_honeypot),
        "map_id=88, accessor_pid=0"
    );

    let alert_forensics = make_defense_alert(ALERT_MEMORY_FORENSICS, 4, TEST_PID, 400, 0xFFFF_0000);
    assert_eq!(
        format_alert_details(&alert_forensics),
        "region=0xffff0000, checksum_delta=0"
    );
}

#[test]
fn test_containment_after_advanced_attack_chain() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    for i in 0..5 {
        engine.process_alert(&make_defense_alert(
            ALERT_SUSPICIOUS_HOOK,
            3,
            TEST_PID,
            i * 100,
            0,
        ));
    }
    engine.process_alert(&make_defense_alert(
        ALERT_BYTECODE_TAMPER,
        4,
        TEST_PID,
        600,
        0,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_MEMORY_FORENSICS,
        4,
        TEST_PID,
        700,
        0,
    ));

    assert!(engine.pid_distinct_types(TEST_PID) >= 3);
    assert!(engine.total_alerts() >= 7);
}

#[test]
fn test_event_context_preserved_through_classification() {
    let event = make_event(EVENT_DMA_STASH, TEST_PID, 0xDEAD_BEEF_CAFE);
    let class = classify_event(&event);
    assert_eq!(
        class,
        EventClassification::DmaStash {
            pid: TEST_PID,
            dma_addr: 0xDEAD_BEEF_CAFE
        }
    );

    let event2 = make_event(EVENT_CONTAINER_PROBE, TEST_PID_2, 0xFF);
    let class2 = classify_event(&event2);
    assert_eq!(
        class2,
        EventClassification::ContainerProbe {
            pid: TEST_PID_2,
            ns_id: 0xFF
        }
    );
}
