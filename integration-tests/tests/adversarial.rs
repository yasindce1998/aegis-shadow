use common::{
    EventHeader, ALERT_BYTECODE_TAMPER, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS,
    ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_LATENCY, EVENT_ANTI_DETACH, EVENT_DNS_EXFIL,
    EVENT_FILE_OBFUSCATED, EVENT_PACKET_INTERCEPTED, EVENT_PROC_HIDDEN, EVENT_TIMESTOMPED,
};
use defense::{make_defense_alert, make_latency_alert, DefenseEngine};
use offense::{classify_event, make_rootkit_config, EventClassification};

// ─── Scenario: Offense hides a process, defense detects it ────────

#[test]
fn test_offense_hide_pid_triggers_defense_alert() {
    let offense_event = EventHeader {
        event_type: EVENT_PROC_HIDDEN,
        pid: 1337,
        timestamp_ns: 1_000_000,
        context: 0,
    };
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

// ─── Scenario: Offense loads BPF programs, defense detects ghost maps ──

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

// ─── Scenario: Offense hooks syscalls, defense detects latency anomaly ──

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

// ─── Scenario: Offense tampers with bytecode, defense detects ─────

#[test]
fn test_offense_bytecode_tamper_detected() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let tamper_alert = make_defense_alert(ALERT_BYTECODE_TAMPER, 4, 1337, 3_000_000, 0xDEAD);
    let record = engine.process_alert(&tamper_alert).unwrap();

    assert_eq!(record.alert_type, "Bytecode Tampering");
    assert_eq!(record.severity, "CRITICAL");
    assert!(record.details.contains("57005")); // 0xDEAD = 57005
}

// ─── Scenario: Offense installs hooks, defense detects suspicious attach ──

#[test]
fn test_offense_hook_install_detected() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let hook_alert = make_defense_alert(ALERT_SUSPICIOUS_HOOK, 3, 1337, 4_000_000, 5);
    let record = engine.process_alert(&hook_alert).unwrap();

    assert_eq!(record.alert_type, "Suspicious Hook Detected");
    assert_eq!(record.severity, "HIGH");
}

// ─── Scenario: Full attack chain detection ────────────────────────

#[test]
fn test_full_attack_chain_detection() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    engine.finish_calibration();

    let offense_pid = 1337u32;

    let offense_events = vec![
        EventHeader {
            event_type: EVENT_PROC_HIDDEN,
            pid: offense_pid,
            timestamp_ns: 100,
            context: 0,
        },
        EventHeader {
            event_type: EVENT_PACKET_INTERCEPTED,
            pid: 1,
            timestamp_ns: 200,
            context: 53,
        },
        EventHeader {
            event_type: EVENT_FILE_OBFUSCATED,
            pid: offense_pid,
            timestamp_ns: 300,
            context: 12345,
        },
        EventHeader {
            event_type: EVENT_ANTI_DETACH,
            pid: offense_pid,
            timestamp_ns: 400,
            context: 2,
        },
        EventHeader {
            event_type: EVENT_TIMESTOMPED,
            pid: offense_pid,
            timestamp_ns: 500,
            context: 67890,
        },
        EventHeader {
            event_type: EVENT_DNS_EXFIL,
            pid: offense_pid,
            timestamp_ns: 600,
            context: 1,
        },
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

// ─── Scenario: Defense sensitivity vs offense stealth ─────────────

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

// ─── Scenario: Offense config influences detection surface ────────

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

// ─── Scenario: Rapid fire evasion attempt ─────────────────────────

#[test]
fn test_rapid_fire_alerts_all_processed() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    for i in 0..100 {
        let alert = make_defense_alert(ALERT_GHOST_MAP, 2, 1337, i as u64, i as u64);
        engine.process_alert(&alert);
    }

    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 100);
}

// ─── Scenario: Multiple attackers detected simultaneously ─────────

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
