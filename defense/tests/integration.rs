use common::{
    DefenseAlert, ALERT_AUTO_DETACH, ALERT_BYTECODE_TAMPER, ALERT_CONTAINMENT,
    ALERT_CROSS_REFERENCE, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS, ALERT_HONEYPOT_READ,
    ALERT_HW_PERF_COUNTER, ALERT_MAP_AUDIT, ALERT_MEMFD_EXEC, ALERT_MEMORY_FORENSICS,
    ALERT_NET_BASELINE, ALERT_PROG_INVENTORY, ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_ANOMALY,
    ALERT_SYSCALL_LATENCY, ALERT_TRACEPOINT_GAP, ALERT_VERIFIER_ANALYSIS,
};
use defense::{
    classify_alert_type, classify_severity, format_alert_details, make_defense_alert,
    make_latency_alert, AlertRecord, DefenseEngine,
};
use std::io::Read;
use tempfile::NamedTempFile;

// ─── Alert Type Classification ────────────────────────────────────

#[test]
fn test_classify_all_alert_types() {
    assert_eq!(classify_alert_type(ALERT_GHOST_MAP), "Ghost Map Detected");
    assert_eq!(
        classify_alert_type(ALERT_SYSCALL_LATENCY),
        "Syscall Latency Anomaly"
    );
    assert_eq!(
        classify_alert_type(ALERT_BYTECODE_TAMPER),
        "Bytecode Tampering"
    );
    assert_eq!(
        classify_alert_type(ALERT_HIDDEN_PROCESS),
        "Hidden Process Detected"
    );
    assert_eq!(
        classify_alert_type(ALERT_SUSPICIOUS_HOOK),
        "Suspicious Hook Detected"
    );
    assert_eq!(
        classify_alert_type(ALERT_PROG_INVENTORY),
        "Program Inventory Gap"
    );
    assert_eq!(
        classify_alert_type(ALERT_SYSCALL_ANOMALY),
        "Syscall Argument Anomaly"
    );
    assert_eq!(
        classify_alert_type(ALERT_NET_BASELINE),
        "Network Behavior Anomaly"
    );
    assert_eq!(
        classify_alert_type(ALERT_MEMFD_EXEC),
        "Memory-Backed Execution"
    );
    assert_eq!(classify_alert_type(ALERT_MAP_AUDIT), "BPF Map C2 Signature");
    assert_eq!(
        classify_alert_type(ALERT_TRACEPOINT_GAP),
        "Rapid BPF Detach"
    );
    assert_eq!(
        classify_alert_type(ALERT_AUTO_DETACH),
        "Auto-Detach Triggered"
    );
    assert_eq!(classify_alert_type(ALERT_CONTAINMENT), "Process Contained");
    assert_eq!(
        classify_alert_type(ALERT_HONEYPOT_READ),
        "Honeypot Map Accessed"
    );
    assert_eq!(
        classify_alert_type(ALERT_CROSS_REFERENCE),
        "Cross-Reference Anomaly"
    );
    assert_eq!(
        classify_alert_type(ALERT_HW_PERF_COUNTER),
        "HW Perf Counter Deviation"
    );
    assert_eq!(
        classify_alert_type(ALERT_VERIFIER_ANALYSIS),
        "Suspicious BPF Program"
    );
    assert_eq!(
        classify_alert_type(ALERT_MEMORY_FORENSICS),
        "Kernel Data Tampering"
    );
    assert_eq!(classify_alert_type(999), "Unknown Alert");
}

// ─── Severity Classification ──────────────────────────────────────

#[test]
fn test_classify_severity_levels() {
    assert_eq!(classify_severity(1), "LOW");
    assert_eq!(classify_severity(2), "MEDIUM");
    assert_eq!(classify_severity(3), "HIGH");
    assert_eq!(classify_severity(4), "CRITICAL");
    assert_eq!(classify_severity(0), "UNKNOWN");
    assert_eq!(classify_severity(5), "UNKNOWN");
}

// ─── Format Alert Details (All Types) ────────────────────────────

#[test]
fn test_format_ghost_map_details() {
    let mut alert = make_defense_alert(ALERT_GHOST_MAP, 3, 100, 1000, 77);
    alert.details[..8].copy_from_slice(&5u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "map_id=77, suspicious_ops=5");
}

#[test]
fn test_format_latency_alert_details() {
    let alert = make_latency_alert(500, 10000, 217, 5_000_000);
    let details = format_alert_details(&alert);
    assert_eq!(details, "syscall=217, latency=5000000ns");
}

#[test]
fn test_format_bytecode_tamper_details() {
    let mut alert = make_defense_alert(ALERT_BYTECODE_TAMPER, 4, 100, 42, 0);
    alert.details[..8].copy_from_slice(&0xDEADu64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "prog_id=42, checksum_delta=57005");
}

#[test]
fn test_format_hidden_process_details() {
    let mut alert = make_defense_alert(ALERT_HIDDEN_PROCESS, 4, 100, 1337, 0);
    alert.details[..8].copy_from_slice(&1u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "hidden_pid=1337, parent=1");
}

#[test]
fn test_format_suspicious_hook_details() {
    let mut alert = make_defense_alert(ALERT_SUSPICIOUS_HOOK, 3, 100, 0xFFFF0000, 0);
    alert.details[..8].copy_from_slice(&99u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "hook_addr=0xffff0000, target=99");
}

#[test]
fn test_format_prog_inventory_details() {
    let mut alert = make_defense_alert(ALERT_PROG_INVENTORY, 2, 100, 15, 0);
    alert.details[..8].copy_from_slice(&10u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "prog_count=15, expected=10");
}

#[test]
fn test_format_syscall_anomaly_details() {
    let mut alert = make_defense_alert(ALERT_SYSCALL_ANOMALY, 3, 100, 59, 0);
    alert.details[..8].copy_from_slice(&300u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "syscall=59, deviation=300");
}

#[test]
fn test_format_net_baseline_details() {
    let mut alert = make_defense_alert(ALERT_NET_BASELINE, 2, 100, 1048576, 0);
    alert.details[..8].copy_from_slice(&524288u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "bytes=1048576, threshold=524288");
}

#[test]
fn test_format_memfd_exec_details() {
    let mut alert = make_defense_alert(ALERT_MEMFD_EXEC, 4, 100, 7, 0);
    alert.details[..8].copy_from_slice(&500u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "fd=7, pid=500");
}

#[test]
fn test_format_map_audit_details() {
    let mut alert = make_defense_alert(ALERT_MAP_AUDIT, 3, 100, 3, 0);
    alert.details[..8].copy_from_slice(&2u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "map_id=3, violations=2");
}

#[test]
fn test_format_tracepoint_gap_details() {
    let mut alert = make_defense_alert(ALERT_TRACEPOINT_GAP, 3, 100, 500, 0);
    alert.details[..8].copy_from_slice(&100u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "gap_ms=500, expected_interval=100");
}

#[test]
fn test_format_auto_detach_details() {
    let mut alert = make_defense_alert(ALERT_AUTO_DETACH, 4, 100, 42, 0);
    alert.details[..8].copy_from_slice(&1u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "prog_id=42, attach_type=1");
}

#[test]
fn test_format_containment_details() {
    let mut alert = make_defense_alert(ALERT_CONTAINMENT, 4, 100, 1337, 0);
    alert.details[..8].copy_from_slice(&2u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "target_pid=1337, action=2");
}

#[test]
fn test_format_honeypot_read_details() {
    let mut alert = make_defense_alert(ALERT_HONEYPOT_READ, 3, 100, 5, 0);
    alert.details[..8].copy_from_slice(&999u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "map_id=5, accessor_pid=999");
}

#[test]
fn test_format_cross_reference_details() {
    let mut alert = make_defense_alert(ALERT_CROSS_REFERENCE, 3, 100, 7, 0);
    alert.details[..8].copy_from_slice(&3u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "discrepancy=7, source_a=3");
}

#[test]
fn test_format_hw_perf_counter_details() {
    let mut alert = make_defense_alert(ALERT_HW_PERF_COUNTER, 2, 100, 4, 0);
    alert.details[..8].copy_from_slice(&150u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "counter=4, deviation=150");
}

#[test]
fn test_format_verifier_analysis_details() {
    let mut alert = make_defense_alert(ALERT_VERIFIER_ANALYSIS, 3, 100, 88, 0);
    alert.details[..8].copy_from_slice(&1024u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "prog_id=88, complexity=1024");
}

#[test]
fn test_format_memory_forensics_details() {
    let mut alert = make_defense_alert(ALERT_MEMORY_FORENSICS, 4, 100, 0xFFFF8000, 0);
    alert.details[..8].copy_from_slice(&42u64.to_le_bytes());
    let details = format_alert_details(&alert);
    assert_eq!(details, "region=0xffff8000, checksum_delta=42");
}

#[test]
fn test_format_unknown_alert_fallback() {
    let alert = make_defense_alert(999, 2, 100, 12345, 0);
    let details = format_alert_details(&alert);
    assert_eq!(details, "context=12345");
}

// ─── Threshold Filtering ──────────────────────────────────────────

#[test]
fn test_threshold_filters_low_severity() {
    let mut engine = DefenseEngine::new(None, 3).unwrap();

    let low_alert = make_defense_alert(ALERT_GHOST_MAP, 1, 100, 1000, 0);
    let medium_alert = make_defense_alert(ALERT_GHOST_MAP, 2, 101, 2000, 0);
    let high_alert = make_defense_alert(ALERT_GHOST_MAP, 3, 102, 3000, 0);
    let critical_alert = make_defense_alert(ALERT_GHOST_MAP, 4, 103, 4000, 0);

    assert!(engine.process_alert(&low_alert).is_none());
    assert!(engine.process_alert(&medium_alert).is_none());
    assert!(engine.process_alert(&high_alert).is_some());
    assert!(engine.process_alert(&critical_alert).is_some());
}

#[test]
fn test_threshold_1_allows_all() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    for severity in 1..=4 {
        let alert = make_defense_alert(ALERT_GHOST_MAP, severity, 100, 1000, 0);
        assert!(engine.process_alert(&alert).is_some());
    }
}

#[test]
fn test_threshold_4_only_critical() {
    let mut engine = DefenseEngine::new(None, 4).unwrap();

    for severity in 1..=3 {
        let alert = make_defense_alert(ALERT_GHOST_MAP, severity, 100, 1000, 0);
        assert!(engine.process_alert(&alert).is_none());
    }

    let critical = make_defense_alert(ALERT_GHOST_MAP, 4, 100, 1000, 0);
    assert!(engine.process_alert(&critical).is_some());
}

// ─── Alert Counting ───────────────────────────────────────────────

#[test]
fn test_alert_counting_by_type() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 2, 100, 1000, 0));
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, 101, 2000, 0));
    engine.process_alert(&make_defense_alert(ALERT_HIDDEN_PROCESS, 4, 102, 3000, 0));

    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 2);
    assert_eq!(engine.alerts_by_type(ALERT_HIDDEN_PROCESS), 1);
    assert_eq!(engine.alerts_by_type(ALERT_BYTECODE_TAMPER), 0);
    assert_eq!(engine.total_alerts(), 3);
}

#[test]
fn test_alert_counting_respects_threshold() {
    let mut engine = DefenseEngine::new(None, 3).unwrap();

    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 1, 100, 1000, 0));
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 2, 101, 2000, 0));
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, 102, 3000, 0));

    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 1);
    assert_eq!(engine.total_alerts(), 1);
}

#[test]
fn test_alert_counting_all_types() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let base_ts = 1_000_000_000u64;

    for alert_type in 1..=18u32 {
        let alert = make_defense_alert(
            alert_type,
            2,
            100 + alert_type,
            base_ts + alert_type as u64 * 1000,
            0,
        );
        engine.process_alert(&alert);
    }

    assert_eq!(engine.total_alerts(), 18);
    for alert_type in 1..=18u32 {
        assert_eq!(engine.alerts_by_type(alert_type), 1);
    }
}

// ─── Alert Record Construction ────────────────────────────────────

#[test]
fn test_alert_record_fields() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let alert = make_defense_alert(ALERT_HIDDEN_PROCESS, 4, 1337, 9999, 42);

    let record = engine.process_alert(&alert).unwrap();
    assert_eq!(record.timestamp, 9999);
    assert_eq!(record.alert_type, "Hidden Process Detected");
    assert_eq!(record.severity, "CRITICAL");
    assert_eq!(record.pid, 1337);
    assert_eq!(record.context, 42);
}

#[test]
fn test_alert_record_for_advanced_types() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let alert = make_defense_alert(ALERT_MEMORY_FORENSICS, 4, 500, 12345, 0xDEAD);
    let record = engine.process_alert(&alert).unwrap();
    assert_eq!(record.alert_type, "Kernel Data Tampering");
    assert_eq!(record.severity, "CRITICAL");
    assert_eq!(record.pid, 500);
    assert_eq!(record.context, 0xDEAD);

    let alert = make_defense_alert(ALERT_VERIFIER_ANALYSIS, 3, 600, 67890, 88);
    let record = engine.process_alert(&alert).unwrap();
    assert_eq!(record.alert_type, "Suspicious BPF Program");
    assert_eq!(record.severity, "HIGH");
}

// ─── Latency Alert Details ────────────────────────────────────────

#[test]
fn test_latency_alert_details_parsing() {
    let alert = make_latency_alert(500, 10000, 217, 5_000_000);
    let details = format_alert_details(&alert);
    assert_eq!(details, "syscall=217, latency=5000000ns");
}

#[test]
fn test_latency_alert_large_values() {
    let alert = make_latency_alert(1, 0, 0, u64::MAX);
    let details = format_alert_details(&alert);
    assert!(details.contains(&u64::MAX.to_string()));
}

// ─── Calibration State ────────────────────────────────────────────

#[test]
fn test_engine_starts_calibrating() {
    let engine = DefenseEngine::new(None, 2).unwrap();
    assert!(engine.calibrating);
}

#[test]
fn test_finish_calibration() {
    let mut engine = DefenseEngine::new(None, 2).unwrap();
    assert!(engine.calibrating);
    engine.finish_calibration();
    assert!(!engine.calibrating);
}

// ─── JSON Output ──────────────────────────────────────────────────

#[test]
fn test_json_output_to_file() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let mut engine = DefenseEngine::new(Some(path.clone()), 1).unwrap();

    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, 100, 5000, 42));
    engine.process_alert(&make_defense_alert(ALERT_HIDDEN_PROCESS, 4, 200, 6000, 99));

    drop(engine);

    let mut contents = String::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();

    let lines: Vec<&str> = contents.trim().lines().collect();
    assert_eq!(lines.len(), 2);

    let record1: AlertRecord = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(record1.alert_type, "Ghost Map Detected");
    assert_eq!(record1.severity, "HIGH");
    assert_eq!(record1.pid, 100);

    let record2: AlertRecord = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(record2.alert_type, "Hidden Process Detected");
    assert_eq!(record2.severity, "CRITICAL");
    assert_eq!(record2.pid, 200);
}

#[test]
fn test_json_output_latency_details() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let mut engine = DefenseEngine::new(Some(path.clone()), 1).unwrap();
    engine.process_alert(&make_latency_alert(300, 7000, 1, 12345));

    drop(engine);

    let contents = std::fs::read_to_string(&path).unwrap();
    let record: AlertRecord = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(record.details, "syscall=1, latency=12345ns");
}

#[test]
fn test_no_output_without_file() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let record = engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, 100, 5000, 0));
    assert!(record.is_some());
}

// ─── Struct Layout ────────────────────────────────────────────────

#[test]
fn test_defense_alert_size() {
    assert_eq!(std::mem::size_of::<DefenseAlert>(), 48);
}

// ─── Burst Alert Processing ──────────────────────────────────────

#[test]
fn test_process_many_alerts() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    for i in 0..1000 {
        let alert_type = match i % 5 {
            0 => ALERT_GHOST_MAP,
            1 => ALERT_SYSCALL_LATENCY,
            2 => ALERT_BYTECODE_TAMPER,
            3 => ALERT_HIDDEN_PROCESS,
            _ => ALERT_SUSPICIOUS_HOOK,
        };
        let alert = make_defense_alert(alert_type, 2, i as u32, i as u64 * 100, 0);
        engine.process_alert(&alert);
    }

    assert_eq!(engine.total_alerts(), 1000);
    assert_eq!(engine.alerts_by_type(ALERT_GHOST_MAP), 200);
    assert_eq!(engine.alerts_by_type(ALERT_SYSCALL_LATENCY), 200);
    assert_eq!(engine.alerts_by_type(ALERT_BYTECODE_TAMPER), 200);
    assert_eq!(engine.alerts_by_type(ALERT_HIDDEN_PROCESS), 200);
    assert_eq!(engine.alerts_by_type(ALERT_SUSPICIOUS_HOOK), 200);
}

#[test]
fn test_process_all_alert_types_burst() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    for round in 0..50u64 {
        for alert_type in 1..=18u32 {
            let alert = make_defense_alert(
                alert_type,
                2,
                alert_type * 100,
                round * 18 + alert_type as u64,
                0,
            );
            engine.process_alert(&alert);
        }
    }

    assert_eq!(engine.total_alerts(), 900);
    for alert_type in 1..=18u32 {
        assert_eq!(engine.alerts_by_type(alert_type), 50);
    }
}

// ─── Sliding Window Eviction ─────────────────────────────────────

#[test]
fn test_sliding_window_eviction() {
    let window_ns = 10_000_000_000; // 10 seconds
    let mut engine = DefenseEngine::new(None, 1).unwrap().with_window(window_ns);

    let pid = 42u32;

    // Insert alerts at t=1s, t=2s, t=3s
    for i in 1..=3 {
        let alert = make_defense_alert(ALERT_GHOST_MAP, 2, pid, i * 1_000_000_000, 0);
        engine.process_alert(&alert);
    }
    assert!(engine.pid_rate(pid) > 0.0);

    // Insert alert at t=20s — should evict all previous (beyond 10s window)
    let alert = make_defense_alert(ALERT_GHOST_MAP, 2, pid, 20_000_000_000, 0);
    engine.process_alert(&alert);

    // Only 1 alert should remain in the window (t=20s, window covers 10s-20s)
    let rate = engine.pid_rate(pid);
    let expected = 1.0 / (window_ns as f64 / 1_000_000_000.0);
    assert!((rate - expected).abs() < 0.001);
}

// ─── Anomaly Scoring ─────────────────────────────────────────────

#[test]
fn test_anomaly_score_during_calibration() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let alert = make_defense_alert(ALERT_GHOST_MAP, 3, 100, 1_000_000_000, 0);
    let record = engine.process_alert(&alert).unwrap();

    // During calibration, anomaly score should be 0
    assert_eq!(record.anomaly_score, 0.0);
}

#[test]
fn test_anomaly_score_after_calibration() {
    let window_ns = 10_000_000_000; // 10 seconds
    let mut engine = DefenseEngine::new(None, 1).unwrap().with_window(window_ns);

    // Calibration: 2 alerts over 10 seconds = 0.2 alerts/sec baseline
    engine.process_alert(&make_defense_alert(
        ALERT_GHOST_MAP,
        2,
        200,
        1_000_000_000,
        0,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_GHOST_MAP,
        2,
        200,
        5_000_000_000,
        0,
    ));
    engine.finish_calibration_at(10_000_000_000);

    // Post-calibration: burst of 10 alerts in 1 second from same type
    // Use a different PID to get a clean window
    let mut last_record = None;
    for i in 0..10 {
        let alert =
            make_defense_alert(ALERT_GHOST_MAP, 2, 300, 11_000_000_000 + i * 100_000_000, 0);
        last_record = engine.process_alert(&alert);
    }

    let record = last_record.unwrap();
    // Rate is ~10 alerts in 10s window = 1.0/sec, baseline is 0.2/sec → score ~5.0
    assert!(record.anomaly_score > 1.0);
}

// ─── Attack Chain Detection ──────────────────────────────────────

#[test]
fn test_attack_chain_detection() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let pid = 666u32;
    let base_ts = 1_000_000_000u64;

    // 3 distinct alert types from same PID → attack chain
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, pid, base_ts, 0));
    engine.process_alert(&make_defense_alert(
        ALERT_BYTECODE_TAMPER,
        3,
        pid,
        base_ts + 1000,
        0,
    ));
    let record = engine.process_alert(&make_defense_alert(
        ALERT_SUSPICIOUS_HOOK,
        3,
        pid,
        base_ts + 2000,
        0,
    ));

    let record = record.unwrap();
    assert!(record.is_attack_chain);
    assert_eq!(record.correlated_types.len(), 3);
    assert!(record
        .correlated_types
        .contains(&"Ghost Map Detected".to_string()));
    assert!(record
        .correlated_types
        .contains(&"Bytecode Tampering".to_string()));
    assert!(record
        .correlated_types
        .contains(&"Suspicious Hook Detected".to_string()));
}

#[test]
fn test_attack_chain_with_advanced_alerts() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let pid = 888u32;
    let base_ts = 1_000_000_000u64;

    engine.process_alert(&make_defense_alert(
        ALERT_MEMORY_FORENSICS,
        4,
        pid,
        base_ts,
        0,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_VERIFIER_ANALYSIS,
        3,
        pid,
        base_ts + 1000,
        0,
    ));
    let record = engine.process_alert(&make_defense_alert(
        ALERT_HW_PERF_COUNTER,
        3,
        pid,
        base_ts + 2000,
        0,
    ));

    let record = record.unwrap();
    assert!(record.is_attack_chain);
    assert_eq!(record.correlated_types.len(), 3);
    assert!(record
        .correlated_types
        .contains(&"Kernel Data Tampering".to_string()));
    assert!(record
        .correlated_types
        .contains(&"Suspicious BPF Program".to_string()));
    assert!(record
        .correlated_types
        .contains(&"HW Perf Counter Deviation".to_string()));
}

#[test]
fn test_attack_chain_below_threshold() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let pid = 777u32;
    let base_ts = 1_000_000_000u64;

    // Only 2 distinct types — not an attack chain
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, pid, base_ts, 0));
    let record = engine.process_alert(&make_defense_alert(
        ALERT_BYTECODE_TAMPER,
        3,
        pid,
        base_ts + 1000,
        0,
    ));

    let record = record.unwrap();
    assert!(!record.is_attack_chain);
    assert_eq!(engine.pid_distinct_types(pid), 2);
}

// ─── Per-PID Rate Tracking ───────────────────────────────────────

#[test]
fn test_per_pid_rate_tracking() {
    let window_ns = 10_000_000_000; // 10 seconds
    let mut engine = DefenseEngine::new(None, 1).unwrap().with_window(window_ns);

    let pid = 100u32;
    let base_ts = 5_000_000_000u64;

    // 5 alerts within the window
    for i in 0..5 {
        let alert = make_defense_alert(ALERT_GHOST_MAP, 2, pid, base_ts + i * 1_000_000_000, 0);
        engine.process_alert(&alert);
    }

    // Rate should be 5 alerts / 10 seconds = 0.5 alerts/sec
    let rate = engine.pid_rate(pid);
    assert!((rate - 0.5).abs() < 0.01);
}

#[test]
fn test_mixed_pids_independent() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();

    let base_ts = 1_000_000_000u64;

    // PID 100: ghost_map + bytecode_tamper (2 types)
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, 100, base_ts, 0));
    engine.process_alert(&make_defense_alert(
        ALERT_BYTECODE_TAMPER,
        3,
        100,
        base_ts + 1000,
        0,
    ));

    // PID 200: only ghost_map (1 type)
    engine.process_alert(&make_defense_alert(
        ALERT_GHOST_MAP,
        3,
        200,
        base_ts + 2000,
        0,
    ));

    assert_eq!(engine.pid_distinct_types(100), 2);
    assert_eq!(engine.pid_distinct_types(200), 1);
    assert!(
        !engine
            .process_alert(&make_defense_alert(
                ALERT_GHOST_MAP,
                3,
                200,
                base_ts + 3000,
                0
            ))
            .unwrap()
            .is_attack_chain
    );
}

// ─── Metrics ─────────────────────────────────────────────────────

#[test]
fn test_metrics_counting() {
    let mut engine = DefenseEngine::new(None, 3).unwrap();

    // 2 below threshold (suppressed) + 1 above
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 1, 100, 1000, 0));
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 2, 101, 2000, 0));
    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, 102, 3000, 0));

    let metrics = engine.metrics();
    assert_eq!(metrics.alerts_processed, 3);
    assert_eq!(metrics.alerts_suppressed, 2);
}

#[test]
fn test_metrics_attack_chain_count() {
    let mut engine = DefenseEngine::new(None, 1).unwrap();
    let pid = 500u32;
    let base_ts = 1_000_000_000u64;

    engine.process_alert(&make_defense_alert(ALERT_GHOST_MAP, 3, pid, base_ts, 0));
    engine.process_alert(&make_defense_alert(
        ALERT_BYTECODE_TAMPER,
        3,
        pid,
        base_ts + 1000,
        0,
    ));
    engine.process_alert(&make_defense_alert(
        ALERT_SUSPICIOUS_HOOK,
        3,
        pid,
        base_ts + 2000,
        0,
    ));

    assert!(engine.metrics().attack_chains_detected > 0);
}
