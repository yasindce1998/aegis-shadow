use common::{
    DefenseAlert, ALERT_BYTECODE_TAMPER, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS,
    ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_LATENCY,
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
    assert_eq!(record.details, "context=42");
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

#[test]
fn test_non_latency_alert_details() {
    let alert = make_defense_alert(ALERT_GHOST_MAP, 3, 100, 1000, 77);
    let details = format_alert_details(&alert);
    assert_eq!(details, "context=77");
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
