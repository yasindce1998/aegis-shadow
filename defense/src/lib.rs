use common::{
    DefenseAlert, ALERT_BYTECODE_TAMPER, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS,
    ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_LATENCY,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap as StdHashMap;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AlertRecord {
    pub timestamp: u64,
    pub alert_type: String,
    pub severity: String,
    pub pid: u32,
    pub context: u64,
    pub details: String,
}

pub struct DefenseEngine {
    pub alert_count: StdHashMap<u32, u64>,
    output_file: Option<File>,
    pub threshold: u8,
    pub calibrating: bool,
}

impl DefenseEngine {
    pub fn new(output_path: Option<String>, threshold: u8) -> anyhow::Result<Self> {
        let output_file = if let Some(path) = output_path {
            Some(File::create(path)?)
        } else {
            None
        };

        Ok(Self {
            alert_count: StdHashMap::new(),
            output_file,
            threshold,
            calibrating: true,
        })
    }

    pub fn process_alert(&mut self, alert: &DefenseAlert) -> Option<AlertRecord> {
        if alert.severity < self.threshold as u32 {
            return None;
        }

        *self.alert_count.entry(alert.alert_type).or_insert(0) += 1;

        let alert_type_str = classify_alert_type(alert.alert_type);
        let severity_str = classify_severity(alert.severity);
        let details = format_alert_details(alert);

        let record = AlertRecord {
            timestamp: alert.timestamp_ns,
            alert_type: alert_type_str.to_string(),
            severity: severity_str.to_string(),
            pid: alert.pid,
            context: alert.context,
            details,
        };

        if let Some(ref mut file) = self.output_file {
            if let Ok(json) = serde_json::to_string(&record) {
                let _ = writeln!(file, "{}", json);
            }
        }

        Some(record)
    }

    pub fn finish_calibration(&mut self) {
        self.calibrating = false;
    }

    pub fn total_alerts(&self) -> u64 {
        self.alert_count.values().sum()
    }

    pub fn alerts_by_type(&self, alert_type: u32) -> u64 {
        self.alert_count.get(&alert_type).copied().unwrap_or(0)
    }
}

pub fn classify_alert_type(alert_type: u32) -> &'static str {
    match alert_type {
        ALERT_GHOST_MAP => "Ghost Map Detected",
        ALERT_SYSCALL_LATENCY => "Syscall Latency Anomaly",
        ALERT_BYTECODE_TAMPER => "Bytecode Tampering",
        ALERT_HIDDEN_PROCESS => "Hidden Process Detected",
        ALERT_SUSPICIOUS_HOOK => "Suspicious Hook Detected",
        _ => "Unknown Alert",
    }
}

pub fn classify_severity(severity: u32) -> &'static str {
    match severity {
        1 => "LOW",
        2 => "MEDIUM",
        3 => "HIGH",
        4 => "CRITICAL",
        _ => "UNKNOWN",
    }
}

pub fn format_alert_details(alert: &DefenseAlert) -> String {
    if alert.alert_type == ALERT_SYSCALL_LATENCY {
        let latency_ns = u64::from_le_bytes([
            alert.details[0],
            alert.details[1],
            alert.details[2],
            alert.details[3],
            alert.details[4],
            alert.details[5],
            alert.details[6],
            alert.details[7],
        ]);
        format!("syscall={}, latency={}ns", alert.context, latency_ns)
    } else {
        format!("context={}", alert.context)
    }
}

pub fn make_defense_alert(
    alert_type: u32,
    severity: u32,
    pid: u32,
    timestamp_ns: u64,
    context: u64,
) -> DefenseAlert {
    DefenseAlert {
        alert_type,
        severity,
        pid,
        _pad: 0,
        timestamp_ns,
        context,
        details: [0u8; 16],
    }
}

pub fn make_latency_alert(
    pid: u32,
    timestamp_ns: u64,
    syscall_nr: u64,
    latency_ns: u64,
) -> DefenseAlert {
    let mut details = [0u8; 16];
    details[..8].copy_from_slice(&latency_ns.to_le_bytes());
    DefenseAlert {
        alert_type: ALERT_SYSCALL_LATENCY,
        severity: 3,
        pid,
        _pad: 0,
        timestamp_ns,
        context: syscall_nr,
        details,
    }
}
