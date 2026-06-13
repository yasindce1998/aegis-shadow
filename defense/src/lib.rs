use common::{
    DefenseAlert, ALERT_BYTECODE_TAMPER, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS,
    ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_LATENCY,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap as StdHashMap, VecDeque};
use std::fs::File;
use std::io::Write;

const DEFAULT_WINDOW_NS: u64 = 30_000_000_000; // 30 seconds
const ANOMALY_CRITICAL: f64 = 10.0;
const ATTACK_CHAIN_THRESHOLD: u32 = 3;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AlertRecord {
    pub timestamp: u64,
    pub alert_type: String,
    pub severity: String,
    pub pid: u32,
    pub context: u64,
    pub details: String,
    #[serde(default)]
    pub anomaly_score: f64,
    #[serde(default)]
    pub correlated_types: Vec<String>,
    #[serde(default)]
    pub is_attack_chain: bool,
}

#[derive(Debug, Clone)]
struct PidHistory {
    timestamps: VecDeque<u64>,
    alert_types_seen: u32,
    total_count: u64,
}

impl PidHistory {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
            alert_types_seen: 0,
            total_count: 0,
        }
    }

    fn push(&mut self, timestamp_ns: u64, alert_type: u32, window_ns: u64) {
        self.timestamps.push_back(timestamp_ns);
        self.alert_types_seen |= 1 << alert_type;
        self.total_count += 1;
        self.evict(timestamp_ns, window_ns);
    }

    fn evict(&mut self, now_ns: u64, window_ns: u64) {
        let cutoff = now_ns.saturating_sub(window_ns);
        while let Some(&front) = self.timestamps.front() {
            if front < cutoff {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    fn rate(&self, window_ns: u64) -> f64 {
        let window_sec = window_ns as f64 / 1_000_000_000.0;
        self.timestamps.len() as f64 / window_sec
    }

    fn distinct_alert_types(&self) -> u32 {
        self.alert_types_seen.count_ones()
    }

    fn correlated_type_list(&self) -> Vec<u32> {
        (0..32)
            .filter(|&bit| self.alert_types_seen & (1 << bit) != 0)
            .collect()
    }
}

#[derive(Debug, Clone)]
struct CalibrationData {
    counts_per_type: StdHashMap<u32, u64>,
    sample_start_ns: u64,
    total_samples: u64,
}

impl CalibrationData {
    fn new(start_ns: u64) -> Self {
        Self {
            counts_per_type: StdHashMap::new(),
            sample_start_ns: start_ns,
            total_samples: 0,
        }
    }

    fn record(&mut self, alert_type: u32) {
        *self.counts_per_type.entry(alert_type).or_insert(0) += 1;
        self.total_samples += 1;
    }

    fn baseline_rate(&self, alert_type: u32, end_ns: u64) -> f64 {
        let duration_sec = (end_ns.saturating_sub(self.sample_start_ns)) as f64 / 1_000_000_000.0;
        if duration_sec <= 0.0 {
            return 0.0;
        }
        let count = self.counts_per_type.get(&alert_type).copied().unwrap_or(0);
        count as f64 / duration_sec
    }
}

#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub alerts_processed: u64,
    pub alerts_suppressed: u64,
    pub attack_chains_detected: u64,
    pub anomaly_escalations: u64,
}

pub struct DefenseEngine {
    pub alert_count: StdHashMap<u32, u64>,
    pid_history: StdHashMap<u32, PidHistory>,
    calibration_data: Option<CalibrationData>,
    baseline_rates: StdHashMap<u32, f64>,
    output_file: Option<File>,
    pub threshold: u8,
    pub calibrating: bool,
    window_duration_ns: u64,
    metrics: Metrics,
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
            pid_history: StdHashMap::new(),
            calibration_data: Some(CalibrationData::new(0)),
            baseline_rates: StdHashMap::new(),
            output_file,
            threshold,
            calibrating: true,
            window_duration_ns: DEFAULT_WINDOW_NS,
            metrics: Metrics::default(),
        })
    }

    pub fn with_window(mut self, window_ns: u64) -> Self {
        self.window_duration_ns = window_ns;
        self
    }

    pub fn process_alert(&mut self, alert: &DefenseAlert) -> Option<AlertRecord> {
        self.metrics.alerts_processed += 1;

        if alert.severity < self.threshold as u32 {
            self.metrics.alerts_suppressed += 1;
            return None;
        }

        *self.alert_count.entry(alert.alert_type).or_insert(0) += 1;

        if self.calibrating {
            if let Some(ref mut cal) = self.calibration_data {
                if cal.sample_start_ns == 0 {
                    cal.sample_start_ns = alert.timestamp_ns;
                }
                cal.record(alert.alert_type);
            }
        }

        let history = self
            .pid_history
            .entry(alert.pid)
            .or_insert_with(PidHistory::new);
        history.push(
            alert.timestamp_ns,
            alert.alert_type,
            self.window_duration_ns,
        );

        let current_rate = history.rate(self.window_duration_ns);
        let anomaly_score = if !self.calibrating {
            let baseline = self
                .baseline_rates
                .get(&alert.alert_type)
                .copied()
                .unwrap_or(0.0);
            if baseline > 0.0 {
                current_rate / baseline
            } else {
                current_rate
            }
        } else {
            0.0
        };

        if anomaly_score >= ANOMALY_CRITICAL {
            self.metrics.anomaly_escalations += 1;
        }

        let is_attack_chain = history.distinct_alert_types() >= ATTACK_CHAIN_THRESHOLD;
        if is_attack_chain {
            self.metrics.attack_chains_detected += 1;
        }

        let correlated_types: Vec<String> = history
            .correlated_type_list()
            .iter()
            .map(|&t| classify_alert_type(t).to_string())
            .collect();

        let alert_type_str = classify_alert_type(alert.alert_type);
        let severity_str = if anomaly_score >= ANOMALY_CRITICAL {
            "CRITICAL"
        } else {
            classify_severity(alert.severity)
        };
        let details = format_alert_details(alert);

        let record = AlertRecord {
            timestamp: alert.timestamp_ns,
            alert_type: alert_type_str.to_string(),
            severity: severity_str.to_string(),
            pid: alert.pid,
            context: alert.context,
            details,
            anomaly_score,
            correlated_types,
            is_attack_chain,
        };

        if let Some(ref mut file) = self.output_file {
            if let Ok(json) = serde_json::to_string(&record) {
                let _ = writeln!(file, "{}", json);
            }
        }

        Some(record)
    }

    pub fn finish_calibration(&mut self) {
        if let Some(ref cal) = self.calibration_data {
            let now_ns = cal.sample_start_ns + cal.total_samples.saturating_mul(1_000_000);
            for (&alert_type, _) in &cal.counts_per_type {
                self.baseline_rates
                    .insert(alert_type, cal.baseline_rate(alert_type, now_ns));
            }
        }
        self.calibrating = false;
    }

    pub fn finish_calibration_at(&mut self, end_ns: u64) {
        if let Some(ref cal) = self.calibration_data {
            for (&alert_type, _) in &cal.counts_per_type {
                self.baseline_rates
                    .insert(alert_type, cal.baseline_rate(alert_type, end_ns));
            }
        }
        self.calibrating = false;
    }

    pub fn total_alerts(&self) -> u64 {
        self.alert_count.values().sum()
    }

    pub fn alerts_by_type(&self, alert_type: u32) -> u64 {
        self.alert_count.get(&alert_type).copied().unwrap_or(0)
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn pid_rate(&self, pid: u32) -> f64 {
        self.pid_history
            .get(&pid)
            .map(|h| h.rate(self.window_duration_ns))
            .unwrap_or(0.0)
    }

    pub fn pid_distinct_types(&self, pid: u32) -> u32 {
        self.pid_history
            .get(&pid)
            .map(|h| h.distinct_alert_types())
            .unwrap_or(0)
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
