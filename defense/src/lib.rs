pub mod error;
pub mod ml;
pub use error::DefenseError;

use common::{
    DefenseAlert, ALERT_AUTO_DETACH, ALERT_BYTECODE_TAMPER, ALERT_CONTAINMENT,
    ALERT_CROSS_REFERENCE, ALERT_GHOST_MAP, ALERT_HIDDEN_PROCESS, ALERT_HONEYPOT_READ,
    ALERT_HW_PERF_COUNTER, ALERT_MAP_AUDIT, ALERT_MEMFD_EXEC, ALERT_MEMORY_FORENSICS,
    ALERT_NET_BASELINE, ALERT_PROG_INVENTORY, ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_ANOMALY,
    ALERT_SYSCALL_LATENCY, ALERT_TRACEPOINT_GAP, ALERT_VERIFIER_ANALYSIS,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap as StdHashMap, HashSet, VecDeque};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_threshold() -> u8 {
    2
}

fn default_window_secs() -> u64 {
    30
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            threshold: default_threshold(),
            window_secs: default_window_secs(),
        }
    }
}

impl RuntimeConfig {
    pub fn load_from_file(path: &str) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }
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
    pub auto_detach_candidates: StdHashMap<u32, u32>,
    pub contained_pids: HashSet<u32>,
    pub correlation_graph: CorrelationGraph,
    pub auto_detach_enabled: bool,
    pub auto_contain_enabled: bool,
    pub ml_engine: Option<ml::AdversarialMLEngine>,
}

impl DefenseEngine {
    pub fn new(output_path: Option<String>, threshold: u8) -> Result<Self, DefenseError> {
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
            auto_detach_candidates: StdHashMap::new(),
            contained_pids: HashSet::new(),
            correlation_graph: CorrelationGraph::new(),
            auto_detach_enabled: false,
            auto_contain_enabled: false,
            ml_engine: None,
        })
    }

    pub fn with_window(mut self, window_ns: u64) -> Self {
        self.window_duration_ns = window_ns;
        self
    }

    pub fn apply_config(&mut self, config: &RuntimeConfig) {
        self.threshold = config.threshold;
        self.window_duration_ns = config.window_secs * 1_000_000_000;
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
        let mut anomaly_score = if !self.calibrating {
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

        if let Some(ref mut ml) = self.ml_engine {
            if alert.alert_type == ALERT_SYSCALL_ANOMALY {
                ml.record_syscall(alert.pid, alert.context as u32);
            }
            if !self.calibrating {
                let ml_score = ml.score_pid(alert.pid);
                if ml_score > 0.0 {
                    anomaly_score = anomaly_score.max(ml_score);
                }
            }
        }

        if anomaly_score >= ANOMALY_CRITICAL {
            self.metrics.anomaly_escalations += 1;
        }

        self.correlation_graph.add_alert(alert);

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
            for &alert_type in cal.counts_per_type.keys() {
                self.baseline_rates
                    .insert(alert_type, cal.baseline_rate(alert_type, now_ns));
            }
        }
        if let Some(ref mut ml) = self.ml_engine {
            ml.finish_calibration();
        }
        self.calibrating = false;
    }

    pub fn finish_calibration_at(&mut self, end_ns: u64) {
        if let Some(ref cal) = self.calibration_data {
            for &alert_type in cal.counts_per_type.keys() {
                self.baseline_rates
                    .insert(alert_type, cal.baseline_rate(alert_type, end_ns));
            }
        }
        if let Some(ref mut ml) = self.ml_engine {
            ml.finish_calibration();
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

    pub fn should_auto_detach(&self, prog_id: u32) -> bool {
        if !self.auto_detach_enabled {
            return false;
        }
        self.auto_detach_candidates
            .get(&prog_id)
            .copied()
            .unwrap_or(0)
            >= ATTACK_CHAIN_THRESHOLD
    }

    pub fn record_suspicious_prog(&mut self, prog_id: u32) {
        *self.auto_detach_candidates.entry(prog_id).or_insert(0) += 1;
    }

    pub fn should_contain(&self, pid: u32) -> bool {
        if !self.auto_contain_enabled {
            return false;
        }
        if self.contained_pids.contains(&pid) {
            return false;
        }
        self.pid_distinct_types(pid) >= ATTACK_CHAIN_THRESHOLD
    }

    pub fn mark_contained(&mut self, pid: u32) {
        self.contained_pids.insert(pid);
    }

    pub fn correlation_summary(&self) -> String {
        let chains = self.correlation_graph.find_chains();
        if chains.is_empty() {
            return String::from("[]");
        }
        serde_json::to_string(&chains).unwrap_or_else(|_| String::from("[]"))
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Alert Correlation Graph (DAG)
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNode {
    pub id: usize,
    pub alert_type: u32,
    pub pid: u32,
    pub timestamp_ns: u64,
    pub severity: u32,
}

#[derive(Debug, Clone, Default)]
pub struct CorrelationGraph {
    nodes: Vec<AlertNode>,
    edges: Vec<(usize, usize)>,
}

const TEMPORAL_PROXIMITY_NS: u64 = 1_000_000_000; // 1 second

impl CorrelationGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_alert(&mut self, alert: &DefenseAlert) {
        let node_id = self.nodes.len();
        let node = AlertNode {
            id: node_id,
            alert_type: alert.alert_type,
            pid: alert.pid,
            timestamp_ns: alert.timestamp_ns,
            severity: alert.severity,
        };

        // Add edges: same-PID or temporal proximity
        for (i, existing) in self.nodes.iter().enumerate() {
            let same_pid = existing.pid == alert.pid && alert.pid != 0;
            let temporal =
                alert.timestamp_ns.saturating_sub(existing.timestamp_ns) < TEMPORAL_PROXIMITY_NS;

            if same_pid || temporal {
                self.edges.push((i, node_id));
            }
        }

        self.nodes.push(node);

        // Prune old nodes (keep last 256)
        if self.nodes.len() > 256 {
            let remove_count = self.nodes.len() - 256;
            self.nodes.drain(..remove_count);
            // Reindex edges
            self.edges
                .retain(|(a, b)| *a >= remove_count && *b >= remove_count);
            for edge in &mut self.edges {
                edge.0 -= remove_count;
                edge.1 -= remove_count;
            }
            for (i, node) in self.nodes.iter_mut().enumerate() {
                node.id = i;
            }
        }
    }

    pub fn find_chains(&self) -> Vec<Vec<usize>> {
        // Find connected components with 3+ nodes (attack chains)
        let n = self.nodes.len();
        if n == 0 {
            return Vec::new();
        }

        let mut visited = vec![false; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(a, b) in &self.edges {
            if a < n && b < n {
                adj[a].push(b);
                adj[b].push(a);
            }
        }

        let mut chains = Vec::new();
        for start in 0..n {
            if visited[start] {
                continue;
            }
            let mut component = Vec::new();
            let mut stack = vec![start];
            while let Some(node) = stack.pop() {
                if node >= n || visited[node] {
                    continue;
                }
                visited[node] = true;
                component.push(node);
                for &neighbor in &adj[node] {
                    if !visited[neighbor] {
                        stack.push(neighbor);
                    }
                }
            }
            if component.len() >= ATTACK_CHAIN_THRESHOLD as usize {
                chains.push(component);
            }
        }
        chains
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

pub fn classify_alert_type(alert_type: u32) -> &'static str {
    match alert_type {
        ALERT_GHOST_MAP => "Ghost Map Detected",
        ALERT_SYSCALL_LATENCY => "Syscall Latency Anomaly",
        ALERT_BYTECODE_TAMPER => "Bytecode Tampering",
        ALERT_HIDDEN_PROCESS => "Hidden Process Detected",
        ALERT_SUSPICIOUS_HOOK => "Suspicious Hook Detected",
        ALERT_PROG_INVENTORY => "Program Inventory Gap",
        ALERT_SYSCALL_ANOMALY => "Syscall Argument Anomaly",
        ALERT_NET_BASELINE => "Network Behavior Anomaly",
        ALERT_MEMFD_EXEC => "Memory-Backed Execution",
        ALERT_MAP_AUDIT => "BPF Map C2 Signature",
        ALERT_TRACEPOINT_GAP => "Rapid BPF Detach",
        ALERT_AUTO_DETACH => "Auto-Detach Triggered",
        ALERT_CONTAINMENT => "Process Contained",
        ALERT_HONEYPOT_READ => "Honeypot Map Accessed",
        ALERT_CROSS_REFERENCE => "Cross-Reference Anomaly",
        ALERT_HW_PERF_COUNTER => "HW Perf Counter Deviation",
        ALERT_VERIFIER_ANALYSIS => "Suspicious BPF Program",
        ALERT_MEMORY_FORENSICS => "Kernel Data Tampering",
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
    let detail_u64 = u64::from_le_bytes([
        alert.details[0],
        alert.details[1],
        alert.details[2],
        alert.details[3],
        alert.details[4],
        alert.details[5],
        alert.details[6],
        alert.details[7],
    ]);
    match alert.alert_type {
        ALERT_GHOST_MAP => format!("map_id={}, suspicious_ops={}", alert.context, detail_u64),
        ALERT_SYSCALL_LATENCY => format!("syscall={}, latency={}ns", alert.context, detail_u64),
        ALERT_BYTECODE_TAMPER => format!("prog_id={}, checksum_delta={}", alert.context, detail_u64),
        ALERT_HIDDEN_PROCESS => format!("hidden_pid={}, parent={}", alert.context, detail_u64),
        ALERT_SUSPICIOUS_HOOK => format!("hook_addr=0x{:x}, target={}", alert.context, detail_u64),
        ALERT_PROG_INVENTORY => format!("prog_count={}, expected={}", alert.context, detail_u64),
        ALERT_SYSCALL_ANOMALY => format!("syscall={}, deviation={}", alert.context, detail_u64),
        ALERT_NET_BASELINE => format!("bytes={}, threshold={}", alert.context, detail_u64),
        ALERT_MEMFD_EXEC => format!("fd={}, pid={}", alert.context, detail_u64),
        ALERT_MAP_AUDIT => format!("map_id={}, violations={}", alert.context, detail_u64),
        ALERT_TRACEPOINT_GAP => format!("gap_ms={}, expected_interval={}", alert.context, detail_u64),
        ALERT_AUTO_DETACH => format!("prog_id={}, attach_type={}", alert.context, detail_u64),
        ALERT_CONTAINMENT => format!("target_pid={}, action={}", alert.context, detail_u64),
        ALERT_HONEYPOT_READ => format!("map_id={}, accessor_pid={}", alert.context, detail_u64),
        ALERT_CROSS_REFERENCE => format!("discrepancy={}, source_a={}", alert.context, detail_u64),
        ALERT_HW_PERF_COUNTER => format!("counter={}, deviation={}", alert.context, detail_u64),
        ALERT_VERIFIER_ANALYSIS => format!("prog_id={}, complexity={}", alert.context, detail_u64),
        ALERT_MEMORY_FORENSICS => format!("region=0x{:x}, checksum_delta={}", alert.context, detail_u64),
        _ => format!("context={}", alert.context),
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
