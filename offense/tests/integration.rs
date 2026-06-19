use common::{
    CredentialCapture, EventHeader, RootkitConfig, TimestompEntry, EVENT_ANCESTRY_SPOOFED,
    EVENT_ANTI_DETACH, EVENT_BPF_CLOAKED, EVENT_BYTECODE_WIPED, EVENT_C2_AUTH_FAILED,
    EVENT_CONTAINER_PROBE, EVENT_CRED_RELAYED, EVENT_DNS_EXFIL, EVENT_FILE_OBFUSCATED,
    EVENT_ICMP_EXFIL, EVENT_KALLSYMS_HIDDEN, EVENT_LOG_TAMPERED, EVENT_MEMFD_STAGED,
    EVENT_MODULE_MASQUERADE, EVENT_NETNS_HIDDEN, EVENT_PACKET_INTERCEPTED, EVENT_PROC_HIDDEN,
    EVENT_SOCKET_CLONED, EVENT_SYSLOG_STRIPPED, EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
    // Kernel evasion
    EVENT_KPROBE_DETECTED, EVENT_TAIL_CALL_CHAIN, EVENT_FTRACE_BLINDED, EVENT_BPF_ITER_ABUSED,
    // Memory & process
    EVENT_VDSO_HOOKED, EVENT_SHM_COVERT_MSG, EVENT_UFFD_INJECTION, EVENT_COREDUMP_SUPPRESSED,
    // Network covert
    EVENT_ISN_COVERT, EVENT_IPV6_EXT_ABUSE, EVENT_ARP_POISONED, EVENT_PORT_KNOCK_AUTH,
    EVENT_BGP_HIJACK,
    // Hardware
    EVENT_DR_BREAKPOINT, EVENT_PMC_COVERT, EVENT_TSC_SIDECHAN,
    // Anti-forensics
    EVENT_AUDIT_KILLED, EVENT_INODE_SLACK_HIDE, EVENT_JOURNAL_MANIPULATED, EVENT_PROC_DEEP_SPOOF,
    // Advanced persistence
    EVENT_INITRAMFS_IMPLANT, EVENT_MODSIGN_BYPASS, EVENT_BPF_LINK_PINNED,
    // Hypervisor evasion
    EVENT_HYPERVISOR_DETECTED, EVENT_HYPERVISOR_FINGERPRINT, EVENT_HYPERVISOR_BLINDSPOT,
    EVENT_LIVE_MIGRATION_DETECTED,
    // Polymorphic
    EVENT_BYTECODE_MORPHED, EVENT_PATTERN_ROTATED, EVENT_OPAQUE_PREDICATE,
    // Phantom network
    EVENT_PHANTOM_SYN_ACK, EVENT_PHANTOM_CONN_ESTABLISHED, EVENT_PHANTOM_DATA_XFER,
    // Container lateral
    EVENT_CGROUP_BPF_INJECT, EVENT_CONTAINER_LATERAL, EVENT_NAMESPACE_ESCAPE,
    // DMA covert
    EVENT_DMA_STASH, EVENT_PCIE_TLP_SIGNAL, EVENT_NIC_EXFIL,
    // Behavioral AI
    EVENT_BEHAVIOR_PROFILED, EVENT_ACTIVITY_THROTTLED, EVENT_NORM_DEVIATION_AVOIDED,
    // Supply chain
    EVENT_PKG_MANAGER_HOOKED, EVENT_BINARY_PATCHED_INFLIGHT, EVENT_INTEGRITY_BYPASSED,
    // Dead man's switch
    EVENT_HEARTBEAT_RECEIVED, EVENT_DEADMAN_ARMED, EVENT_SCORCHED_EARTH,
    // BPF parasitism
    EVENT_BPF_PROG_DETECTED, EVENT_TAILCALL_INJECTED, EVENT_PROG_ARRAY_HIJACKED,
    // Advanced rootkit
    EVENT_TASK_STRUCT_PATCHED, EVENT_LSM_HOOK_SUBVERTED, EVENT_IDT_HOOKED,
    EVENT_FTRACE_SELF_HIDDEN, EVENT_LIVEPATCH_ABUSED,
    // Network stealth
    EVENT_RAW_SOCKET_C2, EVENT_TC_TRAFFIC_INJECTED, EVENT_DOH_C2_ESTABLISHED,
    EVENT_TRAFFIC_SHAPED,
    // Advanced persistence 4
    EVENT_OBFUSCATED_PIN, EVENT_CGROUP_PERSIST, EVENT_MODULE_PARAM_INJECT,
    EVENT_INITRAMFS_LOADER,
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

// ─── Event Classification (Original 1-24) ────────────────────────

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
fn test_classify_all_original_events() {
    let types: &[(u32, &str)] = &[
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
        (EVENT_NETNS_HIDDEN, "NetnsHidden"),
        (EVENT_BPF_CLOAKED, "BpfCloaked"),
        (EVENT_MODULE_MASQUERADE, "ModuleMasquerade"),
        (EVENT_MEMFD_STAGED, "MemfdStaged"),
        (EVENT_SYSLOG_STRIPPED, "SyslogStripped"),
        (EVENT_BYTECODE_WIPED, "BytecodeWiped"),
        (EVENT_ICMP_EXFIL, "IcmpExfil"),
        (EVENT_SOCKET_CLONED, "SocketCloned"),
        (EVENT_CRED_RELAYED, "CredRelayed"),
        (EVENT_CONTAINER_PROBE, "ContainerProbe"),
    ];

    for &(event_type, name) in types {
        let event = EventHeader {
            event_type,
            pid: 42,
            timestamp_ns: 1000,
            context: 0xCAFE,
        };
        let classification = classify_event(&event);
        assert!(
            !matches!(classification, EventClassification::Unknown { .. }),
            "Event type {} ({}) should not be Unknown",
            event_type,
            name
        );
    }
}

#[test]
fn test_classify_netns_hidden() {
    let event = EventHeader {
        event_type: EVENT_NETNS_HIDDEN,
        pid: 500,
        timestamp_ns: 0,
        context: 0xDEAD,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::NetnsHidden {
            pid: 500,
            netns_ino: 0xDEAD
        }
    );
}

#[test]
fn test_classify_bpf_cloaked() {
    let event = EventHeader {
        event_type: EVENT_BPF_CLOAKED,
        pid: 600,
        timestamp_ns: 0,
        context: 77,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::BpfCloaked {
            pid: 600,
            prog_id: 77
        }
    );
}

#[test]
fn test_classify_container_probe() {
    let event = EventHeader {
        event_type: EVENT_CONTAINER_PROBE,
        pid: 700,
        timestamp_ns: 0,
        context: 0xABCD,
    };
    assert_eq!(
        classify_event(&event),
        EventClassification::ContainerProbe {
            pid: 700,
            ns_ino: 0xABCD
        }
    );
}

// ─── Event Classification (Advanced 25-88) ───────────────────────

#[test]
fn test_classify_kernel_evasion_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_KPROBE_DETECTED, |pid, ctx| EventClassification::KprobeDetected { pid, addr: ctx }),
        (EVENT_TAIL_CALL_CHAIN, |pid, ctx| EventClassification::TailCallChain { pid, depth: ctx }),
        (EVENT_FTRACE_BLINDED, |pid, ctx| EventClassification::FtraceBlinded { pid, target: ctx }),
        (EVENT_BPF_ITER_ABUSED, |pid, ctx| EventClassification::BpfIterAbused { pid, iter_id: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 100, timestamp_ns: 5000, context: 0xFF00 };
        assert_eq!(classify_event(&event), make_expected(100, 0xFF00));
    }
}

#[test]
fn test_classify_memory_process_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_VDSO_HOOKED, |pid, ctx| EventClassification::VdsoHooked { pid, offset: ctx }),
        (EVENT_SHM_COVERT_MSG, |pid, ctx| EventClassification::ShmCovertMsg { pid, shm_id: ctx }),
        (EVENT_UFFD_INJECTION, |pid, ctx| EventClassification::UffdInjection { pid, addr: ctx }),
        (EVENT_COREDUMP_SUPPRESSED, |pid, ctx| EventClassification::CoredumpSuppressed { pid, signal: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 200, timestamp_ns: 0, context: 4096 };
        assert_eq!(classify_event(&event), make_expected(200, 4096));
    }
}

#[test]
fn test_classify_network_covert_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_ISN_COVERT, |pid, ctx| EventClassification::IsnCovert { pid, seq_num: ctx }),
        (EVENT_IPV6_EXT_ABUSE, |pid, ctx| EventClassification::Ipv6ExtAbuse { pid, ext_type: ctx }),
        (EVENT_ARP_POISONED, |pid, ctx| EventClassification::ArpPoisoned { pid, target_ip: ctx }),
        (EVENT_PORT_KNOCK_AUTH, |pid, ctx| EventClassification::PortKnockAuth { pid, port_seq: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 300, timestamp_ns: 0, context: 8080 };
        assert_eq!(classify_event(&event), make_expected(300, 8080));
    }
}

#[test]
fn test_classify_bgp_hijack() {
    let event = EventHeader { event_type: EVENT_BGP_HIJACK, pid: 1, timestamp_ns: 0, context: 0xC0A80000 };
    assert_eq!(classify_event(&event), EventClassification::BgpHijack { pid: 1, prefix: 0xC0A80000 });
}

#[test]
fn test_classify_hardware_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_DR_BREAKPOINT, |pid, ctx| EventClassification::DrBreakpoint { pid, dr_index: ctx }),
        (EVENT_PMC_COVERT, |pid, ctx| EventClassification::PmcCovert { pid, counter_id: ctx }),
        (EVENT_TSC_SIDECHAN, |pid, ctx| EventClassification::TscSidechan { pid, delta: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 400, timestamp_ns: 0, context: 3 };
        assert_eq!(classify_event(&event), make_expected(400, 3));
    }
}

#[test]
fn test_classify_anti_forensics_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_AUDIT_KILLED, |pid, ctx| EventClassification::AuditKilled { pid, audit_pid: ctx }),
        (EVENT_INODE_SLACK_HIDE, |pid, ctx| EventClassification::InodeSlackHide { pid, inode: ctx }),
        (EVENT_JOURNAL_MANIPULATED, |pid, ctx| EventClassification::JournalManipulated { pid, offset: ctx }),
        (EVENT_PROC_DEEP_SPOOF, |pid, ctx| EventClassification::ProcDeepSpoof { pid, field_id: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 500, timestamp_ns: 0, context: 12345 };
        assert_eq!(classify_event(&event), make_expected(500, 12345));
    }
}

#[test]
fn test_classify_advanced_persistence_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_INITRAMFS_IMPLANT, |pid, ctx| EventClassification::InitramfsImplant { pid, size: ctx }),
        (EVENT_MODSIGN_BYPASS, |pid, ctx| EventClassification::ModsignBypass { pid, module_hash: ctx }),
        (EVENT_BPF_LINK_PINNED, |pid, ctx| EventClassification::BpfLinkPinned { pid, link_id: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 600, timestamp_ns: 0, context: 0xBEEF };
        assert_eq!(classify_event(&event), make_expected(600, 0xBEEF));
    }
}

#[test]
fn test_classify_hypervisor_evasion_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_HYPERVISOR_DETECTED, |pid, ctx| EventClassification::HypervisorDetected { pid, hv_type: ctx }),
        (EVENT_HYPERVISOR_FINGERPRINT, |pid, ctx| EventClassification::HypervisorFingerprint { pid, signature: ctx }),
        (EVENT_HYPERVISOR_BLINDSPOT, |pid, ctx| EventClassification::HypervisorBlindspot { pid, gap_ns: ctx }),
        (EVENT_LIVE_MIGRATION_DETECTED, |pid, ctx| EventClassification::LiveMigrationDetected { pid, tsc_delta: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 700, timestamp_ns: 0, context: 1000000 };
        assert_eq!(classify_event(&event), make_expected(700, 1000000));
    }
}

#[test]
fn test_classify_polymorphic_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_BYTECODE_MORPHED, |pid, ctx| EventClassification::BytecodeMorphed { pid, gen_id: ctx }),
        (EVENT_PATTERN_ROTATED, |pid, ctx| EventClassification::PatternRotated { pid, pattern_hash: ctx }),
        (EVENT_OPAQUE_PREDICATE, |pid, ctx| EventClassification::OpaquePredicate { pid, predicate_id: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 800, timestamp_ns: 0, context: 42 };
        assert_eq!(classify_event(&event), make_expected(800, 42));
    }
}

#[test]
fn test_classify_phantom_network_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_PHANTOM_SYN_ACK, |pid, ctx| EventClassification::PhantomSynAck { pid, port: ctx }),
        (EVENT_PHANTOM_CONN_ESTABLISHED, |pid, ctx| EventClassification::PhantomConnEstablished { pid, conn_id: ctx }),
        (EVENT_PHANTOM_DATA_XFER, |pid, ctx| EventClassification::PhantomDataXfer { pid, bytes: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 900, timestamp_ns: 0, context: 443 };
        assert_eq!(classify_event(&event), make_expected(900, 443));
    }
}

#[test]
fn test_classify_container_lateral_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_CGROUP_BPF_INJECT, |pid, ctx| EventClassification::CgroupBpfInject { pid, cgroup_id: ctx }),
        (EVENT_CONTAINER_LATERAL, |pid, ctx| EventClassification::ContainerLateral { pid, target_ns: ctx }),
        (EVENT_NAMESPACE_ESCAPE, |pid, ctx| EventClassification::NamespaceEscape { pid, ns_ino: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1000, timestamp_ns: 0, context: 0xA0B0 };
        assert_eq!(classify_event(&event), make_expected(1000, 0xA0B0));
    }
}

#[test]
fn test_classify_dma_covert_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_DMA_STASH, |pid, ctx| EventClassification::DmaStash { pid, dma_addr: ctx }),
        (EVENT_PCIE_TLP_SIGNAL, |pid, ctx| EventClassification::PcieTlpSignal { pid, device_id: ctx }),
        (EVENT_NIC_EXFIL, |pid, ctx| EventClassification::NicExfil { pid, bytes: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1100, timestamp_ns: 0, context: 0xDMA0 };
        assert_eq!(classify_event(&event), make_expected(1100, 0xDMA0));
    }
}

#[test]
fn test_classify_behavioral_ai_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_BEHAVIOR_PROFILED, |pid, ctx| EventClassification::BehaviorProfiled { pid, profile_id: ctx }),
        (EVENT_ACTIVITY_THROTTLED, |pid, ctx| EventClassification::ActivityThrottled { pid, rate: ctx }),
        (EVENT_NORM_DEVIATION_AVOIDED, |pid, ctx| EventClassification::NormDeviationAvoided { pid, margin: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1200, timestamp_ns: 0, context: 95 };
        assert_eq!(classify_event(&event), make_expected(1200, 95));
    }
}

#[test]
fn test_classify_supply_chain_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_PKG_MANAGER_HOOKED, |pid, ctx| EventClassification::PkgManagerHooked { pid, pkg_hash: ctx }),
        (EVENT_BINARY_PATCHED_INFLIGHT, |pid, ctx| EventClassification::BinaryPatchedInflight { pid, inode: ctx }),
        (EVENT_INTEGRITY_BYPASSED, |pid, ctx| EventClassification::IntegrityBypassed { pid, check_id: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1300, timestamp_ns: 0, context: 0xF00D };
        assert_eq!(classify_event(&event), make_expected(1300, 0xF00D));
    }
}

#[test]
fn test_classify_deadman_switch_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_HEARTBEAT_RECEIVED, |pid, ctx| EventClassification::HeartbeatReceived { pid, interval: ctx }),
        (EVENT_DEADMAN_ARMED, |pid, ctx| EventClassification::DeadmanArmed { pid, timeout: ctx }),
        (EVENT_SCORCHED_EARTH, |pid, ctx| EventClassification::ScorchedEarth { pid, targets: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1400, timestamp_ns: 0, context: 60000 };
        assert_eq!(classify_event(&event), make_expected(1400, 60000));
    }
}

#[test]
fn test_classify_bpf_parasitism_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_BPF_PROG_DETECTED, |pid, ctx| EventClassification::BpfProgDetected { pid, prog_id: ctx }),
        (EVENT_TAILCALL_INJECTED, |pid, ctx| EventClassification::TailcallInjected { pid, map_id: ctx }),
        (EVENT_PROG_ARRAY_HIJACKED, |pid, ctx| EventClassification::ProgArrayHijacked { pid, index: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1500, timestamp_ns: 0, context: 7 };
        assert_eq!(classify_event(&event), make_expected(1500, 7));
    }
}

#[test]
fn test_classify_advanced_rootkit_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_TASK_STRUCT_PATCHED, |pid, ctx| EventClassification::TaskStructPatched { pid, field_offset: ctx }),
        (EVENT_LSM_HOOK_SUBVERTED, |pid, ctx| EventClassification::LsmHookSubverted { pid, hook_id: ctx }),
        (EVENT_IDT_HOOKED, |pid, ctx| EventClassification::IdtHooked { pid, vector: ctx }),
        (EVENT_FTRACE_SELF_HIDDEN, |pid, ctx| EventClassification::FtraceSelfHidden { pid, prog_id: ctx }),
        (EVENT_LIVEPATCH_ABUSED, |pid, ctx| EventClassification::LivepatchAbused { pid, target_addr: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1600, timestamp_ns: 0, context: 0xFFFF };
        assert_eq!(classify_event(&event), make_expected(1600, 0xFFFF));
    }
}

#[test]
fn test_classify_network_stealth_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_RAW_SOCKET_C2, |pid, ctx| EventClassification::RawSocketC2 { pid, port: ctx }),
        (EVENT_TC_TRAFFIC_INJECTED, |pid, ctx| EventClassification::TcTrafficInjected { pid, bytes: ctx }),
        (EVENT_DOH_C2_ESTABLISHED, |pid, ctx| EventClassification::DohC2Established { pid, domain_hash: ctx }),
        (EVENT_TRAFFIC_SHAPED, |pid, ctx| EventClassification::TrafficShaped { pid, rate_limit: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1700, timestamp_ns: 0, context: 53 };
        assert_eq!(classify_event(&event), make_expected(1700, 53));
    }
}

#[test]
fn test_classify_advanced_persistence4_events() {
    let cases: &[(u32, fn(u32, u64) -> EventClassification)] = &[
        (EVENT_OBFUSCATED_PIN, |pid, ctx| EventClassification::ObfuscatedPin { pid, path_hash: ctx }),
        (EVENT_CGROUP_PERSIST, |pid, ctx| EventClassification::CgroupPersist { pid, cgroup_id: ctx }),
        (EVENT_MODULE_PARAM_INJECT, |pid, ctx| EventClassification::ModuleParamInject { pid, module_hash: ctx }),
        (EVENT_INITRAMFS_LOADER, |pid, ctx| EventClassification::InitramfsLoader { pid, loader_size: ctx }),
    ];

    for &(event_type, make_expected) in cases {
        let event = EventHeader { event_type, pid: 1800, timestamp_ns: 0, context: 2048 };
        assert_eq!(classify_event(&event), make_expected(1800, 2048));
    }
}

#[test]
fn test_classify_all_events_not_unknown() {
    let all_events: Vec<u32> = (1..=88).collect();
    for event_type in all_events {
        let event = EventHeader { event_type, pid: 1, timestamp_ns: 0, context: 0 };
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

#[test]
fn test_classify_boundary_unknown() {
    let event = EventHeader { event_type: 89, pid: 1, timestamp_ns: 0, context: 0 };
    assert_eq!(classify_event(&event), EventClassification::Unknown { event_type: 89 });

    let event = EventHeader { event_type: 0, pid: 1, timestamp_ns: 0, context: 0 };
    assert_eq!(classify_event(&event), EventClassification::Unknown { event_type: 0 });
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
