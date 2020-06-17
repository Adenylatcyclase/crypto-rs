#![allow(non_snake_case)]

use std::iter::FromIterator;
use crate::misc::{padding::bit_padding, to_bytes::ToBytes};

fn ch (x: u32, y: u32, z:u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn maj (x: u32, y: u32, z:u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0 (x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn bsig1 (x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn ssig0 (x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn ssig1 (x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

pub fn sha2(msg: &impl ToBytes, h0: &mut [u32; 8], len: usize) -> Vec<u8> {
    let mut v = msg.to_bytes_be();
    let l = (v.len() * 8) as u64;
    bit_padding(&mut v, 448);
    v.append(&mut Vec::from_iter(l.to_be_bytes().iter().cloned()));

    let mut message = Vec::new();
    let mut buf = [0u8; 4];
    for i in v.chunks(4) {
        buf.clone_from_slice(i);
        message.push(u32::from_be_bytes(buf));
    }
    
    let mut w = vec![0; 64];
    let k = vec![0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

    for chunk in message.chunks(16) {

        // Set initial w values
        for (i, u) in chunk.iter().enumerate() {
            w[i] = *u;
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in 16..64 {
            let s0 = ssig0(w[i-15]);
            let s1 = ssig1(w[i-2]);
            w[i] = w[i-16].overflowing_add(s0).0.overflowing_add(w[i-7]).0.overflowing_add(s1).0;
        }

        // Initialize working variables to current hash value:
        let mut a = h0[0];
        let mut b = h0[1];
        let mut c = h0[2];
        let mut d = h0[3];
        let mut e = h0[4];
        let mut f = h0[5];
        let mut g = h0[6];
        let mut h = h0[7];

        for (i, w) in w.iter().enumerate() {
            let S1 = bsig1(e);
            let ch = ch(e, f, g);
            let temp1 = h.overflowing_add(S1).0.overflowing_add(ch).0.overflowing_add(k[i]).0.overflowing_add(*w).0;
            let S0 = bsig0(a);
            let maj = maj(a, b, c);
            let temp2 = S0.overflowing_add(maj).0;

            h = g;
            g = f;
            f = e;
            e = d.overflowing_add(temp1).0;
            d = c;
            c = b;
            b = a;
            a = temp1.overflowing_add(temp2).0;
        }

        h0[0] = h0[0].overflowing_add(a).0;
        h0[1] = h0[1].overflowing_add(b).0;
        h0[2] = h0[2].overflowing_add(c).0;
        h0[3] = h0[3].overflowing_add(d).0;
        h0[4] = h0[4].overflowing_add(e).0;
        h0[5] = h0[5].overflowing_add(f).0;
        h0[6] = h0[6].overflowing_add(g).0;
        h0[7] = h0[7].overflowing_add(h).0;
    }

    let mut vec = Vec::new();
    for i in 0..len / 32 {
        vec.append(&mut Vec::from_iter(h0[i].to_be_bytes().iter().cloned()));
    }
    
    vec
}

fn sha2_as_hex(msg: &impl ToBytes, mut h0: &mut [u32; 8], len: usize) -> String {
    let mut s = String::new();
    let v = sha2(msg, &mut h0, len);
    for h in v {
        s.push_str(&format!("{:02X}", h));
    }
    s
}

pub fn sha224(msg: &impl ToBytes) -> Vec<u8> {
    sha2(msg, &mut [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4], 224)
}

pub fn sha224_as_hex(msg: &impl ToBytes) -> String {
    sha2_as_hex(msg, &mut [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4], 224)
}

pub fn sha256(msg: &impl ToBytes) -> Vec<u8> {
    sha2(msg, &mut [0x6a09e667,  0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], 256)
}

pub fn sha256_as_hex(msg: &impl ToBytes) -> String {
    sha2_as_hex(msg, &mut [0x6a09e667,  0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], 256)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_test() {
        // Test single use
        let hex = sha256_as_hex(&"Hello, World!".to_string());
        assert_eq!(hex, "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F".to_string());

        let bytes = sha256(&"Hello, World!".to_string());
        assert_eq!(bytes, [0xDF, 0xFD, 0x60, 0x21, 0xBB, 0x2B, 0xD5, 0xB0, 
                                0xAF, 0x67, 0x62, 0x90, 0x80, 0x9E, 0xC3, 0xA5, 
                                0x31, 0x91, 0xDD, 0x81, 0xC7, 0xF7, 0x0A, 0x4B, 
                                0x28, 0x68, 0x8A, 0x36, 0x21, 0x82, 0x98, 0x6F]);
    }

    #[test]
    fn sha224_test() {
        // Test single use
        let hex = sha224_as_hex(&"Hello, World!".to_string());
        assert_eq!(hex, "72A23DFA411BA6FDE01DBFABF3B00A709C93EBF273DC29E2D8B261FF".to_string());

        let bytes = sha224(&"Hello, World!".to_string());
        assert_eq!(bytes, [0x72, 0xA2, 0x3D, 0xFA, 0x41, 0x1B, 0xA6,
                                  0xFD, 0xE0, 0x1D, 0xBF, 0xAB, 0xF3, 0xB0,
                                  0x0A, 0x70, 0x9C, 0x93, 0xEB, 0xF2, 0x73,
                                  0xDC, 0x29, 0xE2, 0xD8, 0xB2, 0x61, 0xFF]);
    }
}
