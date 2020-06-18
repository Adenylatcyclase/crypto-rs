#![allow(non_snake_case)]

use std::iter::FromIterator;
use crate::misc::{padding::bit_padding, to_bytes::ToBytes};

fn ch (x: u64, y: u64, z:u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

fn maj (x: u64, y: u64, z:u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0 (x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn bsig1 (x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn ssig0 (x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn ssig1 (x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}


pub fn sha3(msg: &impl ToBytes, h0: &mut [u64; 8], len: usize) -> Vec<u8> {
    let mut v = msg.to_bytes_be();
    let l = (v.len() * 8) as u128;
    bit_padding(&mut v, 896);
    v.append(&mut Vec::from_iter(l.to_be_bytes().iter().cloned()));

    let mut message= Vec::new();
    let mut buf = [0u8; 8];
    for i in v.chunks(8) {
        buf.clone_from_slice(i);
        message.push(u64::from_be_bytes(buf));
    }

    let mut w = vec![0; 80];
    let k = vec![0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

    for chunk in message.chunks(16) {

        // Set initial w values
        for (i, u) in chunk.iter().enumerate() {
            w[i] = *u;
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in 16..80 {
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
    for i in 0..len/64 {
        vec.append(&mut Vec::from_iter(h0[i].to_be_bytes().iter().cloned()));
    }
    vec
}

fn sha3_as_hex(msg: &impl ToBytes, mut h0: &mut [u64; 8], len: usize) -> String {
    let mut s = String::new();
    let v = sha3(msg, &mut h0, len);
    for h in v {
        s.push_str(&format!("{:02X}", h));
    }
    s
}

pub fn sha384(msg: &impl ToBytes) -> Vec<u8> {
    sha3(msg, &mut [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4], 384)
}

pub fn sha384_as_hex(msg: &impl ToBytes) -> String {
    sha3_as_hex(msg, &mut [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4], 384)
}

pub fn sha512(msg: &impl ToBytes) -> Vec<u8> {
    sha3(msg, &mut [0x6a09e667f3bcc908,  0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179], 512)
}

pub fn sha512_as_hex(msg: &impl ToBytes) -> String {
    sha3_as_hex(msg, &mut [0x6a09e667f3bcc908,  0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179], 512)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha512_test() {

        let hex = sha512_as_hex(&"Hello, World!".to_string());
        assert_eq!(hex, "374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387".to_string());

        let bytes = sha512(&"Hello, World!".to_string());
        assert_eq!(bytes, vec![0x37, 0x4D, 0x79, 0x4A, 0x95, 0xCD, 0xCF, 0xD8,
                                      0xB3, 0x59, 0x93, 0x18, 0x5F, 0xEF, 0x9B, 0xA3,
                                      0x68, 0xF1, 0x60, 0xD8, 0xDA, 0xF4, 0x32, 0xD0,
                                      0x8B, 0xA9, 0xF1, 0xED, 0x1E, 0x5A, 0xBE, 0x6C,
                                      0xC6, 0x92, 0x91, 0xE0, 0xFA, 0x2F, 0xE0, 0x00,
                                      0x6A, 0x52, 0x57, 0x0E, 0xF1, 0x8C, 0x19, 0xDE,
                                      0xF4, 0xE6, 0x17, 0xC3, 0x3C, 0xE5, 0x2E, 0xF0,
                                      0xA6, 0xE5, 0xFB, 0xE3, 0x18, 0xCB, 0x03, 0x87]);
    }

    #[test]
    fn sha384_test() {

        let hex = sha384_as_hex(&"Hello, World!".to_string());
        assert_eq!(hex, "5485CC9B3365B4305DFB4E8337E0A598A574F8242BF17289E0DD6C20A3CD44A089DE16AB4AB308F63E44B1170EB5F515".to_string());

        let bytes = sha384(&"Hello, World!".to_string());
        assert_eq!(bytes, vec![0x54, 0x85, 0xCC, 0x9B, 0x33 ,0x65, 0xB4, 0x30, 
                                      0x5D, 0xFB, 0x4E, 0x83 ,0x37, 0xE0, 0xA5 ,0x98,
                                      0xA5, 0x74, 0xF8, 0x24, 0x2B, 0xF1, 0x72, 0x89,
                                      0xE0, 0xDD, 0x6C, 0x20, 0xA3, 0xCD, 0x44, 0xA0,
                                      0x89, 0xDE, 0x16, 0xAB, 0x4A, 0xB3, 0x08, 0xF6, 
                                      0x3E, 0x44, 0xB1, 0x17, 0x0E ,0xB5, 0xF5, 0x15]);
    }
}
