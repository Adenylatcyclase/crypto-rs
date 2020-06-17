#![allow(non_snake_case)]

use std::iter::FromIterator;
use crate::misc::padding::bit_padding;
use crate::misc::to_bytes::ToBytes;


fn f(t: usize, b: u32, c: u32, d:u32) -> u32 {
    if t < 20 {
        (b & c) | ((!b) & d)
    } else if  t >= 40 && t < 60 {
        (b & c) | (b & d) | (c & d)
    } else {
        b ^ c ^ d
    }
}

fn get_k (t: usize) -> u32 {
    if t < 20 {
        0x5A827999
    } else if t < 40 {
        0x6ED9EBA1
    } else if t < 60 {
        0x8F1BBCDC
    } else {
        0xCA62C1D6
    }
}

pub fn sha1(msg: &impl ToBytes) -> Vec<u8> {
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
    
    println!("ok1");

    let mut w = vec![0; 80];
    let mut h0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk in message.chunks(16) {

        // Set initial w values
        for (i, u) in chunk.iter().enumerate() {
            w[i] = *u;
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in 16..80 {
            w[i] =( w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }

        // Initialize working variables to current hash value:
        let mut a = h0[0];
        let mut b = h0[1];
        let mut c = h0[2];
        let mut d = h0[3];
        let mut e = h0[4];

        for (i, w) in w.iter().enumerate() {
            let temp = a.rotate_left(5).overflowing_add(f(i, b, c, d)).0.overflowing_add(e).0.overflowing_add(*w).0.overflowing_add(get_k(i)).0;

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0[0] = h0[0].overflowing_add(a).0;
        h0[1] = h0[1].overflowing_add(b).0;
        h0[2] = h0[2].overflowing_add(c).0;
        h0[3] = h0[3].overflowing_add(d).0;
        h0[4] = h0[4].overflowing_add(e).0;
    }

    let mut vec = Vec::new();
    for u in h0.iter() {
        vec.append(&mut Vec::from_iter(u.to_be_bytes().iter().cloned()));
    }
    vec
}

pub fn sha1_as_hex(msg: &impl ToBytes) -> String {
    let v = sha1(msg);
    let mut s = String::new();
    for h in v {
        s.push_str(&format!("{:02X}", h));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_test() {
        // Test single use
        let s = sha1_as_hex(&"Hello, World!".to_string());
        assert_eq!(s, "0A0A9F2A6772942557AB5355D76AF442F8F65E01".to_string());

        let v = sha1(&"Hello, World!".to_string());
        assert_eq!(v, [0x0A, 0x0A, 0x9F, 0x2A, 0x67,
                                  0x72, 0x94, 0x25, 0x57, 0xAB,
                                  0x53, 0x55, 0xD7, 0x6A, 0xF4,
                                  0x42, 0xF8, 0xF6, 0x5E, 0x01]);
    }

}