#![allow(non_snake_case)]

use std::iter::FromIterator;
use crate::misc::{padding::bit_padding, to_bytes::ToBytes};


fn F(X: u32, Y: u32, Z: u32) -> u32 {
    X & Y | !X & Z
}

fn G(X: u32, Y: u32, Z: u32) -> u32 {
    X & Z | Y & !Z
}

fn H(X: u32, Y: u32, Z: u32) -> u32 {
    X ^ Y ^ Z
}

fn I(X: u32, Y: u32, Z: u32) -> u32 {
    Y ^ (X | !Z)
}

fn f_round1(mut a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize, X: &[u32], T: &[u32]) -> u32 {
    let tmp = F(b, c, d).overflowing_add(X[k]).0.overflowing_add(T[i-1]).0;
    a = a.overflowing_add(tmp).0;
    a = a.rotate_left(s);
    a = a.overflowing_add(b).0;
    a
}

fn f_round2(mut a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize, X: &[u32], T: &[u32]) -> u32 {
    let tmp = G(b, c, d).overflowing_add(X[k]).0.overflowing_add(T[i-1]).0;
    a = a.overflowing_add(tmp).0;
    a = a.rotate_left(s);
    a = a.overflowing_add(b).0;
    a
}

fn f_round3(mut a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize, X: &[u32], T: &[u32]) -> u32 {
    let tmp = H(b, c, d).overflowing_add(X[k]).0.overflowing_add(T[i-1]).0;
    a = a.overflowing_add(tmp).0;
    a = a.rotate_left(s);
    a = a.overflowing_add(b).0;
    a
}

fn f_round4(mut a: u32, b: u32, c: u32, d: u32, k: usize, s: u32, i: usize, X: &[u32], T: &[u32]) -> u32 {
    let tmp = I(b, c, d).overflowing_add(X[k]).0.overflowing_add(T[i-1]).0;
    a = a.overflowing_add(tmp).0;
    a = a.rotate_left(s);
    a = a.overflowing_add(b).0;
    a
}

pub fn md5(msg: &impl ToBytes) -> Vec<u8> {
    let mut bytes = msg.to_bytes_le();
    let l = (bytes.len() * 8) as u64;
    bit_padding(&mut bytes, 448);
    
    bytes.append(&mut Vec::from_iter(l.to_le_bytes().iter().cloned()));

    let mut message = Vec::new();
    let mut buf = [0u8; 4];
    for i in bytes.chunks(4) {
        buf.clone_from_slice(i);
        message.push(u32::from_le_bytes(buf));
    }

    let T = vec![0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453,  0xd8a1e681, 0xe7d3fbc8,
                 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

    let mut A: u32 = 0x67452301;
    let mut B: u32 = 0xefcdab89;
    let mut C: u32 = 0x98badcfe;
    let mut D: u32 = 0x10325476;

    for X in message.chunks(16) {

        // Initialize working variables to current hash value:
        let aa = A;
        let bb = B;
        let cc = C;
        let dd = D;

        // Tis gon get UGLY
        // Round1
        A = f_round1(A, B, C, D,  0,  7,  1, &X, &T);
        D = f_round1(D, A, B, C,  1, 12,  2, &X, &T);
        C = f_round1(C, D, A, B,  2, 17,  3, &X, &T);
        B = f_round1(B, C, D, A,  3, 22,  4, &X, &T);

        A = f_round1(A, B, C, D,  4,  7,  5, &X, &T);
        D = f_round1(D, A, B, C,  5, 12,  6, &X, &T);
        C = f_round1(C, D, A, B,  6, 17,  7, &X, &T);
        B = f_round1(B, C, D, A,  7, 22,  8, &X, &T);

        A = f_round1(A, B, C, D,  8,  7,  9, &X, &T);
        D = f_round1(D, A, B, C,  9, 12, 10, &X, &T);
        C = f_round1(C, D, A, B, 10, 17, 11, &X, &T);
        B = f_round1(B, C, D, A, 11, 22, 12, &X, &T);

        A = f_round1(A, B, C, D, 12,  7, 13, &X, &T);
        D = f_round1(D, A, B, C, 13, 12, 14, &X, &T);
        C = f_round1(C, D, A, B, 14, 17, 15, &X, &T);
        B = f_round1(B, C, D, A, 15, 22, 16, &X, &T);

        // Round2
        A = f_round2(A, B, C, D,  1,  5, 17, &X, &T);
        D = f_round2(D, A, B, C,  6,  9, 18, &X, &T);
        C = f_round2(C, D, A, B, 11, 14, 19, &X, &T);
        B = f_round2(B, C, D, A,  0, 20, 20, &X, &T);

        A = f_round2(A, B, C, D,  5,  5, 21, &X, &T);
        D = f_round2(D, A, B, C, 10,  9, 22, &X, &T);
        C = f_round2(C, D, A, B, 15, 14, 23, &X, &T);
        B = f_round2(B, C, D, A,  4, 20, 24, &X, &T);

        A = f_round2(A, B, C, D,  9,  5, 25, &X, &T);
        D = f_round2(D, A, B, C, 14,  9, 26, &X, &T);
        C = f_round2(C, D, A, B,  3, 14, 27, &X, &T);
        B = f_round2(B, C, D, A,  8, 20, 28, &X, &T);

        A = f_round2(A, B, C, D, 13,  5, 29, &X, &T);
        D = f_round2(D, A, B, C,  2,  9, 30, &X, &T);
        C = f_round2(C, D, A, B,  7, 14, 31, &X, &T);
        B = f_round2(B, C, D, A, 12, 20, 32, &X, &T);

        //Round3
        A = f_round3(A, B, C, D,  5,  4, 33, &X, &T);
        D = f_round3(D, A, B, C,  8, 11, 34, &X, &T);
        C = f_round3(C, D, A, B, 11, 16, 35, &X, &T);
        B = f_round3(B, C, D, A, 14, 23, 36, &X, &T);

        A = f_round3(A, B, C, D,  1,  4, 37, &X, &T);
        D = f_round3(D, A, B, C,  4, 11, 38, &X, &T);
        C = f_round3(C, D, A, B,  7, 16, 39, &X, &T);
        B = f_round3(B, C, D, A, 10, 23, 40, &X, &T);

        A = f_round3(A, B, C, D, 13,  4, 41, &X, &T);
        D = f_round3(D, A, B, C,  0, 11, 42, &X, &T);
        C = f_round3(C, D, A, B,  3, 16, 43, &X, &T);
        B = f_round3(B, C, D, A,  6, 23, 44, &X, &T);

        A = f_round3(A, B, C, D,  9,  4, 45, &X, &T);
        D = f_round3(D, A, B, C, 12, 11, 46, &X, &T);
        C = f_round3(C, D, A, B, 15, 16, 47, &X, &T);
        B = f_round3(B, C, D, A,  2, 23, 48, &X, &T);

        //Round4
        A = f_round4(A, B, C, D,  0,  6, 49, &X, &T);
        D = f_round4(D, A, B, C,  7, 10, 50, &X, &T);
        C = f_round4(C, D, A, B, 14, 15, 51, &X, &T);
        B = f_round4(B, C, D, A,  5, 21, 52, &X, &T);

        A = f_round4(A, B, C, D, 12,  6, 53, &X, &T);
        D = f_round4(D, A, B, C,  3, 10, 54, &X, &T);
        C = f_round4(C, D, A, B, 10, 15, 55, &X, &T);
        B = f_round4(B, C, D, A,  1, 21, 56, &X, &T);

        A = f_round4(A, B, C, D,  8,  6, 57, &X, &T);
        D = f_round4(D, A, B, C, 15, 10, 58, &X, &T);
        C = f_round4(C, D, A, B,  6, 15, 59, &X, &T);
        B = f_round4(B, C, D, A, 13, 21, 60, &X, &T);

        A = f_round4(A, B, C, D,  4,  6, 61, &X, &T);
        D = f_round4(D, A, B, C, 11, 10, 62, &X, &T);
        C = f_round4(C, D, A, B,  2, 15, 63, &X, &T);
        B = f_round4(B, C, D, A,  9, 21, 64, &X, &T);

        A = A.overflowing_add(aa).0;
        B = B.overflowing_add(bb).0;
        C = C.overflowing_add(cc).0;
        D = D.overflowing_add(dd).0;
    }

    let mut vec = Vec::new();
    vec.append(&mut Vec::from_iter(A.to_le_bytes().iter().cloned()));
    vec.append(&mut Vec::from_iter(B.to_le_bytes().iter().cloned()));
    vec.append(&mut Vec::from_iter(C.to_le_bytes().iter().cloned()));
    vec.append(&mut Vec::from_iter(D.to_le_bytes().iter().cloned()));
    
    vec
}

pub fn md5_as_hex(msg: &impl ToBytes) -> String {
    let v = md5(msg);
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
    fn md5_test() {

        let hex = md5_as_hex(&"Hello, World!".to_string());
        assert_eq!(hex, "65A8E27D8879283831B664BD8B7F0AD4".to_string());

        let bytes = md5(&"Hello, World!".to_string());
        assert_eq!(bytes, [0x65, 0xA8, 0xE2, 0x7D,
                                  0x88, 0x79, 0x28, 0x38,
                                  0x31, 0xB6, 0x64, 0xBD,
                                  0x8B, 0x7F, 0x0A, 0xD4]);
    }

}
