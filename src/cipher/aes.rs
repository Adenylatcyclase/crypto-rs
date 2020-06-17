#![allow(unused)]
use std::iter::FromIterator;

struct AES {
    message: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    key_len: usize,
    s_box: [[u8; 16]; 16],
    inv_s_box: [[u8; 16]; 16]
}

pub trait WORD{
    fn sub_word(&mut self, s_box: &[[u8;16]; 16]);
}

impl WORD for u32{
    fn sub_word(&mut self, s_box: &[[u8;16]; 16]){
        let mut t = (s_box[(*self >> 28) as usize][((*self >> 24) & 0xf) as usize] as Self) << 24;
        t += (s_box[(*self >> 20) as usize][((*self >> 16) & 0xf) as usize]as Self) << 16;
        t += (s_box[(*self >> 12) as usize][((*self >> 8) & 0xf) as usize] as Self) << 8;
        t += s_box[(*self >> 4) as usize][((*self) & 0xf) as usize] as Self;
        *self = t;
    }
}

fn galois_mul(mut a: u8, mut b: u8) -> u8{
    let mut p = 0;
    for i in 0..8 {
        if b & 1 == 1 {
            p = p ^ a;
        }
        b = b >> 1;
        let carry = a >> 7;
        a = a << 1;
        if carry == 1 {
            a = a ^ 0x1b;
        }
    }
    p as u8
}


impl AES {
    pub fn aes(key: &[u8], iv: &[u8]) -> Self {
        AES{message: Vec::new(),
            key_len: key.len(),
            key: Vec::from_iter(key.iter().cloned()),
            iv: Vec::from_iter(iv.iter().cloned()),
            s_box: [[0x63,  0x7c,  0x77,  0x7b,  0xf2,  0x6b,  0x6f,  0xc5,  0x30,  0x01,  0x67,  0x2b,  0xfe,  0xd7,  0xab,  0x76],
                    [0xca,  0x82,  0xc9,  0x7d,  0xfa,  0x59,  0x47,  0xf0,  0xad,  0xd4,  0xa2,  0xaf,  0x9c,  0xa4,  0x72,  0xc0],
                    [0xb7,  0xfd,  0x93,  0x26,  0x36,  0x3f,  0xf7,  0xcc,  0x34,  0xa5,  0xe5,  0xf1,  0x71,  0xd8,  0x31,  0x15],
                    [0x04,  0xc7,  0x23,  0xc3,  0x18,  0x96,  0x05,  0x9a,  0x07,  0x12,  0x80,  0xe2,  0xeb,  0x27,  0xb2,  0x75],
                    [0x09,  0x83,  0x2c,  0x1a,  0x1b,  0x6e,  0x5a,  0xa0,  0x52,  0x3b,  0xd6,  0xb3,  0x29,  0xe3,  0x2f,  0x84],
                    [0x53,  0xd1,  0x00,  0xed,  0x20,  0xfc,  0xb1,  0x5b,  0x6a,  0xcb,  0xbe,  0x39,  0x4a,  0x4c,  0x58,  0xcf],
                    [0xd0,  0xef,  0xaa,  0xfb,  0x43,  0x4d,  0x33,  0x85,  0x45,  0xf9,  0x02,  0x7f,  0x50,  0x3c,  0x9f,  0xa8],
                    [0x51,  0xa3,  0x40,  0x8f,  0x92,  0x9d,  0x38,  0xf5,  0xbc,  0xb6,  0xda,  0x21,  0x10,  0xff,  0xf3,  0xd2],
                    [0xcd,  0x0c,  0x13,  0xec,  0x5f,  0x97,  0x44,  0x17,  0xc4,  0xa7,  0x7e,  0x3d,  0x64,  0x5d,  0x19,  0x73],
                    [0x60,  0x81,  0x4f,  0xdc,  0x22,  0x2a,  0x90,  0x88,  0x46,  0xee,  0xb8,  0x14,  0xde,  0x5e,  0x0b,  0xdb],
                    [0xe0,  0x32,  0x3a,  0x0a,  0x49,  0x06,  0x24,  0x5c,  0xc2,  0xd3,  0xac,  0x62,  0x91,  0x95,  0xe4,  0x79],
                    [0xe7,  0xc8,  0x37,  0x6d,  0x8d,  0xd5,  0x4e,  0xa9,  0x6c,  0x56,  0xf4,  0xea,  0x65,  0x7a,  0xae,  0x08],
                    [0xba,  0x78,  0x25,  0x2e,  0x1c,  0xa6,  0xb4,  0xc6,  0xe8,  0xdd,  0x74,  0x1f,  0x4b,  0xbd,  0x8b,  0x8a],
                    [0x70,  0x3e,  0xb5,  0x66,  0x48,  0x03,  0xf6,  0x0e,  0x61,  0x35,  0x57,  0xb9,  0x86,  0xc1,  0x1d,  0x9e],
                    [0xe1,  0xf8,  0x98,  0x11,  0x69,  0xd9,  0x8e,  0x94,  0x9b,  0x1e,  0x87,  0xe9,  0xce,  0x55,  0x28,  0xdf],
                    [0x8c,  0xa1,  0x89,  0x0d,  0xbf,  0xe6,  0x42,  0x68,  0x41,  0x99,  0x2d,  0x0f,  0xb0,  0x54,  0xbb,  0x16]],
            inv_s_box: [[0; 16]; 16],
            }
    }

    fn sub_bytes(&self, state: &mut[[u8; 4]; 4]) {
        for row in state.iter_mut() {
            for cell in row.iter_mut() {
                *cell = self.s_box[(*cell >> 4) as usize][(*cell & 0xf) as usize];
            }
        }
    }

    fn shift_rows(&self, state: &mut[[u8; 4]; 4]) {
        // I know this is bad
        // row 1
        state[1].swap(0, 3);
        state[1].swap(0, 2);
        state[1].swap(0, 1);
        // row 2
        state[2].swap(0, 2);
        state[2].swap(1, 3);
        // row 3
        state[3].swap(0, 1);
        state[3].swap(0, 2);
        state[3].swap(0, 3);
    }

    fn mix_columns(&self, state: &mut[[u8; 4]; 4]) {
        let mut buf = [10; 4];
        for i in 0..state.len() {
            buf[0] = galois_mul(0x02, state[0][i]) ^ galois_mul(0x03, state[1][i]) ^ state[2][i] ^ state[3][i];
            buf[1] = state[0][i] ^ galois_mul(0x02, state[1][i]) ^ galois_mul(0x03, state[2][i]) ^ state[3][i];
            buf[2] = state[0][i] ^ state[1][i] ^ galois_mul(0x02, state[2][i]) ^ galois_mul(0x03, state[3][i]);
            buf[3] = galois_mul(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ galois_mul(0x02, state[3][i]);
            state[0][i] = buf[0];
            state[1][i] = buf[1];
            state[2][i] = buf[2];
            state[3][i] = buf[3];
        }
    }

    fn expand_key(&mut self) {}
    fn add_round_key(&mut self) {}
    fn inv_shift_rows(&mut self) {}
    fn inv_sub_bytes(&mut self) {}
    fn inv_mix_columns(&mut self) {}
    fn inv_add_round_key(&mut self) {}
    fn encrypt(&mut self) {}
}


#[cfg(test)]
mod tests {
    use super::*;
    fn get_state() -> [[u8; 4]; 4] {
        [[0x00, 0x01, 0x02, 0x03],
         [0x10, 0x11, 0x12, 0x13],
         [0x20, 0x21, 0x22, 0x23],
         [0x30, 0x31, 0x32, 0x33]]
    }
    #[test]
    fn sub_bytes_test() {
        let aes = AES::aes(&[0xff], &[0xff]);
        let mut state = get_state();
        aes.sub_bytes(&mut state);
        assert_eq!(state, [[0x63, 0x7c, 0x77, 0x7b],
                           [0xca, 0x82, 0xc9, 0x7d],
                           [0xb7, 0xfd, 0x93, 0x26],
                           [0x04, 0xc7, 0x23, 0xc3]]);
    }

    #[test]
    fn shift_rows_test() {
        let aes = AES::aes(&[0xff], &[0xff]);
        let mut state = get_state();
        aes.shift_rows(&mut state);
        assert_eq!(state, [[0x00, 0x01, 0x02, 0x03],
                           [0x11, 0x12, 0x13, 0x10],
                           [0x22, 0x23, 0x20, 0x21],
                           [0x33, 0x30, 0x31, 0x32]]);
    }

    #[test]
    fn gal_mul_test() {
        assert_eq!(galois_mul(0x53, 0xca), 1);
        assert_eq!(galois_mul(0x57, 0x83), 193);
    }

    #[test]
    fn mix_columns_test() {
        let aes = AES::aes(&[0xff], &[0xff]);
        let mut state = [[0xdb,  0xf2,  0xc6,  0xd4],
                         [0x13,  0x0a,  0xc6,  0xd4],
                         [0x53,  0x22,  0xc6,  0xd4],
                         [0x45,  0x5c,  0xc6,  0xd5]];
        aes.mix_columns(&mut state);
        assert_eq!(state, [[0x8e,  0x9f,  0xc6,  0xd5],
                           [0x4d,  0xdc,  0xc6,  0xd5],
                           [0xa1,  0x58,  0xc6,  0xd7],
                           [0xbc,  0x9d,  0xc6,  0xd6]]);
    }
}