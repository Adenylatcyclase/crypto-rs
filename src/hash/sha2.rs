use std::iter::FromIterator;
use std::fmt;

pub struct Sha2 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    k: Vec<u32>
}

impl Sha2 {
    pub fn sha256() -> Self {
        Self{h0: 0x6a09e667,
            h1: 0xbb67ae85,
            h2: 0x3c6ef372,
            h3: 0xa54ff53a,
            h4: 0x510e527f,
            h5: 0x9b05688c,
            h6: 0x1f83d9ab,
            h7: 0x5be0cd19,
            k: Self::get_k()}
    }

    pub fn sha224() -> Self {
        Self{h0: 0xc1059ed8,
            h1: 0x367cd507,
            h2: 0x3070dd17,
            h3: 0xf70e5939,
            h4: 0xffc00b31,
            h5: 0x68581511,
            h6: 0x64f98fa7,
            h7: 0xbefa4fa4,
            k: Self::get_k()}
    }

    fn get_k () -> Vec<u32> {
        vec![0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    }
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

    fn padding(message: String) -> Vec<u32> {
        let mut bytes = message.into_bytes();
        let n = (440 - (bytes.len() * 8) % 440) / 8;
        let l = (bytes.len() * 8) as u64;
        bytes.push(0x80);

        for i in 0..n {
            bytes.push(0);
        }
        
        bytes.append(&mut Vec::from_iter(l.to_be_bytes().iter().cloned()));

        let mut vec = Vec::new();
        let mut buf = [0u8; 4];
        for i in bytes.chunks(4) {
            buf.clone_from_slice(i);
            vec.push(u32::from_be_bytes(buf));
        }
        vec
    }

    pub fn update(&mut self, message: String) {
        let mut w = vec![0; 64];
        let message = Self::padding(message);

        for chunk in message.chunks(16) {

            // Set initial w values
            for (i, u) in chunk.iter().enumerate() {
                w[i] = *u;
            }

            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
            for i in 16..64 {
                let s0 = Self::ssig0(w[i-15]);
                let s1 = Self::ssig1(w[i-2]);
                w[i] = w[i-16].overflowing_add(s0).0.overflowing_add(w[i-7]).0.overflowing_add(s1).0;
            }

            // Initialize working variables to current hash value:
            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;
            let mut f = self.h5;
            let mut g = self.h6;
            let mut h = self.h7;

            for i in 0..64 {
                let S1 = Self::bsig1(e);
                let ch = Self::ch(e, f, g);
                let temp1 = h.overflowing_add(S1).0.overflowing_add(ch).0.overflowing_add(self.k[i]).0.overflowing_add(w[i]).0;
                let S0 = Self::bsig0(a);
                let maj = Self::maj(a, b, c);
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

            self.h0 = self.h0.overflowing_add(a).0;
            self.h1 = self.h1.overflowing_add(b).0;
            self.h2 = self.h2.overflowing_add(c).0;
            self.h3 = self.h3.overflowing_add(d).0;
            self.h4 = self.h4.overflowing_add(e).0;
            self.h5 = self.h5.overflowing_add(f).0;
            self.h6 = self.h6.overflowing_add(g).0;
            self.h7 = self.h7.overflowing_add(h).0;
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.append(&mut Vec::from_iter(self.h0.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h1.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h2.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h3.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h4.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h5.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h6.to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(self.h7.to_be_bytes().iter().cloned()));
        vec
    }

    pub fn hexdigest(&self) -> String {
        format!("{:X}{:X}{:X}{:X}{:X}{:X}{:X}{:X}", self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7)
    }
}

pub fn sha2 (msg : String) -> String {
    // Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
    // Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
    // Note 3: The compression function uses 8 working variables, a through h
    // Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    //     and when parsing message block data from bytes to words, for example,
    //     the first word of the input message "abc" after padding is 0x61626380

    // Initialize hash values:
    // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    let mut h0 : u32 = 0x6a09e667;
    let mut h1 : u32 = 0xbb67ae85;
    let mut h2 : u32 = 0x3c6ef372;
    let mut h3 : u32 = 0xa54ff53a;
    let mut h4 : u32 = 0x510e527f;
    let mut h5 : u32 = 0x9b05688c;
    let mut h6 : u32 = 0x1f83d9ab;
    let mut h7 : u32 = 0x5be0cd19;

    let mut v = msg.into_bytes();
    
    // Initialize array of round constants:
    // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    let k : Vec<u32> = vec![0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    
    // Pre-processing (Padding)
    let rest = 512 - (v.len() * 8 + 1 + 64) % 512;
    let l = (v.len() * 8) as u64;
    v.push(0x80);

    for i in 0..(rest - 7)/8 {
        v.push(0);
    }
    
    v.append(&mut Vec::from_iter(l.to_be_bytes().iter().cloned()));

    let mut vv = Vec::new();
    let mut buf = [0u8; 4];
    for i in v.chunks(4) {
        buf.clone_from_slice(i);
        vv.push(u32::from_be_bytes(buf));
    }

    for v in vv.chunks(16) {
        let mut w = vec![0; 64];
        // (The initial values in w[0..63] don't matter, so many implementations zero them here)
        for (e, u) in v.iter().enumerate() {
            w[e] = *u;
        }
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for e in 16..64 {
            let s0 = w[e-15].rotate_right(7) ^ w[e-15].rotate_right(18) ^ (w[e-15] >> 3);
            let s1 = w[e- 2].rotate_right(17) ^ w[e- 2].rotate_right(19) ^ (w[e- 2] >> 10);
            w[e] = w[e-16].overflowing_add(s0).0.overflowing_add(w[e-7]).0.overflowing_add(s1).0;
        }

        // Initialize working variables to current hash value:
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for j in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.overflowing_add(s1).0.overflowing_add(ch).0.overflowing_add(k[j]).0.overflowing_add(w[j]).0;
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.overflowing_add(maj).0;

            h = g;
            g = f;
            f = e;
            e = d.overflowing_add(temp1).0;
            d = c;
            c = b;
            b = a;
            a = temp1.overflowing_add(temp2).0;
        }

        h0 = h0.overflowing_add(a).0;
        h1 = h1.overflowing_add(b).0;
        h2 = h2.overflowing_add(c).0;
        h3 = h3.overflowing_add(d).0;
        h4 = h4.overflowing_add(e).0;
        h5 = h5.overflowing_add(f).0;
        h6 = h6.overflowing_add(g).0;
        h7 = h7.overflowing_add(h).0;
    }
    format!("{:X}{:X}{:X}{:X}{:X}{:X}{:X}{:X}", h0, h1, h2, h3, h4, h5, h6, h7)
}