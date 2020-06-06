#![allow(non_snake_case)]

use std::iter::FromIterator;


enum Sha2Type {
    Sha256,
    Sha224

}
impl Sha2Type {
    pub fn get_h(&self) -> [u32; 8] {
        match self {
            Self::Sha256 => [0x6a09e667,  0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            Self::Sha224 => [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
        }
    }

    pub fn get_k (&self) -> Vec<u32> {
        vec![0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    }
}
pub struct Sha2 {
    msg: Vec<u8>,
    sha_type: Sha2Type,
}

impl Sha2 {
    pub fn sha256() -> Self {
        Self{msg: Vec::new(), sha_type: Sha2Type::Sha256}
    }

    pub fn sha224() -> Self {
        Self{msg: Vec::new(), sha_type: Sha2Type::Sha224}
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

    fn padding(&self) -> Vec<u32> {
        let mut bytes = self.msg.clone();
        let n = (440 - (bytes.len() * 8) % 440) / 8;
        let l = (bytes.len() * 8) as u64;
        bytes.push(0x80);

        for _ in 0..n {
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
        self.msg.append(&mut message.into_bytes());
    }

    pub fn digest(&self) -> Vec<u8> {

        let mut w = vec![0; 64];
        let message = self.padding();

        let mut h0 = self.sha_type.get_h();
        let k = self.sha_type.get_k();

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
            let mut a = h0[0];
            let mut b = h0[1];
            let mut c = h0[2];
            let mut d = h0[3];
            let mut e = h0[4];
            let mut f = h0[5];
            let mut g = h0[6];
            let mut h = h0[7];

            for (i, w) in w.iter().enumerate() {
                let S1 = Self::bsig1(e);
                let ch = Self::ch(e, f, g);
                let temp1 = h.overflowing_add(S1).0.overflowing_add(ch).0.overflowing_add(k[i]).0.overflowing_add(*w).0;
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
        vec.append(&mut Vec::from_iter(h0[0].to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(h0[1].to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(h0[2].to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(h0[3].to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(h0[4].to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(h0[5].to_be_bytes().iter().cloned()));
        vec.append(&mut Vec::from_iter(h0[6].to_be_bytes().iter().cloned()));
        if let Sha2Type::Sha256 = self.sha_type {
            vec.append(&mut Vec::from_iter(h0[7].to_be_bytes().iter().cloned()));
        }
        
        vec
    }

    pub fn hexdigest(&self) -> String {
        let mut s = String::new();
        for h in self.digest() {
            s.push_str(&format!("{:02X}", h));
        }
        s
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_test() {
        // Test single use
        let mut sha = Sha2::sha256();
        sha.update("Hello, World!".to_string());
        assert_eq!(sha.hexdigest(), "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F".to_string());

        assert_eq!(sha.digest(), [0xDF, 0xFD, 0x60, 0x21, 0xBB, 0x2B, 0xD5, 0xB0, 
                                0xAF, 0x67, 0x62, 0x90, 0x80, 0x9E, 0xC3, 0xA5, 
                                0x31, 0x91, 0xDD, 0x81, 0xC7, 0xF7, 0x0A, 0x4B, 
                                0x28, 0x68, 0x8A, 0x36, 0x21, 0x82, 0x98, 0x6F]);

        // Test multiple use like Pythons hashlib
        let mut sha1 = Sha2::sha256();
        sha1.update("Bananensaft".to_string());
        assert_eq!(sha1.hexdigest(), "23814372675176D5115189E78BEA52E992E09F47CD0CF2E3D446F4FA4C9568FA".to_string());
        sha1.update("Schokokuchen".to_string());

        let mut sha2 = Sha2::sha256();
        sha2.update("BananensaftSchokokuchen".to_string());
        assert_eq!(sha1.hexdigest(), sha2.hexdigest()); 
    }

    #[test]
    fn sha224_test() {
        // Test single use
        let mut sha = Sha2::sha224();
        sha.update("Hello, World!".to_string());
        assert_eq!(sha.hexdigest(), "72A23DFA411BA6FDE01DBFABF3B00A709C93EBF273DC29E2D8B261FF".to_string());

        assert_eq!(sha.digest(), [0x72, 0xA2, 0x3D, 0xFA, 0x41, 0x1B, 0xA6,
                                  0xFD, 0xE0, 0x1D, 0xBF, 0xAB, 0xF3, 0xB0,
                                  0x0A, 0x70, 0x9C, 0x93, 0xEB, 0xF2, 0x73,
                                  0xDC, 0x29, 0xE2, 0xD8, 0xB2, 0x61, 0xFF]);

        // Test multiple use like Pythons hashlib
        let mut sha1 = Sha2::sha224();
        sha1.update("Bananensaft".to_string());
        assert_eq!(sha1.hexdigest(), "FA25E7A96CFAFF5AAB97F0CC4D6E0252DA1F39B3789AB096FAD39228".to_string());
        sha1.update("Schokokuchen".to_string());

        let mut sha2 = Sha2::sha224();
        sha2.update("BananensaftSchokokuchen".to_string());
        assert_eq!(sha1.hexdigest(), sha2.hexdigest()); 
    }
}
