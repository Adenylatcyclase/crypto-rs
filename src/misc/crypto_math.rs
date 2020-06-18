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

fn galois_pow(i: usize) -> u8{
    let mut rc: u16 = 1;
    for _ in 1..i {
        if rc >= 0x80 {
            rc = (rc << 1) ^ 0x11B;
        } else {
            rc <<= 1;
        }
    }
    rc as u8
}


#[test]
    fn gal_mul_test() {
        assert_eq!(galois_mul(0x53, 0xca), 1);
        assert_eq!(galois_mul(0x57, 0x83), 193);
    }

    #[test]
    fn gal_pow_test() {
        assert_eq!(galois_pow(1), 1, "rcon 1 is wrong");
        assert_eq!(galois_pow(4), 8, "rcon 4 is wrong");
        assert_eq!(galois_pow(6), 0x20, "rcon 4 is wrong");
        assert_eq!(galois_pow(8), 0x80, "rcon 8 is wrong");
        assert_eq!(galois_pow(9), 0x1B, "rcon 9 is wrong");
        assert_eq!(galois_pow(10), 0x36, "rcon 10 is wrong");
    }