pub fn bit_padding(msg: &mut Vec<u8>, len: usize) {
    msg.push(0x80);
    for _ in 0..(len / 8) - (msg.len() % (len / 8)) {
        msg.push(0);
    }
}

pub fn pkcs7_padding(msg: &mut Vec<u8>, len: usize) {
    let mut rest = len - (msg.len() * 8) % len;
    if rest == 0 {
        rest = len / 8;
    } else {
        rest /= 8;
    }
    for _ in 0..rest {
        msg.push(rest as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nit_padding_test() {
       let mut msg = vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
       bit_padding(&mut msg, 128);
       assert_eq!(msg, vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
       msg = vec![1, 2, 3 ,4 ,5 ,6 ,7 ,8 ,9, 10, 11, 12, 13, 14, 15, 16];
       bit_padding(&mut msg, 128);
       assert_eq!(msg, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            128, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0]);
    }

    #[test]
    fn pkcs7_padding_test() {
        let mut msg = vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
       pkcs7_padding(&mut msg, 128);
       assert_eq!(msg, vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a]);
       msg = vec![1, 2, 3 ,4 ,5 ,6 ,7 ,8 ,9, 10, 11, 12, 13, 14, 15, 16];
       pkcs7_padding(&mut msg, 128);
       assert_eq!(msg, vec![ 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                            16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]);
    }
}