mod hash;
use hash::sha2::Sha2;

fn main() {
    let mut sha2 = Sha2::sha256();
    sha2.update("abcdefgh".to_string());
    println!("{}", sha2.hexdigest());
}
