fn main() {
    println!("Examples of SHA-3 variants");
    println!("https://en.wikipedia.org/wiki/SHA-3#Examples_of_SHA-3_variants");
    println!();

    let data = "";
    println!("SHA3-224(\"{data}\")");
    println!("{}", hashlib::stringify(&hashlib::sha3::sha224(data.as_bytes())));
    println!("SHA3-256(\"{data}\")");
    println!("{}", hashlib::stringify(&hashlib::sha3::sha256(data.as_bytes())));
    println!("SHA3-384(\"{data}\")");
    println!("{}", hashlib::stringify(&hashlib::sha3::sha384(data.as_bytes())));
    println!("SHA3-512(\"{data}\")");
    println!("{}", hashlib::stringify(&hashlib::sha3::sha512(data.as_bytes())));
    println!("SHAKE128(\"{data}\", 256)");
    println!("{}", hashlib::stringify(&hashlib::sha3::shake128(data.as_bytes(), 256)));
    println!("SHAKE256(\"{data}\", 512)");
    println!("{}", hashlib::stringify(&hashlib::sha3::shake256(data.as_bytes(), 512)));
    println!();

    let data = "The quick brown fox jumps over the lazy dog";
    println!("SHAKE128(\"{data}\", 256)");
    println!("{}", hashlib::stringify(&hashlib::sha3::shake128(data.as_bytes(), 256)));
    let data = "The quick brown fox jumps over the lazy dof";
    println!("SHAKE128(\"{data}\", 256)");
    println!("{}", hashlib::stringify(&hashlib::sha3::shake128(data.as_bytes(), 256)));
}
