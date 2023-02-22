fn main() {
    println!("Test vectors");
    println!("https://en.wikipedia.org/wiki/SHA-2#Test_vectors");
    println!();

    let data = "";
    println!("SHA224(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha224(data.as_bytes())));
    println!("SHA256(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha256(data.as_bytes())));
    println!("SHA384(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha384(data.as_bytes())));
    println!("SHA512(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha512(data.as_bytes())));
    println!("SHA512/224(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha512_224(data.as_bytes())));
    println!("SHA512/256(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha512_256(data.as_bytes())));
    println!();

    let data = "The quick brown fox jumps over the lazy dog";
    println!("SHA224(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha224(data.as_bytes())));
    let data = "The quick brown fox jumps over the lazy dog.";
    println!("SHA224(\"{data}\")");
    println!("0x {}", hashlib::stringify(&hashlib::sha2::sha224(data.as_bytes())));
}
