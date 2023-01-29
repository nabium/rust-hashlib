use std::env;

fn main() {
    let files: Vec<String> = env::args().skip(1).collect();

    hashlib::foreach_file(&files, |filename, file| {
        let checksum = hashlib::sha2::sha512(file);
        println!("{} {}{filename}", hashlib::stringify(&checksum), hashlib::symbol_of(filename));
    });
}
