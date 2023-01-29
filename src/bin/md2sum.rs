use std::env;

fn main() {
    let files: Vec<String> = env::args().skip(1).collect();

    hashlib::foreach_file(&files, |filename, file| {
        let checksum = hashlib::md2::compute(file);
        println!("{} {}{filename}", hashlib::stringify(&checksum), hashlib::symbol_of(filename));
    });
}
