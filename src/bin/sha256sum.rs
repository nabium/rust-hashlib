use std::process::ExitCode;
use clap::Parser;

/// Print SHA-256 hash value of files.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct HashArgs {

    /// Files to print the hash value, use "-" for STDIN
    file: Vec<String>,
}

fn main() -> ExitCode {
    let args = HashArgs::parse();

    hashlib::foreach_file(&args.file, |filename, file| {
        let checksum = hashlib::sha2::sha256(file);
        println!("{} {}{filename}", hashlib::stringify(&checksum), hashlib::symbol_of(filename));
    });

    ExitCode::SUCCESS
}
