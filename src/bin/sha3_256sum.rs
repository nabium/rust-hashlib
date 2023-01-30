use std::process::ExitCode;
use clap::Parser;

/// Print SHA3-224 hash value of files.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Sha3Args {

    /// Files to print the hash value, use "-" for STDIN
    file: Vec<String>,

    /// Print intermediate states
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let args = Sha3Args::parse();

    if args.verbose {
        unsafe {
            hashlib::sha3::TRACE_INTERMEDIATE = true;
        }
    }

    hashlib::foreach_file(&args.file, |filename, file| {
        let checksum = hashlib::sha3::sha256(file);
        println!("{} {}{filename}", hashlib::stringify(&checksum), hashlib::symbol_of(filename));
    });

    ExitCode::SUCCESS
}
