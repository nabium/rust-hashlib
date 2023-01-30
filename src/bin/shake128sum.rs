use std::process::ExitCode;
use clap::Parser;

/// Print SHAKE128 hash value of files.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct ShakeArgs {

    /// Files to print the hash value, use "-" for STDIN
    file: Vec<String>,

    /// Length of output in bits, must be divisible by 8
    #[arg(short, long, value_name = "BITS", default_value_t = 256, value_parser = hashlib::hash_width_parser)]
    width: usize,

    /// Print intermediate states
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let args = ShakeArgs::parse();

    if args.verbose {
        unsafe {
            hashlib::sha3::TRACE_INTERMEDIATE = true;
        }
    }

    hashlib::foreach_file(&args.file, |filename, file| {
        let checksum = hashlib::sha3::shake128(file, args.width);
        println!("{} {}{filename}", hashlib::stringify(&checksum), hashlib::symbol_of(filename));
    });

    ExitCode::SUCCESS
}
