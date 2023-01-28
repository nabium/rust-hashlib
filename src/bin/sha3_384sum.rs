use std::env;
use std::fs::File;
use std::io;
use hashlib::sha3;

fn main() {
    let args = parse_args();

    for filename in &args {
        let checksum;
        if is_stdin(filename) {
            checksum = sha3::sha384(&mut io::stdin());
        } else {
            let mut file = File::open(filename).unwrap_or_else(|err| {
                panic!("Failed to open <{}>: {:?}", filename, err);
            });
            checksum = sha3::sha384(&mut file);
        }
        println!("{}  {filename}", hashlib::stringify(&checksum));
    }
}

/// Parse command line args, if none return ["-"] for stdin
fn parse_args() -> Vec<String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        vec![String::from("-")]
    } else {
        args
    }
}

/// is the filename for stdin?
fn is_stdin(filename: &str) -> bool {
    filename == "-"
}
