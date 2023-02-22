fn main() {
    print!("const RHO: [u32; SLICE_SIZE] = [");
    for (i, v) in hashlib::sha3::generate_rho().iter().enumerate() {
        if i != 0 {
            print!(", ");
        }
        print!("{v}");
    }
    println!("];");

    print!("const PI: [usize; SLICE_SIZE] = [");
    for (i, v) in hashlib::sha3::generate_pi().iter().enumerate() {
        if i != 0 {
            print!(", ");
        }
        print!("{v}");
    }
    println!("];");

    println!("const RC: [u64; NUM_ROUNDS] = [");
    for (i, v) in hashlib::sha3::generate_rc().iter().enumerate() {
        if i % 2 == 0 {
            print!("    0x{v:016x},");
        } else {
            println!(" 0x{v:016x},");
        }
    }
    println!("];");
}
