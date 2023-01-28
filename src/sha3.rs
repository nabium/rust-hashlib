//! Hash functions using SHA-3 (Secure Hash Algorithm 3).
//!
//! # Example
//!
//! ```
//! use hashlib::sha3;
//!
//! let hash = sha3::sha224("abc".as_bytes());
//! let hash = sha3::sha256("abc".as_bytes());
//! let hash = sha3::sha384("abc".as_bytes());
//! let hash = sha3::sha512("abc".as_bytes());
//! let hash = sha3::shake128("abc".as_bytes(), 256);
//! let hash = sha3::shake256("abc".as_bytes(), 512);
//! ```
//!
//! # See
//! * <https://csrc.nist.gov/publications/fips#202>
//! * <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>
//! * <https://csrc.nist.gov/Projects/cryptographic-standards-and-guidelines/example-values>
//! * <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing>
//! * <https://keccak.team/>
//! * <https://en.wikipedia.org/wiki/SHA-3>
//! * <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf>
//!
//! # More decent implementation
//! * <https://docs.rs/tiny-keccak>
//! * <https://docs.rs/sha3>
//!
use std::io::Read;

// https://csrc.nist.gov/Projects/cryptographic-standards-and-guidelines/example-values
pub static mut TRACE_INTERMEDIATE: bool = false;

const ROW_SIZE: usize = 5;
const COLUMN_SIZE: usize = 5;
const SLICE_SIZE: usize = ROW_SIZE * COLUMN_SIZE;

/// b: with of permutation in bits
const WIDTH_B: usize = 1600;

/// w: size of lane in bits
/// w = b / SLICE_SIZE = 64
const LANE_SIZE: usize = WIDTH_B / SLICE_SIZE;

/// size of state array in bytes
const STATE_SIZE_U8: usize = SLICE_SIZE * (LANE_SIZE / u8::BITS as usize);

/// nr: number of rounds
/// nr = 12 + 2 * log2(LANE_SIZE) = 24
const NUM_ROUNDS: usize = 24;


enum OutputKind {
    /// SHA-3 fixed output length, value is message suffix bits(0b01) in byte
    FIXED = 0x06,
    /// SHA-3 XOF variable output length, value is message suffix bits(0b1111) in byte
    SHAKE = 0x1f,
}

/// returns rate of sponge in bits
fn rate_of(capacity: usize) -> usize {
    // b = 1600 ; with of permutation in bits
    // r ; rate of sponge in bits
    // c ; capacity of sponge in bits
    // r + c = b
    WIDTH_B - capacity
}

/// byte-aligned message appended with suffix and padding
struct Message<R: Read> {
    /// original message
    file: R,
    /// rate of sponge in bits
    rate: usize,
    /// 0x06 for SHA, 0x1f for SHAKE
    suffix: u8,
    /// true if `self.file` reached EOF
    file_ended: bool,
    /// true if all chunks are consumed
    eof: bool,
}

impl<R: Read> Message<R> {

    fn new(file: R, capacity: usize, output_kind: OutputKind) -> Message<R> {
        // capacity should be on byte boudary
        // AND for SHA3 and SHAKE,
        // capacity and rate should be on u64::BITS boundary
        if capacity % 64 != 0 {
            panic!("invalid capacity={capacity}")
        }

        Message {
            file,
            rate: rate_of(capacity),
            suffix: output_kind as u8,
            file_ended: false,
            eof: false,
        }
    }

    fn has_next(&self) -> bool {
        return !self.eof;
    }

    fn next(&mut self) -> [u64; SLICE_SIZE] {
        // self.rate is in bits
        let rate_u8 = self.rate / 8;
        let mut buf = [0; STATE_SIZE_U8];
        let mut buf_head: usize = 0;

        if self.eof {
            panic!("Reading after EOF");
        }

        while !self.file_ended && buf_head < rate_u8 {
            let bytes_read = self.file.read(&mut buf[buf_head..rate_u8]).unwrap();
            buf_head += bytes_read;

            // TODO 0 retunred from read() does not necessary mean EOF
            if bytes_read == 0 {
                self.file_ended = true;
                break;
            }
        }

        // B.2 Hexadecimal Form of Padding Bits
        // pad if needed
        let remain = rate_u8 - buf_head;
         if 0 < remain {
            buf[buf_head] = self.suffix;
            buf[rate_u8 - 1] |= 0x80;
            // no more data
            self.eof = true;
        }

        // block contains (5 * 5)=SLICE of (u64)=LANE
        [
            // y=0
            u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            // y=1
            u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            u64::from_le_bytes(buf[56..64].try_into().unwrap()),
            u64::from_le_bytes(buf[64..72].try_into().unwrap()),
            u64::from_le_bytes(buf[72..80].try_into().unwrap()),
            // y=2
            u64::from_le_bytes(buf[80..88].try_into().unwrap()),
            u64::from_le_bytes(buf[88..96].try_into().unwrap()),
            u64::from_le_bytes(buf[96..104].try_into().unwrap()),
            u64::from_le_bytes(buf[104..112].try_into().unwrap()),
            u64::from_le_bytes(buf[112..120].try_into().unwrap()),
            // y=3
            u64::from_le_bytes(buf[120..128].try_into().unwrap()),
            u64::from_le_bytes(buf[128..136].try_into().unwrap()),
            u64::from_le_bytes(buf[136..144].try_into().unwrap()),
            u64::from_le_bytes(buf[144..152].try_into().unwrap()),
            u64::from_le_bytes(buf[152..160].try_into().unwrap()),
            // y=4
            u64::from_le_bytes(buf[160..168].try_into().unwrap()),
            u64::from_le_bytes(buf[168..176].try_into().unwrap()),
            u64::from_le_bytes(buf[176..184].try_into().unwrap()),
            u64::from_le_bytes(buf[184..192].try_into().unwrap()),
            u64::from_le_bytes(buf[192..200].try_into().unwrap()),
        ]
    }
}

// 3.2.1 Specification of &theta; Algorithm 1
fn theta(state: &mut [u64; SLICE_SIZE]) {
    // plane C
    let mut plane = [0; ROW_SIZE];

    for x in 0..ROW_SIZE {
        plane[x] = state[0 + x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
    }

    for x in 0..ROW_SIZE {
        // plane D[x]
        let plane_dx = plane[(x + 4) % 5] ^ (plane[(x + 1) % 5].rotate_left(1));
        for y in 0..COLUMN_SIZE {
            state[y * ROW_SIZE + x] ^= plane_dx;
        }
    }
}

/// precomputed bits to shift for u64 lane in RHO
const RHO: [u32; SLICE_SIZE] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

// 3.2.2 Specification of &rho; Algorithm 2
fn rho(state: &mut [u64; SLICE_SIZE]) {

    // To create RHO array:
    // let mut rho = [0; SLICE_SIZE];
    // let mut x = 1;
    // let mut y = 0;
    // for t in 0..24 {
    //     rho[y * ROW_SIZE + x] = ((t + 1) * (t + 2) / 2) % u64::BITS;
    //     let tmp = y;
    //     y = (2 * x + 3 * y) % 5;
    //     x = tmp;
    // }

    for index in 0..SLICE_SIZE {
        state[index] = state[index].rotate_left(RHO[index]);
    }
}

/// precomputed indices for PI
const PI: [usize; SLICE_SIZE] = [0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21];

// 3.2.3 Specification of &pi; Algorithm 3
fn pi(state: &mut [u64; SLICE_SIZE]) {

    // To create PI array:
    // let mut pi = [0; SLICE_SIZE];
    // for x in 0..5 {
    //     for y in 0..5 {
    //         pi[y * ROW_SIZE + x] = x * ROW_SIZE + (x + 3 * y) % 5;
    //     }
    // }

    let old_state = state.clone();
    for index in 0..SLICE_SIZE {
        state[index] = old_state[PI[index]];
    }
 }

// 3.2.4 Specification of &chi; Algorithm 4
fn chi(state: &mut [u64; SLICE_SIZE]) {
    let old_state = state.clone();

    for y in 0..COLUMN_SIZE {
        let yoff = y * ROW_SIZE;

        for x in 0..ROW_SIZE {
            let index = yoff + x;
            state[index] = old_state[index] ^ !old_state[yoff + (x + 1) % 5] & old_state[yoff + (x + 2) % 5];
        }
    }
}

/// precomputed round constants for u64 lane
const RC: [u64; NUM_ROUNDS] = [
    0x1, 0x8082, 0x800000000000808a, 0x8000000080008000,
    0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
    0x8a, 0x88, 0x80008009, 0x8000000a,
    0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008,
];

// 3.2.5 Specification of &iota; Algorithm 6
/// state: state array (A)
/// ir: round index (ir)
fn iota(state: &mut [u64; SLICE_SIZE], ir: usize) {
    // // w = lane size in bits
    // // l = log2(w) = 6
    // let l = 6;
    // let mut iota = [0; NUM_ROUNDS];
    // for ir in 0..NUM_ROUNDS {
    //     let mut rc: u64 = 0;
    //     for j in 0..=l {
    //         let bitpos = 2u32.pow(j) - 1;
    //         let t = (j as usize + 7 * ir) % 255;
    //         // 3.2.5 Specification of &iota;
    //         // Algorithm 5
    //         let bitval: u64;
    //         if t == 0 {
    //             bitval = 1;
    //         } else {
    //             let mut r: u8 = 0b10000000;
    //             for _ in 1..=t {
    //                 let lsb = r & 0x01;
    //                 r >>= 1;
    //                 if lsb != 0 {
    //                     r ^= 0b10001110;
    //                 }
    //             }
    //             bitval = ((r >> 7) & 0x01) as u64;
    //         }
    //         // should be bitval << (63 - bitpos) and/or rc.reverse_bits()?
    //         rc |= bitval << bitpos;
    //     }
    //     iota[ir] = rc;
    // }

    state[0] ^= RC[ir];
}

// 3.3 KECCAK-p[b, nr]
// Keccak-p[1600, 24](S), it is f of sponge[f, pad, r]
fn keccak_p(state: &mut [u64; 25]) {
    for ir in 0..NUM_ROUNDS {
        unsafe {
            if TRACE_INTERMEDIATE {
                println!("Round #{ir}");
            }
        }

        theta(state);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(state, "After Theta");
            }
        }

        rho(state);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(state, "After Rho");
            }
        }

        pi(state);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(state, "After Pi");
            }
        }

        chi(state);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(state, "After Chi");
            }
        }

        iota(state, ir);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(state, "After Iota");
            }
        }
    }
}

// Keccak[capacity](input + output_kind, hash_size)
// Keccac[c](N, d) = sponge[Keccak-p[1600, 24], pad, 1600-c](N, d)
fn keccak<R: Read>(input: R, capacity: usize, hash_size: usize, output_kind: OutputKind) -> Vec<u8> {
    assert!(hash_size % 8 == 0);

    let mut msg = Message::new(input, capacity, output_kind);

    let mut state = [0u64; SLICE_SIZE];
    while msg.has_next() {

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(&state, "State (in bytes)");
            }
        }

        // message to absorb
        let block = msg.next();

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(&block, "Data to be absorbed");
            }
        }

        // xor input block
        state.iter_mut().zip(block).for_each(|(a, b)| *a ^= b);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(&state, "Xor'd state (in bytes)");
                debug_print_block(&state, "Xor'd state (as lanes of integers)");
            }
        }

        // Keccak-p[WIDTH_B, NUM_ROUNDS](input)
        keccak_p(&mut state);

        unsafe {
            if TRACE_INTERMEDIATE {
                debug_print_block_bytes(&state, "After Permutation");
                debug_print_block(&state, "State (as lanes of integers)");
            }
        }
    }

    let mut remain = hash_size / 8;
    let mut hash: Vec<u8> = vec![];
    while 0 < remain {
        // truncate S to length of r, then append to Z
        // for SHA3 and SHAKE, r is divisible by u64::BITS
        for lane in &state[..(msg.rate / 64)] {
            if 8 < remain {
                hash.extend(lane.to_le_bytes());
                remain -= 8;
            } else {
                hash.extend(&lane.to_le_bytes()[..remain]);
                remain -= remain;
            }
            if remain == 0 {
                break;
            }
        }
        if remain != 0 {
            // squeeze the sponge
            keccak_p(&mut state);
        }
    }

    hash
}

fn keccak_fixed<R: Read>(input: R, hash_size: usize) -> Vec<u8> {
    // c ; capacity of sponge in bits
    // d ; width of output
    // c = 2 * d
    keccak(input, hash_size * 2, hash_size, OutputKind::FIXED)
}

fn keccak_shake<R: Read>(input: R, capacity: usize, hash_size: usize) -> Vec<u8> {
    keccak(input, capacity, hash_size, OutputKind::SHAKE)
}

// 6.1 SHA-3 Functions
// SHA3-224(M) = Keccak[448](M + 0b01, 224)
// SHA3-256(M) = Keccak[512](M + 0b01, 256)
// SHA3-384(M) = Keccak[768](M + 0b01, 384)
// SHA3-512(M) = Keccak[1024](M + 0b01, 512)

pub fn sha224<R: Read>(input: R) -> Vec<u8> {
    keccak_fixed(input, 224)
}

pub fn sha256<R: Read>(input: R) -> Vec<u8> {
    keccak_fixed(input, 256)
}

pub fn sha384<R: Read>(input: R) -> Vec<u8> {
    keccak_fixed(input, 384)
}

pub fn sha512<R: Read>(input: R) -> Vec<u8> {
    keccak_fixed(input, 512)
}

// 6.2 6.2 SHA-3 Extendable-Output Functions
// SHAKE128(M, d) = Keccak[256](M + 0b1111, d)
// SHAKE256(M, d) = Keccak[512](M + 0b1111, d)

pub fn shake128<R: Read>(input: R, hash_size: usize) -> Vec<u8> {
    keccak_shake(input, 256, hash_size)
}

pub fn shake256<R: Read>(input: R, hash_size: usize) -> Vec<u8> {
    keccak_shake(input, 512, hash_size)
}

fn debug_print_block(block: &[u64], msg: &str) {
    println!("{msg}:");
    for y in 0..5 {
        for x in 0..5 {
            println!("    [{x}, {y}] = {:016x}", block[x + y * 5]);
        }
    }
}

fn debug_print_block_bytes(block: &[u64], msg: &str) {
    println!("{msg}:");
    for (index, val) in block.iter().enumerate() {
        if index % 2 == 0 {
            print!("   ");
        } else {
            print!(" ");
        }

        for b in val.to_le_bytes() {
            print!(" {b:02x}");
        }

        if index % 2 == 1 {
            println!()
        }
    }
    if block.len() % 2 != 0 {
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stringify;

    #[test]
    fn test_message_sha3_224() {
        // capacity = output width(d) * 2
        let capacity = 224 * 2;
        // rate of the sponge (r) for u8
        let rate_u8 = (WIDTH_B - capacity) / 8;
        // rate of the sponge (r) for u64
        let rate_u64 = (WIDTH_B - capacity) / 64;

        let data = [0xa3; STATE_SIZE_U8 + 1];

        let mut msg = Message::new("".as_bytes(), capacity, OutputKind::FIXED);
        assert!(msg.has_next());
        let block = msg.next();
        assert_eq!(SLICE_SIZE, block.len());
        assert_eq!(0x0000000000000006, block[0]);
        for &v in &block[1..(rate_u64 - 1)] {
            assert_eq!(0x0000000000000000, v);
        }
        assert_eq!(0x8000000000000000, block[rate_u64 - 1]);
        for &v in &block[rate_u64..] {
            assert_eq!(0x0000000000000000, v);
        }
        assert!(!msg.has_next());

        let mut msg = Message::new(&data[..1], capacity, OutputKind::FIXED);
        assert!(msg.has_next());
        let block = msg.next();
        assert_eq!(SLICE_SIZE, block.len());
        assert_eq!(0x00000000000006a3, block[0]);
        for &v in &block[1..(rate_u64 - 1)] {
            assert_eq!(0x0000000000000000, v);
        }
        assert_eq!(0x8000000000000000, block[rate_u64 - 1]);
        for &v in &block[rate_u64..] {
            assert_eq!(0x0000000000000000, v);
        }
        assert!(!msg.has_next());

        let mut msg = Message::new(&data[..(rate_u8 - 1)], capacity, OutputKind::FIXED);
        assert!(msg.has_next());
        let block = msg.next();
        assert_eq!(SLICE_SIZE, block.len());
        for &v in &block[..(rate_u64 - 1)] {
            assert_eq!(0xa3a3a3a3a3a3a3a3, v);
        }
        assert_eq!(0x86a3a3a3a3a3a3a3, block[rate_u64 - 1]);
        for &v in &block[rate_u64..] {
            assert_eq!(0x0000000000000000, v);
        }
        assert!(!msg.has_next());

        let mut msg = Message::new(&data[..(rate_u8)], capacity, OutputKind::FIXED);
        assert!(msg.has_next());
        let block = msg.next();
        assert_eq!(SLICE_SIZE, block.len());
        for &v in &block[..rate_u64] {
            assert_eq!(0xa3a3a3a3a3a3a3a3, v);
        }
        for &v in &block[rate_u64..] {
            assert_eq!(0x0000000000000000, v);
        }
        assert!(msg.has_next());
        let block = msg.next();
        assert_eq!(SLICE_SIZE, block.len());
        assert_eq!(0x0000000000000006, block[0]);
        for &v in &block[1..(rate_u64 - 1)] {
            assert_eq!(0x0000000000000000, v);
        }
        assert_eq!(0x8000000000000000, block[rate_u64 - 1]);
        for &v in &block[rate_u64..] {
            assert_eq!(0x0000000000000000, v);
        }
        assert!(!msg.has_next());
    }

    #[test]
    fn test_sha224() {
        let result = sha224("".as_bytes());
        assert_eq!("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", stringify(&result));

        let data = [0xa3; 200];
        let result = sha224(data.as_slice());
        assert_eq!("9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0", stringify(&result));
    }

    #[test]
    fn test_sha256() {
        let result = sha256("".as_bytes());
        assert_eq!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", stringify(&result));
    }

    #[test]
    fn test_sha384() {
        let result = sha384("".as_bytes());
        assert_eq!("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
            stringify(&result));
    }

    #[test]
    fn test_sha512() {
        let result = sha512("".as_bytes());
        assert_eq!("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            stringify(&result));
    }

    #[test]
    fn test_shake128() {
        let result = shake128("".as_bytes(), 256);
        assert_eq!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", stringify(&result));

        let result = shake128("The quick brown fox jumps over the lazy dog".as_bytes(), 256);
        assert_eq!("f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e", stringify(&result));

        let result = shake128("The quick brown fox jumps over the lazy dof".as_bytes(), 256);
        assert_eq!("853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c", stringify(&result));

        let result = shake128(b"\x84\xe9\x50\x05\x18\x76\x05\x0d\xc8\x51\xfb\xd9\x9e\x62\x47\xb8".as_slice(), 128);
        assert_eq!("8599bd89f63a848c49ca593ec37a12c6", stringify(&result));

        let result = shake128(b"\x9a\x33\x57\x90\xab\xf7\x69\x87\x7c\x9e\x6c\xd3\xd5\x19\x9e\x8c".as_slice(), 128);
        assert_eq!("2ece1768a6ef6568a2dff699613f49d0", stringify(&result));

        let result = shake128(b"\x0a\x13\xad\x2c\x7a\x23\x9b\x4b\xa7\x3e\xa6\x59\x2a\xe8\x4e\xa9".as_slice(), 1120);
        assert_eq!("5feaf99c15f48851943ff9baa6e5055d8377f0dd347aa4dbece51ad3a6d9ce0c01aee9fe2260b80a4673a909b532adcdd1e421c32d6460535b5fe392a58d2634979a5a104d6c470aa3306c400b061db91c463b2848297bca2bc26d1864ba49d7ff949ebca50fbf79a5e63716dc82b600bd52ca7437ed774d169f6bf02e46487956fba2230f34cd2a0485484d", stringify(&result));
    }

    #[test]
    fn test_shake256() {
        let result = shake256("".as_bytes(), 512);
        assert_eq!(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            stringify(&result)
        );

        // may fail if output width (d) is larger then (r) = (b - c) = (1600 - 512) = 1088
        // if squeezing of sponge is not implemented

        let result = shake256(b"\
            \x8d\x80\x01\xe2\xc0\x96\xf1\xb8\x8e\x7c\x92\x24\xa0\x86\xef\xd4\
            \x79\x7f\xbf\x74\xa8\x03\x3a\x2d\x42\x2a\x2b\x6b\x8f\x67\x47\xe4\
        ".as_slice(), 1096);
        assert_eq!("2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d429615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc601b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43c46ca9fd6ee29ada5e", stringify(&result));
    }
}
