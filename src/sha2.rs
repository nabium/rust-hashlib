//! Hash functions using SHA-1 (Secure Hash Algorithm 1).
//! 
//! # Example
//! 
//! ```
//! use hashlib::sha2;
//! 
//! let hash = sha2::sha224("abc".as_bytes());
//! let hash = sha2::sha256("abc".as_bytes());
//! let hash = sha2::sha384("abc".as_bytes());
//! let hash = sha2::sha512("abc".as_bytes());
//! let hash = sha2::sha512_224("abc".as_bytes());
//! let hash = sha2::sha512_256("abc".as_bytes());
//! ```
//! 
//! # See
//! * <https://csrc.nist.gov/publications/fips#180-4>
//! * <https://datatracker.ietf.org/doc/html/rfc6234>
//! * <https://en.wikipedia.org/wiki/SHA-2>
//! * <https://csrc.nist.gov/Projects/cryptographic-standards-and-guidelines/example-values>
//! * <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing>
//! * <https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/index.html>

use std::io::Read;
use super::{Endian, MessageBuffer64, MessageBuffer128};

/// Table of round constants K.
const K32_TABLE: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash value for SHA-224.
const INIT224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// Initial hash value for SHA-256.
const INIT256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-2 hash function for 32 bit word size.
/// Using pseudocode from <https://en.wikipedia.org/wiki/SHA-2>.
fn compute32<R: Read>(input: R, init: [u32; 8]) -> Vec<u8> {

    // prepare message buffer with paddings and length
    let mut buffer = MessageBuffer64::new(input, Endian::Big);

    // message in array of u32
    let mut m_array = [0; 64];

    // Initialize Buffer
    let mut h0 = init[0];
    let mut h1 = init[1];
    let mut h2 = init[2];
    let mut h3 = init[3];
    let mut h4 = init[4];
    let mut h5 = init[5];
    let mut h6 = init[6];
    let mut h7 = init[7];

    // feed 512-bit blocks
    while buffer.has_next() {
        let block = buffer.next();
        assert!(block.len() == 64);

        // chunk contains 16 BIG-endian u32
        for i in 0..16 {
            m_array[i] = u32::from_be_bytes(block[(i*4)..(i*4)+4].try_into().unwrap());
        }

        // extend chunk to 64 u32
        for i in 16..64 {
            let s0 = m_array[i - 15].rotate_right(7) ^ m_array[i - 15].rotate_right(18) ^ (m_array[i - 15] >> 3);
            let s1 = m_array[i - 2].rotate_right(17) ^ m_array[i - 2].rotate_right(19) ^ (m_array[i - 2] >> 10);
            m_array[i] = m_array[i - 16].wrapping_add(s0.wrapping_add(m_array[i - 7].wrapping_add(s1)));
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1.wrapping_add(ch.wrapping_add(K32_TABLE[i].wrapping_add(m_array[i]))));
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    // output in BIG-endian
    vec![
        (h0 >> 24) as u8, (h0 >> 16) as u8, (h0 >> 8) as u8, h0 as u8,
        (h1 >> 24) as u8, (h1 >> 16) as u8, (h1 >> 8) as u8, h1 as u8,
        (h2 >> 24) as u8, (h2 >> 16) as u8, (h2 >> 8) as u8, h2 as u8,
        (h3 >> 24) as u8, (h3 >> 16) as u8, (h3 >> 8) as u8, h3 as u8,
        (h4 >> 24) as u8, (h4 >> 16) as u8, (h4 >> 8) as u8, h4 as u8,
        (h5 >> 24) as u8, (h5 >> 16) as u8, (h5 >> 8) as u8, h5 as u8,
        (h6 >> 24) as u8, (h6 >> 16) as u8, (h6 >> 8) as u8, h6 as u8,
        (h7 >> 24) as u8, (h7 >> 16) as u8, (h7 >> 8) as u8, h7 as u8,
    ]
}

/// Table of round constants K.
const K64_TABLE: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Initial hash value for SHA-384.
const INIT384 : [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

/// Initial hash value for SHA-512.
const INIT512 : [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Initial hash value for modified SHA-512.
const INIT512MOD : [u64; 8] = [
    0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5, 0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5,
    0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5, 0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5,
    0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5, 0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5,
    0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5, 0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5,
];

/// SHA-2 hash function for 64 bit word size.
/// Using pseudocode from <https://en.wikipedia.org/wiki/SHA-2>.
fn compute64<R: Read>(input: R, init: [u64; 8]) -> Vec<u8> {

    // prepare message buffer with paddings and length
    let mut buffer = MessageBuffer128::new(input);

    // message in array of u64
    let mut m_array = [0; 80];

    // Initialize Buffer
    let mut h0 = init[0];
    let mut h1 = init[1];
    let mut h2 = init[2];
    let mut h3 = init[3];
    let mut h4 = init[4];
    let mut h5 = init[5];
    let mut h6 = init[6];
    let mut h7 = init[7];

    // feed 512-bit blocks
    while buffer.has_next() {
        let block = buffer.next();
        assert!(block.len() == 128);

        // chunk contains 16 BIG-endian u32
        for i in 0..16 {
            m_array[i] = u64::from_be_bytes(block[(i*8)..(i*8)+8].try_into().unwrap());
        }

        // extend chunk to 80 u32
        for i in 16..80 {
            let s0 = m_array[i - 15].rotate_right(1) ^ m_array[i - 15].rotate_right(8) ^ (m_array[i - 15] >> 7);
            let s1 = m_array[i - 2].rotate_right(19) ^ m_array[i - 2].rotate_right(61) ^ (m_array[i - 2] >> 6);
            m_array[i] = m_array[i - 16].wrapping_add(s0.wrapping_add(m_array[i - 7].wrapping_add(s1)));
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1.wrapping_add(ch.wrapping_add(K64_TABLE[i].wrapping_add(m_array[i]))));
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    // output in BIG-endian
    vec![
        (h0 >> 56) as u8, (h0 >> 48) as u8, (h0 >> 40) as u8, (h0 >> 32) as u8,
        (h0 >> 24) as u8, (h0 >> 16) as u8, (h0 >> 8) as u8, h0 as u8,
        (h1 >> 56) as u8, (h1 >> 48) as u8, (h1 >> 40) as u8, (h1 >> 32) as u8,
        (h1 >> 24) as u8, (h1 >> 16) as u8, (h1 >> 8) as u8, h1 as u8,
        (h2 >> 56) as u8, (h2 >> 48) as u8, (h2 >> 40) as u8, (h2 >> 32) as u8,
        (h2 >> 24) as u8, (h2 >> 16) as u8, (h2 >> 8) as u8, h2 as u8,
        (h3 >> 56) as u8, (h3 >> 48) as u8, (h3 >> 40) as u8, (h3 >> 32) as u8,
        (h3 >> 24) as u8, (h3 >> 16) as u8, (h3 >> 8) as u8, h3 as u8,
        (h4 >> 56) as u8, (h4 >> 48) as u8, (h4 >> 40) as u8, (h4 >> 32) as u8,
        (h4 >> 24) as u8, (h4 >> 16) as u8, (h4 >> 8) as u8, h4 as u8,
        (h5 >> 56) as u8, (h5 >> 48) as u8, (h5 >> 40) as u8, (h5 >> 32) as u8,
        (h5 >> 24) as u8, (h5 >> 16) as u8, (h5 >> 8) as u8, h5 as u8,
        (h6 >> 56) as u8, (h6 >> 48) as u8, (h6 >> 40) as u8, (h6 >> 32) as u8,
        (h6 >> 24) as u8, (h6 >> 16) as u8, (h6 >> 8) as u8, h6 as u8,
        (h7 >> 56) as u8, (h7 >> 48) as u8, (h7 >> 40) as u8, (h7 >> 32) as u8,
        (h7 >> 24) as u8, (h7 >> 16) as u8, (h7 >> 8) as u8, h7 as u8,
    ]
}

/// Returns 28 byte hash value produced from `input` using SHA-224(SHA-2).
/// 
/// Length of returned Vec<u8> is 28.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-2>.
pub fn sha224<R: Read>(input: R) -> Vec<u8> {
    let mut hash = compute32(input, INIT224);
    hash.resize(28, 0);
    hash
}

/// Returns 32 byte hash value produced from `input` using SHA-256(SHA-2).
/// 
/// Length of returned Vec<u8> is 32.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-2>.
pub fn sha256<R: Read>(input: R) -> Vec<u8> {
    compute32(input, INIT256)
}

/// Returns 48 byte hash value produced from `input` using SHA-384(SHA-2).
/// 
/// Length of returned Vec<u8> is 48.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-2>.
pub fn sha384<R: Read>(input: R) -> Vec<u8> {
    let mut hash = compute64(input, INIT384);
    hash.resize(48, 0);
    hash
}

/// Returns 64 byte hash value produced from `input` using SHA-512(SHA-2).
/// 
/// Length of returned Vec<u8> is 64.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-2>.
pub fn sha512<R: Read>(input: R) -> Vec<u8> {
    compute64(input, INIT512)
}

/// Returns 28 byte hash value produced from `input` using SHA-512/224(SHA-2).
/// 
/// Length of returned Vec<u8> is 28.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-2>.
pub fn sha512_224<R: Read>(input: R) -> Vec<u8> {
    let hash = compute64("SHA-512/224".as_bytes(), INIT512MOD);

    let mut iter = hash.chunks_exact(8);
    let init = [
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
    ];

    let mut hash = compute64(input, init);
    hash.resize(28, 0);
    hash
}

/// Returns 32 byte hash value produced from `input` using SHA-512/256(SHA-2).
/// 
/// Length of returned Vec<u8> is 32.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-2>.
pub fn sha512_256<R: Read>(input: R) -> Vec<u8> {
    let hash = compute64("SHA-512/256".as_bytes(), INIT512MOD);

    let mut iter = hash.chunks_exact(8);
    let init = [
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
        u64::from_be_bytes(iter.next().unwrap().try_into().unwrap()),
    ];

    let mut hash = compute64(input, init);
    hash.resize(32, 0);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stringify;

    #[test]
    fn test_sha224() {
        let result = sha224("".as_bytes());
        assert_eq!("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", stringify(&result));

        let result = sha224("The quick brown fox jumps over the lazy dog".as_bytes());
        assert_eq!("730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525", stringify(&result));

        let result = sha224("The quick brown fox jumps over the lazy dog.".as_bytes());
        assert_eq!("619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c", stringify(&result));
    }

    #[test]
    fn test_sha256() {
        let result = sha256("".as_bytes());
        assert_eq!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", stringify(&result));

        let result = sha256("abc".as_bytes());
        assert_eq!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", stringify(&result));

        let result = sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
        assert_eq!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", stringify(&result));

        let result = sha256("1234567890".repeat(8).as_bytes());
        assert_eq!("f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e", stringify(&result));
    }

    #[test]
    fn test_sha384() {
        let result = sha384("".as_bytes());
        assert_eq!("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", stringify(&result));

        let result = sha384("abc".as_bytes());
        assert_eq!("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", stringify(&result));

        let result = sha384("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
        assert_eq!("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b", stringify(&result));

        let result = sha384("1234567890".repeat(8).as_bytes());
        assert_eq!("b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026", stringify(&result));
    }

    #[test]
    fn test_sha512() {
        let result = sha512("".as_bytes());
        assert_eq!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", stringify(&result));

        let result = sha512("abc".as_bytes());
        assert_eq!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", stringify(&result));

        let result = sha512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
        assert_eq!("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445", stringify(&result));

        let result = sha512("1234567890".repeat(8).as_bytes());
        assert_eq!("72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843", stringify(&result));
    }

    #[test]
    fn test_sha512_224() {
        let result = sha512_224("".as_bytes());
        assert_eq!("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", stringify(&result));
    }

    #[test]
    fn test_sha512_256() {
        let result = sha512_256("".as_bytes());
        assert_eq!("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", stringify(&result));
    }
}
