//! Hash function using SHA-1 (Secure Hash Algorithm 1).
//!
//! # Example
//!
//! ```
//! use hashlib::sha1;
//!
//! let hash = sha1::compute("abc".as_bytes());
//! ```
//!
//! # See
//! * <https://csrc.nist.gov/publications/fips#180-4>
//! * <https://datatracker.ietf.org/doc/html/rfc3174>
//! * <https://en.wikipedia.org/wiki/SHA-1>
//! * <https://csrc.nist.gov/Projects/cryptographic-standards-and-guidelines/example-values>
//! * <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing>
//! * <https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/index.html>

use std::io::Read;
use super::{MessageBuffer64, Endian};

/// Returns 20 byte hash value produced from `input` using SHA-1.
///
/// Length of returned Vec<u8> is 20.
///
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
///
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/SHA-1>.
pub fn compute<R: Read>(input: R) -> Vec<u8> {

    // prepare message buffer with paddings and length
    let mut buffer = MessageBuffer64::new(input, Endian::Big);

    // message in array of u32
    let mut m_array = [0; 80];

    // Initialize Buffer
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;

    // feed 512-bit blocks
    while buffer.has_next() {
        let block = buffer.next();
        assert!(block.len() == 64);

        // chunk contains 16 BIG-endian u32
        for i in 0..16 {
            m_array[i] = u32::from_be_bytes(block[(i*4)..(i*4)+4].try_into().unwrap());
        }

        // extend chunk to 80 u32
        for i in 16..80 {
            m_array[i] = (m_array[i - 3] ^ m_array[i - 8] ^ m_array[i - 14] ^ m_array[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let f: u32;
            let k: u32;
            if i < 20 {
                f = (b & c) ^ (!b & d);
                k = 0x5a827999;
            } else if i < 40 {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if i < 60 {
                f = (b & c) ^ (b & d) ^ (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }

            let temp = a.rotate_left(5).wrapping_add(f.wrapping_add(e.wrapping_add(k.wrapping_add(m_array[i]))));
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    // output in BIG-endian
    vec![
        (h0 >> 24) as u8, (h0 >> 16) as u8, (h0 >> 8) as u8, h0 as u8,
        (h1 >> 24) as u8, (h1 >> 16) as u8, (h1 >> 8) as u8, h1 as u8,
        (h2 >> 24) as u8, (h2 >> 16) as u8, (h2 >> 8) as u8, h2 as u8,
        (h3 >> 24) as u8, (h3 >> 16) as u8, (h3 >> 8) as u8, h3 as u8,
        (h4 >> 24) as u8, (h4 >> 16) as u8, (h4 >> 8) as u8, h4 as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stringify;

    #[test]
    fn test_sha1() {
        let result = compute("".as_bytes());
        assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy dog".as_bytes());
        assert_eq!("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy cog".as_bytes());
        assert_eq!("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3", stringify(&result));

        let result = compute("abc".as_bytes());
        assert_eq!("a9993e364706816aba3e25717850c26c9cd0d89d", stringify(&result));

        let result = compute("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes());
        assert_eq!("84983e441c3bd26ebaae4aa1f95129e5e54670f1", stringify(&result));

        let result = compute("a".repeat(1000000).as_bytes());
        assert_eq!("34aa973cd4c4daa4f61eeb2bdbad27316534016f", stringify(&result));
    }
}
