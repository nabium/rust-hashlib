//! Hash function using MD4 Message-Digest Algorithm.
//!
//! # Example
//!
//! ```
//! use hashlib::md4;
//!
//! let hash = md4::compute("abc".as_bytes());
//! ```
//!
//! # See
//!
//! * <https://datatracker.ietf.org/doc/html/rfc1320>

use std::io::Read;
use super::{MessageBuffer64, Endian};

fn round1(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    a.wrapping_add(((b & c) | (!b & d)).wrapping_add(x)).rotate_left(s)
}

fn round2(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    a.wrapping_add(((b & c) | (b & d) | (c & d)).wrapping_add(x.wrapping_add(0x5A827999))).rotate_left(s)
}

fn round3(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    a.wrapping_add((b ^ c ^ d).wrapping_add(x.wrapping_add(0x6ED9EBA1))).rotate_left(s)
}

/// Returns 16 byte hash value produced from `input` using MD4.
///
/// Length of returned Vec<u8> is 16.
///
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
pub fn compute<R: Read>(input: R) -> Vec<u8> {

    // prepare message buffer with paddings and length
    let mut buffer = MessageBuffer64::new(input, Endian::Little);

    // message in array of u32
    let mut m_array = [0; 16];

    // Initialize MD Buffer
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;

    // feed 512-bit blocks
    while buffer.has_next() {
        let block = buffer.next();
        assert!(block.len() == 64);

        for i in 0..16 {
            m_array[i] = u32::from_le_bytes(block[(i*4)..(i*4)+4].try_into().unwrap());
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;

        for i in 0..4 {
            a = round1(a, b, c, d, m_array[i * 4 + 0], 3);
            d = round1(d, a, b, c, m_array[i * 4 + 1], 7);
            c = round1(c, d, a, b, m_array[i * 4 + 2], 11);
            b = round1(b, c, d, a, m_array[i * 4 + 3], 19);
        }

        for i in 0..4 {
            a = round2(a, b, c, d, m_array[i], 3);
            d = round2(d, a, b, c, m_array[4 + i], 5);
            c = round2(c, d, a, b, m_array[8 + i], 9);
            b = round2(b, c, d, a, m_array[12 + i], 13);
        }

        for i in [0, 2, 1, 3] {
            a = round3(a, b, c, d, m_array[i], 3);
            d = round3(d, a, b, c, m_array[8 + i], 9);
            c = round3(c, d, a, b, m_array[4 + i], 11);
            b = round3(b, c, d, a, m_array[12 + i], 15);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }

    vec![
        h0 as u8, (h0 >> 8) as u8, (h0 >> 16) as u8, (h0 >> 24) as u8,
        h1 as u8, (h1 >> 8) as u8, (h1 >> 16) as u8, (h1 >> 24 )as u8,
        h2 as u8, (h2 >> 8) as u8, (h2 >> 16) as u8, (h2 >> 24) as u8,
        h3 as u8, (h3 >> 8) as u8, (h3 >> 16) as u8, (h3 >> 24) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stringify;

    #[test]
    fn test_md4() {
        let result = compute("".as_bytes());
        assert_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", stringify(&result));

        let result = compute("a".as_bytes());
        assert_eq!("bde52cb31de33e46245e05fbdbd6fb24", stringify(&result));

        let result = compute("abc".as_bytes());
        assert_eq!("a448017aaf21d8525fc10ae87aa6729d", stringify(&result));

        let result = compute("message digest".as_bytes());
        assert_eq!("d9130a8164549fe818874806e1c7014b", stringify(&result));

        let result = compute("abcdefghijklmnopqrstuvwxyz".as_bytes());
        assert_eq!("d79e1c308aa5bbcdeea8ed63df412da9", stringify(&result));

        let result = compute("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes());
        assert_eq!("043f8582f241db351ce627e153e7f0e4", stringify(&result));

        let result = compute("12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes());
        assert_eq!("e33b4ddc9c38f2199c3e7b164fcc0536", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy dog".as_bytes());
        assert_eq!("1bee69a46ba811185c194762abaeae90", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy cog".as_bytes());
        assert_eq!("b86e130ce7028da59e672d56ad0113df", stringify(&result));
    }
}
