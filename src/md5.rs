//! Hash function using MD5 Message-Digest Algorithm.
//! 
//! # Example
//! 
//! ```
//! use hashlib::md5;
//! 
//! let hash = md5::compute("abc".as_bytes());
//! ```
//! 
//! # See
//! 
//! * <https://datatracker.ietf.org/doc/html/rfc1321>
//! * <https://en.wikipedia.org/wiki/MD5>

use std::io::Read;
use super::{MessageBuffer64, Endian};

/// Table of precomputed K.
const K_TABLE: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Table of per-round shift amount.
const S_TABLE: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
];

/// Returns 16 byte hash value produced from `input` using MD5.
/// 
/// Length of returned Vec<u8> is 16.
/// 
/// Parameter `input` must implement [`Read`].
/// Some examples are:
/// * std::fs::File::open("filename")
/// * std::io::stdin()
/// * "string data".as_bytes()
/// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
/// 
/// This implementaion uses pseudo code from <https://en.wikipedia.org/wiki/MD5>.
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

        for i in 0..64 {
            let mut f;
            let g;
            if i < 16 {
                f = (b & c) | (!b & d);
                g = i;
            } else if i < 32 {
                f = (d & b) | (!d & c);
                g = (5 * i + 1) % 16;
            } else if i < 48 {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | !d);
                g = (7 * i) % 16
            }

            f = f.wrapping_add(a.wrapping_add(K_TABLE[i].wrapping_add(m_array[g])));

            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S_TABLE[i]));
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
    }

    // slice.flatten() is still experimental.
    // [h0.to_le_bytes(), h1.to_le_bytes(), h2.to_le_bytes(), h3.to_le_bytes()].flatten();

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
    fn test_md5() {
        let result = compute("".as_bytes());
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", stringify(&result));

        let result = compute("a".as_bytes());
        assert_eq!("0cc175b9c0f1b6a831c399e269772661", stringify(&result));

        let result = compute("abc".as_bytes());
        assert_eq!("900150983cd24fb0d6963f7d28e17f72", stringify(&result));

        let result = compute("message digest".as_bytes());
        assert_eq!("f96b697d7cb7938d525a2f31aaf161d0", stringify(&result));

        let result = compute("abcdefghijklmnopqrstuvwxyz".as_bytes());
        assert_eq!("c3fcd3d76192e4007dfb496cca67e13b", stringify(&result));

        let result = compute("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes());
        assert_eq!("d174ab98d277d9f5a5611c2c9f419d9f", stringify(&result));

        let result = compute("12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes());
        assert_eq!("57edf4a22be3c955ac49da2e2107b67a", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy dog".as_bytes());
        assert_eq!("9e107d9d372bb6826bd81d3542a419d6", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy dog.".as_bytes());
        assert_eq!("e4d909c290d0fb1ca068ffaddf22cbd0", stringify(&result));
    }
}
