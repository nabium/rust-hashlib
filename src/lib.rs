//! Cryptographic hash functions and utilities.
//!
//! Supported hash functions:
//! * MD5
//!   [`md5::compute()`]
//! * SHA-1
//!   [`sha1::compute()`]
//! * SHA-2
//!   * SHA-224
//!     [`sha2::sha224()`]
//!   * SHA-256
//!     [`sha2::sha256()`]
//!   * SHA-384
//!     [`sha2::sha384()`]
//!   * SHA-512
//!     [`sha2::sha512()`]
//!   * SHA-512/224
//!     [`sha2::sha512_224()`]
//!   * SHA-512/256
//!     [`sha2::sha512_256()`]
//!
//! [`self::stringify()`] converts byte array into hex string.

use std::io::{self, Read};
use std::fs::File;

pub mod md2;
pub mod md4;
pub mod md5;
pub mod sha1;
pub mod sha2;
pub mod sha3;

const STDIN: &str = "-";

fn is_stdin(filename: &str) -> bool {
    filename == STDIN
}

fn openfile(filename: &str) -> Box<dyn Read> {
    if is_stdin(filename) {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(filename).unwrap_or_else(|err| {
            panic!("Failed to open <{}>: {:?}", filename, err);
        }))
    }
}

/// Apply f() to each file in files.
///
/// # Arguments
/// 
/// 
/// 
/// # Panics
///
/// Panics if file cannot be opened.
pub fn foreach_file(files: &Vec<String>, f: fn(&str, Box<dyn Read>)) {
    if files.is_empty() {
        f(STDIN, openfile(STDIN));
    } else {
        for filename in files {
            f(filename, openfile(filename))
        }
    }
}

/// Returns a symbol, " " or "*", to prepend the filename,
/// as GNU coreutils does.
pub fn symbol_of(filename: &str) -> &str {
    if is_stdin(filename) {
        " "
    } else {
        "*"
    }
}

/// Table of stringified bytes
const HEX: [&str; 256] = [
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
];

/// Returns the hex string representation of bytes.
///
/// Bytes are concatinated without delimiters or new lines.
pub fn stringify(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);

    for &v in data {
        result.push_str(HEX[v as usize]);
    }

    result
}

/// Endian to use in hash functions.
enum Endian {
    Big,
    Little,
}

/// Iterator of message split in 512-bit chunks with padding and file size appended.
///
/// Used by MD5(little-endian) and SHA-1(BIG-endian), SHA-2(BIG-endian).
struct MessageBuffer64<R: Read> {
    /// original message
    file: R,
    // 512-bit chunk
    buffer: [u8; 64],
    /// length of the file in bits, only the lower 64-bit is used
    file_length: u64,
    /// true if `self.file` reached EOF
    file_ended: bool,
    /// true if all chunks are consumed
    eof: bool,
    /// endian to use
    endian: Endian,
}

impl<R: Read> MessageBuffer64<R> {
    /// Constructor of struct MessageBuffer64.
    ///
    /// Example of types implementing `std::io::Read`:
    /// * std::fs::File::open("filename")
    /// * std::io::stdin()
    /// * "string data".as_bytes()
    /// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
    fn new(file: R, endian: Endian) -> MessageBuffer64<R> {
        MessageBuffer64 {
            file,
            buffer: [0; 64],
            file_length: 0,
            file_ended: false,
            eof: false,
            endian,
        }
    }

    /// Returns true if there is a chunk to read.
    ///
    /// Do not call `self.next()` if this function returns `false`.
    fn has_next(&self) -> bool {
        !self.eof
    }

    /// Returns next chunk.
    ///
    /// Reads 512 bits(64 bytes) block from the file.
    /// If EOF is reached, add padding and the size of the file to fill the block.
    ///
    /// # Panics
    ///
    /// If called when `self.has_next()` returns `false`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut buf = MessageBuffer64::new("abc".as_bytes(), Endian::Big);
    /// while buf.has_next() {
    ///   let chunk = buf.next();
    ///   println!("{chunk:?}");
    /// }
    /// ```
    fn next(&mut self) -> &[u8] {
        let mut buf_head: usize = 0;

        if self.eof {
            panic!("Reading after EOF");
        }

        while !self.file_ended && buf_head < 64 {
            let bytes_read = self.file.read(&mut self.buffer[buf_head..]).unwrap();
            self.file_length += (bytes_read * 8) as u64;
            buf_head += bytes_read;

            // TODO 0 retunred from read() does not necessary mean EOF
            if bytes_read == 0 {
                self.file_ended = true;
                // first byte of padding is 0x80, and padding should always exist
                self.buffer[buf_head] = 0x80;
                buf_head += 1;
                break;
            }
        }

        // pad if needed
        if buf_head <= 56 {
            // fill until 448th bit(56 byte)
            self.buffer[buf_head..56].fill(0);
            // add length as u64 in specified endian
            match self.endian {
                Endian::Little => {
                    self.buffer[56] = self.file_length as u8;
                    self.buffer[57] = (self.file_length >> 8) as u8;
                    self.buffer[58] = (self.file_length >> 16) as u8;
                    self.buffer[59] = (self.file_length >> 24) as u8;
                    self.buffer[60] = (self.file_length >> 32) as u8;
                    self.buffer[61] = (self.file_length >> 40) as u8;
                    self.buffer[62] = (self.file_length >> 48) as u8;
                    self.buffer[63] = (self.file_length >> 56) as u8;
                },
                Endian::Big => {
                    self.buffer[56] = (self.file_length >> 56) as u8;
                    self.buffer[57] = (self.file_length >> 48) as u8;
                    self.buffer[58] = (self.file_length >> 40) as u8;
                    self.buffer[59] = (self.file_length >> 32) as u8;
                    self.buffer[60] = (self.file_length >> 24) as u8;
                    self.buffer[61] = (self.file_length >> 16) as u8;
                    self.buffer[62] = (self.file_length >> 8) as u8;
                    self.buffer[63] = self.file_length as u8;
                },
            }
            // no more data
            self.eof = true;
        } else if buf_head < 64 {
            // fill until end
            self.buffer[buf_head..].fill(0);
        }

        &self.buffer[..]
    }
}

/// Iterator of message split in 1024-bit chunks with padding and file size appended.
///
/// Used by SHA-2(BIG-endian).
struct MessageBuffer128<R: Read> {
    /// original message
    file: R,
    // 1024-bit chunk
    buffer: [u8; 128],
    /// length of the file in bits, only the lower 128-bit is used
    file_length: u128,
    /// true if `self.file` reached EOF
    file_ended: bool,
    /// true if all chunks are consumed
    eof: bool,
}

impl<R: Read> MessageBuffer128<R> {
    /// Constructor of struct MessageBuffer128.
    ///
    /// Example of types implementing `std::io::Read`:
    /// * std::fs::File::open("filename")
    /// * std::io::stdin()
    /// * "string data".as_bytes()
    /// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
    fn new(file: R) -> MessageBuffer128<R> {
        MessageBuffer128 {
            file,
            buffer: [0; 128],
            file_length: 0,
            file_ended: false,
            eof: false,
        }
    }

    /// Returns true if there is a chunk to read.
    ///
    /// Do not call `self.next()` if this function returns `false`.
    fn has_next(&self) -> bool {
        !self.eof
    }

    /// Returns next chunk.
    ///
    /// Reads 1024 bits(128 bytes) block from the file.
    /// If EOF is reached, add padding and the size of the file to fill the block.
    ///
    /// # Panics
    ///
    /// If called when `self.has_next()` returns `false`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut buf = MessageBuffer128::new("abc".as_bytes());
    /// while buf.has_next() {
    ///   let chunk = buf.next();
    ///   println!("{chunk:?}");
    /// }
    /// ```
    fn next(&mut self) -> &[u8] {
        let mut buf_head: usize = 0;

        if self.eof {
            panic!("Reading after EOF");
        }

        while !self.file_ended && buf_head < 128 {
            let bytes_read = self.file.read(&mut self.buffer[buf_head..]).unwrap();
            self.file_length += (bytes_read * 8) as u128;
            buf_head += bytes_read;

            // TODO 0 retunred from read() does not necessary mean EOF
            if bytes_read == 0 {
                self.file_ended = true;
                // first byte of padding is 0x80, and padding should always exist
                self.buffer[buf_head] = 0x80;
                buf_head += 1;
                break;
            }
        }

        // pad if needed
        if buf_head <= 112 {
            // fill until (1024 - 128)=896th bit(112 byte)
            self.buffer[buf_head..112].fill(0);
            // add length as u128 BIG-endian
            self.buffer[112] = (self.file_length >> 120) as u8;
            self.buffer[113] = (self.file_length >> 112) as u8;
            self.buffer[114] = (self.file_length >> 104) as u8;
            self.buffer[115] = (self.file_length >> 96) as u8;
            self.buffer[116] = (self.file_length >> 88) as u8;
            self.buffer[117] = (self.file_length >> 80) as u8;
            self.buffer[118] = (self.file_length >> 72) as u8;
            self.buffer[119] = (self.file_length >> 64) as u8;
            self.buffer[120] = (self.file_length >> 56) as u8;
            self.buffer[121] = (self.file_length >> 48) as u8;
            self.buffer[122] = (self.file_length >> 40) as u8;
            self.buffer[123] = (self.file_length >> 32) as u8;
            self.buffer[124] = (self.file_length >> 24) as u8;
            self.buffer[125] = (self.file_length >> 16) as u8;
            self.buffer[126] = (self.file_length >> 8) as u8;
            self.buffer[127] = self.file_length as u8;
            // no more data
            self.eof = true;
        } else if buf_head < 128 {
            // fill until end
            self.buffer[buf_head..].fill(0);
        }

        &self.buffer[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stringify() {
        let result = stringify(&[]);
        assert_eq!(result, "");

        let result = stringify(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
        assert_eq!(result, "010203040506070809000a0b0c0d0e0f");

        let result = stringify(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0x00, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0]);
        assert_eq!(result, "10203040506070809000a0b0c0d0e0f0");
    }

    #[test]
    fn test_message_buffer_64_le() {
        let data = [0xcbu8; 65];

        let mut buffer = MessageBuffer64::new(&data[..0], Endian::Little);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        // first pad
        assert_eq!(0x80, block[0]);
        // rest of the padding and the length
        for &v in &block[1..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..1], Endian::Little);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        assert_eq!(0xcb, block[0]);
        // padding
        assert_eq!(0x80, block[1]);
        for &v in &block[2..56] {
            assert_eq!(0, v);
        }
        // length
        assert_eq!(8, block[56]);
        for i in 57..64 {
            assert_eq!(0, block[i], "at index {i}");
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..55], Endian::Little);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for &v in &block[..55] {
            assert_eq!(0xcb, v);
        }
        // padding
        assert_eq!(0x80, block[55]);
        // length
        assert_eq!(0xb8, block[56]);
        assert_eq!(0x01, block[57]);
        for &v in &block[58..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..56], Endian::Little);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for i in 0..56 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        // padding
        assert_eq!(0x80, block[56]);
        for i in 57..64 {
            assert_eq!(0, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        // padding
        for i in 0..56 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        assert_eq!(0xc0, block[56]);
        assert_eq!(0x01, block[57]);
        for &v in &block[58..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..64], Endian::Little);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for i in 0..64 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        // padding
        assert_eq!(0x80, block[0]);
        for i in 1..56 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        assert_eq!(0x00, block[56]);
        assert_eq!(0x02, block[57]);
        for &v in &block[58..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..65], Endian::Little);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for i in 0..64 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(0xcb, block[0]);
        // padding
        assert_eq!(0x80, block[1]);
        for i in 2..56 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        assert_eq!(0x08, block[56]);
        assert_eq!(0x02, block[57]);
        for &v in &block[58..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());
    }

    #[test]
    fn test_message_buffer_64_be() {
        let data = [0xcbu8; 65];

        let mut buffer = MessageBuffer64::new(&data[..0], Endian::Big);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        // first pad
        assert_eq!(0x80, block[0]);
        // rest of the padding and the length
        for &v in &block[1..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..1], Endian::Big);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        assert_eq!(0xcb, block[0]);
        // padding
        assert_eq!(0x80, block[1]);
        for &v in &block[2..56] {
            assert_eq!(0, v);
        }
        // length
        for i in 56..63 {
            assert_eq!(0, block[i], "at index {i}");
        }
        assert_eq!(8, block[63]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..55], Endian::Big);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for &v in &block[..55] {
            assert_eq!(0xcb, v);
        }
        // padding
        assert_eq!(0x80, block[55]);
        // length
        for &v in &block[56..62] {
            assert_eq!(0, v);
        }
        assert_eq!(0x01, block[62]);
        assert_eq!(0xb8, block[63]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..56], Endian::Big);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for i in 0..56 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        // padding
        assert_eq!(0x80, block[56]);
        for i in 57..64 {
            assert_eq!(0, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        // padding
        for i in 0..56 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        for &v in &block[57..62] {
            assert_eq!(0, v);
        }
        assert_eq!(0x01, block[62]);
        assert_eq!(0xc0, block[63]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..64], Endian::Big);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for i in 0..64 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        // padding
        assert_eq!(0x80, block[0]);
        for i in 1..56 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        for &v in &block[57..62] {
            assert_eq!(0, v);
        }
        assert_eq!(0x02, block[62]);
        assert_eq!(0x00, block[63]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer64::new(&data[..65], Endian::Big);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(64, block.len());
        for i in 0..64 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(0xcb, block[0]);
        // padding
        assert_eq!(0x80, block[1]);
        for i in 2..56 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        for &v in &block[57..62] {
            assert_eq!(0, v);
        }
        assert_eq!(0x02, block[62]);
        assert_eq!(0x08, block[63]);
        assert!(!buffer.has_next());
    }

    #[test]
    fn test_message_buffer_128_be() {
        let data = [0xcbu8; 129];

        let mut buffer = MessageBuffer128::new(&data[..0]);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(128, block.len());
        // first pad
        assert_eq!(0x80, block[0]);
        // rest of the padding and the length
        for &v in &block[1..] {
            assert_eq!(0, v);
        }
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer128::new(&data[..1]);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(128, block.len());
        assert_eq!(0xcb, block[0]);
        // padding
        assert_eq!(0x80, block[1]);
        for &v in &block[2..112] {
            assert_eq!(0, v);
        }
        // length
        for i in 112..127 {
            assert_eq!(0, block[i], "at index {i}");
        }
        assert_eq!(8, block[127]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer128::new(&data[..111]);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(128, block.len());
        for &v in &block[..111] {
            assert_eq!(0xcb, v);
        }
        // padding
        assert_eq!(0x80, block[111]);
        // length
        for &v in &block[112..126] {
            assert_eq!(0, v);
        }
        assert_eq!(0x03, block[126]);
        assert_eq!(0x78, block[127]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer128::new(&data[..112]);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(128, block.len());
        for i in 0..112 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        // padding
        assert_eq!(0x80, block[112]);
        for i in 113..128 {
            assert_eq!(0, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        // padding
        for i in 0..112 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        for &v in &block[112..126] {
            assert_eq!(0, v);
        }
        assert_eq!(0x03, block[126]);
        assert_eq!(0x80, block[127]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer128::new(&data[..128]);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(128, block.len());
        for i in 0..128 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        // padding
        assert_eq!(0x80, block[0]);
        for i in 1..112 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        for &v in &block[112..126] {
            assert_eq!(0, v);
        }
        assert_eq!(0x04, block[126]);
        assert_eq!(0x00, block[127]);
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer128::new(&data[..129]);
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(128, block.len());
        for i in 0..128 {
            assert_eq!(0xcb, block[i], "at index {i}");
        }
        assert!(buffer.has_next());
        let block = buffer.next();
        assert_eq!(0xcb, block[0]);
        // padding
        assert_eq!(0x80, block[1]);
        for i in 2..112 {
            assert_eq!(0, block[i], "at index {i}");
        }
        // length
        for &v in &block[112..126] {
            assert_eq!(0, v);
        }
        assert_eq!(0x04, block[126]);
        assert_eq!(0x08, block[127]);
        assert!(!buffer.has_next());
    }
}
