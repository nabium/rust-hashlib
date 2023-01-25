//! Hash function using MD2 Message-Digest Algorithm.
//!
//! # Example
//!
//! ```
//! use hashlib::md2;
//!
//! let hash = md2::compute("abc".as_bytes());
//! ```
//!
//! # See
//!
//! * <https://datatracker.ietf.org/doc/html/rfc1319>
//! * <https://www.rfc-editor.org/rfc/inline-errata/rfc1319.html>

use std::io::Read;

/// Iterator of message split in 16-byte chunks with padding and checksum appended.
struct MessageBuffer<R: Read> {
    /// original message
    file: R,
    /// 16-byte chunk
    buffer: [u8; 16],
    /// 16-byte checksum
    checksum: [u8; 16],
    /// true if `self.file` reached EOF
    file_ended: bool,
    /// true if padding was applied
    pad_ended: bool,
    /// true if all chunks are consumed
    eof: bool,
}

const S_TABLE: [u8; 256] = [
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
];

impl<R: Read> MessageBuffer<R> {
    /// Constructor of struct MessageBuffer.
    ///
    /// Example of types implementing `std::io::Read`:
    /// * std::fs::File::open("filename")
    /// * std::io::stdin()
    /// * "string data".as_bytes()
    /// * slice of byte array `&[u8]` as in `&[0x00u8; 16][..4]`
    fn new(file: R) -> MessageBuffer<R> {
        MessageBuffer {
            file,
            buffer: [0; 16],
            checksum: [0; 16],
            file_ended: false,
            pad_ended: false,
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
    /// Reads 16 byte block from the file.
    /// If EOF is reached, add padding and the checksum of the file to fill the block.
    ///
    /// # Panics
    ///
    /// If called when `self.has_next()` returns `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut buf = MessageBuffer::new("abc".as_bytes())
    /// while buf.has_next() {
    ///   let chunk = buf.next();
    ///   println!("{chunk:?}")
    /// }
    /// ```
    fn next(&mut self) -> &[u8] {
        let mut buf_head: usize = 0;

        if self.eof {
            panic!("Reading after EOF");
        }

        if self.pad_ended {
            // no more data
            self.eof = true;
            // return checksum
            return &self.checksum[..];
        }

        while !self.file_ended && buf_head < 16 {
            let bytes_read = self.file.read(&mut self.buffer[buf_head..]).unwrap();
            buf_head += bytes_read;

            // TODO 0 retunred from read() does not necessary mean EOF
            if bytes_read == 0 {
                self.file_ended = true;
                break;
            }
        }

        // pad if needed
        if buf_head < 16 {
            let pad = (16 - buf_head) as u8;
            self.buffer[buf_head..16].fill(pad);
            // padded
            self.pad_ended = true;
        }

        // calculate checksum
        let mut last_byte = self.checksum[15];
        for i in 0..16 {
            // There is an ERRATA in RFC 1319
            self.checksum[i] = self.checksum[i] ^ S_TABLE[(self.buffer[i] ^ last_byte) as usize];
            last_byte = self.checksum[i];
        }

        &self.buffer[..]
    }
}

/// Returns 16 byte hash value produced from `input` using MD2.
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
    let mut message = MessageBuffer::new(input);

    // register to store message digest and working data
    let mut register = [0; 48];

    // feed 16-byte blocks
    while message.has_next() {
        let block = message.next();
        assert!(block.len() == 16);

        for i in 0..16 {
            register[16 + i] = block[i];
            register[32 + i] = block[i] ^ register[i];
        }

        let mut t: u8 = 0;

        for round in 0..18 {
            for i in 0..48 {
                register[i] = register[i] ^ S_TABLE[t as usize];
                t = register[i];
            }

            t = t.wrapping_add(round);
        }
    }

    Vec::from(&register[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stringify;

    #[test]
    fn test_message_buffer() {
        let data = [0xcbu8; 17];

        let mut buffer = MessageBuffer::new(&data[..0]);
        assert!(buffer.has_next());
        // block with padding
        let block = buffer.next();
        assert_eq!(16, block.len());
        // padding
        for &v in &block[0..] {
            assert_eq!(16, v);
        }
        assert!(buffer.has_next());
        // checksum
        let block = buffer.next();
        assert_eq!(16, block.len());
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer::new(&data[..1]);
        assert!(buffer.has_next());
        // block with padding
        let block = buffer.next();
        assert_eq!(16, block.len());
        let num_data = 1;
        for &v in &block[..num_data] {
            assert_eq!(0xcb, v);
        }
        // padding
        for &v in &block[num_data..] {
            assert_eq!((16 - num_data) as u8, v);
        }
        assert!(buffer.has_next());
        // checksum
        let block = buffer.next();
        assert_eq!(16, block.len());
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer::new(&data[..15]);
        assert!(buffer.has_next());
        // block with padding
        let block = buffer.next();
        assert_eq!(16, block.len());
        let num_data = 15;
        for &v in &block[..num_data] {
            assert_eq!(0xcb, v);
        }
        // padding
        for &v in &block[num_data..] {
            assert_eq!((16 - num_data) as u8, v);
        }
        assert!(buffer.has_next());
        // checksum
        let block = buffer.next();
        assert_eq!(16, block.len());
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer::new(&data[..16]);
        assert!(buffer.has_next());
        // block with data
        let block = buffer.next();
        assert_eq!(16, block.len());
        for &v in block {
            assert_eq!(0xcb, v);
        }
        assert!(buffer.has_next());
        // block with padding
        let block = buffer.next();
        assert_eq!(16, block.len());
        let num_data = 0;
        for &v in &block[..num_data] {
            assert_eq!(0xcb, v);
        }
        // padding
        for &v in &block[num_data..] {
            assert_eq!((16 - num_data) as u8, v);
        }
        assert!(buffer.has_next());
        // checksum
        let block = buffer.next();
        assert_eq!(16, block.len());
        assert!(!buffer.has_next());

        let mut buffer = MessageBuffer::new(&data[..17]);
        assert!(buffer.has_next());
        // block with data
        let block = buffer.next();
        assert_eq!(16, block.len());
        for &v in block {
            assert_eq!(0xcb, v);
        }
        assert!(buffer.has_next());
        // block with padding
        let block = buffer.next();
        assert_eq!(16, block.len());
        let num_data = 1;
        for &v in &block[..num_data] {
            assert_eq!(0xcb, v);
        }
        // padding
        for &v in &block[num_data..] {
            assert_eq!((16 - num_data) as u8, v);
        }
        assert!(buffer.has_next());
        // checksum
        let block = buffer.next();
        assert_eq!(16, block.len());
        assert!(!buffer.has_next());
    }

    #[test]
    fn test_md2() {
        let result = compute("".as_bytes());
        assert_eq!("8350e5a3e24c153df2275c9f80692773", stringify(&result));

        let result = compute("a".as_bytes());
        assert_eq!("32ec01ec4a6dac72c0ab96fb34c0b5d1", stringify(&result));

        let result = compute("abc".as_bytes());
        assert_eq!("da853b0d3f88d99b30283a69e6ded6bb", stringify(&result));

        let result = compute("message digest".as_bytes());
        assert_eq!("ab4f496bfb2a530b219ff33031fe06b0", stringify(&result));

        let result = compute("abcdefghijklmnopqrstuvwxyz".as_bytes());
        assert_eq!("4e8ddff3650292ab5a4108c3aa47940b", stringify(&result));

        let result = compute("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes());
        assert_eq!("da33def2a42df13975352846c30338cd", stringify(&result));

        let result = compute("12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes());
        assert_eq!("d5976f79d83d3a0dc9806c3c66f3efd8", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy dog".as_bytes());
        assert_eq!("03d85a0d629d2c442e987525319fc471", stringify(&result));

        let result = compute("The quick brown fox jumps over the lazy cog".as_bytes());
        assert_eq!("6b890c9292668cdbbfda00a4ebf31f05", stringify(&result));
    }
}
