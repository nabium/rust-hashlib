use std::io::Read;

struct MessageBuffer<R: Read> {
    file: R,
    buffer: [u8; 64],
    // length of the file in bits, only the lower 64-bit is used
    file_length: u64,
    file_ended: bool,
    eof: bool,
}

impl<R: Read> MessageBuffer<R> {
    fn new(file: R) -> MessageBuffer<R> {
        MessageBuffer {
            file,
            buffer: [0; 64],
            file_length: 0,
            file_ended: false,
            eof: false,
        }
    }

    fn has_next(&self) -> bool {
        !self.eof
    }

    /// Read 512 bits(64 bytes) block from the file
    /// If EOF is reached, add padding and the size of the file to fill the block
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
            // add length as u64 little endian
            let length: u64 = self.file_length as u64;
            self.buffer[56] = length as u8;
            self.buffer[57] = (length >> 8) as u8;
            self.buffer[58] = (length >> 16) as u8;
            self.buffer[59] = (length >> 24) as u8;
            self.buffer[60] = (length >> 32) as u8;
            self.buffer[61] = (length >> 40) as u8;
            self.buffer[62] = (length >> 48) as u8;
            self.buffer[63] = (length >> 56) as u8;
            // no more data
            self.eof = true;
        } else if buf_head < 512 {
            // fill until end
            self.buffer[buf_head..].fill(0);
        }

        &self.buffer[..]
    }
}

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

const S_TABLE: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
];

pub fn compute<R: Read>(input: R) -> [u8; 16] {

    // prepare message buffer with paddings and length
    let mut buffer = MessageBuffer::new(input);

    // message in array of u32
    let mut m_array = [0; 16];

    // Initialize MD Buffer
    let mut a_sum: u32 = 0x67452301;
    let mut b_sum: u32 = 0xefcdab89;
    let mut c_sum: u32 = 0x98badcfe;
    let mut d_sum: u32 = 0x10325476;

    // feed 512-bit blocks
    while buffer.has_next() {
        let block = buffer.next();
        assert!(block.len() == 64);

        for i in 0..16 {
            m_array[i] = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }

        let mut a = a_sum;
        let mut b = b_sum;
        let mut c = c_sum;
        let mut d = d_sum;

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

        a_sum = a_sum.wrapping_add(a);
        b_sum = b_sum.wrapping_add(b);
        c_sum = c_sum.wrapping_add(c);
        d_sum = d_sum.wrapping_add(d);
    }

    // [a_sum.to_le_bytes(), b_sum.to_le_bytes(), c_sum.to_le_bytes(), d_sum.to_le_bytes()].flatten();

    [
        a_sum as u8, (a_sum >> 8) as u8, (a_sum >> 16) as u8, (a_sum >> 24) as u8,
        b_sum as u8, (b_sum >> 8) as u8, (b_sum >> 16) as u8, (b_sum >> 24 )as u8,
        c_sum as u8, (c_sum >> 8) as u8, (c_sum >> 16) as u8, (c_sum >> 24) as u8,
        d_sum as u8, (d_sum >> 8) as u8, (d_sum >> 16) as u8, (d_sum >> 24) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stringify;

    #[test]
    fn test_message_buffer() {
        let data = [0xcbu8; 65];

        let mut buffer = MessageBuffer::new(&data[..0]);
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

        let mut buffer = MessageBuffer::new(&data[..1]);
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

        let mut buffer = MessageBuffer::new(&data[..55]);
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

        let mut buffer = MessageBuffer::new(&data[..56]);
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

        let mut buffer = MessageBuffer::new(&data[..64]);
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

        let mut buffer = MessageBuffer::new(&data[..65]);
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
    fn test_compute() {
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
