/// SHA1 implementation from <https://en.wikipedia.org/wiki/SHA-1>
///
/// Solution for problem 5 from set 4: <https://cryptopals.com/sets/4/challenges/28>
pub fn sha1(b: &[u8]) -> Vec<u8> {
    let mut H0: u32 = 0x67452301;
    let mut H1: u32 = 0xEFCDAB89;
    let mut H2: u32 = 0x98BADCFE;
    let mut H3: u32 = 0x10325476;
    let mut H4: u32 = 0xC3D2E1F0;

    // Pre-processing:
    let msg = {
        let mut m = Vec::from(b);
        m.push(0x80);
        m.extend_from_slice(&vec![0 as u8; 56 - m.len()]);
        m.extend_from_slice(&((b.len() * 8) as u64).to_be_bytes());
        m
    };

    // Process the message in successive 512-bit chunks:
    for chunk in msg.chunks(64) {
        let mut w = [0 as u32; 80];

        // break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // Initialize hash value for this chunk:
        let mut a = H0;
        let mut b = H1;
        let mut c = H2;
        let mut d = H3;
        let mut e = H4;

        // Main loop:
        for i in 0..80 {
            let (f, k) = {
                if i >= 0 && i <= 19 {
                    ((d ^ (b & (c ^ d))) as u32, 0x5A827999 as u32)
                } else if i >= 20 && i <= 39 {
                    ((b ^ c ^ d) as u32, 0x6ED9EBA1 as u32)
                } else if i >= 40 && i <= 59 {
                    (((b & c) | (d & (b | c))) as u32, 0x8F1BBCDC as u32)
                } else {
                    ((b ^ c ^ d) as u32, 0xCA62C1D6 as u32)
                }
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result so far:
        H0 = H0.wrapping_add(a);
        H1 = H1.wrapping_add(b);
        H2 = H2.wrapping_add(c);
        H3 = H3.wrapping_add(d);
        H4 = H4.wrapping_add(e);
    }

    // Produce the final hash value (big-endian) as a 160-bit number:
    let mut result = Vec::new();
    result.extend_from_slice(&H0.to_be_bytes());
    result.extend_from_slice(&H1.to_be_bytes());
    result.extend_from_slice(&H2.to_be_bytes());
    result.extend_from_slice(&H3.to_be_bytes());
    result.extend_from_slice(&H4.to_be_bytes());

    Vec::from(hex::encode(&result).as_bytes())
}

mod test {
    use super::sha1;

    #[test]
    fn test_sha1() {
        assert_eq!(sha1(b"abc"), b"a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1(b"secret-key-secret-msg"),
            b"92eae756cf3d5ab26c75f985769622d586cb428c"
        );
    }
}
