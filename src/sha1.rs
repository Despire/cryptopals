pub fn sha1_mac(k: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::from(k);
    v.extend_from_slice(b);

    sha1(&v, None, None, None, None, None, None)
}

/// SHA1 implementation from <https://en.wikipedia.org/wiki/SHA-1>
///
/// Solution for problem 5 from set 4: <https://cryptopals.com/sets/4/challenges/28>
pub fn sha1(
    b: &[u8],
    l: Option<usize>,
    H0: Option<u32>,
    H1: Option<u32>,
    H2: Option<u32>,
    H3: Option<u32>,
    H4: Option<u32>,
) -> Vec<u8> {
    let mut H0: u32 = match H0 {
        Some(v) => v,
        None => 0x67452301,
    };

    let mut H1: u32 = match H1 {
        Some(v) => v,
        None => 0xEFCDAB89,
    };

    let mut H2: u32 = match H2 {
        Some(v) => v,
        None => 0x98BADCFE,
    };

    let mut H3: u32 = match H3 {
        Some(v) => v,
        None => 0x10325476,
    };

    let mut H4: u32 = match H4 {
        Some(v) => v,
        None => 0xC3D2E1F0,
    };

    // Pre-processing:
    let msg = {
        let mut m = Vec::from(b);
        m.push(0x80);

        let mut k = (56 - m.len() as i64) % 64;
        if k < 0 {
            k = 64 + k;
        }

        m.extend_from_slice(&vec![0 as u8; k as usize]);
        m.extend_from_slice(
            &match l {
                Some(v) => v,
                None => b.len() * 8,
            }
            .to_be_bytes(),
        );

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
    use super::sha1_mac;

    #[test]
    fn test_sha1_mac() {
        assert_eq!(
            sha1_mac(b"key", b"msg"),
            b"4c4293beb197faa80f0f5249c98b6491a2099127",
        )
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            sha1(b"abc", None, None, None, None, None, None),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            sha1(b"secret-key-secret-msg", None, None, None, None, None, None),
            b"92eae756cf3d5ab26c75f985769622d586cb428c"
        );

        assert_eq!(
            sha1(
                b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",
                None,
                None,
                None,
                None,
                None,
                None
            ),
            b"d343f49e7176d1c9b8ce6d92c9696462f3d1580d",
        )
    }
}
