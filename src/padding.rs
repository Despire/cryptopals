/// PKCS#7 padding
///
/// Solution for problem 1 from set 2: <https://cryptopals.com/sets/2/challenges/9>
pub fn pkcs7(b: &[u8], l: usize) -> Vec<u8> {
    if b.len() % l == 0 {
        return Vec::from(b);
    }

    let blocks = l - (b.len() % l);

    let mut result = Vec::from(b);

    for _ in 0..blocks {
        result.push(blocks as u8);
    }

    result
}

/// PKCS#7 padding validation
///
/// Solution for problem 7 from set 2: <https://cryptopals.com/sets/2/challenges/15>
pub fn pkcs7validate(b: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let padding = b[b.len() - 1];

    if padding == 0 {
        return Err(crate::Error::InvalidPKCS7);
    }

    if padding as usize > b.len() {
        return Err(crate::Error::InvalidPKCS7);
    }

    for i in 1..padding as usize {
        if b[b.len() - 1 - i] != padding {
            return Err(crate::Error::InvalidPKCS7);
        }
    }

    Ok(Vec::from(&b[..b.len() - padding as usize]))
}

mod test {
    use super::pkcs7;
    use super::pkcs7validate;

    #[test]
    fn test_pkcs7() {
        let input = String::from("YELLOW SUBMARINE");
        let have = pkcs7(input.as_bytes(), 20);

        assert_eq!(have, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());

        let input = String::from("TT");
        let have = pkcs7(input.as_bytes(), 7);
        assert_eq!(have, "TT\x05\x05\x05\x05\x05".as_bytes());

        let input = String::from("TTTT");
        let have = pkcs7(input.as_bytes(), 3);
        assert_eq!(have, "TTTT\x02\x02".as_bytes());
    }

    #[test]
    fn test_pkcs7_validate() {
        let input = String::from("ICE ICE BABY\u{4}\u{4}\u{4}\u{4}");
        let have = pkcs7validate(input.as_bytes());

        assert_eq!(have.unwrap(), "ICE ICE BABY".as_bytes());

        let input = String::from("ICE ICE BABY\u{5}\u{5}\u{5}\u{5}");
        let have = pkcs7validate(input.as_bytes());

        assert_eq!(have.err().unwrap(), crate::Error::InvalidPKCS7);

        let input = String::from("ICE ICE BABY\u{1}\u{2}\u{3}\u{4}");
        let have = pkcs7validate(input.as_bytes());

        assert_eq!(have.err().unwrap(), crate::Error::InvalidPKCS7);

        let input = String::from("ICE ICE BABY");
        let have = pkcs7validate(input.as_bytes());

        assert_eq!(have.err().unwrap(), crate::Error::InvalidPKCS7);

        let input = String::from("ICE ICE BABY\u{1}");
        let have = pkcs7validate(input.as_bytes());

        assert_eq!(have.unwrap(), "ICE ICE BABY".as_bytes());
    }
}
