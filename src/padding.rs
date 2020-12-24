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

mod test {
    use super::pkcs7;

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
}
