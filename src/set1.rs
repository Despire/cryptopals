/// Convert hex to base64
///
/// Solution to problem 1 from set 1: <https://cryptopals.com/sets/1/challenges/1>
fn hex_to_b64(b: &[u8]) -> Result<Vec<u8>, hex::FromHexError> { 
    Ok(base64::encode(hex::decode(b)?).into_bytes())
}

mod test {
    use super::hex_to_b64;

    #[test]
    fn test_hex_to_b64() {
        let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let want = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

        let have = hex_to_b64(input.as_bytes());

        assert_eq!(have.unwrap(), want.into_bytes());
    }
}
