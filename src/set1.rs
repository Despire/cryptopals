/// Convert hex to base64
///
/// Solution to problem 1 from set 1: <https://cryptopals.com/sets/1/challenges/1>
fn hex_to_b64(b: &[u8]) -> Result<Vec<u8>, hex::FromHexError> { 
    Ok(base64::encode(hex::decode(b)?).into_bytes())
}

/// Fixed XOR for two byte buffers
/// 
/// Solution to problem 2 from set 1: <https://cryptopals.com/sets/1/challenges/2>
fn xor_buffers(l: &[u8], r: &[u8]) -> Result<Vec<u8>, hex::FromHexError> {
    assert_eq!(l.len(), r.len());

    let l = hex::decode(l)?;
    let r = hex::decode(r)?;
    let mut result = Vec::new();

    for i in 0..l.len() {
        result.push(l[i]^r[i]);
    }

    Ok(result)
}

mod test {
    use super::hex_to_b64;
    use super::xor_buffers;

    #[test]
    fn test_hex_to_b64() {
        let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let want = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

        let have = hex_to_b64(input.as_bytes());

        assert_eq!(have.unwrap(), want.into_bytes());
    }

    #[test]
    fn text_xor_buffers() {
        // input
        let (l, r) = (String::from("1c0111001f010100061a024b53535009181c"), String::from("686974207468652062756c6c277320657965"));
        let have =  xor_buffers(l.as_bytes(), r.as_bytes());
        let want = String::from("746865206b696420646f6e277420706c6179").into_bytes();

        assert_eq!(have.unwrap(), hex::decode(&want).unwrap());
    }
}
