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
        result.push(l[i] ^ r[i]);
    }

    Ok(result)
}

/// letter score is a helper function for problem 3/set1.
/// scores are assigned from table: <http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html>
fn letter_score(b: u8) -> f64 {
    match b {
        b'E' => 12.02,
        b'T' => 9.10,
        b'A' => 8.12,
        b'O' => 7.68,
        b'I' => 7.31,
        b'N' => 6.95,
        b'S' => 6.28,
        b'R' => 6.02,
        b'H' => 5.92,
        b'D' => 4.32,
        b'L' => 3.98,
        b'U' => 2.88,
        b'C' => 2.71,
        b'M' => 2.61,
        b'F' => 2.30,
        b'Y' => 2.11,
        b'W' => 2.09,
        b'G' => 2.03,
        b'P' => 1.82,
        b'B' => 1.49,
        b'V' => 1.11,
        b'K' => 0.69,
        b'X' => 0.17,
        b'Q' => 0.11,
        b'J' => 0.10,
        b'Z' => 0.07,
        b' ' => 0.15,
        _ => -15.0, // apply a high cut to words not in our dictionary.
    }
}

/// score cipher is a helper function for problem 3/set1.
fn score_cipher(cipher: &[u8]) -> f64 {
    let mut score = 0.0;

    for letter in cipher {
        let mut c = *letter as char;
        if c.is_ascii_alphabetic() {
            c = c.to_ascii_uppercase();
        }

        score += letter_score(c as u8);
    }

    score
}

/// Single byte xor cipher
///
/// Solution for problem 3 from set1: <https://cryptopals.com/sets/1/challenges/3>
fn single_byte_xor(b: &[u8]) -> Result<(u8, Vec<u8>), hex::FromHexError> {
    let input = hex::decode(b)?;

    let (mut high_score, mut message, mut key) = (0.0, Vec::new(), 0 as u8);

    for i in 0..128 {
        let mut plaintext = Vec::new();

        for c in &input {
            plaintext.push(c ^ i);
        }

        let score = score_cipher(&plaintext);

        if score > high_score {
            high_score = score;
            message = plaintext;
            key = i;
        }
    }

    Ok((key, message))
}

mod test {
    use super::hex_to_b64;
    use super::single_byte_xor;
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
        let (l, r) = (
            String::from("1c0111001f010100061a024b53535009181c"),
            String::from("686974207468652062756c6c277320657965"),
        );
        let have = xor_buffers(l.as_bytes(), r.as_bytes());
        let want = String::from("746865206b696420646f6e277420706c6179").into_bytes();

        assert_eq!(have.unwrap(), hex::decode(&want).unwrap());
    }

    #[test]
    fn test_single_xor_cipher() {
        let input =
            String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let (_, message) = single_byte_xor(input.as_bytes()).unwrap();

        assert_eq!(
            "Cooking MC's like a pound of bacon",
            String::from_utf8(message).unwrap()
        );
    }
}
