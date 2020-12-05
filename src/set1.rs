/// Convert hex to base64
///
/// Solution to problem 1 from set 1: <https://cryptopals.com/sets/1/challenges/1>
fn hex_to_b64(b: &[u8]) -> Result<Vec<u8>, hex::FromHexError> {
    Ok(base64::encode(hex::decode(b)?).into_bytes())
}

/// helper function to convert from b64 to hex
fn b64_to_hex(b: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let b: Vec<_> = b.iter().cloned().filter(|&x| x != b'\n').collect();
    let d = base64::decode(b)?;
    let e = hex::encode(d);

    Ok(e.into_bytes())
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
fn single_byte_xor(b: &[u8]) -> Result<(f64, u8, Vec<u8>), hex::FromHexError> {
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

    Ok((high_score, key, message))
}

/// Find single byte xor
///
/// Solution for problem 4 from set1: <https://cryptopals.com/sets/1/challenges/4>
fn find_single_byte_xor(b: Vec<Vec<u8>>) -> Result<Vec<u8>, hex::FromHexError> {
    let (mut score, mut result) = (0.0, Vec::new());

    for cipher in b {
        let (s, _, m) = single_byte_xor(&cipher)?;

        if s > score {
            score = s;
            result = m;
        }
    }

    Ok((result))
}

/// Repeating XOR-Key
///
/// Solution for problem 5 from set1: <https://cryptopals.com/sets/1/challenges/5>
fn repeating_xor_key(b: &[u8]) -> Vec<u8> {
    const KEY: &'static str = "ICE";

    let mut result = Vec::new();

    for i in 0..b.len() {
        result.push(b[i] ^ KEY.bytes().nth(i % KEY.len()).unwrap());
    }

    result
}

/// hamming distnace is a helper function is a helper function for solving problem 6.
///
/// Calculates the number of bits that differ.
fn hamming_distance(b1: &[u8], b2: &[u8]) -> Result<usize, hex::FromHexError> {
    let bits = xor_buffers(b1, b2)?;

    let mut count = 0;

    for mut i in bits {
        for _ in 0..8 {
            if i & 0x1 == 1 {
                count += 1;
            }

            i >>= 1;
        }
    }

    Ok(count)
}

/// Break repeating XOR-cipher
///
/// Solution for problem 6 from set1: <https://cryptopals.com/sets/1/challenges/6>
fn break_repeating_xor_cipher(b: &[u8]) -> Result<Vec<u8>, hex::FromHexError> {
    let (mut score, mut size) = (1000, 0);
    // Find the keysize.
    for key_size in 2..41 {
        let chunk1 = &b[..4 * key_size];
        let chunk2 = &b[4 * key_size..(8 * key_size % b.len())];

        let dist = hamming_distance(
            &hex::encode(&chunk1).into_bytes(),
            &hex::encode(&chunk2).into_bytes(),
        )? / key_size;

        if dist <= score {
            score = dist;
            size = key_size
        }
    }

    let mut key: Vec<u8> = Vec::with_capacity(size);
    for i in 0..size {
        let d: Vec<_> = b.chunks(size).filter_map(|x| x.get(i).cloned()).collect();
        let (_, k, m) = single_byte_xor(&hex::encode(d).into_bytes())?;

        key.push(k);

    }

    Ok(key)
}

mod test {
    use super::b64_to_hex;
    use super::break_repeating_xor_cipher;
    use super::find_single_byte_xor;
    use super::hamming_distance;
    use super::hex_to_b64;
    use super::repeating_xor_key;
    use super::single_byte_xor;
    use super::xor_buffers;

    use std::fs::File;
    use std::io::{self, prelude::*, BufReader};

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
        let (_, _, message) = single_byte_xor(input.as_bytes()).unwrap();

        assert_eq!(
            "Cooking MC's like a pound of bacon",
            String::from_utf8(message).unwrap()
        );
    }

    #[test]
    fn test_find_single_xor_cipher() {
        let mut input: Vec<Vec<u8>> = Vec::new();

        let reader = BufReader::new(File::open("./src/mock_data/single_xor_ciphers.txt").unwrap());

        for line in reader.lines() {
            input.push(line.unwrap().into_bytes());
        }

        assert_eq!(
            find_single_byte_xor(input).unwrap(),
            "Now that the party is jumping\n".as_bytes()
        );
    }

    #[test]
    fn test_repeating_xor_key() {
        let input = String::from(
            r"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal",
        );

        let have = repeating_xor_key(input.as_bytes());

        assert_eq!(hex::encode(have), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn test_hamming_distance() {
        let (b1, b2) = (hex::encode("this is a test"), hex::encode("wokka wokka!!!"));
        let res = hamming_distance(b1.as_bytes(), b2.as_bytes());

        assert_eq!(res.unwrap(), 37);
    }

    #[test]
    fn test_break_repeating_xor_cipher() {
        let bytes = base64::decode("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").unwrap();

        assert_eq!(
            break_repeating_xor_cipher(&bytes).unwrap(),
            "Terminator X: Bring the noise".as_bytes()
        );
    }
}
