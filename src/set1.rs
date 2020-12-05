use crypto::buffer::ReadBuffer;
use crypto::buffer::WriteBuffer;
use crypto::*;

use std::collections::HashSet;

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

/// AES in ECB mode
///
/// Solution for problem 7 from set 1: <https://cryptopals.com/sets/1/challenges/7>
fn decrypt_aes_128_ecb(b: &[u8], k: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, k, blockmodes::NoPadding);

    let mut plaintext = Vec::new();
    let mut read_buffer = buffer::RefReadBuffer::new(&b);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(result) => {
                plaintext.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .map(|&i| i),
                );
                match result {
                    buffer::BufferResult::BufferUnderflow => break,
                    buffer::BufferResult::BufferOverflow => {}
                }
            }

            Err(_) => return Err(crate::Error::Empty),
        }
    }

    Ok(plaintext)
}

/// Is AES ECB
///
/// Solution for problem 8 from set 1: <https://cryptopals.com/sets/1/challenges/8>
fn detect_aes_128_ecb_mode(b: &[u8]) -> Result<bool, hex::FromHexError> {
    let b = hex::decode(b)?;

    const block_size: usize = 16; // 128 bits

    if b.len() % block_size != 0 {
        panic!("unsuported bytes length");
    }

    let blocks = b.len() / block_size;

    let mut is_ecb = false;
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut iteration = 0;

    loop {
        let current = &b[iteration * block_size..(iteration + 1) * block_size];
        if seen.contains(current) {
            is_ecb = true;
            break;
        }

        seen.insert(current);

        iteration += 1;
        if iteration == blocks {
            break;
        }
    }

    Ok(is_ecb)
}

mod test {
    use super::b64_to_hex;
    use super::break_repeating_xor_cipher;
    use super::decrypt_aes_128_ecb;
    use super::detect_aes_128_ecb_mode;
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

    #[test]
    fn test_decrypt_aes_in_ecb() {
        let bytes = base64::decode("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").unwrap();

        let have = decrypt_aes_128_ecb(&bytes, "YELLOW SUBMARINE".as_bytes()).unwrap();

        assert_eq!(have, "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}".as_bytes());
    }

    #[test]
    fn test_is_aes_in_ecb() {
        let bytes = String::from("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a").into_bytes();
        assert_eq!(detect_aes_128_ecb_mode(&bytes).unwrap(), true);
    }

    #[test]
    fn find_aes_in_ecb() {
        let reader = BufReader::new(File::open("./src/mock_data/aes_encrypted.txt").unwrap());

        let mut count = 0;
        for line in reader.lines() {
            if detect_aes_128_ecb_mode(&line.unwrap().into_bytes()).unwrap() {
                break
            }

            count += 1;
        }

        assert_eq!(count, 132);
    }
}
