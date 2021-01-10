use crate::mt19937::MT19937;
use crypto::symmetriccipher;
use rand::Rng;
use std::collections::HashMap;
use std::{thread, time};

/// break_mt19937_stream_cipher breaks the mt19937 stream cipher
///
/// Solution for problem 8 from set 3: <https://cryptopals.com/sets/3/challenges/24>
pub fn break_mt19937_stream_cipher(seed: i16, b: &[u8]) -> Option<i16> {
    let msg_string = String::from_utf8(Vec::from(b)).unwrap();

    let encrypt = |b: &[u8]| -> Vec<u8> {
        let mut prefix: Vec<u8> = vec![b'B', (seed % 16) as u8];
        prefix.extend_from_slice(b);
        prefix.extend_from_slice(";password_reset=true".as_bytes());

        return crate::mt_19937_cipher::mt19937_stream_cipher(seed, &prefix);
    };

    let ciphertext = encrypt(b);
    for i in std::i16::MIN..std::i16::MAX {
        let plaintext_bytes = crate::mt_19937_cipher::mt19937_stream_cipher(i, &ciphertext);
        let plaintext_string = String::from_utf8_lossy(&plaintext_bytes);

        if plaintext_string.contains(&msg_string) {
            return Some(i);
        }
    }

    None
}

/// clone_mt19937_from_output creates a clone mt19937 generator
/// form the output of another (with which we can predict values).
///
/// Solution for problem 7 from set 3: <https://cryptopals.com/sets/3/challenges/23>
pub fn clone_mt19937_from_output(seed: i32) -> MT19937 {
    let mut gen = MT19937::new(seed);

    let mut outputs = Vec::new();
    for _ in 0..624 {
        outputs.push(gen.extract_number().unwrap());
    }

    let mut gen2 = MT19937::uninitialized();
    for i in (0..624).rev() {
        gen2.untemper(i, outputs[i]);
    }

    gen2
}

/// crack_mt19937_seed cracks the seed for the mt19937 generator.
///
/// Solution for problem 6 from set 3: <https://cryptopals.com/sets/3/challenges/22>
pub fn crack_mt19937_seed(seed: i32) -> Option<i32> {
    let mut gen = MT19937::new(seed);

    let first_ouput = gen.extract_number().unwrap();

    let mut guessed_seed: Option<i32> = None;
    for i in std::i32::MIN..std::i32::MAX {
        if MT19937::new(i).extract_number().unwrap() == first_ouput {
            guessed_seed = Some(i);
            break;
        }
    }

    guessed_seed
}

/// break_fixed_nonce_ctr breaks aes_ctr with fixed nonce
///
/// Solution for problem 3 from set 3: <https://cryptopals.com/sets/3/challenges/19>
pub fn break_fixed_nonce_ctr(
    input: &Vec<Vec<u8>>,
    k: &[u8],
) -> Result<Vec<Vec<u8>>, symmetriccipher::SymmetricCipherError> {
    let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
    let mut longest = 0;
    for line in input {
        if line.len() > longest {
            longest = line.len();
        }

        ciphertexts.push(crate::aes_ctr::aes_128_ctr(&line, k, &[0 as u8; 8])?);
    }

    let to_break: Vec<_> = ciphertexts.iter().cloned().map(|x| x).collect();
    let mut key = Vec::new();

    for column in 0..longest {
        let column_vec: Vec<_> = to_break
            .iter()
            .map(|x| match x.get(column) {
                Some(v) => *v,
                None => to_break[0][0],
            })
            .collect();
        let (_, k, _) = crate::set1::single_byte_xor(hex::encode(&column_vec).as_bytes()).unwrap();
        key.push(k);
    }

    let mut plaintexts = Vec::new();

    for v in to_break {
        let plaintext = crate::set1::xor_buffers(
            hex::encode(&v).as_bytes(),
            hex::encode(&key[..v.len()]).as_bytes(),
        )
        .unwrap();

        plaintexts.push(plaintext);
    }

    Ok(plaintexts)
}

/// encrypt_random_chosen_msg is a helper function for problem 1 from set 3.
///
/// Solution for problem 1 from set 3: <https://cryptopals.com/sets/3/challenges/17>
pub fn encrypt_random_chosen_msg(
    random_msg: &[u8],
    k: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    crate::aes_cbc::encrypt_aes_128_cbc(random_msg, k, iv)
}

/// decrypt_random_chosen_msg is a helper function for problem 1 from set 3.
///
/// Solution for problem 1 from set 3: <https://cryptopals.com/sets/3/challenges/17>
pub fn decrypt_random_chosen_msg(b: &[u8], k: &[u8], iv: &[u8]) -> Result<bool, crate::Error> {
    let plaintext = crate::aes_cbc::decrypt_aes_128_cbc(b, k, iv).unwrap();
    let k = String::from_utf8_lossy(&plaintext.clone());
    let _ = k;
    if let Err(_) = crate::padding::pkcs7validate(&plaintext) {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// attack_two_cbc_blocks decrypts the second block.
/// Help source: <https://en.wikipedia.org/wiki/Padding_oracle_attack>
/// Solution for problem 1 from set 3: <https://cryptopals.com/sets/3/challenges/17>
pub fn attack_two_cbc_blocks(
    block_size: usize,
    first: &[u8],
    second: &[u8],
    k: &[u8],
    iv: &[u8],
) -> Vec<u8> {
    let mut plaintext_prior_xor = Vec::new();
    let mut plaintext = Vec::new();

    for b in (0..block_size).rev() {
        let padding_byte = (block_size - b) as u8;

        let mut block = Vec::from(first);
        block.extend_from_slice(second);

        for j in 0..plaintext_prior_xor.len() {
            block[j + b + 1] = plaintext_prior_xor[j] ^ padding_byte;
        }

        for i in 0..=255 as u8 {
            block[b] = i;

            if !decrypt_random_chosen_msg(&block, k, iv).unwrap() {
                continue;
            }

            plaintext.insert(0, (padding_byte ^ i) ^ first[b]);
            plaintext_prior_xor.insert(0, padding_byte ^ i);
            break;
        }
    }

    plaintext
}

/// cbc_oracle decrypts the ciphertext without the key.
///
/// Solution for problem 1 from set 3: <https://cryptopals.com/sets/3/challenges/17>
pub fn cbc_oracle(random_msgs: &[String], k: &[u8], iv: &[u8]) -> String {
    let msg =
        base64::decode(random_msgs[rand::thread_rng().gen_range(0, random_msgs.len())].as_bytes())
            .unwrap();

    let ciphertext = encrypt_random_chosen_msg(&msg, k, iv).unwrap();
    let block_size = 16; // 128 bit

    let mut plaintext = Vec::new();

    let mut iter = ciphertext.chunks(block_size);
    let mut previous_block = iv;
    loop {
        let current_block = match iter.next() {
            Some(v) => v,
            None => break,
        };

        plaintext.extend_from_slice(&attack_two_cbc_blocks(
            block_size,
            previous_block,
            current_block,
            k,
            iv,
        ));

        previous_block = current_block;
    }

    String::from_utf8_lossy(&plaintext).to_string()
}

mod test {
    use super::break_fixed_nonce_ctr;
    use super::break_mt19937_stream_cipher;
    use super::cbc_oracle;
    use super::clone_mt19937_from_output;
    use super::crack_mt19937_seed;
    use crate::mt19937::MT19937;

    use rand::Rng;
    use rand_core::{OsRng, RngCore};
    use std::fs::File;
    use std::io::{self, prelude::*, BufReader};

    #[test]
    fn test_break_mt19937_stream_cipher() {
        let mut seed: i16 = rand::thread_rng().gen();
        let known_plaintext = "despire".as_bytes();
        let have = break_mt19937_stream_cipher(seed, known_plaintext);
        assert_eq!(have.unwrap(), seed);
    }

    #[test]
    fn test_clone_mt19937_from_output() {
        let seed: i32 = rand::thread_rng().gen();

        let mut cloned_gen = clone_mt19937_from_output(seed);
        let mut gen = MT19937::new(seed);

        for _ in 0..624 {
            assert_eq!(
                cloned_gen.extract_number().unwrap(),
                gen.extract_number().unwrap(),
            )
        }
    }

    #[test]
    fn test_crack_mt19937_seed() {
        let seed: i32 = rand::thread_rng().gen();
        let guessed_seed = crack_mt19937_seed(seed);
        assert_eq!(seed, guessed_seed.unwrap());
    }

    #[test]
    fn test_break_fixed_nonce_statistically() {
        let mut input: Vec<Vec<u8>> = Vec::new();

        let reader = BufReader::new(File::open("./src/mock_data/aes_ctr.txt").unwrap());

        for line in reader.lines() {
            input.push(base64::decode(line.unwrap().into_bytes()).unwrap());
        }

        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        for plaintext in break_fixed_nonce_ctr(&input, &unknown_key).unwrap() {
            println!("{:?}", String::from_utf8_lossy(&plaintext));
        }
    }

    #[test]
    fn test_break_fixed_nonce_ctr() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let mut inputs: Vec<Vec<u8>> = Vec::new();
        inputs.push(base64::decode("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==").unwrap());
        inputs.push(base64::decode("Q29taW5nIHdpdGggdml2aWQgZmFjZXM=").unwrap());
        inputs.push(base64::decode("RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==").unwrap());
        inputs.push(base64::decode("RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=").unwrap());
        inputs.push(base64::decode("SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk").unwrap());
        inputs.push(base64::decode("T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==").unwrap());
        inputs.push(base64::decode("T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=").unwrap());
        inputs.push(base64::decode("UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==").unwrap());
        inputs.push(base64::decode("QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=").unwrap());
        inputs.push(base64::decode("T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl").unwrap());
        inputs.push(base64::decode("VG8gcGxlYXNlIGEgY29tcGFuaW9u").unwrap());
        inputs.push(base64::decode("QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==").unwrap());
        inputs.push(base64::decode("QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=").unwrap());
        inputs.push(base64::decode("QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==").unwrap());
        inputs.push(base64::decode("QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=").unwrap());
        inputs.push(base64::decode("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").unwrap());
        inputs.push(base64::decode("VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==").unwrap());
        inputs.push(base64::decode("SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==").unwrap());
        inputs.push(base64::decode("SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==").unwrap());
        inputs.push(base64::decode("VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==").unwrap());
        inputs.push(base64::decode("V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==").unwrap());
        inputs.push(base64::decode("V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==").unwrap());
        inputs.push(base64::decode("U2hlIHJvZGUgdG8gaGFycmllcnM/").unwrap());
        inputs.push(base64::decode("VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=").unwrap());
        inputs.push(base64::decode("QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=").unwrap());
        inputs.push(base64::decode("VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=").unwrap());
        inputs.push(base64::decode("V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=").unwrap());
        inputs.push(base64::decode("SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==").unwrap());
        inputs.push(base64::decode("U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==").unwrap());
        inputs.push(base64::decode("U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=").unwrap());
        inputs.push(base64::decode("VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==").unwrap());
        inputs.push(base64::decode("QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu").unwrap());
        inputs.push(base64::decode("SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=").unwrap());
        inputs.push(base64::decode("VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs").unwrap());
        inputs.push(base64::decode("WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=").unwrap());
        inputs.push(base64::decode("SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0").unwrap());
        inputs.push(base64::decode("SW4gdGhlIGNhc3VhbCBjb21lZHk7").unwrap());
        inputs
            .push(base64::decode("SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=").unwrap());
        inputs.push(base64::decode("VHJhbnNmb3JtZWQgdXR0ZXJseTo=").unwrap());
        inputs.push(base64::decode("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").unwrap());

        for plaintext in break_fixed_nonce_ctr(&inputs, &unknown_key).unwrap() {
            println!("{:?}", String::from_utf8_lossy(&plaintext));
        }
    }

    #[test]
    fn test_cbc_oracle() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let mut iv = [0 as u8; 16];
        OsRng.fill_bytes(&mut iv);

        let random_msgs = [
            String::from("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
            String::from(
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            ),
            String::from("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
            String::from("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
            String::from("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
            String::from("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
            String::from("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
            String::from("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
            String::from("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
            String::from("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
        ];

        let have = cbc_oracle(&random_msgs, &unknown_key, &iv);
        println!("{}", have);
    }
}
