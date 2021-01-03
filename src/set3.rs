use crypto::symmetriccipher;
use rand::Rng;

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
    use super::cbc_oracle;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_cbc_oracle() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        unknown_key = [
            26, 131, 86, 171, 76, 19, 96, 26, 65, 251, 57, 215, 16, 45, 211, 160,
        ];

        let mut iv = [0 as u8; 16];
        OsRng.fill_bytes(&mut iv);

        iv = [
            168, 147, 123, 79, 169, 65, 15, 214, 174, 136, 104, 60, 160, 186, 118, 109,
        ];

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
