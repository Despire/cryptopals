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

/// cbc_oracle decrypts the ciphertext without the key.
///
/// Solution for problem 1 from set 3: <https://cryptopals.com/sets/3/challenges/17>
pub fn cbc_oracle(random_msgs: &[String], k: &[u8], iv: &[u8]) -> String {
    let msg =
        base64::decode(random_msgs[rand::thread_rng().gen_range(0, random_msgs.len())].as_bytes())
            .unwrap();

    let ciphertext = encrypt_random_chosen_msg(&msg, k, iv).unwrap();
    let block_size = 16; // 128 bit

    let mut plaintext = Vec::from(ciphertext.clone());

    let mut iter = ciphertext.chunks(block_size).rev();

    loop {
        let current_block = match iter.next() {
            Some(v) => v,
            None => break,
        };

        let previous_block = match iter.next() {
            Some(v) => v,
            None => iv,
        };

        for b in (0..block_size).rev() {
            let padding_byte = (block_size - b) as u8;

            let mut test_block = Vec::from(previous_block);
            test_block.extend_from_slice(current_block);

            for j in b + 1..block_size {
                test_block[j] = previous_block[j] ^ plaintext[j] ^ padding_byte;
            }

            for i in 0..=255 as u8 {
                test_block[b] = i;

                if !decrypt_random_chosen_msg(&test_block, k, iv).unwrap() {
                    continue;
                }

                plaintext[b] = (padding_byte ^ i) ^ previous_block[b];
                break;
            }
        }
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

        // Sometimes is gets decrypted half way trough sometimes giberish comes out
        // I did not finish this problem.
        let have = cbc_oracle(&random_msgs, &unknown_key, &iv);
        println!("{}", have);
    }
}
