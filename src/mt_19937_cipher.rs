use crate::mt19937::MT19937;

/// mt19937_stream_cipher creates a stream cipher from the ouput of the mt19937 generator.///
///
/// Solution for problem 8 from set 3: <https://cryptopals.com/sets/3/challenges/24>
pub fn mt19937_stream_cipher(seed: i16, b: &[u8]) -> Vec<u8> {
    let mut keystream = Vec::new();
    let mut gen = MT19937::new(seed as i32);

    for chunk in b.chunks(4) {
        keystream.extend_from_slice(
            &crate::set1::xor_buffers(
                hex::encode(&chunk).as_bytes(),
                hex::encode(&(gen.extract_number().unwrap() as u32).to_le_bytes()[..chunk.len()])
                    .as_bytes(),
            )
            .unwrap(),
        )
    }

    keystream
}

mod test {
    use super::mt19937_stream_cipher;
    use rand::Rng;

    #[test]
    fn test_encrypt_decrypt() {
        // Test case 2
        let seed: i16 = rand::thread_rng().gen();
        let bytes = "some unpadded text".as_bytes();
        let ciphertext = mt19937_stream_cipher(seed, bytes);
        let plaintext = mt19937_stream_cipher(seed, &ciphertext);
        assert_eq!(plaintext, "some unpadded text".as_bytes());
    }
}
