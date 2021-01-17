use crypto::symmetriccipher;

/// Implement CTR mode
///
/// Solution for problem 2 from set3: <https://cryptopals.com/sets/3/challenges/18>
pub fn aes_128_ctr(
    b: &[u8],
    k: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    if nonce.len() != 8 {
        panic!("invalid nonce length, must be 8 bytes");
    }

    let mut keystream = Vec::new();
    let mut counter: u64 = 0x0;

    for chunk in b.chunks(16) {
        let mut v = Vec::from(nonce);
        v.extend_from_slice(&counter.to_le_bytes());

        let mut k = crate::aes_ecb::encrypt_aes_128_ecb(&v, k)?;

        if chunk.len() < k.len() {
            k.truncate(chunk.len());
        }

        keystream.extend_from_slice(
            &crate::set1::xor_buffers(hex::encode(&chunk).as_bytes(), hex::encode(&k).as_bytes())
                .unwrap(),
        );

        counter += 1;
    }

    Ok(keystream)
}

mod test {
    use super::aes_128_ctr;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_aes_128_ctr() {
        // Test case 1
        let bytes = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();

        let mut nonce = [0 as u8; 8];
        let have = aes_128_ctr(&bytes, "YELLOW SUBMARINE".as_bytes(), &nonce).unwrap();

        assert_eq!(
            have,
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".as_bytes()
        );

        // Test case 2
        let bytes = "some unpadded text".as_bytes();
        let mut nonce = [0 as u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = aes_128_ctr(bytes, "KEY".as_bytes(), &nonce).unwrap();
        let plaintext = aes_128_ctr(&ciphertext, "KEY".as_bytes(), &nonce).unwrap();
        assert_eq!(plaintext, "some unpadded text".as_bytes());
    }
}
