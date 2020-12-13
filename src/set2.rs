use crypto::symmetriccipher;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;

/// BATE (Byte at a time encryption)
///
/// Soludion for problem 4 from set 2: <https://cryptopals.com/sets/2/challenges/12>
pub fn ecb_oracle(b: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    static key: [u8; 16] = [
        117, 73, 22, 23, 214, 139, 241, 39, 171, 181, 118, 0, 207, 117, 229, 162,
    ];

    static unknown_string: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let decoded_unknown = base64::decode(&unknown_string).unwrap();

    let mut plaintext = Vec::from(b);
    plaintext.extend_from_slice(&decoded_unknown);

    crate::aes_ecb::encrypt_aes_128_ecb(&plaintext, &key)
}

/// Decrypts the unknown string for the ecb oracle
/// described in problem: <https://cryptopals.com/sets/2/challenges/12>
pub fn decrypt_unknown_string_ecb_oracle() -> Vec<u8> {
    let block_size = {
        let unknown_output = ecb_oracle(&Vec::new()).unwrap();
        let mut current_length = unknown_output.len();

        let mut m = Vec::new();
        while current_length == unknown_output.len() {
            m.push(b'A');
            current_length = ecb_oracle(&m).unwrap().len();
        }

        current_length - unknown_output.len()
    };

    let is_ecb = {
        let mut block = Vec::with_capacity(block_size * 2);
        for i in 0..block.capacity() {
            block.push(b'A');
        }

        let is_ecb = crate::set1::detect_aes_128_ecb_mode(
            hex::encode(ecb_oracle(&block).unwrap()).as_bytes(),
        )
        .unwrap();

        is_ecb
    };

    if !is_ecb {
        panic!("the cipher is not using ecb mode");
    }

    let end = ecb_oracle(&Vec::new()).unwrap().len();
    let mut cracked_text = Vec::new();

    while cracked_text.len() != end {
        cracked_text.push({
            let mut prefix = block_size - ((1 + cracked_text.len()) % block_size);
            if prefix == block_size {
                prefix -= block_size;
            }

            let mut base = Vec::new();
            for i in 0..prefix {
                base.push(b'A');
            }

            let expanded_length: usize = base.len() + 1 + cracked_text.len();
            let ciphertext = ecb_oracle(&base).unwrap();

            let mut dict = HashMap::new();
            for i in 0..256 {
                let mut b = base.clone();
                b.extend_from_slice(&cracked_text);
                b.push(i as u8);

                let mut c = ecb_oracle(&b).unwrap();
                c.truncate(expanded_length);

                dict.insert(c, b);
            }

            match dict.get(&ciphertext[..expanded_length]) {
                Some(v) => *v.get(v.len() - 1).unwrap(),
                None => b'\0',
            }
        })
    }

    cracked_text
}

/// generate_key generetes a random key
///
/// Reads exactly k.len() bytes into k.
pub fn generate_key(k: &mut [u8]) {
    OsRng.fill_bytes(k)
}

pub fn encryption_oracle(
    b: &[u8],
    r: u8, // for test mocking
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut key = [0 as u8; 16]; // 128 bit key
    generate_key(&mut key);

    let mut ps: Vec<u8> = Vec::new();
    ps.resize(rand::thread_rng().gen_range(5, 11), 0x0);

    generate_key(&mut ps);

    let mut plaintext = ps.clone();

    plaintext.extend_from_slice(b);
    plaintext.extend_from_slice(&ps);

    if r % 2 == 1 {
        return crate::aes_ecb::encrypt_aes_128_ecb(&plaintext, &key);
    }

    let mut iv = [0 as u8; 16];
    generate_key(&mut iv);

    return crate::aes_cbc::encrypt_aes_128_cbc(&plaintext, &key, &iv);
}

mod test {
    use super::decrypt_unknown_string_ecb_oracle;
    use super::ecb_oracle;
    use super::encryption_oracle;
    use super::generate_key;

    #[test]
    fn test_generate_random_key() {
        let mut input = [0x0, 0x0, 0x0, 0x0];
        generate_key(&mut input);

        assert_ne!(input, [0x0, 0x0, 0x0, 0x0]);
    }

    #[test]
    fn test_encryption_oracle() {
        let input = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}";
        let r = 1;

        let have = encryption_oracle(input.as_bytes(), r).unwrap();

        assert_eq!(
            crate::set1::detect_aes_128_ecb_mode(hex::encode(&have).as_bytes()).unwrap(),
            true
        );

        let r = 2;

        let have = encryption_oracle(input.as_bytes(), r).unwrap();

        assert_eq!(
            crate::set1::detect_aes_128_ecb_mode(hex::encode(&have).as_bytes()).unwrap(),
            false
        );
    }

    #[test]
    fn test_decrypt_unknown_string_ecb_oracle() {
        // let mut input: Vec<u8> = Vec::new();

        // let mut result = ecb_oracle(&input).unwrap();
        // let initial_length = result.len();
        // let mut new_length = initial_length;

        // while initial_length == new_length {
        //     input.push(b'A');
        //     result = ecb_oracle(&input).unwrap();
        //     new_length = result.len();
        // }

        // let block_size = new_length - initial_length;
        // println!("{}", block_size);

        // // detect if it is ecb (two block with same input map to the same output).
        // let mut block = Vec::new();

        // for i in 0..block_size {
        //     block.push(b'A');
        // }

        // let mut plaintext = block.clone();
        // plaintext.extend_from_slice(&block);

        // let ciphertext = ecb_oracle(&plaintext).unwrap();

        // assert_eq!(
        //     crate::set1::detect_aes_128_ecb_mode(hex::encode(&ciphertext).as_bytes()).unwrap(),
        //     true
        // );

        // let unknown_string = ecb_oracle(&Vec::new()).unwrap();
        // let mut cracked = Vec::new();

        // while cracked.len() != unknown_string.len() {
        //     cracked.push(next_byte(block_size, &cracked));
        // }

        assert_eq!(
            decrypt_unknown_string_ecb_oracle(), "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{1}\u{0}\u{0}\u{0}\u{0}\u{0}".as_bytes()
        );
    }

    // fn next_byte(block_size: usize, cracked: &[u8]) -> u8 {
    //     let mut prefix = block_size - ((1 + cracked.len()) % block_size);
    //     if prefix == block_size {
    //         prefix -= block_size;
    //     }

    //     let mut base: Vec<u8> = Vec::new();
    //     for i in 0..prefix {
    //         base.push(b'A');
    //     }

    //     let expanded_length: usize = base.len() + 1 + cracked.len();

    //     let ciphertext = ecb_oracle(&base).unwrap();

    //     let mut dict = HashMap::new();

    //     for i in 0..256 {
    //         let mut b = base.clone();
    //         b.extend_from_slice(&cracked);
    //         b.push(i as u8);

    //         let mut c = ecb_oracle(&b).unwrap();
    //         c.truncate(expanded_length);

    //         dict.insert(c, b);
    //     }

    //     match dict.get(&ciphertext[..expanded_length]) {
    //         Some(v) => {
    //             let v = *v.get(v.len() - 1).unwrap();
    //             v
    //         }
    //         None => b'\0',
    //     }
    // }
}
