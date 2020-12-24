use crypto::symmetriccipher;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::collections::HashSet;

/// ECB oracle harder
///
/// Solution for problem 6 from set 2: <https://cryptopals.com/sets/2/challenges/14>
pub fn ecb_oracle_harder(
    p: &[u8],
    b: &[u8],
    k: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut prefix = Vec::from(p);

    static UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let decoded_unknown = base64::decode(&UNKNOWN_STRING).unwrap();

    prefix.extend_from_slice(b);
    prefix.extend_from_slice(&decoded_unknown);

    crate::aes_ecb::encrypt_aes_128_ecb(&prefix, k)
}

/// Decrypts the unknown string for the ecb oracle
/// described in problem: <https://cryptopals.com/sets/2/challenges/14>
pub fn decrypt_unknown_string_ecb_oracle_harder(p: &[u8], k: &[u8]) -> Vec<u8> {
    let block_size = {
        let unknown_prefix_suffix = ecb_oracle_harder(p, &Vec::new(), k).unwrap();
        let mut current_length = unknown_prefix_suffix.len();

        let mut m = Vec::new();
        while current_length == unknown_prefix_suffix.len() {
            m.push(b'A');
            current_length = ecb_oracle_harder(p, &m, k).unwrap().len();
        }

        current_length - unknown_prefix_suffix.len()
    };

    let is_ecb = {
        let mut block = Vec::with_capacity(block_size * 4);
        for _ in 0..block.capacity() {
            block.push(b'A');
        }

        let is_ecb = crate::set1::detect_aes_128_ecb_mode(
            hex::encode(ecb_oracle_harder(p, &block, k).unwrap()).as_bytes(),
        )
        .unwrap();

        is_ecb
    };

    if !is_ecb {
        panic!("the cipher is not using ecb mode");
    }

    let prefix_length = {
        let mut chars = vec![b'A'];

        let empty = ecb_oracle_harder(p, &Vec::new(), k).unwrap();
        let one_char = ecb_oracle_harder(p, &chars, k).unwrap();

        let mut index = 0;
        for i in (0..one_char.len()).step_by(block_size) {
            let left_block = &empty[i..i + block_size];
            let right_block = &one_char[i..i + block_size];

            if left_block != right_block {
                index = i;
                break;
            }
        }

        let mut previous_block = Vec::from(&one_char[index..index + block_size]);
        loop {
            chars.push(b'A');

            let temp = ecb_oracle_harder(p, &chars, k).unwrap();
            let current_block = Vec::from(&temp[index..index + block_size]);

            if previous_block == current_block {
                chars.pop();
                break;
            }

            previous_block = current_block;
        }

        index + block_size - chars.len()
    };

    if prefix_length < 0 {
        panic!("couldn't find prefix length");
    }

    let end = ecb_oracle_harder(p, &Vec::new(), k).unwrap().len() - prefix_length;
    let mut cracked_text = Vec::new();

    while cracked_text.len() != end {
        cracked_text.push({
            let mut prefix = block_size - ((1 + prefix_length + cracked_text.len()) % block_size);
            if prefix == block_size {
                prefix -= block_size;
            }

            let mut base = Vec::new();
            for _ in 0..prefix {
                base.push(b'A');
            }

            let expanded_length: usize = prefix_length + base.len() + 1 + cracked_text.len();
            let ciphertext = ecb_oracle_harder(p, &base, k).unwrap();

            let mut dict = HashMap::new();
            for i in 0..256 {
                let mut b = base.clone();
                b.extend_from_slice(&cracked_text);
                b.push(i as u8);

                let mut c = ecb_oracle_harder(p, &b, k).unwrap();
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

pub fn encrypt_profile(
    profile: &str,
    k: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    return crate::aes_ecb::encrypt_aes_128_ecb(kv_encode(profile).as_bytes(), &k);
}

pub fn decrypt_profile(
    profile: &[u8],
    k: &[u8],
) -> Result<String, symmetriccipher::SymmetricCipherError> {
    let kv = crate::aes_ecb::decrypt_aes_128_ecb(profile, &k)?;
    Ok(kv_parse(&String::from_utf8(kv).unwrap()).unwrap())
}

/// ECB cut-and-paste
///
/// Solution for problem 5 from set 2: <https://cryptopals.com/sets/2/challenges/13>
pub fn ecb_cut_and_paste(k: &[u8]) -> Vec<u8> {
    // block1: email=zod@gmail. block2: com&uid=10&role= bock3: user\0xC\0xC\0xC\0xC\0xC\0xC\0xC\0xC\0xC\0xC\0xC\0xC
    let my_profile = profile_for("zod@gmail.com");
    let ciphertext = encrypt_profile(&my_profile, k).unwrap();

    let my_profile2 =
        profile_for("xxxxxxxxxxadmin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}");
    let ciphertext2 = encrypt_profile(&my_profile2, k).unwrap();

    // take the first two block of ciphertext1 and the second block from ciphertext 2
    let mut new_ciphertext = Vec::from(&ciphertext[..32]);
    new_ciphertext.extend_from_slice(&ciphertext2[16..32]);

    new_ciphertext
}

/// profile_for
///
/// Solution for problem 5 from set 2: <https://cryptopals.com/sets/2/challenges/13>
pub fn profile_for(email: &str) -> String {
    return serde_json::json!({
        "email": email.replace("&", "").replace("=", ""),
        "uid": 10,
        "role": "user",
    })
    .to_string();
}

/// encoding for key-value pairs
///
/// Solution for problem 5 from set 2: <https://cryptopals.com/sets/2/challenges/13>
pub fn kv_encode(profile: &str) -> String {
    let m: serde_json::Value = serde_json::from_str(profile).unwrap();

    let mut result = String::from("");
    result.push_str("email=");
    result.push_str(m["email"].as_str().unwrap());
    result.push('&');
    result.push_str("uid=");
    result.push_str(&serde_json::to_string(&m["uid"]).unwrap());
    result.push('&');
    result.push_str("role=");
    result.push_str(m["role"].as_str().unwrap());

    result
}

/// decoding for key-value pairs
///
/// Solution for problem 5 from set 2: <https://cryptopals.com/sets/2/challenges/13>
pub fn kv_parse(kv: &str) -> Result<String, crate::Error> {
    let mut iter = kv.split('&');

    let mut result = serde_json::Map::new();

    loop {
        match iter.next() {
            Some(inner_kv) => {
                if inner_kv.matches('=').count() != 1 {
                    return Err(crate::Error::InvalidKVPair);
                }

                let mut inner_iter = inner_kv.split('=');

                let left = inner_iter.next().unwrap();
                let right = inner_iter.next().unwrap();

                result.insert(
                    left.to_string(),
                    match right.parse::<i64>() {
                        Ok(v) => serde_json::Value::Number(serde_json::Number::from(v)),
                        Err(_) => serde_json::Value::String(right.to_string()),
                    },
                );
            }
            None => break,
        };
    }

    Ok(serde_json::to_string(&result).unwrap())
}

/// BATE (Byte at a time encryption)
///
/// Soludion for problem 4 from set 2: <https://cryptopals.com/sets/2/challenges/12>
pub fn ecb_oracle(b: &[u8], k: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    static UNKNOWN_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let decoded_unknown = base64::decode(&UNKNOWN_STRING).unwrap();

    let mut plaintext = Vec::from(b);
    plaintext.extend_from_slice(&decoded_unknown);

    crate::aes_ecb::encrypt_aes_128_ecb(&plaintext, &k)
}

/// Decrypts the unknown string for the ecb oracle
/// described in problem: <https://cryptopals.com/sets/2/challenges/12>
pub fn decrypt_unknown_string_ecb_oracle(k: &[u8]) -> Vec<u8> {
    let block_size = {
        let unknown_output = ecb_oracle(&Vec::new(), k).unwrap();
        let mut current_length = unknown_output.len();

        let mut m = Vec::new();
        while current_length == unknown_output.len() {
            m.push(b'A');
            current_length = ecb_oracle(&m, k).unwrap().len();
        }

        current_length - unknown_output.len()
    };

    let is_ecb = {
        let mut block = Vec::with_capacity(block_size * 2);
        for _ in 0..block.capacity() {
            block.push(b'A');
        }

        let is_ecb = crate::set1::detect_aes_128_ecb_mode(
            hex::encode(ecb_oracle(&block, k).unwrap()).as_bytes(),
        )
        .unwrap();

        is_ecb
    };

    if !is_ecb {
        panic!("the cipher is not using ecb mode");
    }

    let end = ecb_oracle(&Vec::new(), k).unwrap().len();
    let mut cracked_text = Vec::new();

    while cracked_text.len() != end {
        cracked_text.push({
            let mut prefix = block_size - ((1 + cracked_text.len()) % block_size);
            if prefix == block_size {
                prefix -= block_size;
            }

            let mut base = Vec::new();

            for _ in 0..prefix {
                base.push(b'A');
            }

            let expanded_length: usize = base.len() + 1 + cracked_text.len();
            let ciphertext = ecb_oracle(&base, k).unwrap();

            let mut dict = HashMap::new();
            for i in 0..256 {
                let mut b = base.clone();
                b.extend_from_slice(&cracked_text);
                b.push(i as u8);

                let mut c = ecb_oracle(&b, k).unwrap();
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
    use super::decrypt_profile;
    use super::decrypt_unknown_string_ecb_oracle;
    use super::decrypt_unknown_string_ecb_oracle_harder;
    use super::ecb_cut_and_paste;
    use super::ecb_oracle;
    use super::ecb_oracle_harder;
    use super::encrypt_profile;
    use super::encryption_oracle;
    use super::generate_key;
    use super::kv_encode;
    use super::kv_parse;
    use super::profile_for;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_ecb_cut_and_paste() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let ciphertext = ecb_cut_and_paste(&unknown_key);
        let plaintext = decrypt_profile(&ciphertext, &unknown_key).unwrap();
        assert_eq!(plaintext, "{\"email\":\"zod@gmail.com\",\"role\":\"admin\\u000b\\u000b\\u000b\\u000b\\u000b\\u000b\\u000b\\u000b\\u000b\\u000b\\u000b\",\"uid\":10}");
    }

    #[test]
    fn test_encrypt_decrypt_profile() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let profile = profile_for("my@email.com");
        let ciphertext = encrypt_profile(&profile, &unknown_key).unwrap();
        let plaintext = decrypt_profile(&ciphertext, &unknown_key).unwrap();
        assert_eq!(plaintext, "{\"email\":\"my@email.com\",\"role\":\"user\\r\\r\\r\\r\\r\\r\\r\\r\\r\\r\\r\\r\\r\",\"uid\":10}");
    }

    #[test]
    fn test_kv_encode() {
        let obj = kv_encode(&profile_for("foo@bar.com"));
        assert_eq!(obj, "email=foo@bar.com&uid=10&role=user");
    }

    #[test]
    fn test_profile_for() {
        let obj = profile_for("foo@bar.com");
        assert_eq!(
            obj,
            "{\"email\":\"foo@bar.com\",\"role\":\"user\",\"uid\":10}"
        );

        let obj = profile_for("foo@bar.com&role=admin");
        assert_eq!(
            obj,
            "{\"email\":\"foo@bar.comroleadmin\",\"role\":\"user\",\"uid\":10}"
        );
    }

    #[test]
    fn test_kv_parse() {
        let obj = kv_parse("foo=10&baz=qux&zap=zazzle").unwrap();
        assert_eq!(obj, "{\"baz\":\"qux\",\"foo\":10,\"zap\":\"zazzle\"}");

        let obj = kv_parse("foo=bar&baz=qux&zap=zazzle").unwrap();
        assert_eq!(obj, "{\"baz\":\"qux\",\"foo\":\"bar\",\"zap\":\"zazzle\"}");
    }

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
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        assert_eq!(
            decrypt_unknown_string_ecb_oracle(&unknown_key), "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{1}\u{0}\u{0}\u{0}\u{0}\u{0}".as_bytes()
        );
    }

    #[test]
    fn test_decrypt_unknown_string_ecb_oracle_harder() {
        fn strip_0s(mut V: Vec<u8>) -> Vec<u8> {
            let mut last = 0;
            for i in 0..V.len() {
                if V[i] == 0 {
                    last = i;
                    break;
                }
            }

            V.truncate(last);
            return V
        }

        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let mut prefix = Vec::with_capacity((OsRng.next_u32() % 256) as usize);
        while prefix.len() != prefix.capacity() {
            prefix.push((OsRng.next_u32() % 256) as u8);
        }

        assert_eq!(
            strip_0s(decrypt_unknown_string_ecb_oracle_harder(&prefix, &unknown_key)), "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\u{1}".as_bytes()
        );
    }
}
