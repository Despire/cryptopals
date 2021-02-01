use crypto::symmetriccipher;
use std::time::{Duration, Instant};

use rocket::http::Status;
use rocket::local::Client;

fn next_byte(client: &Client, cracked_mac: &[u8], filename: &[u8], i: usize) -> u8 {
    const HMAC_LEN: usize = 20;

    let s = hex::encode(&cracked_mac);
    println!("cracked so far: {}", &s);

    let mut cracked_mac = Vec::from(cracked_mac);
    cracked_mac.extend_from_slice(&vec![0 as u8; HMAC_LEN - cracked_mac.len()]);

    let max_time = {
        let mut cracked_mac = cracked_mac.clone();

        let mut meds = Vec::new();
        for b in &[111, 187, 147, 200, 223, 79, 39] {
            cracked_mac[i] = *b;

            let mut counters = [0 as u128; 9];
            for c in 0..9 {
                let now = Instant::now();
                client
                    .get(format!(
                        "/test?file={}&signature={}",
                        String::from_utf8(Vec::from(filename)).unwrap(),
                        &hex::encode(&cracked_mac),
                    ))
                    .dispatch();

                counters[c] = now.elapsed().as_micros()
            }

            meds.push(crate::utils::med3_u128(
                crate::utils::med3_u128(counters[0], counters[1], counters[2]),
                crate::utils::med3_u128(counters[3], counters[4], counters[5]),
                crate::utils::med3_u128(counters[6], counters[7], counters[8]),
            ));
        }

        meds.sort();

        meds[4]
    };

    let mut cracked_byte = 0;
    let mut distance = 0;

    for b in 0..=255 {
        cracked_mac[i] = b;

        let mut counters = [0 as u128; 3];
        for c in 0..3 {
            let now = Instant::now();
            client
                .get(format!(
                    "/test?file={}&signature={}",
                    String::from_utf8(Vec::from(filename)).unwrap(),
                    &hex::encode(&cracked_mac),
                ))
                .dispatch();

            counters[c] = now.elapsed().as_micros()
        }

        println!("calculted med_time_failure: {}", max_time);
        let cm = crate::utils::med3_u128(counters[0], counters[1], counters[2]);
        println!("caculated current_med: {}", cm);
        let d = crate::utils::distance(cm, max_time);
        println!("calculated distance: {}", d);
        if d > distance {
            cracked_byte = b;
            distance = d;
        }
    }

    cracked_byte
}

pub fn discover_mac_timing_attack(k: &[u8], filename: &[u8]) -> Vec<u8> {
    const HMAC_LEN: usize = 20;

    let client = Client::new(crate::hmac_server::rocket(k)).expect("valid rocket instance");
    let mut cracked_mac = Vec::new();

    while cracked_mac.len() < HMAC_LEN {
        cracked_mac.push(next_byte(
            &client,
            &cracked_mac,
            filename,
            cracked_mac.len(),
        ));
    }

    Vec::from(hex::encode(cracked_mac).as_bytes())
}

/// md_pad pads the message the same way as the sha-1 implementation from [sha1.rs]
///
/// Solution for problem 5 from set4: <https://cryptopals.com/sets/4/challenges/29>
fn md_pad(b: &[u8]) -> Vec<u8> {
    let mut m = Vec::from(b);
    m.push(0x80);

    let mut k = (56 - m.len() as i64) % 64;
    if k < 0 {
        k = 64 + k;
    }

    m.extend_from_slice(&vec![0 as u8; k as usize]);
    m.extend_from_slice(&((b.len() * 8) as u64).to_be_bytes());
    m
}

/// break_sha1_length_extension breaks the sha 1 using length extension
///
/// Solution for problem 5 from set 4: <https://cryptopals.com/sets/4/challenges/29>
pub fn break_sha1_length_extension(
    b: &[u8],
    k: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let suffix = b";admin=true";

    let digest = hex::decode(digest).unwrap();

    let mut H = Vec::new();
    for chunk in digest.chunks(4) {
        H.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }

    for l in 0..256 {
        // (key || message || padding || new-msg)
        let mut new_msg = Vec::from(vec![0 as u8; l]);
        new_msg.extend_from_slice(b);
        new_msg = md_pad(&new_msg);
        new_msg.extend_from_slice(suffix);

        let new_digest = crate::sha1::sha1(
            suffix,
            Some(new_msg.len() * 8),
            Some(H[0]),
            Some(H[1]),
            Some(H[2]),
            Some(H[3]),
            Some(H[4]),
        );

        if crate::sha1::sha1_mac(k, &new_msg[l..]) == new_digest {
            return Ok(new_digest);
        }
    }

    Err(crate::Error::FailedToCrackKey)
}

/// is_all_ascii returns true if all bytes are under 128 (original ascii set)
///
/// Solution for problem 3 from set 4: <https://cryptopals.com/sets/4/challenges/27>
fn is_all_ascii(b: &[u8]) -> bool {
    for b in b {
        if *b >= 128 {
            return false;
        }
    }

    return true;
}

/// CBC bitflipping attack recover key
///
/// Solution for problem 3 from set 4: <https://cryptopals.com/sets/4/challenges/27>
pub fn cbc_bitflipping_attack_recover_key(k: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let block_size = 16;
    let A = vec![b'A'; block_size];
    let B = vec![b'B'; block_size];
    let C = vec![b'C'; block_size];

    let mut secret_msg = Vec::new();
    secret_msg.extend_from_slice(&A);
    secret_msg.extend_from_slice(&B);
    secret_msg.extend_from_slice(&C);

    let ciphertext = &crate::set2::encrypt_user_data(&secret_msg, k, k).unwrap();
    let prefix_length = "comment1=cooking%20MCs;userdata=".len();

    let mut mutated_ciphertext = Vec::new();
    mutated_ciphertext.extend_from_slice(&ciphertext[prefix_length..prefix_length + block_size]);
    mutated_ciphertext.extend_from_slice(&vec![0; block_size]);
    mutated_ciphertext.extend_from_slice(&ciphertext[prefix_length..prefix_length + block_size]);

    let result = decrypt_user_data_with_error(&mutated_ciphertext, k);
    if let Err(err) = result {
        if let crate::Error::InvalidASCII(msg) = err {
            let p1 = &msg[..block_size];
            let p3 = &msg[2 * block_size..];

            return Ok(crate::set1::xor_buffers(
                hex::encode(p1).as_bytes(),
                hex::encode(p3).as_bytes(),
            )
            .unwrap());
        }

        Err(err)
    } else {
        Err(crate::Error::FailedToCrackKey)
    }
}

/// decrypt_user_data is a helper function for CBC bitflipping attacks recover key
///
/// Solution for problem 3 from set 4: <https://cryptopals.com/sets/4/challenges/27>
pub fn decrypt_user_data_with_error(b: &[u8], k: &[u8]) -> Result<bool, crate::Error> {
    let plaintext = crate::aes_cbc::decrypt_aes_128_cbc(b, k, k).unwrap();

    if !is_all_ascii(&plaintext) {
        return Err(crate::Error::InvalidASCII(plaintext));
    }

    let mut plaintext = String::from_utf8_lossy(&plaintext);

    let mut iter = plaintext.split(";");
    let mut contains = false;

    loop {
        match iter.next() {
            Some(inner_kv) => {
                if inner_kv == "admin=true" {
                    return Ok(true);
                }
            }
            None => return Ok(false),
        };
    }
}

/// encrypt_user_data is a helper function for CTR bitflipping attacks
///
/// Solution for problem 2 from set 4: <https://cryptopals.com/sets/4/challenges/26>
pub fn encrypt_user_data(
    b: &[u8],
    k: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut user_data = Vec::new();

    for c in b {
        match c {
            b';' => {}
            b'=' => {}
            _ => user_data.push(*c),
        }
    }

    let mut plaintext = Vec::from("comment1=cooking%20MCs;userdata=");
    plaintext.extend_from_slice(&user_data);
    plaintext.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");

    return crate::aes_ctr::aes_128_ctr(&plaintext, k, nonce);
}

/// decrypt_user_data is a helper function for CTR bitflipping attacks
///
/// Solution for problem 2 from set 4: <https://cryptopals.com/sets/4/challenges/26>
pub fn decrypt_user_data(b: &[u8], k: &[u8], nonce: &[u8]) -> Result<bool, crate::Error> {
    let plaintext = crate::aes_ctr::aes_128_ctr(b, k, nonce).unwrap();
    let mut plaintext = String::from_utf8_lossy(&plaintext);

    let mut iter = plaintext.split(";");
    let mut contains = false;

    loop {
        match iter.next() {
            Some(inner_kv) => {
                if inner_kv == "admin=true" {
                    return Ok(true);
                }
            }
            None => return Ok(false),
        };
    }
}

/// CTR bitflipping attack
///
/// Solution for problem 2 from set 4: <https://cryptopals.com/sets/4/challenges/26
pub fn ctr_bitflipping_attack(k: &[u8], nonce: &[u8]) -> Result<bool, crate::Error> {
    let plaintext = Vec::from(",admin-true".as_bytes());
    let mut ciphertext = encrypt_user_data(&plaintext, k, nonce).unwrap();

    // we need to figure out the prefix length
    let t1 = encrypt_user_data(b"A", k, nonce).unwrap();
    let t2 = encrypt_user_data(b"B", k, nonce).unwrap();
    // since it is encrypted in a bitwise fashion we can find the exact
    // starting position by looking for the first bit change.
    let mut position: i32 = -1;
    for i in 0..t1.len() {
        if t1[i] != t2[i] {
            position = i as i32;
        }
    }

    let mut keystream = Vec::new();
    for i in 0..plaintext.len() {
        keystream.push(ciphertext[position as usize + i] ^ plaintext[i]);
    }

    ciphertext[position as usize] = {
        let mut result = 0;

        for i in 0..=255 {
            if keystream[0] ^ i == b';' {
                result = i;
            }
        }

        result
    };

    ciphertext[position as usize + 6] = {
        let mut result = 0;

        for i in 0..=255 {
            if keystream[6] ^ i == b'=' {
                result = i;
            }
        }

        result
    };

    decrypt_user_data(&ciphertext, k, nonce)
}

/// edit replaces the old text at a given offset with new text
///
///  Solution for problem 1 from set 4: <https://cryptopals.com/sets/4/challenges/25>
pub fn break_ciphertext_with_edit(b: &[u8], nb: &[u8], k: &[u8], offset: usize) -> Vec<u8> {
    return edit(b, k, offset, nb);
}

/// edit replaces the old text at a given offset with new text
///
///  Solution for problem 1 from set 4: <https://cryptopals.com/sets/4/challenges/25>
pub fn edit(b: &[u8], k: &[u8], offset: usize, nb: &[u8]) -> Vec<u8> {
    if offset < 0 || offset > b.len() {
        panic!("offset out of bounds")
    }

    const block_size: usize = 16;

    let start = offset / block_size;
    let end = ((offset + nb.len() - 1) / block_size) + 1;

    let mut keystream = Vec::new();
    for b in start..end {
        let mut v = Vec::from([0 as u8; 8]);
        v.extend_from_slice(&(b as u64).to_le_bytes());

        keystream.extend_from_slice(&crate::aes_ecb::encrypt_aes_128_ecb(&v, k).unwrap());
    }

    // the precise address is offet % 16: (offset % 16)+nb.len()
    let ciphertext = crate::set1::xor_buffers(
        hex::encode(nb).as_bytes(),
        hex::encode(&keystream[(offset % block_size)..(offset % block_size) + nb.len()]).as_bytes(),
    )
    .unwrap();

    let mut result = Vec::new();
    result.extend_from_slice(&b[..offset]);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&b[offset + nb.len()..]);

    result
}

mod test {
    use super::break_ciphertext_with_edit;
    use super::break_sha1_length_extension;
    use super::cbc_bitflipping_attack_recover_key;
    use super::ctr_bitflipping_attack;
    use super::decrypt_user_data;
    use super::discover_mac_timing_attack;
    use super::encrypt_user_data;

    use rand::Rng;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_discover_mac_timing_attack() {
        assert_eq!(
            discover_mac_timing_attack(b"YELLOW_SUBMARINE", b"server_file.txt"),
            b"8a6d26219f5c4ea40192805b6db4d26bea394df2",
        );
    }

    #[test]
    fn test_break_sha1_length_extension() {
        let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let digest = crate::sha1::sha1_mac(&unknown_key, msg);

        assert_eq!(
            break_sha1_length_extension(msg, &unknown_key, &digest).unwrap(),
            crate::sha1::sha1_mac(
                &unknown_key,
                &[
                    99, 111, 109, 109, 101, 110, 116, 49, 61, 99, 111, 111, 107, 105, 110, 103, 37,
                    50, 48, 77, 67, 115, 59, 117, 115, 101, 114, 100, 97, 116, 97, 61, 102, 111,
                    111, 59, 99, 111, 109, 109, 101, 110, 116, 50, 61, 37, 50, 48, 108, 105, 107,
                    101, 37, 50, 48, 97, 37, 50, 48, 112, 111, 117, 110, 100, 37, 50, 48, 111, 102,
                    37, 50, 48, 98, 97, 99, 111, 110, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 232, 59, 97, 100,
                    109, 105, 110, 61, 116, 114, 117, 101
                ]
            ),
        );
    }

    #[test]
    fn test_cbc_bitflipping_attack_recover_key() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let result = cbc_bitflipping_attack_recover_key(&unknown_key).unwrap();
        assert_eq!(unknown_key, &result[..]);
    }

    #[test]
    fn test_cbc_blitflipping_attack() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let mut nonce = [0 as u8; 8];
        OsRng.fill_bytes(&mut nonce);

        let result = ctr_bitflipping_attack(&unknown_key, &nonce).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_encrypt_decrypt_user_data() {
        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let mut nonce = [0 as u8; 8];
        OsRng.fill_bytes(&mut nonce);

        let data = String::from("admin=true");

        let ciphertext = encrypt_user_data(data.as_bytes(), &unknown_key, &nonce);
        let plaintext = decrypt_user_data(&ciphertext.unwrap(), &unknown_key, &nonce);
        assert_eq!(plaintext.unwrap(), false);
    }

    #[test]
    fn test_break_ciphertext_with_edit() {
        let input = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}";

        let mut unknown_key = [0 as u8; 16];
        OsRng.fill_bytes(&mut unknown_key);

        let ciphertext =
            crate::aes_ctr::aes_128_ctr(input.as_bytes(), &unknown_key, &[0 as u8; 8]).unwrap();
        let offset = 0;
        let plaintext = break_ciphertext_with_edit(&ciphertext, &ciphertext, &unknown_key, 0);

        assert_eq!(plaintext, input.as_bytes());
    }
}
