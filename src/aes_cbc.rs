use crypto::symmetriccipher;

/// Implement CBC mode
///
/// Solution for problem 2 from set2: <https://cryptopals.com/sets/2/challenges/10>
pub fn encrypt_aes_128_cbc(
    b: &[u8],
    k: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    const BLOCK_SIZE: usize = 16; // 128 bits

    let mut result = Vec::new();
    let mut iteration = 0;
    let mut prev = Vec::from(iv);

    loop {
        let beg = iteration * BLOCK_SIZE;
        let mut end = (iteration + 1) * BLOCK_SIZE;

        let done = end >= b.len();

        if done && end > b.len() {
            end = beg + (b.len() - beg);
        }

        let current = crate::padding::pkcs7(&b[beg..end], BLOCK_SIZE);

        let xored = crate::set1::xor_buffers(
            hex::encode(current).as_bytes(),
            hex::encode(prev).as_bytes(),
        )
        .unwrap();

        let ciphertext = crate::aes_ecb::encrypt_aes_128_ecb(&xored, k)?;

        result.extend_from_slice(&ciphertext);
        prev = ciphertext;

        if done {
            break;
        }

        iteration += 1;
    }

    Ok(result)
}

/// Implement CBC mode
///
/// Solution for problem 2 from set2: <https://cryptopals.com/sets/2/challenges/10>
pub fn decrypt_aes_128_cbc(
    b: &[u8],
    k: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    const BLOCK_SIZE: usize = 16; // 128 bits

    if b.len() % BLOCK_SIZE != 0 {
        panic!("unsuported bytes length");
    }

    let blocks = b.len() / BLOCK_SIZE;

    let mut result = Vec::new();
    let mut iteration = 0;
    let mut prev = iv;

    loop {
        let current = &b[iteration * BLOCK_SIZE..(iteration + 1) * BLOCK_SIZE];
        let plaintext = crate::aes_ecb::decrypt_aes_128_ecb(current, k)?;

        let un_xored = crate::set1::xor_buffers(
            hex::encode(plaintext).as_bytes(),
            hex::encode(prev).as_bytes(),
        )
        .unwrap();

        result.extend_from_slice(&un_xored);

        prev = current;

        iteration += 1;
        if iteration == blocks {
            break;
        }
    }

    Ok(result)
}

mod test {
    use super::decrypt_aes_128_cbc;
    use super::encrypt_aes_128_cbc;

    #[test]
    fn test_cbc_aes_decrypt() {
        let input = base64::decode(String::from("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"));

        let have = decrypt_aes_128_cbc(
            &input.unwrap(),
            "YELLOW SUBMARINE".as_bytes(),
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        );

        assert_eq!(have.unwrap(), "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}".as_bytes());
    }

    #[test]
    fn test_cbc_aes_encrypt() {
        let input = String::from("I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}");
        let expected = base64::decode(String::from("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"));

        let have = encrypt_aes_128_cbc(
            input.as_bytes(),
            "YELLOW SUBMARINE".as_bytes(),
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        );

        assert_eq!(have.unwrap(), expected.unwrap());
    }
}
