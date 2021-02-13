use crate::set5::DiffieHellman;
use num_bigint::BigUint;
use num_bigint::{RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::ToPrimitive;
use rand_core::{OsRng, RngCore};
use std::ops::Sub;

/// G P-1 attack
///
/// Solution for problem 3 from set5: <https://cryptopals.com/sets/5/challenges/35>
pub fn g_p_1(alice: &DiffieHellman, bob: &DiffieHellman, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Oscar acts a the MITM.

    // Oscars intercepts the set-up from alice
    let mut A = alice.public_key();

    // Oscar intercepts bob response to alice
    let mut B = bob.public_key();

    // Alice generate a random iv.
    let mut iv = [0 as u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Alice creates a msg and sends it to bob.
    let mut alice_request = crate::aes_cbc::encrypt_aes_128_cbc(
        msg,
        &crate::sha1::sha1(
            &alice.session_key(B.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        &iv,
    )
    .unwrap();

    alice_request.extend_from_slice(&iv);

    // Oscar intercepts the msg.
    // Oscar forwards it to bob.

    // Bob receives alices request
    let alice_iv = &alice_request[alice_request.len() - 16..];
    let alice_msg = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &crate::sha1::sha1(
            &bob.session_key(A.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        alice_iv,
    )
    .unwrap();

    // Bob re-encrypts the msg back to alice
    let mut bob_iv = [0 as u8; 16];
    OsRng.fill_bytes(&mut bob_iv);

    let mut bob_response = crate::aes_cbc::encrypt_aes_128_cbc(
        &alice_msg,
        &crate::sha1::sha1(
            &bob.session_key(A.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        &bob_iv,
    )
    .unwrap();

    // Oscar intercepts bobs reponse
    // Oscar forwards it to alice.

    // if g = p-1
    // pub_key = (p-1 ^ p_key) % p = {1|p-1}

    // Oscars cracks the key.
    let cracked_key = crate::sha1::sha1(&[1], None, None, None, None, None, None);

    // Oscars decrypts the msg from alice.
    let alice_msg_to_bob = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &cracked_key,
        &alice_request[alice_request.len() - 16..],
    )
    .unwrap();

    // Oscars cracks the key second time.
    let cracked_key = crate::sha1::sha1(
        &(alice.p.to_u128().unwrap() - 1).to_le_bytes(),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // Oscars decrypts the msg from alice.
    let alice_msg_to_bob_2 = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &cracked_key,
        &alice_request[alice_request.len() - 16..],
    )
    .unwrap();

    (alice_msg_to_bob, alice_msg_to_bob_2)
}

/// G P attack
///
/// Solution for problem 3 from set5: <https://cryptopals.com/sets/5/challenges/35>
pub fn g_p(alice: &DiffieHellman, bob: &DiffieHellman, msg: &[u8]) -> Vec<u8> {
    // Oscar acts a the MITM.

    // Oscars intercepts the set-up from alice
    let mut A = alice.public_key();

    // Oscar intercepts bob response to alice
    let mut B = bob.public_key();

    // Alice generate a random iv.
    let mut iv = [0 as u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Alice creates a msg and sends it to bob.
    let mut alice_request = crate::aes_cbc::encrypt_aes_128_cbc(
        msg,
        &crate::sha1::sha1(
            &alice.session_key(B.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        &iv,
    )
    .unwrap();

    alice_request.extend_from_slice(&iv);

    // Oscar intercepts the msg.
    // Oscar forwards it to bob.

    // Bob receives alices request
    let alice_iv = &alice_request[alice_request.len() - 16..];
    let alice_msg = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &crate::sha1::sha1(
            &bob.session_key(A.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        alice_iv,
    )
    .unwrap();

    // Bob re-encrypts the msg back to alice
    let mut bob_iv = [0 as u8; 16];
    OsRng.fill_bytes(&mut bob_iv);

    let mut bob_response = crate::aes_cbc::encrypt_aes_128_cbc(
        &alice_msg,
        &crate::sha1::sha1(
            &bob.session_key(A.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        &bob_iv,
    )
    .unwrap();

    // Oscar intercepts bobs reponse
    // Oscar forwards it to alice.

    // if g = p
    // pub_key = (p ^ p_key) % p = 0

    // Oscars cracks the key.
    let cracked_key = crate::sha1::sha1(&[0], None, None, None, None, None, None);

    // Oscars decrypts the msg from alice.
    let alice_msg_to_bob = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &cracked_key,
        &alice_request[alice_request.len() - 16..],
    )
    .unwrap();

    alice_msg_to_bob
}

/// G 1 attack
///
/// Solution for problem 3 from set5: <https://cryptopals.com/sets/5/challenges/35>
pub fn g_1(alice: &DiffieHellman, bob: &DiffieHellman, msg: &[u8]) -> Vec<u8> {
    // Oscar acts a the MITM.

    // Oscars intercepts the set-up from alice
    let mut A = alice.public_key();

    // Oscar intercepts bob response to alice
    let mut B = bob.public_key();

    // Alice generate a random iv.
    let mut iv = [0 as u8; 16];
    OsRng.fill_bytes(&mut iv);

    // Alice creates a msg and sends it to bob.
    let mut alice_request = crate::aes_cbc::encrypt_aes_128_cbc(
        msg,
        &crate::sha1::sha1(
            &alice.session_key(B.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        &iv,
    )
    .unwrap();

    alice_request.extend_from_slice(&iv);

    // Oscar intercepts the msg.
    // Oscar forwards it to bob.

    // Bob receives alices request
    let alice_iv = &alice_request[alice_request.len() - 16..];
    let alice_msg = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &crate::sha1::sha1(
            &bob.session_key(A.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        alice_iv,
    )
    .unwrap();

    // Bob re-encrypts the msg back to alice
    let mut bob_iv = [0 as u8; 16];
    OsRng.fill_bytes(&mut bob_iv);

    let mut bob_response = crate::aes_cbc::encrypt_aes_128_cbc(
        &alice_msg,
        &crate::sha1::sha1(
            &bob.session_key(A.clone()).to_bytes_le(),
            None,
            None,
            None,
            None,
            None,
            None,
        )[..16],
        &bob_iv,
    )
    .unwrap();

    // Oscar intercepts bobs reponse
    // Oscar forwards it to alice.

    // if g = 1
    // pub_key = (1 ^ p_key) % p = 1

    // Oscars cracks the key.
    let cracked_key = crate::sha1::sha1(&[1], None, None, None, None, None, None);

    // Oscars decrypts the msg from alice.
    let alice_msg_to_bob = crate::aes_cbc::decrypt_aes_128_cbc(
        &alice_request[..alice_request.len() - 16],
        &cracked_key,
        &alice_request[alice_request.len() - 16..],
    )
    .unwrap();

    alice_msg_to_bob
}

mod test {
    use super::g_1;
    use super::g_p;
    use super::g_p_1;
    use crate::set5::DiffieHellman;

    use num_bigint::BigUint;
    use num_bigint::{RandBigInt, ToBigInt};
    use num_traits::FromPrimitive;
    use std::str::FromStr;

    #[test]
    fn test_g_p_1() {
        let mut rng = rand::thread_rng();

        let alice = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(36).unwrap(),
        };

        let bob = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(36).unwrap(),
        };

        let msg = b"some random msg";

        let cracked_msgs = g_p_1(&alice, &bob, msg);
        let mut ok = false;

        if cracked_msgs.0 == "some random msg\u{1}".as_bytes() {
            ok = true;
        }

        if cracked_msgs.1 == "some random msg\u{1}".as_bytes() {
            ok = true;
        }

        assert_eq!(ok, true);
    }

    #[test]
    fn test_g_p() {
        let mut rng = rand::thread_rng();

        let alice = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(37).unwrap(),
        };

        let bob = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(37).unwrap(),
        };

        let msg = b"some random msg";

        assert_eq!(g_p(&alice, &bob, msg), "some random msg\u{1}".as_bytes())
    }

    #[test]
    fn test_g_1() {
        let mut rng = rand::thread_rng();

        let alice = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(1).unwrap(),
        };

        let bob = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(1).unwrap(),
        };

        let msg = b"some random msg";

        assert_eq!(g_1(&alice, &bob, msg), "some random msg\u{1}".as_bytes())
    }
}
