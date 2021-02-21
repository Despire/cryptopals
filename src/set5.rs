use num_bigint::BigUint;
use num_bigint::{RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand_core::{OsRng, RngCore};
use std::ops::Mul;

pub fn e_3_attack(ciphertexts: Vec<(Vec<u8>, BigUint)>) -> Vec<u8> {
    let (c0, c1, c2) = (&ciphertexts[0].0, &ciphertexts[1].0, &ciphertexts[2].0);
    let (n0, n1, n2) = (&ciphertexts[0].1, &ciphertexts[1].1, &ciphertexts[2].1);
    let (m0, m1, m2) = (n1 * n2, n0 * n2, n0 * n1);

    let l0 = &BigUint::from_bytes_be(c0)
        * &m0
        * crate::utils::modinv(&m0.to_bigint().unwrap(), &n0.to_bigint().unwrap())
            .unwrap()
            .to_biguint()
            .unwrap();

    let l1 = &BigUint::from_bytes_be(c1)
        * &m1
        * crate::utils::modinv(&m1.to_bigint().unwrap(), &n1.to_bigint().unwrap())
            .unwrap()
            .to_biguint()
            .unwrap();

    let l2 = &BigUint::from_bytes_be(c2)
        * &m2
        * crate::utils::modinv(&m2.to_bigint().unwrap(), &n2.to_bigint().unwrap())
            .unwrap()
            .to_biguint()
            .unwrap();

    let c = (l0 + l1 + l2) % (n0 * n1 * n2);

    crate::utils::cube_root(&c).to_str_radix(16).into_bytes()
}

/// MITM attack
///
/// Solution for problem 2 from set5: <https://cryptopals.com/sets/5/challenges/34>
pub fn mitm(alice: &DiffieHellman, bob: &DiffieHellman, msg: &[u8]) -> Vec<u8> {
    // Oscar acts a the MITM.

    // Oscars intercepts the set-up from alice
    let mut A = alice.public_key();

    // Oscar replaces the public key with 'p'
    A = alice.p.clone();

    // Oscar intercepts bob response to alice
    let mut B = bob.public_key();

    // Oscars replaces the public key with 'p'
    B = bob.p.clone();

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

    // Oscars cracks the key.
    // (p^x) % p = 0
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

/// Deffie-Hellman key-exchange parameters.
///
/// Solution for problem 1 from set 5: <https://cryptopals.com/sets/5/challenges/33>
pub struct DiffieHellman {
    pub private_key: BigUint,
    pub p: BigUint,
    pub g: BigUint,
}

impl DiffieHellman {
    pub fn public_key(&self) -> BigUint {
        modular_pow(&self.g, &self.private_key, &self.p)
    }

    pub fn session_key(&self, public_key: BigUint) -> BigUint {
        modular_pow(&public_key, &self.private_key, &self.p)
    }
}

/// modexp from wiki: <https://en.wikipedia.org/wiki/Modular_exponentiation>
pub fn modular_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let zero = Zero::zero();
    let one = One::one();

    if *modulus == one {
        return zero;
    }

    let mut exponent = exponent.clone();
    let mut base = base % modulus;

    let mut result = one;

    while exponent > zero {
        if exponent.is_odd() {
            result = (result * &base) % modulus;
        }

        exponent >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

mod test {
    use super::e_3_attack;
    use super::mitm;
    use super::modular_pow;
    use super::DiffieHellman;

    use num_bigint::BigUint;
    use num_bigint::{RandBigInt, ToBigInt};
    use num_traits::FromPrimitive;
    use std::str::FromStr;

    #[test]
    fn test_e_3_attack() {
        let plaintext = hex::encode("rsa e 3 attack");

        let mut ciphers: Vec<(Vec<u8>, BigUint)> = Vec::new();
        for _ in 0..3 {
            loop {
                let c = crate::rsa::RSA::new(512);
                if let Err(_) = c {
                    continue;
                }

                let c = c.unwrap();
                ciphers.push((c.encrypt(plaintext.as_bytes()), c.n.clone()));

                break;
            }
        }

        assert_eq!(&e_3_attack(ciphers), plaintext.as_bytes());
    }

    #[test]
    fn test_mitm() {
        let mut rng = rand::thread_rng();

        let alice = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(5).unwrap(),
        };

        let bob = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(5).unwrap(),
        };

        let msg = b"some random msg";

        assert_eq!(mitm(&alice, &bob, msg), "some random msg\u{1}".as_bytes());
    }

    #[test]
    fn test_diffie_hellman() {
        let mut rng = rand::thread_rng();

        let alice = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(5).unwrap(),
        };

        let alice_public_key = alice.public_key();

        let bob = DiffieHellman {
            private_key: rng.gen_biguint(256),
            p: BigUint::from_u128(37).unwrap(),
            g: BigUint::from_u128(5).unwrap(),
        };

        let bob_public_key = bob.public_key();

        let alice_session_key = alice.session_key(bob_public_key);
        let bob_session_key = bob.session_key(alice_public_key);

        assert_eq!(alice_session_key, bob_session_key);

        let alice = DiffieHellman {
            private_key: rng.gen_biguint(1024),
            p: BigUint::from_bytes_be(&hex::decode("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap()),
            g: BigUint::from_u128(2).unwrap(),
        };

        let alice_public_key = alice.public_key();

        let bob = DiffieHellman {
            private_key: rng.gen_biguint(1024),
            p: BigUint::from_bytes_be(&hex::decode("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap()),
            g: BigUint::from_u128(2).unwrap(),
        };

        let bob_public_key = bob.public_key();

        let alice_session_key = alice.session_key(bob_public_key);
        let bob_session_key = bob.session_key(alice_public_key);

        assert_eq!(alice_session_key, bob_session_key);
    }

    #[test]
    fn test_modular_pow() {
        assert_eq!(
            modular_pow(
                &BigUint::from_u64(2).unwrap(),
                &BigUint::from_u64(3).unwrap(),
                &BigUint::from_u64(5).unwrap()
            ),
            BigUint::from_u64(3).unwrap(),
        );

        assert_eq!(
            modular_pow(
                &BigUint::from_u64(2).unwrap(),
                &BigUint::from_u64(5).unwrap(),
                &BigUint::from_u64(13).unwrap(),
            ),
            BigUint::from_u64(6).unwrap()
        );

        assert_eq!(
            modular_pow(
                &BigUint::from_u64(50).unwrap(),
                &BigUint::from_u64(100).unwrap(),
                &BigUint::from_u64(13).unwrap(),
            ),
            BigUint::from_u64(3).unwrap()
        );

        assert_eq!(
            modular_pow(
                &BigUint::from_u64(100).unwrap(),
                &BigUint::from_u64(517).unwrap(),
                &BigUint::from_u64(14342).unwrap(),
            ),
            BigUint::from_u64(12018).unwrap()
        );

        assert_eq!(
            modular_pow(
                &BigUint::from_u128(12334123134).unwrap(),
                &BigUint::from_u128(23412).unwrap(),
                &BigUint::from_u128(1232452353253).unwrap(),
            ),
            BigUint::from_u128(905600084552).unwrap(),
        );
    }
}
