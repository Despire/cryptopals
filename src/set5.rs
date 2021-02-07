use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use std::ops::Mul;

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
    use super::modular_pow;
    use super::DiffieHellman;

    use num_bigint::BigUint;
    use num_bigint::{RandBigInt, ToBigInt};
    use num_traits::FromPrimitive;
    use std::str::FromStr;

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
