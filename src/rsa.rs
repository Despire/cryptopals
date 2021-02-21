use num_bigint::BigUint;
use num_bigint::ToBigUint;
use num_bigint::{RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::FromPrimitive;
use num_traits::Num;
use num_traits::ToPrimitive;
use num_traits::{One, Zero};

pub struct RSA {
    e: BigUint,
    n: BigUint,
    d: BigUint,
}

impl RSA {
    pub fn new(bitsize: u64) -> Result<RSA, crate::Error> {
        if !bitsize.is_power_of_two() {
            return Err(crate::Error::InvalidBitsize);
        }

        let prime_size = bitsize >> 1;
        let p = crate::rabin_miller::generate_prime(prime_size);
        let q = crate::rabin_miller::generate_prime(prime_size);

        let n = &p * &q;

        let phi = (&p - 1 as u128) * (&q - 1 as u128);

        let e = BigUint::from_u128(3).unwrap();

        let d = crate::utils::modinv(&e.to_bigint().unwrap(), &phi.to_bigint().unwrap())?
            .to_biguint()
            .unwrap();

        Ok(RSA { e: e, d: d, n: n })
    }

    pub fn encrypt(&self, b: &[u8]) -> Vec<u8> {
        BigUint::parse_bytes(b, 16)
            .unwrap()
            .modpow(&self.e, &self.n)
            .to_bytes_be()
    }

    pub fn decrypt(&self, b: &[u8]) -> Vec<u8> {
        BigUint::from_bytes_be(b)
            .modpow(&self.d, &self.n)
            .to_str_radix(16)
            .into_bytes()
    }
}

mod test {
    use super::RSA;

    use num_bigint::BigUint;
    use num_bigint::ToBigUint;

    #[test]
    fn test_rsa() {
        // Some will faill because no inverse was found so try until the inverse was successfull.
        let rsa = RSA::new(1024).unwrap();

        let msg = "Hello from mars";
        let cipher = rsa.encrypt(hex::encode(msg).as_bytes());
        let plaintext = hex::decode(&rsa.decrypt(&cipher)).unwrap();

        assert_eq!(&plaintext, msg.as_bytes());
    }
}
