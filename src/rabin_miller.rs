use num_bigint::BigUint;
use num_bigint::ToBigUint;
use num_bigint::{RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use num_traits::{One, Zero};
use std::ops::Div;

pub fn is_prime(n: &BigUint) -> bool {
    if n == &BigUint::from_u128(2).unwrap() || n == &BigUint::from_u128(3).unwrap() {
        return true;
    }

    if n == &One::one() || n.is_even() {
        return false;
    }

    let mut s: BigUint = Zero::zero();
    let mut r: BigUint = n.clone() - 1 as u128;

    while (&r).is_even() {
        s = s + 1 as u128;
        r = &r / 2 as u128;
    }

    for _ in 0..128 {
        let mut rng = rand::thread_rng();
        let a = rng.gen_biguint_range(&BigUint::from_u128(2).unwrap(), &(n.clone() - 1 as u128));
        let mut x = crate::set5::modular_pow(
            &a.to_biguint().unwrap(),
            &r.to_biguint().unwrap(),
            &n.to_biguint().unwrap(),
        );

        if x != One::one() && x != (n - 1 as u128) {
            let mut j: BigUint = One::one();
            while j < s && x != (n - 1 as u128) {
                x = crate::set5::modular_pow(
                    &x.to_biguint().unwrap(),
                    &BigUint::from_u128(2).unwrap(),
                    &n.to_biguint().unwrap(),
                );

                if x == One::one() {
                    return false;
                }

                j = j + 1 as u128;
            }

            if x != (n - 1 as u128) {
                return false;
            }
        }
    }

    true
}

pub fn generate_prime(bitsize: u64) -> BigUint {
    let mut guess = BigUint::from_u128(6).unwrap();
    let mut rng = rand::thread_rng();

    while !is_prime(&guess) {
        guess = rng.gen_biguint(bitsize);
    }

    return guess;
}

mod test {
    use num_bigint::BigUint;
    use num_bigint::ToBigUint;
    use num_bigint::{RandBigInt, ToBigInt};
    use num_integer::Integer;
    use num_traits::FromPrimitive;
    use num_traits::ToPrimitive;
    use num_traits::{One, Zero};

    use super::generate_prime;

    #[test]
    pub fn test_generate_prime() {
        let prime = generate_prime(512);
        // check with wolfram for primness...
        println!("{}", prime.to_str_radix(10));
    }
}
