use num_bigint::BigInt;
use num_bigint::{RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::FromPrimitive;
use num_traits::{One, Zero};
use std::ops::Div;

pub fn med3_u128(mut left: u128, mut mid: u128, mut right: u128) -> u128 {
    if mid > right {
        let tmp = right;
        right = mid;
        mid = tmp;
    }

    if left > right {
        let tmp = right;
        right = left;
        left = tmp;
    }

    if left > mid {
        let tmp = mid;
        mid = left;
        left = tmp;
    }

    mid
}

pub fn max_of_3(l: u128, m: u128, r: u128) -> u128 {
    if l >= m && l >= r {
        return l;
    }

    if m >= l && m >= r {
        return m;
    }

    r
}

pub fn max_of_2(l: u128, r: u128) -> u128 {
    if l > r {
        return l;
    }

    r
}

pub fn med3_f64(mut left: f64, mut mid: f64, mut right: f64) -> f64 {
    if mid > right {
        let tmp = right;
        right = mid;
        mid = tmp;
    }

    if left > right {
        let tmp = right;
        right = left;
        left = tmp;
    }

    if left > mid {
        let tmp = mid;
        mid = left;
        left = tmp;
    }

    mid
}

pub fn distance(l: u128, r: u128) -> u128 {
    if l > r {
        return l - r;
    }

    r - l
}

pub fn distance_f64(l: f64, r: f64) -> f64 {
    (l - r).abs()
}

pub fn mean(b: &[f64]) -> f64 {
    b.iter().fold(0f64, |a, b| a + b) / b.len() as f64
}

pub fn mean_u128(b: &[u128]) -> f64 {
    b.iter().fold(0u128, |a, b| a + b) as f64 / b.len() as f64
}

// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
pub fn modinv(a: &BigInt, m: &BigInt) -> Result<BigInt, crate::Error> {
    let mut x = BigInt::from_u128(1).unwrap();
    let mut y = BigInt::from_u128(0).unwrap();

    let mut new_x = BigInt::from_u128(0).unwrap();
    let mut new_y = BigInt::from_u128(1).unwrap();
    let mut new_r = m.clone();
    let mut r = a.clone();

    while &new_r != &Zero::zero() {
        let q = &r / &new_r;

        let tmp = r.clone();
        r = new_r.clone();
        new_r = tmp - &q * new_r;

        let tmp = x.clone();
        x = new_x.clone();
        new_x = tmp - &q * new_x;

        let tmp = y.clone();
        y = new_y.clone();
        new_y = tmp - &q * new_y;
    }

    if &r > &One::one() {
        return Err(crate::Error::NotInvertible);
    }

    if &x < &Zero::zero() {
        x = x + m;
    }

    Ok(x)
}

mod test {
    use super::med3_f64;
    use super::modinv;

    use num_bigint::BigInt;
    use num_bigint::{RandBigInt, ToBigInt};
    use num_integer::Integer;
    use num_traits::FromPrimitive;
    use num_traits::{One, Zero};

    #[test]
    pub fn test_modinv() {
        let a = BigInt::from_u128(10).unwrap();
        let m = BigInt::from_u128(17).unwrap();
        assert_eq!(modinv(&a, &m).unwrap(), BigInt::from_u128(12).unwrap());

        let a = BigInt::from_u128(2321321).unwrap();
        let m = BigInt::from_u128(12321).unwrap();
        assert_eq!(modinv(&a, &m).unwrap(), BigInt::from_u128(11216).unwrap());

        let a = BigInt::from_u128(0).unwrap();
        let m = BigInt::from_u128(12321).unwrap();
        assert_eq!(modinv(&a, &m), Err(crate::Error::NotInvertible));

        let a = BigInt::from_u128(17).unwrap();
        let m = BigInt::from_u128(3120).unwrap();
        assert_eq!(modinv(&a, &m).unwrap(), BigInt::from_u128(2753).unwrap());
    }

    #[test]
    pub fn test_med_f64() {
        let left = 5.67;
        let mid = 3.84;
        let right = 1.12;

        assert_eq!(med3_f64(left, mid, right), 3.84);
        assert_eq!(med3_f64(mid, left, right), 3.84);
        assert_eq!(med3_f64(mid, right, left), 3.84);
        assert_eq!(med3_f64(right, mid, left), 3.84);
    }
}
