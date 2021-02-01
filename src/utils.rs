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

mod test {
    use super::med3_f64;

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
