pub fn get_ith_bit_u32(n: u32, i: i8) -> u8 {
    if i < 0 || i > 31 {
        return 0;
    }

    (n >> i & 0x1) as u8
}

pub fn set_ith_bit_u32(n: &mut u32, i: i8) {
    *n |= 1 << i
}

pub fn toggle_ith_bit_u32(n: &mut u32, i: i8) {
    *n ^= 1 << i
}

mod test {
    use super::get_ith_bit_u32;
    use super::set_ith_bit_u32;
    use super::toggle_ith_bit_u32;

    #[test]
    fn test_toggle_ith_bit_u32() {
        let mut val: u32 = 0b11001110001111011001000111001101;

        toggle_ith_bit_u32(&mut val, 29);

        assert_eq!(get_ith_bit_u32(val, 0), 1);
        assert_eq!(get_ith_bit_u32(val, 1), 0);
        assert_eq!(get_ith_bit_u32(val, 31), 1);
        assert_eq!(get_ith_bit_u32(val, 30), 1);
        assert_eq!(get_ith_bit_u32(val, 29), 1);

        toggle_ith_bit_u32(&mut val, 29);

        assert_eq!(get_ith_bit_u32(val, 0), 1);
        assert_eq!(get_ith_bit_u32(val, 1), 0);
        assert_eq!(get_ith_bit_u32(val, 31), 1);
        assert_eq!(get_ith_bit_u32(val, 30), 1);
        assert_eq!(get_ith_bit_u32(val, 29), 0);
    }

    #[test]
    fn test_set_ith_bit_u32() {
        let mut val: u32 = 0b11001110001111011001000111001101;

        set_ith_bit_u32(&mut val, 29);
        set_ith_bit_u32(&mut val, 1);

        assert_eq!(get_ith_bit_u32(val, 0), 1);
        assert_eq!(get_ith_bit_u32(val, 1), 1);
        assert_eq!(get_ith_bit_u32(val, 31), 1);
        assert_eq!(get_ith_bit_u32(val, 30), 1);
        assert_eq!(get_ith_bit_u32(val, 29), 1);
    }

    #[test]
    fn test_get_ith_bit_u32() {
        let val: u32 = 0b11001110001111011001000111001101;

        assert_eq!(get_ith_bit_u32(val, 0), 1);
        assert_eq!(get_ith_bit_u32(val, 1), 0);
        assert_eq!(get_ith_bit_u32(val, 31), 1);
        assert_eq!(get_ith_bit_u32(val, 30), 1);
        assert_eq!(get_ith_bit_u32(val, 29), 0);
    }
}
