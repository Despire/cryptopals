const N: usize = 624;
const LOWER_MASK: u32 = (1 << 31) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

#[derive(Debug)]
pub struct MT19937 {
    mt: [u32; N],
    index: usize,
}

impl MT19937 {
    pub fn uninitialized() -> MT19937 {
        MT19937 {
            index: 0,
            mt: [0 as u32; N],
        }
    }

    pub fn new(seed: i32) -> MT19937 {
        let mut mt = [0 as u32; N];

        mt[0] = seed as u32;
        for i in 1..mt.len() {
            mt[i] = (mt[i - 1] ^ (mt[i - 1] >> (30)))
                .wrapping_mul(1812433253u32)
                .wrapping_add(i as u32);
        }

        MT19937 { index: N, mt: mt }
    }

    fn twist(&mut self) {
        for i in 0..self.mt.len() {
            let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % self.mt.len()] & LOWER_MASK);

            let mut x_a = x >> 1;
            if x & 0x1 == 0x1 {
                x_a = x_a ^ 0x9908B0DFu32;
            }

            self.mt[i] = self.mt[(i + 397) % self.mt.len()] ^ x_a;
        }

        self.index = 0;
    }

    pub fn extract_number(&mut self) -> Result<i32, crate::Error> {
        if self.index >= self.mt.len() {
            if self.index > self.mt.len() {
                return Err(crate::Error::MT19937InvalidState);
            }

            self.twist();
        }

        let mut y = self.mt[self.index];
        y ^= (y >> 11) & 0xFFFFFFFFu32;
        y ^= (y << 7) & 0x9D2C5680u32;
        y ^= (y << 15) & 0xEFC60000u32;
        y ^= y >> 18;

        self.index += 1;

        Ok(y as i32)
    }

    pub fn untemper(&mut self, i: usize, n: i32) {
        let mut unsigned_n = n as u32;

        unsigned_n = self.invert_l_xor(unsigned_n);
        unsigned_n = self.invert_t_xor(unsigned_n);
        unsigned_n = self.invert_s_xor(unsigned_n);
        unsigned_n = self.invert_u_xor(unsigned_n);

        self.mt[i] = unsigned_n;
    }

    fn invert_l_xor(&self, n: u32) -> u32 {
        n ^ (n >> 18)
    }

    fn invert_t_xor(&self, n: u32) -> u32 {
        ((n << 15) & 0xEFC60000u32) ^ n // bit Magic ;)
    }

    fn invert_s_xor(&self, n: u32) -> u32 {
        let mut result: u32 = 0;

        for i in 0..32 {
            let bit = crate::bits::get_ith_bit_u32(n, i);
            let shifted = crate::bits::get_ith_bit_u32(result, i - 7);
            let and = crate::bits::get_ith_bit_u32(0x9D2C5680u32, i);

            if bit ^ (shifted & and) == 1 {
                crate::bits::set_ith_bit_u32(&mut result, i);
            }
        }

        result
    }

    fn invert_u_xor(&self, mut n: u32) -> u32 {
        let mut result: u32 = 0;

        for i in (0..32).rev() {
            let bit = crate::bits::get_ith_bit_u32(n, i);
            let shifted = crate::bits::get_ith_bit_u32(result, i + 11);

            if bit ^ shifted == 1 {
                crate::bits::set_ith_bit_u32(&mut result, i);
            }
        }

        result
    }
}

mod test {
    use super::MT19937;

    #[test]
    fn test_untemper() {
        let mut gen = MT19937::new(1);
        let first_number = gen.extract_number().unwrap();
        let second_number = gen.extract_number().unwrap();

        let mut gen2 = MT19937::uninitialized();
        gen2.untemper(1, second_number);
        gen2.untemper(0, first_number);

        assert_eq!(&gen2.mt[..2], &[2629073562 as u32, 2983301384 as u32]);
    }

    #[test]
    fn test_invert_s_xor() {
        let gen = MT19937::uninitialized();

        assert_eq!(
            gen.invert_s_xor(
                0b11001110001111011001000111001101
                    ^ ((0b11001110001111011001000111001101 << 7) & 0x9D2C5680u32)
            ),
            0b11001110001111011001000111001101,
        );
    }

    #[test]
    fn test_invert_u_xor() {
        let gen = MT19937::uninitialized();

        assert_eq!(
            gen.invert_u_xor(
                0b11001110001111011001000111001101 ^ (0b11001110001111011001000111001101 >> 11)
            ),
            0b11001110001111011001000111001101,
        );
    }

    #[test]
    fn test_invert_t_xor() {
        let gen = MT19937::uninitialized();

        assert_eq!(
            gen.invert_t_xor(0b00000110111110111001000111001101),
            0b11001110001111011001000111001101
        );

        assert_eq!(
            gen.invert_t_xor(
                0b11001110001111011001000111001101
                    ^ ((0b11001110001111011001000111001101 << 15) & 0xEFC60000u32)
            ),
            0b11001110001111011001000111001101,
        );

        assert_eq!(gen.invert_t_xor(1 ^ ((1 << 15) & 0xEFC60000u32)), 1);
    }

    #[test]
    fn test_invert_l_xor() {
        let gen = MT19937::uninitialized();

        assert_eq!(gen.invert_l_xor(5 ^ 0), 5);
        assert_eq!(
            gen.invert_l_xor(
                0b11001110001111011001000111001101 ^ 0b00000000000000000011001110001111
            ),
            0b11001110001111011001000111001101
        );
    }

    #[test]
    fn test_new_mt19937() {
        let gen = MT19937::new(1);

        assert_eq!(gen.index, super::N);
        assert_ne!(gen.mt, [0 as u32; super::N]);
    }

    #[test]
    fn test_mt19937_extract_number() {
        let mut gen1 = MT19937::new(1);
        let mut gen2 = MT19937::new(1);

        let mut vec1 = Vec::new();
        let mut vec2 = Vec::new();

        for _ in 0..100 {
            vec1.push(gen1.extract_number().unwrap());
            vec2.push(gen2.extract_number().unwrap());
        }

        assert_eq!(vec1, vec2);
        assert_eq!(gen1.index, gen2.index);
        assert_eq!(gen1.mt, gen2.mt);
    }
}
