const N: usize = 624;
const LOWER_MASK: u32 = (1 << 31) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

#[derive(Debug)]
struct MT19937 {
    mt: [u32; N],
    index: usize,
}

impl MT19937 {
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
}

mod test {
    use super::MT19937;

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

        for i in 0..100 {
            vec1.push(gen1.extract_number().unwrap());
            vec2.push(gen2.extract_number().unwrap());
        }

        assert_eq!(vec1, vec2);
    }
}
