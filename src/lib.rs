#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    Empty,
    InvalidKVPair,
    InvalidPKCS7,
    MT19937InvalidState,
}

pub mod aes_cbc;
pub mod aes_ctr;
pub mod aes_ecb;
pub mod bits;
pub mod mt19937;
pub mod mt_19937_cipher;
pub mod padding;
pub mod set1;
pub mod set2;
pub mod set3;
