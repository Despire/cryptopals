#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    Empty,
    InvalidKVPair,
    InvalidPKCS7,
    MT19937InvalidState,
    InvalidASCII(Vec<u8>),
    FailedToCrackKey,
}

pub mod sha1;
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
pub mod set4;
