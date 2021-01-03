#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    Empty,
    InvalidKVPair,
    InvalidPKCS7,
}

pub mod aes_cbc;
pub mod aes_ecb;
pub mod padding;
pub mod set1;
pub mod set2;
pub mod set3;
