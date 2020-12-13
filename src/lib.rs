#[derive(Debug)]
pub enum Error {
    Empty,
    InvalidKVPair,
}

pub mod aes_cbc;
pub mod aes_ecb;
pub mod padding;
pub mod set1;
pub mod set2;
