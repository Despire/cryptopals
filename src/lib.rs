#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    Empty,
    InvalidKVPair,
    InvalidPKCS7,
    MT19937InvalidState,
    InvalidASCII(Vec<u8>),
    FailedToCrackKey,
    NotInvertible,
    InvalidBitsize,
}

pub mod aes_cbc;
pub mod aes_ctr;
pub mod aes_ecb;
pub mod bits;
pub mod hmac_server;
pub mod mitm_g_attacks;
pub mod mt19937;
pub mod mt_19937_cipher;
pub mod padding;
pub mod rabin_miller;
pub mod rsa;
pub mod set1;
pub mod set2;
pub mod set3;
pub mod set4;
pub mod set5;
pub mod sha1;
pub mod utils;
