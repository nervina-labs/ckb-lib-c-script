/*
 * @Author: your name
 * @Date: 2021-08-31 19:57:42
 * @LastEditTime: 2021-09-01 22:00:25
 * @LastEditors: your name
 * @Description: In User Settings Edit
 * @FilePath: /ckb-lib-c-script/ckb-lib-rsa/src/lib.rs
 */
#![no_std]
#[cfg(all(feature = "c_file", feature = "no_std"))]
compile_error!("feature \"no_std\" and feature \"c_file\" cannot be enabled at the same time");

#[cfg(feature = "no_std")]
extern crate alloc;

mod code_hashes;
#[cfg(feature = "no_std")]
mod librsa;

pub use code_hashes::CODE_HASH_RSA;
#[cfg(feature = "no_std")]
pub use librsa::*;
pub mod email_rs {
    pub use email_rs::*;
}

#[cfg(feature = "c_file")]
pub fn get_librsa_bin() -> &'static [u8] {
    include_bytes!("../lib/rsa_sighash_all")
}
