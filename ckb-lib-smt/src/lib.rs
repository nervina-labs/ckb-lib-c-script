#![no_std]
#[cfg(all(feature = "c_file", feature = "no_std"))]
compile_error!("feature \"no_std\" and feature \"c_file\" cannot be enabled at the same time");
#[cfg(feature = "no_std")]
extern crate alloc;

mod code_hashes;
#[cfg(feature = "no_std")]
mod libsmt;

pub use code_hashes::CODE_HASH_CKB_SMT;
#[cfg(feature = "no_std")]
pub use libsmt::*;

#[cfg(feature = "c_file")]
pub fn get_libsmt_bin() -> &'static [u8] {
    include_bytes!("../lib/ckb_smt")
}
