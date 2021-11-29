#![no_std]
#[cfg(all(feature = "c_file", feature = "no_std"))]
compile_error!("feature \"no_std\" and feature \"std\" cannot be enabled at the same time");
#[cfg(feature = "no_std")]
extern crate alloc;

mod code_hashes;
#[cfg(feature = "no_std")]
mod libsecp256k1;

pub use code_hashes::CODE_HASH_SECP256K1;
#[cfg(feature = "no_std")]
pub use libsecp256k1::*;

#[cfg(feature = "c_file")]
pub fn get_libsecp256k1_bin() -> &'static [u8] {
    include_bytes!("../lib/secp256k1_blake2b_sighash_all_dual")
}
