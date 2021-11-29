#[cfg(feature = "c_file")]
#[cfg(not(feature = "default"))]
mod test_c_file {
    use ckb_lib_secp256k1::get_libsecp256k1_bin;

    #[test]
    fn test_get_c_bin() {
        println!("{:?}", get_libsecp256k1_bin());
    }
}
