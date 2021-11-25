# ckb-lib-c-script
wrap some c lib for rust call.

## compile
```sh

cd c

mkdir deps

git clone https://github.com/nervosnetwork/ckb-c-stdlib deps/ckb-c-stdlib

make ckb_smt-via-docker

cd ..

git clone https://github.com/nervosnetwork/ckb-miscellaneous-scripts

cd ckb-miscellaneous-scripts

make all-via-docker

mv ./c/build/ckb_smt ./ckb-lib-smt/lib/

mv ./ckb-miscellaneous-scripts/build/secp256k1_blake2b_sighash_all_dual ./ckb-lib-secp256k1/lib

mv ./ckb-miscellaneous-scripts/build/rsa_sighash_all ./ckb-lib-rsa/lib
