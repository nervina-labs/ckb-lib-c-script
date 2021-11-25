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

git checkout -b static-lib

git pull origin static-lib

make all-via-docker

make static-via-docker

cp ./ckb-miscellaneous-scripts/build/librsa_secp256k1.a ./ckb-lib-smt/lib/

cp ./ckb-miscellaneous-scripts/build/librsa_secp256k1.a ./ckb-lib-secp256k1/lib

cp ./ckb-miscellaneous-scripts/build/librsa_secp256k1.a ./ckb-lib-rsa/lib
```
