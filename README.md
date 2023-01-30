hashlib
============================================================

暗号学的ハッシュ関数を計算するライブラリ。


ビルドコマンド
------------------------------------------------------------

    cargo check
    cargo test
    cargo run --bin md5sum -- <FILE>


modules
------------------------------------------------------------

* hashlib
  * md2 - MD2 Message-Digest Algorithm
  * md4 - MD4 Message-Digest Algorithm
  * md5 - MD5 Message-Digest Algorithm
  * sha1 - SHA-1
  * sha2 - SHA-2
  * sha3 - SHA-3 and SHAKE


binaries
------------------------------------------------------------

* md2sum
* md4sum
* md5sum
* sha1sum
* sha224sum
* sha256sum
* sha384sum
* sha512sum
* sha512_224sum
* sha512_256sum
* sha3_224sum
* sha3_256sum
* sha3_384sum
* sha3_512sum
* shake128sum
* shake256sum


TODO
------------------------------------------------------------

* BLAKE2b
  - https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
* BLAKE3
  - https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3
