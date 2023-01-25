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


TODO
------------------------------------------------------------

* SHA-3
  - https://csrc.nist.gov/publications/fips#202
  - https://keccak.team/
  - https://en.wikipedia.org/wiki/SHA-3
  - https://www.nist.gov/publications/sha-3-standard-permutation-based-hash-and-extendable-output-functions
* BLAKE2b
  - https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
* BLAKE3
  - https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3
* フィルタコマンド用ユーティリティ
* コマンドライン解析
