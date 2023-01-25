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
  * md5 - MD5 hash function
  * sha1 - SHA-1 hash function
  * sha2 - SHA-2 hash functions


binaries
------------------------------------------------------------

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
  - https://en.wikipedia.org/wiki/SHA-3
  - https://www.nist.gov/publications/sha-3-standard-permutation-based-hash-and-extendable-output-functions
  - https://keccak.team/
* MD4
* MD2
* フィルタコマンド用ユーティリティ
* コマンドライン解析
