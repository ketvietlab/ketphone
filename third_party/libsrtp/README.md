# libsrtp (vendored)

[libsrtp](https://github.com/cisco/libsrtp) 2.7.0 (tag `v2.7.0`, commit `ee1a77c`), BSD 3-clause licence
([`LICENSE`](LICENSE)). It encrypts and authenticates the call audio (SRTP, RFC 3711).

Only the files the core links are kept, unmodified: `srtp/srtp.c`, the built-in AES-ICM and HMAC-SHA1
(`crypto/cipher/aes*.c`, `crypto/hash/hmac.c`, `crypto/hash/sha1.c`), the null cipher and auth, the
crypto kernel, the replay database and their headers. The OpenSSL, mbedTLS and NSS back ends, AES-GCM,
the tests and the build files are left out. [`config/config.h`](config/config.h) replaces the
generated configuration so CMake and the Swift package build the same code.

To update, copy the same files from a newer tag, update the version in `config/config.h` and here,
and run `scripts/check`.
