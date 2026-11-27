# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-27
* Update MSRV to 1.86, which the SHA hooks need (trait upcasting)
* Fix: on-the-fly clang build on macOS - archive with `llvm-ar` from the `llvm-tools` rustup component (Apple's `ar` drops ELF objects)
* Accept `esp-idf-sys` 0.39 as well as 0.38
* (Breaking) The algorithm hooks are opt-in: the `hook-sha1`, `hook-sha256`, `hook-sha512`, `hook-exp-mod`, `hook-aes`, `hook-ecp-mul` and `hook-ecp-verify` features replace the `nohook*` features. The prebuilt libraries still have all of them
* (Breaking) Move the ESP hardware acceleration (`hook::backend::esp` and the `esp32*` features) to the new `mbedtls-rs-sys-esp` crate
* Publish the installed hooks as the `hooks` metadata key (`DEP_MBEDTLS_HOOKS`)
* Support the `*-windows-msvc` targets: MbedTLS is compiled on the fly with clang, as for other targets
* On ESP-IDF, pass ESP-IDF's configuration on to dependents (`DEP_MBEDTLS_EMBUILD_CFG_ARGS`)
* (Breaking) Add a `tls-sni` feature for `MBEDTLS_SSL_SERVER_NAME_INDICATION`, which `tls-core` no longer enables. The `tls` bundle (and so the default features) include it, so only builds that select `tls-core` on its own need to add `tls-sni` to keep sending the server name

## [0.3.1] - 2026-09-15
* (Breaking) Raise the `esp-idf-sys` dep to 0.38. Yank 0.3.0, as the release order should've been different

## [0.3.0] - 2026-09-14
* Reconfigure CMake from scratch when the compiler changed since the last build, rather than letting CMake half-reset its own cache
* Update MSRV to 1.85
* (Breaking) Un-hooked digests and AES now fall back to MbedTLS's own software implementations rather than to RustCrypto
* `MBEDTLS_AES_FEWER_TABLES` is now set: the software AES tables cost 2.5 KB of flash instead of 8.7 KB, so TLS images end up ~2 KB smaller than with the RustCrypto fallback
* (Breaking) The ESP SHA hooks now drive the `esp-hal` contexts through their native API, so `EspSha*` are `EspDigest<_>` rather than `RustCryptoDigest<_>`
* Build `riscv32imafc-*` with the hard-float `ilp32f` ABI rustc uses, fixing a link failure on ESP32-P4 / ESP32-S31
* Add an opt-in `ecp-restartable` feature that enables `MBEDTLS_ECP_RESTARTABLE`

## [0.2.0] - 2026-08-20
* (Breaking) Enforce the short-enums policy across all of clang, GCC and bindgen (#168)
* Fix the crate build when defmt is enabled (#166)
* (Breaking) AES and ECC accel for esp32XX (#164)
* Add hardware acceleration for ECC and AES, for the esp32XX MCUs

## [0.1.0] - 2026-06-25
* Initial release
