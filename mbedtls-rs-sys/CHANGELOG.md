# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [0.1.0] - 2026-06-25
* Initial release
