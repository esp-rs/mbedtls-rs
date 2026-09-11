# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
* Reconfigure CMake from scratch when the compiler changed since the last build, rather than letting CMake half-reset its own cache
* Update MSRV to 1.85
* (Breaking) Un-hooked digests and AES now fall back to MbedTLS's own software implementations rather than to RustCrypto
* `MBEDTLS_AES_FEWER_TABLES` is now set: the software AES tables cost 2.5 KB of flash instead of 8.7 KB, so TLS images end up ~2 KB smaller than with the RustCrypto fallback
* (Breaking) The ESP SHA hooks now drive the `esp-hal` contexts through their native API, so `EspSha*` are `EspDigest<_>` rather than `RustCryptoDigest<_>`
* Build `riscv32imafc-*` with the hard-float `ilp32f` ABI rustc uses, fixing a link failure on ESP32-P4 / ESP32-S31
* Add an opt-in `ecp-restartable` feature that enables `MBEDTLS_ECP_RESTARTABLE`
* Add an `embassy-crypto` feature: hook implementations in `hook::backend::embassy` delegating to the `embassy-crypto` drivers (SHA-1/224/256/384/512, AES-128/256, the P-256/P-384 scalar multiplication, ECDSA and ECDH)
* Add ECDSA (`hook_ecdsa`) and ECDH (`hook_ecdh`) hooks, with the MbedTLS software implementations as the fallback

## [0.2.0] - 2026-08-20
* (Breaking) Enforce the short-enums policy across all of clang, GCC and bindgen (#168)
* Fix the crate build when defmt is enabled (#166)
* (Breaking) AES and ECC accel for esp32XX (#164)

## [0.1.0] - 2026-06-25
* Initial release
