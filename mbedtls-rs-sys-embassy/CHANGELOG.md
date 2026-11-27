# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
* Initial release: implementations of the `mbedtls-rs-sys` hooks over the `embassy-crypto` drivers (SHA-1/224/256/384/512, AES-128/256, and the P-256/P-384 scalar multiplication, ECDSA and ECDH)
* The `embassy-time` timer (`timer::EmbassyTimer`), moved here from `mbedtls-rs-sys` (`hook::backend::embassy::timer`)
