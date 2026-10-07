# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
* (Breaking) Add a `tls-sni` feature. The `tls` bundle (and so the default features) include it; a build that uses `--no-default-features` no longer sends the Server Name Indication extension unless it enables `tls-sni`. `ClientSessionConfig::server_name` still sets the name the certificate is verified against
* Add `PrivateKey::warm`: performs one private-key operation up front, so the RSA blinding setup that MbedTLS otherwise does inside the first handshake (over a second on a small MCU) happens at a moment the application chooses

## [0.3.0] - 2026-09-14
* Update MSRV to 1.85 due to `rand_core` 0.10
* (Breaking) Update to `rand_core` 0.10
* (Breaking) Add `ClientSessionConfig::skip_hostname_verification`: skip the certificate hostname (CN/SAN) check while still sending SNI and verifying the certificate chain, mirroring esp-idf's `skip_cert_common_name_check` (#174)
* Add an opt-in `ecp-restartable` feature: async sessions turn in-progress restartable ECC operations into cooperative yields, blocking sessions retry them to completion, and `ecp::set_restartable_max_ops` configures the process-wide operation budget; the in-progress result is handled unconditionally, so ESP-IDF builds with `CONFIG_MBEDTLS_ECP_RESTARTABLE` get the same behaviour
* (Breaking) Add an optional `max_version` to `ClientSessionConfig`; capping at TLS 1.2 is what lets a restartable client yield, as Mbed TLS 3.6's TLS 1.3 handshake crypto is not restartable
* Add `Session::new_with_yield` to the blocking session: a platform yield hook (e.g. `std::thread::yield_now`) invoked between restartable-ECC retry slices
* (Breaking) Add an optional ordered key-exchange group allowlist (`key_exchange_groups`, `TlsGroup`) to `ClientSessionConfig`
* Add `Session::tls_version` (blocking and async): the TLS protocol version negotiated during the handshake, `None` until a `connect()` succeeds (#167)

## [0.2.0] - 2026-08-20
* (Breaking) Enforce the short-enums policy across all of clang, GCC and bindgen (#168)
* Fix the crate build when defmt is enabled (#166)
* (Breaking) AES and ECC accel for esp32XX (#164)

## [0.1.0] - 2026-06-25
* Initial release
