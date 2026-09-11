//! Hook implementations for the Embassy ecosystem:
//! - A monotonic timer over `embassy-time` ([`timer::EmbassyTimer`]; the
//!   `embassy-time` and `hook-timer` features)
//! - Hardware acceleration via `embassy-crypto` drivers (the `embassy-crypto`
//!   feature), see below
//!
//! # `embassy-crypto`
//!
//! `embassy-crypto` defines one link-time pluggable driver per operation
//! (SHA-256, AES-128 ECB, P-256 arithmetic, ...): exactly one crate in the
//! firmware registers each driver that is used - a hardware driver, or a
//! software one like those of `embassy-crypto-rustcrypto`. The hook
//! implementations in [`digest`], [`aes`] and [`ecp`] are thin adapters over
//! the `embassy-crypto` types (`embassy_crypto::Sha256`,
//! `embassy_crypto::Aes128`, `embassy_crypto::p256::Point`, ...), which call
//! straight into those drivers.
//!
//! Only the drivers behind the hooks that are actually installed need to be
//! registered. The implementations serving several drivers -
//! [`aes::EmbassyAes`] (one driver per key size) and the elliptic-curve ones
//! (one driver per curve) - are generic over the set of drivers they use, so
//! e.g. an AES peripheral that only does AES-128 can be hooked without
//! registering an AES-256 driver: whatever is outside the set is handled by
//! the MbedTLS software implementation, as when un-hooked.
//!
//! | Hook           | Implementation                         | `embassy-crypto` drivers |
//! |----------------|----------------------------------------|--------------------------|
//! | `hook_sha1`    | [`digest::EmbassySha1`] ([`SHA1`])     | `Sha1`                   |
//! | `hook_sha224`  | [`digest::EmbassySha224`] ([`SHA224`]) | `Sha224`                 |
//! | `hook_sha256`  | [`digest::EmbassySha256`] ([`SHA256`]) | `Sha256`                 |
//! | `hook_sha384`  | [`digest::EmbassySha384`] ([`SHA384`]) | `Sha384`                 |
//! | `hook_sha512`  | [`digest::EmbassySha512`] ([`SHA512`]) | `Sha512`                 |
//! | `hook_aes`     | [`aes::EmbassyAes`] ([`AES`])          | `Aes128Ecb`, `Aes256Ecb` |
//! | `hook_ecp_mul` | [`ecp::EmbassyEcp`] ([`ECP`])          | `P256Arith`, optionally `P384Arith` |
//! | `hook_ecdsa`   | [`ecp::EmbassyEcdsa`] ([`ECDSA`])      | `P256Ecdsa`, optionally `P384Ecdsa` (both drawing their nonces from `Rng`) |
//! | `hook_ecdh`    | [`ecp::EmbassyEcdh`] ([`ECDH`])        | `P256Ecdh`, optionally `P384Ecdh` |
//!
//! Where ECDSA or ECDH are not hooked, the MbedTLS software implementation
//! computes them on top of the (possibly hooked) scalar multiplication.
//!
//! ```ignore
//! use mbedtls_rs_sys::hook::aes::hook_aes;
//! use mbedtls_rs_sys::hook::backend::embassy::{AES, ECDSA, SHA256};
//! use mbedtls_rs_sys::hook::digest::hook_sha256;
//! use mbedtls_rs_sys::hook::ecdsa::hook_ecdsa;
//!
//! // Requires the `Sha256`, `Aes128Ecb`, `Aes256Ecb`, `P256Ecdsa` and `Rng` drivers
//! unsafe {
//!     hook_sha256(Some(&SHA256));
//!     hook_aes(Some(&AES));
//!     hook_ecdsa(Some(&ECDSA));
//! }
//! ```

#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-aes",
    not(feature = "nohook-aes")
))]
pub mod aes;
#[cfg(feature = "embassy-crypto")]
pub mod digest;
#[cfg(all(feature = "embassy-crypto", feature = "alg-ecp"))]
pub mod ecp;
#[cfg(all(feature = "embassy-time", feature = "hook-timer"))]
pub mod timer;

/// SHA-1 via the `embassy-crypto` `Sha1` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-sha1",
    not(feature = "nohook-sha1")
))]
pub static SHA1: digest::EmbassySha1 = digest::EmbassySha1::new();
/// SHA-224 via the `embassy-crypto` `Sha224` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-sha256",
    not(feature = "nohook-sha256")
))]
pub static SHA224: digest::EmbassySha224 = digest::EmbassySha224::new();
/// SHA-256 via the `embassy-crypto` `Sha256` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-sha256",
    not(feature = "nohook-sha256")
))]
pub static SHA256: digest::EmbassySha256 = digest::EmbassySha256::new();
/// SHA-384 via the `embassy-crypto` `Sha384` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-sha512",
    not(feature = "nohook-sha512")
))]
pub static SHA384: digest::EmbassySha384 = digest::EmbassySha384::new();
/// SHA-512 via the `embassy-crypto` `Sha512` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-sha512",
    not(feature = "nohook-sha512")
))]
pub static SHA512: digest::EmbassySha512 = digest::EmbassySha512::new();
/// AES via the `embassy-crypto` `Aes128Ecb` and `Aes256Ecb` drivers
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-aes",
    not(feature = "nohook-aes")
))]
pub static AES: aes::EmbassyAes = aes::EmbassyAes::new();
/// P-256 scalar multiplication via the `embassy-crypto` `P256Arith` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-ecp",
    not(feature = "nohook-ecp-mul")
))]
pub static ECP: ecp::EmbassyEcp = ecp::EmbassyEcp::new();
/// P-256 ECDSA via the `embassy-crypto` `P256Ecdsa` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
pub static ECDSA: ecp::EmbassyEcdsa = ecp::EmbassyEcdsa::new();
/// P-256 ECDH via the `embassy-crypto` `P256Ecdh` driver
#[cfg(all(
    feature = "embassy-crypto",
    feature = "alg-ecp",
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
pub static ECDH: ecp::EmbassyEcdh = ecp::EmbassyEcdh::new();
