//! Pure routing decision for ESP modular-exponentiation: pick the hardware
//! operand size for a given limb count, or fall back to software.
//!
//! This is intentionally free of any `esp_hal` dependency so it can be unit
//! tested on the host. The production ESP backend in
//! [`super::esp::exp_mod`](super::esp::exp_mod) calls [`Route::route_for`] to
//! decide whether a request can be served by the RSA peripheral or must use the
//! MbedTLS software path. Keeping it here (rather than inline in the
//! `esp_hal`-gated module) is what makes the routing logic testable without an
//! ESP target.

use crypto_bigint::U1024;
use crypto_bigint::U2048;
#[cfg(not(feature = "esp32"))]
use crypto_bigint::U256;
#[cfg(not(feature = "esp32"))]
use crypto_bigint::U384;
#[cfg(not(any(
    feature = "esp32c3",
    feature = "esp32c5",
    feature = "esp32c6",
    feature = "esp32h2"
)))]
use crypto_bigint::U4096;
use crypto_bigint::U512;

/// A hardware-supported RSA operand size, identified by its limb count.
///
/// Each variant corresponds 1:1 to an `esp_hal::rsa::operand_sizes::OpN` and is
/// gated by exactly the same chip features as the hardware path, so a variant
/// only exists when the peripheral on that chip can serve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwKind {
    #[cfg(not(feature = "esp32"))]
    Op256,
    #[cfg(not(feature = "esp32"))]
    Op384,
    Op512,
    Op1024,
    Op2048,
    #[cfg(not(any(
        feature = "esp32c3",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    )))]
    Op4096,
}

/// Where a modular-exponentiation request of a given size should be dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// No hardware operand size matches: use the MbedTLS software path.
    Soft,
    /// Serve with the RSA peripheral at this operand size.
    Hw(HwKind),
}

impl Route {
    /// Decide how to serve a modular exponentiation of `num_words` limbs.
    ///
    /// `num_words` is counted in word-sized limbs (`crypto_bigint::Limb`); on
    /// the 32-bit ESP production targets these are the 32-bit `mbedtls_mpi_uint`
    /// limbs. It is the post-`calculate_hw_words` count (already rounded up to
    /// the 512-bit block on `esp32`). Any size the peripheral cannot serve,
    /// including in-range-but-unsupported sizes such as 96 limbs (3072-bit) on a
    /// chip whose RSA arms stop at 2048, returns [`Route::Soft`] instead of
    /// panicking.
    pub fn route_for(num_words: usize) -> Self {
        match num_words {
            #[cfg(not(feature = "esp32"))]
            n if n == U256::LIMBS => Route::Hw(HwKind::Op256),
            #[cfg(not(feature = "esp32"))]
            n if n == U384::LIMBS => Route::Hw(HwKind::Op384),
            n if n == U512::LIMBS => Route::Hw(HwKind::Op512),
            n if n == U1024::LIMBS => Route::Hw(HwKind::Op1024),
            n if n == U2048::LIMBS => Route::Hw(HwKind::Op2048),
            #[cfg(not(any(
                feature = "esp32c3",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            )))]
            n if n == U4096::LIMBS => Route::Hw(HwKind::Op4096),
            _ => Route::Soft,
        }
    }
}
