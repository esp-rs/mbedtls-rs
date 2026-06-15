//! Host tests for the ESP modular-exponentiation routing decision (F-01).
//!
//! Built only under the internal `_route-test` feature, which enables
//! `crypto-bigint` without `esp-hal`, so this runs on the host. It exercises
//! the same `Route::route_for` that the production ESP backend calls, proving
//! that operand sizes the hardware cannot serve route to software instead of
//! panicking - the bug behind F-01.
//!
//! Sizes are expressed relative to `UN::LIMBS` rather than as raw limb counts:
//! `crypto-bigint`'s limb is word-sized (`u64` on a 64-bit host, `u32` on the
//! 32-bit ESP targets), so a fixed integer would denote different bit-widths on
//! host versus target. Deriving from `LIMBS` keeps the assertions meaningful on
//! any word size.

use crypto_bigint::{U1024, U2048, U256, U384, U4096, U512};

use mbedtls_rs_sys::hook::backend::esp_exp_mod_route::{HwKind, Route};

#[test]
fn supported_sizes_route_to_hardware() {
    assert_eq!(Route::route_for(U256::LIMBS), Route::Hw(HwKind::Op256));
    assert_eq!(Route::route_for(U384::LIMBS), Route::Hw(HwKind::Op384));
    assert_eq!(Route::route_for(U512::LIMBS), Route::Hw(HwKind::Op512));
    assert_eq!(Route::route_for(U1024::LIMBS), Route::Hw(HwKind::Op1024));
    assert_eq!(Route::route_for(U2048::LIMBS), Route::Hw(HwKind::Op2048));
    assert_eq!(Route::route_for(U4096::LIMBS), Route::Hw(HwKind::Op4096));
}

#[test]
fn in_range_unsupported_sizes_route_to_software() {
    // A limb count strictly between two supported operand sizes matches no arm.
    // On the 32-bit ESP targets U2048::LIMBS + 1 is 65 limbs (2080-bit); the
    // 3072-bit (96-limb) case that used to hit `unreachable!()` is one instance
    // of this class.
    assert_eq!(Route::route_for(U2048::LIMBS + 1), Route::Soft);
    assert_eq!(Route::route_for(U1024::LIMBS + 1), Route::Soft);
    assert_eq!(Route::route_for(U512::LIMBS + 1), Route::Soft);
}

#[test]
fn out_of_range_sizes_route_to_software() {
    // Below the smallest supported size.
    assert_eq!(Route::route_for(0), Route::Soft);
    assert_eq!(Route::route_for(U256::LIMBS - 1), Route::Soft);
    // Above the largest supported size.
    assert_eq!(Route::route_for(U4096::LIMBS + 1), Route::Soft);
    assert_eq!(Route::route_for(U4096::LIMBS * 2), Route::Soft);
}
