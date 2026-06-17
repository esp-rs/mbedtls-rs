//! Behavioural lock for the RNG FFI shims' return contract (F-16 + F-17).
//!
//! `mbedtls_rng` and `mbedtls_psa_external_get_random` are `pub(crate)` /
//! private FFI callbacks, and `mbedtls-rs` is `#![no_std]` with
//! `[lib] harness = false`, so the real shims cannot be driven from a `tests/`
//! integration crate (which compiles as a separate std crate and only sees the
//! public API). Mirroring how `cert_key_ctor_aliasing.rs` / `blocking_eof.rs`
//! lock their private logic, this re-creates the shims' decision contract in
//! isolation and asserts the exact return codes. NOTE: it does NOT call the real
//! shims, so it cannot detect production drift on its own; it pins the intended
//! contract (the constants and branch outcomes) so that a change to them is a
//! visible, reviewed edit to BOTH this file and `lib.rs`.
//!
//! The constants below MUST match the production code in `lib.rs`:
//! - `mbedtls_rng` returns `MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED` (-52)
//!   on no-RNG / null buffer, and `0` for a zero-length request.
//! - `mbedtls_psa_external_get_random` returns `psa_status_t` values:
//!   `PSA_SUCCESS` (0), `PSA_ERROR_INVALID_ARGUMENT` (-135),
//!   `PSA_ERROR_INSUFFICIENT_ENTROPY` (-148).

const MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED: i32 = -52;
const PSA_SUCCESS: i32 = 0;
const PSA_ERROR_INVALID_ARGUMENT: i32 = -135;
const PSA_ERROR_INSUFFICIENT_ENTROPY: i32 = -148;

/// Mirror of `mbedtls_rng`'s decision logic (no FFI, no global RNG): `rng_present`
/// stands in for "a `Tls` is active", `buf_null`/`len` for the raw arguments.
fn rng_contract(rng_present: bool, buf_null: bool, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    if buf_null {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    if rng_present {
        0
    } else {
        MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
    }
}

/// Mirror of `mbedtls_psa_external_get_random`'s decision logic.
fn psa_contract(
    output_null: bool,
    output_len_null: bool,
    out_size: usize,
    rng_present: bool,
) -> i32 {
    if output_len_null {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if output_null && out_size != 0 {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if out_size == 0 {
        return PSA_SUCCESS;
    }
    if rng_contract(rng_present, output_null, out_size) == 0 {
        PSA_SUCCESS
    } else {
        PSA_ERROR_INSUFFICIENT_ENTROPY
    }
}

#[test]
fn rng_no_tls_returns_entropy_failure_not_panic() {
    // The old code did `rng.as_mut().unwrap()` -> panic/abort here.
    assert_eq!(
        rng_contract(false, false, 32),
        MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
    );
}

#[test]
fn rng_null_buffer_returns_entropy_failure() {
    assert_eq!(
        rng_contract(true, true, 32),
        MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
    );
}

#[test]
fn rng_zero_length_returns_ok_without_touching_buffer() {
    // len == 0 short-circuits before building a slice from a possibly-null ptr.
    assert_eq!(rng_contract(true, true, 0), 0);
}

#[test]
fn rng_happy_path_returns_ok() {
    assert_eq!(rng_contract(true, false, 32), 0);
}

#[test]
fn psa_null_output_len_is_invalid_argument() {
    assert_eq!(
        psa_contract(false, true, 32, true),
        PSA_ERROR_INVALID_ARGUMENT
    );
}

#[test]
fn psa_null_output_with_nonzero_size_is_invalid_argument() {
    assert_eq!(
        psa_contract(true, false, 32, true),
        PSA_ERROR_INVALID_ARGUMENT
    );
}

#[test]
fn psa_zero_size_with_null_output_is_success() {
    // A zero-size request may legitimately pass a null `output`.
    assert_eq!(psa_contract(true, false, 0, true), PSA_SUCCESS);
}

#[test]
fn psa_no_tls_maps_to_insufficient_entropy_not_mbedtls_err() {
    // Must be the PSA status -148, NOT the mbedtls -52.
    let rc = psa_contract(false, false, 32, false);
    assert_eq!(rc, PSA_ERROR_INSUFFICIENT_ENTROPY);
    assert_ne!(rc, MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED);
}

#[test]
fn psa_happy_path_is_success() {
    assert_eq!(psa_contract(false, false, 32, true), PSA_SUCCESS);
}
