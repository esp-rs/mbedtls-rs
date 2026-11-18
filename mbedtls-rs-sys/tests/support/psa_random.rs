//! `mbedtls_psa_external_get_random`, which this crate leaves to its
//! consumer (`mbedtls-rs` defines it), for the tests that link MbedTLS on
//! their own.
//!
//! No test calls it, but the MSVC linker wants every symbol of the objects it
//! links, used or not. It fails rather than give bytes that are not random:
//! the tests use their own RNGs.

use core::ffi::{c_int, c_uchar};

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    _output: *mut c_uchar,
    _out_size: usize,
    _output_len: *mut usize,
) -> c_int {
    // `PSA_ERROR_INSUFFICIENT_ENTROPY`
    -148
}
