//! Host-side MbedTLS crypto self-tests.
//!
//! These matter most for the hooked (`*_ALT`) algorithms, where the
//! implementation behind the MbedTLS API is this crate's Rust code:
//! - The AES self-test runs the NIST KATs for ECB/CBC/CFB/OFB/CTR/XTS against
//!   the `hook::aes` module (the MbedTLS software AES fallback + the Rust
//!   cipher-mode implementations).
//! - The `*_soft` self-tests run the same KATs directly against the software
//!   fallback objects (the hooked modules compiled a second time under
//!   `mbedtls_*_soft_*` names), bypassing the Rust hook layer.
//! - The ECP self-test (and the CCM/GCM/CMAC ones, transitively through the
//!   AES block hooks) exercises the `hook::ecp` shims and their soft
//!   fallbacks.

use std::sync::Mutex;

use mbedtls_rs_sys::*;

#[path = "support/psa_random.rs"]
mod psa_random;

/// The MbedTLS self-tests are not thread-safe (e.g. the ECP self-test
/// compares global operation counters that other concurrently-running ECP
/// users would skew), so serialize them.
static SERIAL: Mutex<()> = Mutex::new(());

fn run(name: &str, test: unsafe extern "C" fn(core::ffi::c_int) -> core::ffi::c_int) {
    let _guard = SERIAL.lock().unwrap();

    let ret = unsafe { test(1) };
    assert_eq!(ret, 0, "mbedtls {name} self-test failed with {ret}");
}

#[cfg(feature = "alg-aes")]
#[test]
fn aes() {
    run("AES", mbedtls_aes_self_test);
}

#[cfg(feature = "alg-ccm")]
#[test]
fn ccm() {
    run("CCM", mbedtls_ccm_self_test);
}

#[cfg(feature = "alg-gcm")]
#[test]
fn gcm() {
    run("GCM", mbedtls_gcm_self_test);
}

#[cfg(feature = "alg-cmac")]
#[test]
fn cmac() {
    run("CMAC", mbedtls_cmac_self_test);
}

#[cfg(feature = "alg-ecp")]
#[test]
fn ecp() {
    run("ECP", mbedtls_ecp_self_test);
}

#[cfg(feature = "alg-ecjpake")]
#[test]
fn ecjpake() {
    run("ECJPAKE", mbedtls_ecjpake_self_test);
}

#[cfg(feature = "alg-sha256")]
#[test]
fn sha256() {
    run("SHA-256", mbedtls_sha256_self_test);
}

#[test]
fn mpi() {
    run("MPI", mbedtls_mpi_self_test);
}

#[cfg(mbedtls_hook = "aes")]
#[test]
fn aes_soft() {
    run("AES (soft)", mbedtls_aes_soft_self_test);
}

#[cfg(mbedtls_hook = "sha1")]
#[test]
fn sha1_soft() {
    run("SHA-1 (soft)", mbedtls_sha1_soft_self_test);
}

#[cfg(mbedtls_hook = "sha256")]
#[test]
fn sha224_soft() {
    run("SHA-224 (soft)", mbedtls_sha224_soft_self_test);
}

#[cfg(mbedtls_hook = "sha256")]
#[test]
fn sha256_soft() {
    run("SHA-256 (soft)", mbedtls_sha256_soft_self_test);
}

#[cfg(mbedtls_hook = "sha512")]
#[test]
fn sha384_soft() {
    run("SHA-384 (soft)", mbedtls_sha384_soft_self_test);
}

#[cfg(mbedtls_hook = "sha512")]
#[test]
fn sha512_soft() {
    run("SHA-512 (soft)", mbedtls_sha512_soft_self_test);
}
