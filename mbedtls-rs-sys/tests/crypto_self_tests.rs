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

#[cfg(all(feature = "alg-aes", not(feature = "nohook-aes")))]
#[test]
fn aes_soft() {
    run("AES (soft)", mbedtls_aes_soft_self_test);
}

#[cfg(all(feature = "alg-sha1", not(feature = "nohook-sha1")))]
#[test]
fn sha1_soft() {
    run("SHA-1 (soft)", mbedtls_sha1_soft_self_test);
}

#[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
#[test]
fn sha224_soft() {
    run("SHA-224 (soft)", mbedtls_sha224_soft_self_test);
}

#[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
#[test]
fn sha256_soft() {
    run("SHA-256 (soft)", mbedtls_sha256_soft_self_test);
}

#[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
#[test]
fn sha384_soft() {
    run("SHA-384 (soft)", mbedtls_sha384_soft_self_test);
}

#[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
#[test]
fn sha512_soft() {
    run("SHA-512 (soft)", mbedtls_sha512_soft_self_test);
}

/// ECDSA through the `mbedtls_ecdsa_sign` / `mbedtls_ecdsa_verify` shims
/// with nothing hooked, i.e. with the software fallback: deterministic
/// (RFC 6979) signatures, the same for the same hash, that verify.
#[cfg(all(feature = "alg-ecdsa", feature = "curve-secp256r1"))]
#[test]
fn ecdsa() {
    let _guard = SERIAL.lock().unwrap();

    let mut seed = 0x0123_4567_89ab_cdef_u64;
    let p_rng = &mut seed as *mut u64 as *mut core::ffi::c_void;

    unsafe {
        let mut ctx = core::mem::MaybeUninit::<mbedtls_ecdsa_context>::uninit();
        mbedtls_ecdsa_init(ctx.as_mut_ptr());
        let ctx = ctx.as_mut_ptr();

        let ret = mbedtls_ecdsa_genkey(
            ctx,
            mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
            Some(rng),
            p_rng,
        );
        assert_eq!(ret, 0);

        let mut hash = [0x5a; 32];
        let mut sigs = [([0; 160], 0); 2];

        for (sig, len) in &mut sigs {
            let ret = mbedtls_ecdsa_write_signature(
                ctx,
                mbedtls_md_type_t_MBEDTLS_MD_SHA256,
                hash.as_ptr(),
                hash.len(),
                sig.as_mut_ptr(),
                sig.len(),
                len,
                Some(rng),
                p_rng,
            );
            assert_eq!(ret, 0);
        }

        let (sig, len) = &sigs[0];
        assert_eq!(sig[..*len], sigs[1].0[..sigs[1].1]);

        let ret = mbedtls_ecdsa_read_signature(ctx, hash.as_ptr(), hash.len(), sig.as_ptr(), *len);
        assert_eq!(ret, 0);

        hash[0] ^= 1;
        let ret = mbedtls_ecdsa_read_signature(ctx, hash.as_ptr(), hash.len(), sig.as_ptr(), *len);
        assert_eq!(ret, MBEDTLS_ERR_ECP_VERIFY_FAILED);

        mbedtls_ecdsa_free(ctx);
    }
}

/// ECDH through the `mbedtls_ecdh_gen_public` /
/// `mbedtls_ecdh_compute_shared` shims with nothing hooked, i.e. with the
/// software fallback: two parties agree on the shared secret.
#[cfg(all(feature = "alg-ecdh", feature = "curve-secp256r1"))]
#[test]
fn ecdh() {
    let _guard = SERIAL.lock().unwrap();

    let mut seed = 0x0123_4567_89ab_cdef_u64;
    let p_rng = &mut seed as *mut u64 as *mut core::ffi::c_void;

    unsafe {
        let mut grp = core::mem::MaybeUninit::<mbedtls_ecp_group>::uninit();
        mbedtls_ecp_group_init(grp.as_mut_ptr());
        let grp = grp.as_mut_ptr();

        let ret = mbedtls_ecp_group_load(grp, mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);
        assert_eq!(ret, 0);

        // The all-zero MPI and point are the initialized ones
        let mut d: [mbedtls_mpi; 2] = core::mem::zeroed();
        let mut q: [mbedtls_ecp_point; 2] = core::mem::zeroed();
        let mut z: [mbedtls_mpi; 2] = core::mem::zeroed();

        for (d, q) in d.iter_mut().zip(q.iter_mut()) {
            assert_eq!(mbedtls_ecdh_gen_public(grp, d, q, Some(rng), p_rng), 0);
        }

        for (i, z) in z.iter_mut().enumerate() {
            let ret = mbedtls_ecdh_compute_shared(grp, z, &q[1 - i], &d[i], Some(rng), p_rng);
            assert_eq!(ret, 0);
        }

        assert_eq!(mbedtls_mpi_cmp_mpi(&z[0], &z[1]), 0);

        for ((d, q), z) in d.iter_mut().zip(q.iter_mut()).zip(z.iter_mut()) {
            mbedtls_mpi_free(d);
            mbedtls_ecp_point_free(q);
            mbedtls_mpi_free(z);
        }
        mbedtls_ecp_group_free(grp);
    }
}

/// A deterministic RNG (xorshift64), good enough for drawing test operands
#[allow(dead_code)]
unsafe extern "C" fn rng(
    state: *mut core::ffi::c_void,
    output: *mut core::ffi::c_uchar,
    len: usize,
) -> core::ffi::c_int {
    let state = unsafe { &mut *(state as *mut u64) };

    for byte in unsafe { core::slice::from_raw_parts_mut(output, len) } {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *byte = (*state >> 24) as u8;
    }

    0
}
