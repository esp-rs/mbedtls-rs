//! Host-side tests of the `embassy-crypto` hook implementations
//! (`hook::backend::embassy`), with the RustCrypto-based software drivers of
//! `embassy-crypto-rustcrypto` and the OS RNG driver of `embassy-crypto-rand`
//! registered.
//!
//! - The MbedTLS self-tests run the digest/AES KATs (and everything built on
//!   AES: CCM, GCM, CMAC, CTR-DRBG) through the hooks and thus the drivers.
//! - The curve tests check that the drivers serve the operations they are
//!   meant to - with results matching the MbedTLS software implementation
//!   (for signatures: verifying with it, both ways) - and that everything
//!   else is left to software.
//! - The ECDSA and ECDH tests go through the hooked MbedTLS API end to end.

use core::ffi::{c_int, c_uchar, c_void};
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard, Once};

use mbedtls_rs_sys::*;

// Register the `embassy-crypto` drivers
use embassy_crypto_rand as _;
use embassy_crypto_rustcrypto as _;

#[cfg(feature = "alg-ecp")]
use mbedtls_rs_sys::hook::backend::embassy::ecp::{self as embassy_ec, EmbassyCurves, P256, P384};

/// Serializes the tests: the MbedTLS self-tests are not thread-safe (see
/// `crypto_self_tests.rs`), and the hooks are process-global.
static SERIAL: Mutex<()> = Mutex::new(());

/// The elliptic-curve implementations hooked by the tests
#[cfg(all(feature = "alg-ecp", not(feature = "nohook-ecp-mul")))]
static ECP: embassy_ec::EmbassyEcp<(P256, P384)> = embassy_ec::EmbassyEcp::new();
#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
static ECDSA: embassy_ec::EmbassyEcdsa<(P256, P384)> = embassy_ec::EmbassyEcdsa::new();
#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
static ECDH: embassy_ec::EmbassyEcdh<(P256, P384)> = embassy_ec::EmbassyEcdh::new();

/// Serialize with the other tests, with the `embassy-crypto` implementations hooked
fn hooked() -> MutexGuard<'static, ()> {
    static HOOK: Once = Once::new();

    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    HOOK.call_once(|| unsafe {
        #[allow(unused_imports)]
        use mbedtls_rs_sys::hook::backend::embassy;

        #[cfg(all(feature = "alg-sha1", not(feature = "nohook-sha1")))]
        hook::digest::hook_sha1(Some(&embassy::SHA1));
        #[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
        {
            hook::digest::hook_sha224(Some(&embassy::SHA224));
            hook::digest::hook_sha256(Some(&embassy::SHA256));
        }
        #[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
        {
            hook::digest::hook_sha384(Some(&embassy::SHA384));
            hook::digest::hook_sha512(Some(&embassy::SHA512));
        }
        #[cfg(all(feature = "alg-aes", not(feature = "nohook-aes")))]
        hook::aes::hook_aes(Some(&embassy::AES));
        #[cfg(all(feature = "alg-ecp", not(feature = "nohook-ecp-mul")))]
        hook::ecp::hook_ecp_mul(Some(&ECP));
        #[cfg(all(
            feature = "alg-ecp",
            feature = "alg-ecdsa",
            not(feature = "nohook-ecdsa"),
            not(feature = "ecp-restartable")
        ))]
        hook::ecdsa::hook_ecdsa(Some(&ECDSA));
        #[cfg(all(
            feature = "alg-ecp",
            feature = "alg-ecdh",
            not(feature = "nohook-ecdh"),
            not(feature = "ecp-restartable")
        ))]
        hook::ecdh::hook_ecdh(Some(&ECDH));
    });

    guard
}

fn self_test(name: &str, test: unsafe extern "C" fn(c_int) -> c_int) {
    let _guard = hooked();

    let ret = unsafe { test(1) };
    assert_eq!(ret, 0, "mbedtls {name} self-test failed with {ret}");
}

#[cfg(feature = "alg-sha1")]
#[test]
fn sha1() {
    self_test("SHA-1", mbedtls_sha1_self_test);
}

#[cfg(feature = "alg-sha256")]
#[test]
fn sha224() {
    self_test("SHA-224", mbedtls_sha224_self_test);
}

#[cfg(feature = "alg-sha256")]
#[test]
fn sha256() {
    self_test("SHA-256", mbedtls_sha256_self_test);
}

#[cfg(feature = "alg-sha512")]
#[test]
fn sha384() {
    self_test("SHA-384", mbedtls_sha384_self_test);
}

#[cfg(feature = "alg-sha512")]
#[test]
fn sha512() {
    self_test("SHA-512", mbedtls_sha512_self_test);
}

#[cfg(feature = "alg-aes")]
#[test]
fn aes() {
    self_test("AES", mbedtls_aes_self_test);
}

#[cfg(feature = "alg-ccm")]
#[test]
fn ccm() {
    self_test("CCM", mbedtls_ccm_self_test);
}

#[cfg(feature = "alg-gcm")]
#[test]
fn gcm() {
    self_test("GCM", mbedtls_gcm_self_test);
}

#[cfg(feature = "alg-cmac")]
#[test]
fn cmac() {
    self_test("CMAC", mbedtls_cmac_self_test);
}

#[cfg(feature = "drbg-ctr")]
#[test]
fn ctr_drbg() {
    self_test("CTR-DRBG", mbedtls_ctr_drbg_self_test);
}

#[cfg(feature = "alg-ecp")]
#[test]
fn ecp() {
    self_test("ECP", mbedtls_ecp_self_test);
}

#[cfg(feature = "alg-ecjpake")]
#[test]
fn ecjpake() {
    self_test("ECJPAKE", mbedtls_ecjpake_self_test);
}

/// A digest cloned mid-stream (a typed clone of the `embassy-crypto` hash)
/// finishes like the original.
#[cfg(feature = "alg-sha256")]
#[test]
fn sha256_clone() {
    const HELLO_WORLD: [u8; 32] = [
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab,
        0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef,
        0xcd, 0xe9,
    ];

    let _guard = hooked();

    let mut ctx = Ctx::new(mbedtls_sha256_init, mbedtls_sha256_free);
    let mut clone = Ctx::new(mbedtls_sha256_init, mbedtls_sha256_free);

    unsafe {
        assert_eq!(mbedtls_sha256_starts(&mut *ctx, 0), 0);
        assert_eq!(mbedtls_sha256_update(&mut *ctx, b"hello ".as_ptr(), 6), 0);

        mbedtls_sha256_clone(&mut *clone, &*ctx);

        for ctx in [&mut ctx, &mut clone] {
            let mut digest = [0; 32];

            assert_eq!(mbedtls_sha256_update(&mut **ctx, b"world".as_ptr(), 5), 0);
            assert_eq!(mbedtls_sha256_finish(&mut **ctx, digest.as_mut_ptr()), 0);

            assert_eq!(digest, HELLO_WORLD);
        }
    }
}

/// `C` serves in-range multiplications on its curve with the driver - by the
/// base point and by an arbitrary point - with the same results as the
/// MbedTLS software implementation, and leaves everything else (out-of-range
/// scalars, points not on the curve, other curves) to software, which
/// reports the MbedTLS error codes through the hooked API.
#[cfg(all(feature = "alg-ecp", not(feature = "nohook-ecp-mul")))]
#[allow(dead_code)]
fn check_mul<C: EmbassyCurves, Other: EmbassyCurves>(id: mbedtls_ecp_group_id) {
    let _guard = hooked();

    let mut grp = group(id);

    let mut seed = 0x0123_4567_89ab_cdef_u64;
    let p_rng = &mut seed as *mut u64 as *mut c_void;

    let g = base_point(&grp);

    let mut m = mpi();

    for _ in 0..8 {
        assert_eq!(
            unsafe { mbedtls_ecp_gen_privkey(&*grp, &mut *m, Some(rng), p_rng) },
            0
        );

        let (_, q) = keypair(&mut grp, p_rng);

        for p in [&g, &q] {
            let mut expected = point();
            unsafe {
                hook::ecp::ecp_mul_soft(
                    &mut grp,
                    &mut expected,
                    &m,
                    p,
                    Some(rng),
                    p_rng,
                    core::ptr::null_mut(),
                )
            }
            .unwrap();

            let mut actual = point();
            assert!(
                matches!(C::mul(&grp, &mut actual, &m, p), Some(Ok(()))),
                "not served by the driver"
            );

            assert_eq!(unsafe { mbedtls_ecp_point_cmp(&*expected, &*actual) }, 0);
        }
    }

    let mut r = point();

    // Scalars outside `[1, n)`
    assert!(C::mul(&grp, &mut r, &mpi(), &g).is_none());

    let mut n = mpi();
    assert_eq!(unsafe { mbedtls_mpi_copy(&mut *n, &grp.N) }, 0);
    assert!(C::mul(&grp, &mut r, &n, &g).is_none());

    // A point not on the curve
    let off_curve = off_curve_point();
    assert!(C::mul(&grp, &mut r, &m, &off_curve).is_none());

    let ret = unsafe { mbedtls_ecp_mul(&mut *grp, &mut *r, &*m, &*off_curve, Some(rng), p_rng) };
    assert_eq!(ret, MBEDTLS_ERR_ECP_INVALID_KEY);

    // Another curve
    assert!(Other::mul(&grp, &mut r, &m, &g).is_none());
}

/// `C` serves ECDSA signing and verification on its curve with the driver -
/// hashes shorter and longer than the curve order included - with signatures
/// the MbedTLS software implementation verifies and vice versa, and leaves
/// out-of-range private keys, public keys not on the curve and other curves
/// to software.
#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
#[allow(dead_code)]
fn check_curve_ecdsa<C: EmbassyCurves, Other: EmbassyCurves>(id: mbedtls_ecp_group_id) {
    let _guard = hooked();

    let mut grp = group(id);

    let mut seed = 0x0f1e_2d3c_4b5a_6978_u64;
    let p_rng = &mut seed as *mut u64 as *mut c_void;

    let (d, q) = keypair(&mut grp, p_rng);

    for len in [20, 32, 48, 64] {
        let hash = (0..len).map(|i| (i * 37 + 1) as u8).collect::<Vec<_>>();
        let mut tampered = hash.clone();
        tampered[0] ^= 1;

        // Signed by the driver, verified by software
        let (mut r, mut s) = (mpi(), mpi());
        assert!(
            matches!(C::ecdsa_sign(&grp, &mut r, &mut s, &d, &hash), Some(Ok(()))),
            "not served by the driver"
        );
        hook::ecdsa::ecdsa_verify_soft(&mut grp, &hash, &q, &r, &s).unwrap();

        // Signed by software, verified by the driver
        let (mut r, mut s) = (mpi(), mpi());
        unsafe {
            hook::ecdsa::ecdsa_sign_soft(&mut grp, &mut r, &mut s, &d, &hash, Some(rng), p_rng)
        }
        .unwrap();
        assert!(matches!(
            C::ecdsa_verify(&grp, &hash, &q, &r, &s),
            Some(Ok(()))
        ));
        assert!(matches!(
            C::ecdsa_verify(&grp, &tampered, &q, &r, &s),
            Some(Err(e)) if e.code() == MBEDTLS_ERR_ECP_VERIFY_FAILED
        ));
    }

    let hash = [0x5a; 32];
    let (mut r, mut s) = (mpi(), mpi());

    // A private key outside `[1, n)`
    assert!(C::ecdsa_sign(&grp, &mut r, &mut s, &mpi(), &hash).is_none());

    // Another curve
    assert!(Other::ecdsa_sign(&grp, &mut r, &mut s, &d, &hash).is_none());

    unsafe { hook::ecdsa::ecdsa_sign_soft(&mut grp, &mut r, &mut s, &d, &hash, Some(rng), p_rng) }
        .unwrap();

    // A public key not on the curve
    assert!(C::ecdsa_verify(&grp, &hash, &off_curve_point(), &r, &s).is_none());

    // Another curve
    assert!(Other::ecdsa_verify(&grp, &hash, &q, &r, &s).is_none());
}

/// `C` serves ECDH public keys and shared secrets on its curve with the
/// driver, with the same results as the MbedTLS software implementation, and
/// leaves out-of-range private keys, peer public keys not on the curve and
/// other curves to software.
#[cfg(all(
    feature = "alg-ecp",
    not(feature = "nohook-ecp-mul"),
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
#[allow(dead_code)]
fn check_curve_ecdh<C: EmbassyCurves, Other: EmbassyCurves>(id: mbedtls_ecp_group_id) {
    let _guard = hooked();

    let mut grp = group(id);

    let mut seed = 0x1357_9bdf_2468_ace0_u64;
    let p_rng = &mut seed as *mut u64 as *mut c_void;

    let g = base_point(&grp);

    for _ in 0..4 {
        let (d, _) = keypair(&mut grp, p_rng);
        let (_, peer) = keypair(&mut grp, p_rng);

        let mut expected = point();
        unsafe {
            hook::ecp::ecp_mul_soft(
                &mut grp,
                &mut expected,
                &d,
                &g,
                Some(rng),
                p_rng,
                core::ptr::null_mut(),
            )
        }
        .unwrap();

        let mut actual = point();
        assert!(
            matches!(C::ecdh_public_key(&grp, &mut actual, &d), Some(Ok(()))),
            "not served by the driver"
        );
        assert_eq!(unsafe { mbedtls_ecp_point_cmp(&*expected, &*actual) }, 0);

        let mut expected = mpi();
        unsafe {
            hook::ecdh::ecdh_compute_shared_soft(
                &mut grp,
                &mut expected,
                &peer,
                &d,
                Some(rng),
                p_rng,
            )
        }
        .unwrap();

        let mut actual = mpi();
        assert!(matches!(
            C::ecdh_shared_secret(&grp, &mut actual, &peer, &d),
            Some(Ok(()))
        ));
        assert_eq!(unsafe { mbedtls_mpi_cmp_mpi(&*expected, &*actual) }, 0);
    }

    let (d, q) = keypair(&mut grp, p_rng);
    let (mut r, mut z) = (point(), mpi());

    // A private key outside `[1, n)`
    assert!(C::ecdh_public_key(&grp, &mut r, &mpi()).is_none());
    assert!(C::ecdh_shared_secret(&grp, &mut z, &q, &mpi()).is_none());

    // A peer public key not on the curve
    assert!(C::ecdh_shared_secret(&grp, &mut z, &off_curve_point(), &d).is_none());

    // Another curve
    assert!(Other::ecdh_public_key(&grp, &mut r, &d).is_none());
    assert!(Other::ecdh_shared_secret(&grp, &mut z, &q, &d).is_none());
}

/// ECDSA through the hooked MbedTLS API: raw and deterministic (ASN.1)
/// signatures - the latter randomized by the driver, so no two are the same -
/// and the MbedTLS error codes for signatures that do not verify and public
/// keys not on the curve (the latter left to software).
#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
#[allow(dead_code)]
fn check_ecdsa(id: mbedtls_ecp_group_id) {
    let _guard = hooked();

    let mut grp = group(id);

    let mut seed = 0xfedc_ba98_7654_3210_u64;
    let p_rng = &mut seed as *mut u64 as *mut c_void;

    let (d, q) = keypair(&mut grp, p_rng);

    let mut hash = [0x5a; 32];
    let (mut r, mut s) = (mpi(), mpi());

    unsafe {
        let ret = mbedtls_ecdsa_sign(
            &mut *grp,
            &mut *r,
            &mut *s,
            &*d,
            hash.as_ptr(),
            hash.len(),
            Some(rng),
            p_rng,
        );
        assert_eq!(ret, 0);

        let ret = mbedtls_ecdsa_verify(&mut *grp, hash.as_ptr(), hash.len(), &*q, &*r, &*s);
        assert_eq!(ret, 0);

        let off_curve = off_curve_point();
        let expected = hook::ecdsa::ecdsa_verify_soft(&mut grp, &hash, &off_curve, &r, &s)
            .unwrap_err()
            .code();
        let ret = mbedtls_ecdsa_verify(&mut *grp, hash.as_ptr(), hash.len(), &*off_curve, &*r, &*s);
        assert_eq!(ret, expected);

        hash[0] ^= 1;
        let ret = mbedtls_ecdsa_verify(&mut *grp, hash.as_ptr(), hash.len(), &*q, &*r, &*s);
        assert_eq!(ret, MBEDTLS_ERR_ECP_VERIFY_FAILED);
    }

    let mut ctx = Ctx::new(mbedtls_ecdsa_init, mbedtls_ecdsa_free);
    let mut sigs = [([0; 160], 0); 2];

    unsafe {
        assert_eq!(mbedtls_ecdsa_genkey(&mut *ctx, id, Some(rng), p_rng), 0);

        for (sig, len) in &mut sigs {
            let ret = mbedtls_ecdsa_write_signature(
                &mut *ctx,
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

            let ret = mbedtls_ecdsa_read_signature(
                &mut *ctx,
                hash.as_ptr(),
                hash.len(),
                sig.as_ptr(),
                *len,
            );
            assert_eq!(ret, 0);
        }

        assert_ne!(sigs[0].0[..sigs[0].1], sigs[1].0[..sigs[1].1]);

        let (sig, len) = &sigs[0];
        hash[0] ^= 1;
        let ret =
            mbedtls_ecdsa_read_signature(&mut *ctx, hash.as_ptr(), hash.len(), sig.as_ptr(), *len);
        assert_eq!(ret, MBEDTLS_ERR_ECP_VERIFY_FAILED);
    }
}

/// ECDH through the hooked MbedTLS API: two parties agree on the shared
/// secret the software implementation computes, and a peer public key not on
/// the curve fails with the MbedTLS error code (left to software).
#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
#[allow(dead_code)]
fn check_ecdh(id: mbedtls_ecp_group_id) {
    let _guard = hooked();

    let mut grp = group(id);

    let mut seed = 0x0246_8ace_1357_9bdf_u64;
    let p_rng = &mut seed as *mut u64 as *mut c_void;

    let (mut d1, mut q1, mut d2, mut q2) = (mpi(), point(), mpi(), point());
    let (mut z1, mut z2, mut expected) = (mpi(), mpi(), mpi());

    unsafe {
        let ret = mbedtls_ecdh_gen_public(&mut *grp, &mut *d1, &mut *q1, Some(rng), p_rng);
        assert_eq!(ret, 0);
        let ret = mbedtls_ecdh_gen_public(&mut *grp, &mut *d2, &mut *q2, Some(rng), p_rng);
        assert_eq!(ret, 0);

        let ret = mbedtls_ecdh_compute_shared(&mut *grp, &mut *z1, &*q2, &*d1, Some(rng), p_rng);
        assert_eq!(ret, 0);
        let ret = mbedtls_ecdh_compute_shared(&mut *grp, &mut *z2, &*q1, &*d2, Some(rng), p_rng);
        assert_eq!(ret, 0);

        assert_eq!(mbedtls_mpi_cmp_mpi(&*z1, &*z2), 0);

        hook::ecdh::ecdh_compute_shared_soft(&mut grp, &mut expected, &q2, &d1, Some(rng), p_rng)
            .unwrap();
        assert_eq!(mbedtls_mpi_cmp_mpi(&*expected, &*z1), 0);

        let off_curve = off_curve_point();
        let expected = hook::ecdh::ecdh_compute_shared_soft(
            &mut grp,
            &mut expected,
            &off_curve,
            &d1,
            Some(rng),
            p_rng,
        )
        .unwrap_err()
        .code();
        let ret =
            mbedtls_ecdh_compute_shared(&mut *grp, &mut *z1, &*off_curve, &*d1, Some(rng), p_rng);
        assert_eq!(ret, expected);
    }
}

#[cfg(all(
    feature = "alg-ecp",
    not(feature = "nohook-ecp-mul"),
    feature = "curve-secp256r1"
))]
#[test]
fn p256_mul() {
    check_mul::<P256, P384>(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);
}

#[cfg(all(
    feature = "alg-ecp",
    not(feature = "nohook-ecp-mul"),
    feature = "curve-secp384r1"
))]
#[test]
fn p384_mul() {
    check_mul::<P384, P256>(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1);
}

#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp256r1"
))]
#[test]
fn p256_curve_ecdsa() {
    check_curve_ecdsa::<P256, P384>(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);
}

#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp384r1"
))]
#[test]
fn p384_curve_ecdsa() {
    check_curve_ecdsa::<P384, P256>(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1);
}

#[cfg(all(
    feature = "alg-ecp",
    not(feature = "nohook-ecp-mul"),
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp256r1"
))]
#[test]
fn p256_curve_ecdh() {
    check_curve_ecdh::<P256, P384>(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);
}

#[cfg(all(
    feature = "alg-ecp",
    not(feature = "nohook-ecp-mul"),
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp384r1"
))]
#[test]
fn p384_curve_ecdh() {
    check_curve_ecdh::<P384, P256>(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1);
}

#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp256r1"
))]
#[test]
fn p256_ecdsa() {
    check_ecdsa(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);
}

#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp384r1"
))]
#[test]
fn p384_ecdsa() {
    check_ecdsa(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1);
}

#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp256r1"
))]
#[test]
fn p256_ecdh() {
    check_ecdh(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1);
}

#[cfg(all(
    feature = "alg-ecp",
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable"),
    feature = "curve-secp384r1"
))]
#[test]
fn p384_ecdh() {
    check_ecdh(mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1);
}

/// An MbedTLS context, initialized and freed with the given functions
struct Ctx<T> {
    inner: T,
    free: unsafe extern "C" fn(*mut T),
}

impl<T> Ctx<T> {
    fn new(init: unsafe extern "C" fn(*mut T), free: unsafe extern "C" fn(*mut T)) -> Self {
        let mut inner = MaybeUninit::uninit();
        unsafe { init(inner.as_mut_ptr()) };

        Self {
            inner: unsafe { inner.assume_init() },
            free,
        }
    }
}

impl<T> Deref for Ctx<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for Ctx<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> Drop for Ctx<T> {
    fn drop(&mut self) {
        unsafe { (self.free)(&mut self.inner) };
    }
}

#[allow(dead_code)]
fn mpi() -> Ctx<mbedtls_mpi> {
    Ctx::new(mbedtls_mpi_init, mbedtls_mpi_free)
}

#[allow(dead_code)]
fn point() -> Ctx<mbedtls_ecp_point> {
    Ctx::new(mbedtls_ecp_point_init, mbedtls_ecp_point_free)
}

#[allow(dead_code)]
fn group(id: mbedtls_ecp_group_id) -> Ctx<mbedtls_ecp_group> {
    let mut grp = Ctx::new(mbedtls_ecp_group_init, mbedtls_ecp_group_free);
    assert_eq!(unsafe { mbedtls_ecp_group_load(&mut *grp, id) }, 0);

    grp
}

/// The base point of the group, as a point of its own (so that the group
/// can be borrowed mutably while using it)
#[allow(dead_code)]
fn base_point(grp: &mbedtls_ecp_group) -> Ctx<mbedtls_ecp_point> {
    let mut g = point();
    assert_eq!(unsafe { mbedtls_ecp_copy(&mut *g, &grp.G) }, 0);

    g
}

/// A random key pair on the group
#[allow(dead_code)]
fn keypair(
    grp: &mut mbedtls_ecp_group,
    p_rng: *mut c_void,
) -> (Ctx<mbedtls_mpi>, Ctx<mbedtls_ecp_point>) {
    let (mut d, mut q) = (mpi(), point());
    assert_eq!(
        unsafe { mbedtls_ecp_gen_keypair(grp, &mut *d, &mut *q, Some(rng), p_rng) },
        0
    );

    (d, q)
}

/// The affine point (1, 1), which is on none of the curves
#[allow(dead_code)]
fn off_curve_point() -> Ctx<mbedtls_ecp_point> {
    let mut pt = point();

    unsafe {
        assert_eq!(mbedtls_mpi_lset(&mut pt.private_X, 1), 0);
        assert_eq!(mbedtls_mpi_lset(&mut pt.private_Y, 1), 0);
        assert_eq!(mbedtls_mpi_lset(&mut pt.private_Z, 1), 0);
    }

    pt
}

/// A deterministic RNG (xorshift64), good enough for drawing test operands
#[allow(dead_code)]
unsafe extern "C" fn rng(state: *mut c_void, output: *mut c_uchar, len: usize) -> c_int {
    let state = unsafe { &mut *(state as *mut u64) };

    for byte in unsafe { core::slice::from_raw_parts_mut(output, len) } {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *byte = (*state >> 24) as u8;
    }

    0
}
