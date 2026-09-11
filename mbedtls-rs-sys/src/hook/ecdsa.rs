//! Hook for the MbedTLS ECDSA signature generation and verification.
//!
//! Every ECDSA signature MbedTLS computes or checks goes through
//! `mbedtls_ecdsa_sign` and `mbedtls_ecdsa_verify` - the deterministic
//! (RFC 6979) and ASN.1 wrappers, the PK and TLS layers, and the PSA crypto
//! implementation included. With the `MBEDTLS_ECDSA_SIGN_ALT` /
//! `MBEDTLS_ECDSA_VERIFY_ALT` options, both are provided here in Rust,
//! dispatching to a hooked implementation - or to the MbedTLS software
//! implementation when un-hooked (or when the hooked implementation itself
//! decides to fall back, e.g. for a curve its engine does not support).
//!
//! The software implementation is kept by compiling `ecdsa.c` a second time
//! under `mbedtls_ecdsa_soft_*` names (see `SoftFallback` in
//! `gen/builder.rs`). It computes signatures with the ECP scalar
//! multiplication, so it is accelerated whenever that is hooked (see
//! [`crate::hook::ecp`]); this hook is for engines doing ECDSA as a whole.
//!
//! Unavailable with the `ecp-restartable` feature: MbedTLS does not support
//! restartable ECP operations together with alternative ECDSA implementations.

use core::ffi::c_void;
use core::ops::Deref;

use crate::hook::ecp::MbedtlsFRng;
use crate::{mbedtls_ecp_group, mbedtls_ecp_point, mbedtls_mpi, MbedtlsError};

/// Trait representing a custom (hooked) MbedTLS ECDSA implementation
pub trait MbedtlsEcdsa {
    /// Sign the message hash `hash` with the private key `d`, producing the
    /// signature `(r, s)`.
    ///
    /// As specified by ECDSA, only the leftmost bits of `hash` - as many as
    /// the curve order has - are signed; it may be of any length.
    ///
    /// Implementations that cannot handle the given group (or operands) are
    /// expected to delegate to [`ecdsa_sign_soft`].
    ///
    /// # Arguments
    /// - `grp` - The ECP group (mutable, as the software implementation
    ///   caches pre-computed tables inside it)
    /// - `r`, `s` - The destination signature
    /// - `d` - The private key
    /// - `hash` - The message hash
    /// - `f_rng`/`p_rng` - The RNG to draw the nonce (and the blinding values)
    ///   from. For deterministic ECDSA (`mbedtls_ecdsa_sign_det_ext`, and all
    ///   signatures of the PK and TLS layers when `MBEDTLS_ECDSA_DETERMINISTIC`
    ///   is enabled), it is an RFC 6979 HMAC-DRBG seeded with the private key
    ///   and the hash: implementations drawing the nonce from elsewhere produce
    ///   valid, but randomized signatures.
    ///
    /// # Safety
    /// - `f_rng`/`p_rng` are raw values passed through from MbedTLS; the
    ///   caller must ensure they are valid for the duration of the call
    ///   (implementations typically just forward them to [`ecdsa_sign_soft`])
    #[allow(clippy::too_many_arguments)]
    unsafe fn sign(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_mpi,
        s: &mut mbedtls_mpi,
        d: &mbedtls_mpi,
        hash: &[u8],
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> Result<(), MbedtlsError>;

    /// Verify the signature `(r, s)` of the message hash `hash` with the
    /// public key `q`.
    ///
    /// Signatures that do not verify are reported with
    /// `MBEDTLS_ERR_ECP_VERIFY_FAILED`. As for [`MbedtlsEcdsa::sign`], only
    /// the leftmost bits of `hash` are considered.
    ///
    /// Implementations that cannot handle the given group (or operands) are
    /// expected to delegate to [`ecdsa_verify_soft`].
    fn verify(
        &self,
        grp: &mut mbedtls_ecp_group,
        hash: &[u8],
        q: &mbedtls_ecp_point,
        r: &mbedtls_mpi,
        s: &mbedtls_mpi,
    ) -> Result<(), MbedtlsError>;
}

impl<T> MbedtlsEcdsa for T
where
    T: Deref,
    T::Target: MbedtlsEcdsa,
{
    unsafe fn sign(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_mpi,
        s: &mut mbedtls_mpi,
        d: &mbedtls_mpi,
        hash: &[u8],
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> Result<(), MbedtlsError> {
        unsafe { self.deref().sign(grp, r, s, d, hash, f_rng, p_rng) }
    }

    fn verify(
        &self,
        grp: &mut mbedtls_ecp_group,
        hash: &[u8],
        q: &mbedtls_ecp_point,
        r: &mbedtls_mpi,
        s: &mbedtls_mpi,
    ) -> Result<(), MbedtlsError> {
        self.deref().verify(grp, hash, q, r, s)
    }
}

/// The MbedTLS software implementation of the ECDSA signature generation.
///
/// Available for hooked implementations to delegate to (e.g. for curves not
/// supported by their engine).
///
/// # Safety
/// - The raw `f_rng`/`p_rng` values must be valid for the duration of the
///   call (they are normally just passed through from the hook).
#[cfg(all(
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn ecdsa_sign_soft(
    grp: &mut mbedtls_ecp_group,
    r: &mut mbedtls_mpi,
    s: &mut mbedtls_mpi,
    d: &mbedtls_mpi,
    hash: &[u8],
    f_rng: MbedtlsFRng,
    p_rng: *mut c_void,
) -> Result<(), MbedtlsError> {
    crate::merr!(unsafe {
        alt::mbedtls_ecdsa_soft_sign(grp, r, s, d, hash.as_ptr(), hash.len(), f_rng, p_rng)
    })?;

    Ok(())
}

/// The MbedTLS software implementation of the ECDSA signature verification.
///
/// Available for hooked implementations to delegate to (e.g. for curves not
/// supported by their engine).
#[cfg(all(
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
pub fn ecdsa_verify_soft(
    grp: &mut mbedtls_ecp_group,
    hash: &[u8],
    q: &mbedtls_ecp_point,
    r: &mbedtls_mpi,
    s: &mbedtls_mpi,
) -> Result<(), MbedtlsError> {
    crate::merr!(unsafe {
        alt::mbedtls_ecdsa_soft_verify(grp, hash.as_ptr(), hash.len(), q, r, s)
    })?;

    Ok(())
}

/// Hook the ECDSA implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use ECDSA, and ensure that the implementation
///   is valid for the duration of its use.
#[cfg(all(
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
pub unsafe fn hook_ecdsa(ecdsa: Option<&'static (dyn MbedtlsEcdsa + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if ecdsa.is_some() {
            debug!("ECDSA hook: added custom/HW accelerated impl");
        } else {
            debug!("ECDSA hook: removed");
        }

        alt::ECDSA.borrow(cs).set(ecdsa);
    });
}

#[cfg(all(
    feature = "alg-ecdsa",
    not(feature = "nohook-ecdsa"),
    not(feature = "ecp-restartable")
))]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar, c_void};

    use critical_section::Mutex;

    use crate::hook::ecp::MbedtlsFRng;
    use crate::{mbedtls_ecp_group, mbedtls_ecp_point, mbedtls_mpi};

    use super::{ecdsa_sign_soft, ecdsa_verify_soft, MbedtlsEcdsa};

    // The software fallback, from the second compilation of `ecdsa.c` (see
    // `SoftFallback` in `gen/builder.rs`)
    extern "C" {
        #[allow(clippy::too_many_arguments)]
        pub(super) fn mbedtls_ecdsa_soft_sign(
            grp: *mut mbedtls_ecp_group,
            r: *mut mbedtls_mpi,
            s: *mut mbedtls_mpi,
            d: *const mbedtls_mpi,
            buf: *const c_uchar,
            blen: usize,
            f_rng: MbedtlsFRng,
            p_rng: *mut c_void,
        ) -> c_int;

        pub(super) fn mbedtls_ecdsa_soft_verify(
            grp: *mut mbedtls_ecp_group,
            buf: *const c_uchar,
            blen: usize,
            q: *const mbedtls_ecp_point,
            r: *const mbedtls_mpi,
            s: *const mbedtls_mpi,
        ) -> c_int;
    }

    pub(crate) static ECDSA: Mutex<Cell<Option<&(dyn MbedtlsEcdsa + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// The message hash MbedTLS passes (possibly null when empty)
    unsafe fn hash<'a>(buf: *const c_uchar, blen: usize) -> &'a [u8] {
        if blen == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(buf, blen) }
        }
    }

    #[no_mangle]
    #[allow(clippy::too_many_arguments)]
    unsafe extern "C" fn mbedtls_ecdsa_sign(
        grp: *mut mbedtls_ecp_group,
        r: *mut mbedtls_mpi,
        s: *mut mbedtls_mpi,
        d: *const mbedtls_mpi,
        buf: *const c_uchar,
        blen: usize,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> c_int {
        let grp = unsafe { &mut *grp };
        let r = unsafe { &mut *r };
        let s = unsafe { &mut *s };
        let d = unsafe { &*d };
        let hash = unsafe { hash(buf, blen) };

        let result = if let Some(ecdsa) = critical_section::with(|cs| ECDSA.borrow(cs).get()) {
            unsafe { ecdsa.sign(grp, r, s, d, hash, f_rng, p_rng) }
        } else {
            unsafe { ecdsa_sign_soft(grp, r, s, d, hash, f_rng, p_rng) }
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_ecdsa_verify(
        grp: *mut mbedtls_ecp_group,
        buf: *const c_uchar,
        blen: usize,
        q: *const mbedtls_ecp_point,
        r: *const mbedtls_mpi,
        s: *const mbedtls_mpi,
    ) -> c_int {
        let grp = unsafe { &mut *grp };
        let hash = unsafe { hash(buf, blen) };
        let q = unsafe { &*q };
        let r = unsafe { &*r };
        let s = unsafe { &*s };

        let result = if let Some(ecdsa) = critical_section::with(|cs| ECDSA.borrow(cs).get()) {
            ecdsa.verify(grp, hash, q, r, s)
        } else {
            ecdsa_verify_soft(grp, hash, q, r, s)
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }
}
