//! Hook for the MbedTLS ECDH key pair generation and shared secret
//! computation.
//!
//! Every ECDH shared secret MbedTLS computes goes through
//! `mbedtls_ecdh_compute_shared` - the `mbedtls_ecdh_context` API (and thus
//! the TLS 1.2 ECDH(E) key exchanges) and the PSA crypto implementation
//! included - and the key pairs of the `mbedtls_ecdh_context` API are
//! generated with `mbedtls_ecdh_gen_public` (PSA generates its own with the
//! ECP scalar multiplication). With the `MBEDTLS_ECDH_GEN_PUBLIC_ALT` /
//! `MBEDTLS_ECDH_COMPUTE_SHARED_ALT` options, both are provided here in Rust,
//! dispatching to a hooked implementation - or to the MbedTLS software
//! implementation when un-hooked (or when the hooked implementation itself
//! decides to fall back, e.g. for a curve its engine does not support).
//!
//! The software implementation is kept by compiling `ecdh.c` a second time
//! under `mbedtls_ecdh_soft_*` names (see `SoftFallback` in
//! `gen/builder.rs`). It is a thin layer over the ECP scalar multiplication,
//! so it is accelerated whenever that is hooked (see [`crate::hook::ecp`]);
//! this hook is for engines doing ECDH as a whole.
//!
//! Unavailable with the `ecp-restartable` feature: MbedTLS does not support
//! restartable ECP operations together with alternative ECDH implementations.

use core::ffi::c_void;
use core::ops::Deref;

use crate::hook::ecp::MbedtlsFRng;
use crate::{mbedtls_ecp_group, mbedtls_ecp_point, mbedtls_mpi, MbedtlsError};

/// Trait representing a custom (hooked) MbedTLS ECDH implementation
pub trait MbedtlsEcdh {
    /// Generate a key pair on `grp`: a random private key `d`, and the public
    /// key `q = d * G`.
    ///
    /// Implementations that cannot handle the given group are expected to
    /// delegate to [`ecdh_gen_public_soft`].
    ///
    /// # Arguments
    /// - `grp` - The ECP group (mutable, as the software implementation
    ///   caches pre-computed tables inside it)
    /// - `d` - The destination private key
    /// - `q` - The destination public key
    /// - `f_rng`/`p_rng` - The RNG to draw the private key (and the blinding
    ///   values) from
    ///
    /// # Safety
    /// - `f_rng`/`p_rng` are raw values passed through from MbedTLS; the
    ///   caller must ensure they are valid for the duration of the call
    ///   (implementations typically use them with `mbedtls_ecp_gen_privkey`,
    ///   or just forward them to [`ecdh_gen_public_soft`])
    unsafe fn gen_public(
        &self,
        grp: &mut mbedtls_ecp_group,
        d: &mut mbedtls_mpi,
        q: &mut mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> Result<(), MbedtlsError>;

    /// Compute the shared secret `z` of the private key `d` and the peer's
    /// public key `q`: the X coordinate of `d * q`.
    ///
    /// `q` is untrusted: public keys that are not valid points on the curve
    /// must be rejected (as the software implementation does, with
    /// `MBEDTLS_ERR_ECP_INVALID_KEY`).
    ///
    /// Implementations that cannot handle the given group (or operands) are
    /// expected to delegate to [`ecdh_compute_shared_soft`].
    ///
    /// # Arguments
    /// - `grp` - The ECP group (mutable, as the software implementation
    ///   caches pre-computed tables inside it)
    /// - `z` - The destination shared secret
    /// - `q` - The peer's public key
    /// - `d` - The private key
    /// - `f_rng`/`p_rng` - RNG callback for blinding (see [`MbedtlsFRng`])
    ///
    /// # Safety
    /// - `f_rng`/`p_rng` are raw values passed through from MbedTLS; the
    ///   caller must ensure they are valid for the duration of the call
    ///   (implementations typically just forward them to
    ///   [`ecdh_compute_shared_soft`])
    unsafe fn compute_shared(
        &self,
        grp: &mut mbedtls_ecp_group,
        z: &mut mbedtls_mpi,
        q: &mbedtls_ecp_point,
        d: &mbedtls_mpi,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> Result<(), MbedtlsError>;
}

impl<T> MbedtlsEcdh for T
where
    T: Deref,
    T::Target: MbedtlsEcdh,
{
    unsafe fn gen_public(
        &self,
        grp: &mut mbedtls_ecp_group,
        d: &mut mbedtls_mpi,
        q: &mut mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> Result<(), MbedtlsError> {
        unsafe { self.deref().gen_public(grp, d, q, f_rng, p_rng) }
    }

    unsafe fn compute_shared(
        &self,
        grp: &mut mbedtls_ecp_group,
        z: &mut mbedtls_mpi,
        q: &mbedtls_ecp_point,
        d: &mbedtls_mpi,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> Result<(), MbedtlsError> {
        unsafe { self.deref().compute_shared(grp, z, q, d, f_rng, p_rng) }
    }
}

/// The MbedTLS software implementation of the ECDH key pair generation.
///
/// Available for hooked implementations to delegate to (e.g. for curves not
/// supported by their engine).
///
/// # Safety
/// - The raw `f_rng`/`p_rng` values must be valid for the duration of the
///   call (they are normally just passed through from the hook).
#[cfg(all(
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
pub unsafe fn ecdh_gen_public_soft(
    grp: &mut mbedtls_ecp_group,
    d: &mut mbedtls_mpi,
    q: &mut mbedtls_ecp_point,
    f_rng: MbedtlsFRng,
    p_rng: *mut c_void,
) -> Result<(), MbedtlsError> {
    crate::merr!(unsafe { alt::mbedtls_ecdh_soft_gen_public(grp, d, q, f_rng, p_rng) })?;

    Ok(())
}

/// The MbedTLS software implementation of the ECDH shared secret
/// computation.
///
/// Available for hooked implementations to delegate to (e.g. for curves not
/// supported by their engine).
///
/// # Safety
/// - The raw `f_rng`/`p_rng` values must be valid for the duration of the
///   call (they are normally just passed through from the hook).
#[cfg(all(
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
pub unsafe fn ecdh_compute_shared_soft(
    grp: &mut mbedtls_ecp_group,
    z: &mut mbedtls_mpi,
    q: &mbedtls_ecp_point,
    d: &mbedtls_mpi,
    f_rng: MbedtlsFRng,
    p_rng: *mut c_void,
) -> Result<(), MbedtlsError> {
    crate::merr!(unsafe { alt::mbedtls_ecdh_soft_compute_shared(grp, z, q, d, f_rng, p_rng) })?;

    Ok(())
}

/// Hook the ECDH implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use ECDH, and ensure that the implementation
///   is valid for the duration of its use.
#[cfg(all(
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
pub unsafe fn hook_ecdh(ecdh: Option<&'static (dyn MbedtlsEcdh + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if ecdh.is_some() {
            debug!("ECDH hook: added custom/HW accelerated impl");
        } else {
            debug!("ECDH hook: removed");
        }

        alt::ECDH.borrow(cs).set(ecdh);
    });
}

#[cfg(all(
    feature = "alg-ecdh",
    not(feature = "nohook-ecdh"),
    not(feature = "ecp-restartable")
))]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_void};

    use critical_section::Mutex;

    use crate::hook::ecp::MbedtlsFRng;
    use crate::{mbedtls_ecp_group, mbedtls_ecp_point, mbedtls_mpi};

    use super::{ecdh_compute_shared_soft, ecdh_gen_public_soft, MbedtlsEcdh};

    // The software fallback, from the second compilation of `ecdh.c` (see
    // `SoftFallback` in `gen/builder.rs`)
    extern "C" {
        pub(super) fn mbedtls_ecdh_soft_gen_public(
            grp: *mut mbedtls_ecp_group,
            d: *mut mbedtls_mpi,
            q: *mut mbedtls_ecp_point,
            f_rng: MbedtlsFRng,
            p_rng: *mut c_void,
        ) -> c_int;

        pub(super) fn mbedtls_ecdh_soft_compute_shared(
            grp: *mut mbedtls_ecp_group,
            z: *mut mbedtls_mpi,
            q: *const mbedtls_ecp_point,
            d: *const mbedtls_mpi,
            f_rng: MbedtlsFRng,
            p_rng: *mut c_void,
        ) -> c_int;
    }

    pub(crate) static ECDH: Mutex<Cell<Option<&(dyn MbedtlsEcdh + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    #[no_mangle]
    unsafe extern "C" fn mbedtls_ecdh_gen_public(
        grp: *mut mbedtls_ecp_group,
        d: *mut mbedtls_mpi,
        q: *mut mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> c_int {
        let grp = unsafe { &mut *grp };
        let d = unsafe { &mut *d };
        let q = unsafe { &mut *q };

        let result = if let Some(ecdh) = critical_section::with(|cs| ECDH.borrow(cs).get()) {
            unsafe { ecdh.gen_public(grp, d, q, f_rng, p_rng) }
        } else {
            unsafe { ecdh_gen_public_soft(grp, d, q, f_rng, p_rng) }
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_ecdh_compute_shared(
        grp: *mut mbedtls_ecp_group,
        z: *mut mbedtls_mpi,
        q: *const mbedtls_ecp_point,
        d: *const mbedtls_mpi,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
    ) -> c_int {
        let grp = unsafe { &mut *grp };
        let z = unsafe { &mut *z };
        let q = unsafe { &*q };
        let d = unsafe { &*d };

        let result = if let Some(ecdh) = critical_section::with(|cs| ECDH.borrow(cs).get()) {
            unsafe { ecdh.compute_shared(grp, z, q, d, f_rng, p_rng) }
        } else {
            unsafe { ecdh_compute_shared_soft(grp, z, q, d, f_rng, p_rng) }
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }
}
