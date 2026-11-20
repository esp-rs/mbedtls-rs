//! Hooks for the MbedTLS ECP (elliptic curve) primitives.
//!
//! Based on the Espressif MbedTLS fork's `MBEDTLS_ECP_MUL_ALT_SOFT_FALLBACK` /
//! `MBEDTLS_ECP_VERIFY_ALT_SOFT_FALLBACK` options: the built-in software
//! implementations are kept, but renamed to `*_soft` symbols, while the
//! primary symbols (`ecp_mul_restartable_internal` and
//! `mbedtls_ecp_check_pubkey`) are provided here in Rust, dispatching to a
//! hooked implementation - or to the software fallback when un-hooked (or
//! when the hooked implementation itself decides to fall back, e.g. for a
//! curve its hardware does not support).
//!
//! Everything ECP funnels through these two functions:
//! - `mbedtls_ecp_mul` / `mbedtls_ecp_muladd` (and thus ECDH, ECDSA sign and
//!   verify, ECJPAKE, and SPAKE2+-style protocol math) call
//!   `ecp_mul_restartable_internal`;
//! - public-key validation (ECDH/ECDSA/TLS and `mbedtls_ecp_mul` itself)
//!   calls `mbedtls_ecp_check_pubkey`.

use core::ffi::c_void;
use core::ops::Deref;

use crate::{mbedtls_ecp_group, mbedtls_ecp_point, mbedtls_mpi, MbedtlsError};

/// The RNG callback type passed through by MbedTLS for coordinate blinding.
///
/// Hardware implementations that are not susceptible to the corresponding
/// side-channel attacks may ignore it; software fallbacks must pass it on.
pub type MbedtlsFRng = crate::mbedtls_f_rng_t;

/// The (opaque) restart context type; null unless Mbed TLS is built with the
/// opt-in `ecp-restartable` feature.
pub type MbedtlsEcpRestartCtx = crate::mbedtls_ecp_restart_ctx;

/// Trait representing a custom (hooked) MbedTLS ECP scalar multiplication:
/// R = m * P on the given group
pub trait MbedtlsEcpMul {
    /// Perform the scalar multiplication R = m * P.
    ///
    /// Implementations that cannot handle the given group (or operand range)
    /// are expected to delegate to [`ecp_mul_soft`].
    ///
    /// # Arguments
    /// - `grp` - The ECP group (mutable, as the software implementation
    ///   caches pre-computed tables inside it)
    /// - `r` - The destination point
    /// - `m` - The scalar
    /// - `p` - The point to multiply
    /// - `f_rng`/`p_rng` - RNG callback for blinding (see [`MbedtlsFRng`])
    /// - `rs_ctx` - Restart context (null unless `ecp-restartable` is enabled)
    ///
    /// # Safety
    /// - `f_rng`/`p_rng`/`rs_ctx` are raw values passed through from MbedTLS;
    ///   the caller must ensure they are valid for the duration of the call
    ///   (implementations typically just forward them to [`ecp_mul_soft`])
    #[allow(clippy::too_many_arguments)]
    unsafe fn mul(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
        rs_ctx: *mut MbedtlsEcpRestartCtx,
    ) -> Result<(), MbedtlsError>;
}

impl<T> MbedtlsEcpMul for T
where
    T: Deref,
    T::Target: MbedtlsEcpMul,
{
    unsafe fn mul(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
        rs_ctx: *mut MbedtlsEcpRestartCtx,
    ) -> Result<(), MbedtlsError> {
        unsafe { self.deref().mul(grp, r, m, p, f_rng, p_rng, rs_ctx) }
    }
}

/// Trait representing a custom (hooked) MbedTLS ECP public key
/// (point-on-curve) check
pub trait MbedtlsEcpVerify {
    /// Check that `pt` is a valid public key (point on curve) for `grp`.
    ///
    /// Implementations that cannot handle the given group are expected to
    /// delegate to [`ecp_check_pubkey_soft`].
    fn check_pubkey(
        &self,
        grp: &mbedtls_ecp_group,
        pt: &mbedtls_ecp_point,
    ) -> Result<(), MbedtlsError>;
}

impl<T> MbedtlsEcpVerify for T
where
    T: Deref,
    T::Target: MbedtlsEcpVerify,
{
    fn check_pubkey(
        &self,
        grp: &mbedtls_ecp_group,
        pt: &mbedtls_ecp_point,
    ) -> Result<(), MbedtlsError> {
        self.deref().check_pubkey(grp, pt)
    }
}

/// The MbedTLS software implementation of the ECP scalar multiplication.
///
/// Available for hooked implementations to delegate to (e.g. for curves not
/// supported by their hardware).
///
/// # Safety
/// - The raw `f_rng`/`p_rng`/`rs_ctx` values must be valid for the duration
///   of the call (they are normally just passed through from the hook).
#[cfg(mbedtls_hook = "ecp_mul")]
#[allow(clippy::too_many_arguments)]
pub unsafe fn ecp_mul_soft(
    grp: &mut mbedtls_ecp_group,
    r: &mut mbedtls_ecp_point,
    m: &mbedtls_mpi,
    p: &mbedtls_ecp_point,
    f_rng: MbedtlsFRng,
    p_rng: *mut c_void,
    rs_ctx: *mut MbedtlsEcpRestartCtx,
) -> Result<(), MbedtlsError> {
    crate::merr!(unsafe {
        crate::ecp_mul_restartable_internal_soft(grp, r, m, p, f_rng, p_rng, rs_ctx)
    })?;

    Ok(())
}

/// The MbedTLS software implementation of the ECP public key check.
///
/// Available for hooked implementations to delegate to (e.g. for curves not
/// supported by their hardware).
#[cfg(mbedtls_hook = "ecp_verify")]
pub fn ecp_check_pubkey_soft(
    grp: &mbedtls_ecp_group,
    pt: &mbedtls_ecp_point,
) -> Result<(), MbedtlsError> {
    crate::merr!(unsafe { crate::mbedtls_ecp_check_pubkey_soft(grp, pt) })?;

    Ok(())
}

/// Hook the ECP scalar multiplication used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use ECP, and ensure that the implementation
///   is valid for the duration of its use.
#[cfg(mbedtls_hook = "ecp_mul")]
pub unsafe fn hook_ecp_mul(ecp_mul: Option<&'static (dyn MbedtlsEcpMul + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if ecp_mul.is_some() {
            debug!("ECP-MUL hook: added custom/HW accelerated impl");
        } else {
            debug!("ECP-MUL hook: removed");
        }

        mul_alt::ECP_MUL.borrow(cs).set(ecp_mul);
    });
}

/// Hook the ECP public key check used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use ECP, and ensure that the implementation
///   is valid for the duration of its use.
#[cfg(mbedtls_hook = "ecp_verify")]
pub unsafe fn hook_ecp_verify(ecp_verify: Option<&'static (dyn MbedtlsEcpVerify + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if ecp_verify.is_some() {
            debug!("ECP-VERIFY hook: added custom/HW accelerated impl");
        } else {
            debug!("ECP-VERIFY hook: removed");
        }

        verify_alt::ECP_VERIFY.borrow(cs).set(ecp_verify);
    });
}

#[cfg(mbedtls_hook = "ecp_mul")]
mod mul_alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_void};

    use critical_section::Mutex;

    use crate::{mbedtls_ecp_group, mbedtls_ecp_point, mbedtls_mpi};

    use super::{ecp_mul_soft, MbedtlsEcpMul, MbedtlsEcpRestartCtx, MbedtlsFRng};

    pub(crate) static ECP_MUL: Mutex<Cell<Option<&(dyn MbedtlsEcpMul + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// R = m * P
    ///
    /// The primary scalar-multiplication symbol expected by the Espressif
    /// MbedTLS fork when `MBEDTLS_ECP_MUL_ALT_SOFT_FALLBACK` is defined
    /// (all public ECP entry points funnel through it).
    #[no_mangle]
    unsafe extern "C" fn ecp_mul_restartable_internal(
        grp: *mut mbedtls_ecp_group,
        r: *mut mbedtls_ecp_point,
        m: *const mbedtls_mpi,
        p: *const mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
        rs_ctx: *mut MbedtlsEcpRestartCtx,
    ) -> c_int {
        let grp = unsafe { &mut *grp };
        let r = unsafe { &mut *r };
        let m = unsafe { &*m };
        let p = unsafe { &*p };

        let result = if let Some(ecp_mul) = critical_section::with(|cs| ECP_MUL.borrow(cs).get()) {
            unsafe { ecp_mul.mul(grp, r, m, p, f_rng, p_rng, rs_ctx) }
        } else {
            unsafe { ecp_mul_soft(grp, r, m, p, f_rng, p_rng, rs_ctx) }
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }
}

#[cfg(mbedtls_hook = "ecp_verify")]
mod verify_alt {
    use core::cell::Cell;
    use core::ffi::c_int;

    use critical_section::Mutex;

    use crate::{mbedtls_ecp_group, mbedtls_ecp_point};

    use super::{ecp_check_pubkey_soft, MbedtlsEcpVerify};

    pub(crate) static ECP_VERIFY: Mutex<Cell<Option<&(dyn MbedtlsEcpVerify + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// The primary point-on-curve check symbol expected by the Espressif
    /// MbedTLS fork when `MBEDTLS_ECP_VERIFY_ALT_SOFT_FALLBACK` is defined.
    #[no_mangle]
    unsafe extern "C" fn mbedtls_ecp_check_pubkey(
        grp: *const mbedtls_ecp_group,
        pt: *const mbedtls_ecp_point,
    ) -> c_int {
        let grp = unsafe { &*grp };
        let pt = unsafe { &*pt };

        let result =
            if let Some(ecp_verify) = critical_section::with(|cs| ECP_VERIFY.borrow(cs).get()) {
                ecp_verify.check_pubkey(grp, pt)
            } else {
                ecp_check_pubkey_soft(grp, pt)
            };

        result.map_or_else(|e| e.code(), |_| 0)
    }
}
