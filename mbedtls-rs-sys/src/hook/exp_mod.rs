//! Hook for mbedtls_mpi_exp_mod

use core::ops::Deref;

use crate::{mbedtls_mpi, MbedtlsError};

/// Trait representing a custom (hooked) MbedTLS modular exponentiation function
/// Z = X ^ Y mod M
pub trait MbedtlsMpiExpMod {
    /// Perform modular exponentiation
    ///
    /// # Arguments
    /// - `z` - The result of the modular exponentiation
    /// - `x` - The base
    /// - `y` - The exponent
    /// - `m` - The modulus
    /// - `prec_rr` - Optional precomputed value for optimization
    ///
    /// # Returns
    /// - `Ok(())` on success, or `Err(MbedtlsError)` on failure
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: Option<&mut mbedtls_mpi>,
    ) -> Result<(), MbedtlsError>;
}

impl<T> MbedtlsMpiExpMod for T
where
    T: Deref,
    T::Target: MbedtlsMpiExpMod,
{
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: Option<&mut mbedtls_mpi>,
    ) -> Result<(), MbedtlsError> {
        self.deref().exp_mod(z, x, y, m, prec_rr)
    }
}

/// Hook the modular exponentiation function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use modular exponentiation, and ensure that the
///   `exp_mod` implementation is valid for the duration of its use.
#[cfg(mbedtls_hook = "exp_mod")]
pub unsafe fn hook_exp_mod(exp_mod: Option<&'static (dyn MbedtlsMpiExpMod + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if exp_mod.is_some() {
            debug!("RSA-EXP-MOD hook: added custom/HW accelerated impl");
        } else {
            debug!("RSA-EXP-MOD hook: removed");
        }

        alt::EXP_MOD.borrow(cs).set(exp_mod);
    });
}

#[cfg(mbedtls_hook = "exp_mod")]
mod alt {
    use core::cell::Cell;
    use core::ffi::c_int;

    use critical_section::Mutex;

    use crate::{mbedtls_mpi, mbedtls_mpi_exp_mod_soft, merr, MbedtlsError};

    use super::MbedtlsMpiExpMod;

    pub(crate) static EXP_MOD: Mutex<Cell<Option<&(dyn MbedtlsMpiExpMod + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static EXP_MOD_FALLBACK: FallbackMpiExpMod = FallbackMpiExpMod::new();

    pub struct FallbackMpiExpMod(());

    impl FallbackMpiExpMod {
        pub const fn new() -> Self {
            Self(())
        }
    }

    impl Default for FallbackMpiExpMod {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MbedtlsMpiExpMod for FallbackMpiExpMod {
        fn exp_mod(
            &self,
            z: &mut mbedtls_mpi,
            x: &mbedtls_mpi,
            y: &mbedtls_mpi,
            m: &mbedtls_mpi,
            prec_rr: Option<&mut mbedtls_mpi>,
        ) -> Result<(), MbedtlsError> {
            merr!(unsafe {
                mbedtls_mpi_exp_mod_soft(
                    z,
                    x,
                    y,
                    m,
                    prec_rr.map_or(core::ptr::null_mut(), |rr| rr as *mut _),
                )
            })?;

            Ok(())
        }
    }

    /// Z = X ^ Y mod M
    #[no_mangle]
    unsafe extern "C" fn mbedtls_mpi_exp_mod(
        z: *mut mbedtls_mpi,
        x: *const mbedtls_mpi,
        y: *const mbedtls_mpi,
        m: *const mbedtls_mpi,
        prec_rr: *mut mbedtls_mpi,
    ) -> c_int {
        let result = if let Some(exp_mod) = critical_section::with(|cs| EXP_MOD.borrow(cs).get()) {
            exp_mod.exp_mod(&mut *z, &*x, &*y, &*m, prec_rr.as_mut())
        } else {
            EXP_MOD_FALLBACK.exp_mod(&mut *z, &*x, &*y, &*m, prec_rr.as_mut())
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }
}
