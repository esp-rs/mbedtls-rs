use crate::bindings::tm;
pub trait MbedtlsWallClock {
    /// Get current wall clock time as broken-down time structure.
    ///
    /// Returns the current calendar time in UTC as a `tm` structure.
    ///
    /// # Note
    /// This function should return the current wall clock time. The wall clock implementation is
    /// decoupled from the timer implementation (which provides monotonic timing for timeouts).
    /// MbedTLS uses this for X.509 certificate time validation.
    ///
    /// # Returns
    /// - `tm` - Current time as a broken-down time structure
    fn instant(&self) -> tm;
}

/// Hook the wall clock function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that need wall clock time (e.g., X.509 certificate
///   time validation), and ensure that the wall clock implementation is valid
///   for the duration of its use.
#[cfg(not(feature = "nohook-wall-clock"))]
pub unsafe fn hook_wall_clock(wc: Option<&'static (dyn MbedtlsWallClock + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if wc.is_some() {
            debug!("Wall Clock hook: added custom impl");
        } else {
            debug!("Wall Clock hook: removed");
        }

        alt::WALL_CLOCK.borrow(cs).set(wc);
    });
}

#[cfg(not(feature = "nohook-wall-clock"))]
mod alt {
    use crate::bindings::tm;
    use core::cell::Cell;
    use core::ptr;
    use critical_section::Mutex;

    use super::MbedtlsWallClock;

    pub(crate) static WALL_CLOCK: Mutex<Cell<Option<&(dyn MbedtlsWallClock + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// Get current wall clock time as broken-down time in UTC.
    ///
    /// MbedTLS calls this function from X.509 certificate validation code
    /// (`x509_get_current_time` and `x509_crt_verify_chain`) to get the current
    /// calendar time. Although the standard `gmtime_r` signature takes a timestamp
    /// to convert, MbedTLS always calls this with a freshly retrieved value from
    /// `mbedtls_time(NULL)`.
    ///
    /// This implementation ignores the timestamp parameter and returns the current
    /// wall clock time directly. This decouples the wall clock (calendar time) from
    /// the timer (monotonic timing used for timeouts), allowing separate implementations
    /// for each concern.
    ///
    /// # Parameters
    /// - `_tt`: Ignored. MbedTLS passes `mbedtls_time(NULL)` here, but we return
    ///   current wall clock time regardless of this value.
    /// - `tm_buf`: Pointer to buffer where the result will be written
    ///
    /// # Returns
    /// Pointer to `tm_buf` on success, or null if:
    /// - `tm_buf` is null
    /// - No wall clock implementation is hooked
    #[no_mangle]
    pub unsafe extern "C" fn mbedtls_platform_gmtime_r(
        _tt: *const i64,
        tm_buf: *mut tm,
    ) -> *mut tm {
        if tm_buf.is_null() {
            return ptr::null_mut();
        }

        critical_section::with(|cs| {
            WALL_CLOCK
                .borrow(cs)
                .get()
                .map(|wc| {
                    *tm_buf = wc.instant();
                    tm_buf
                })
                .unwrap_or_default()
        })
    }
}
