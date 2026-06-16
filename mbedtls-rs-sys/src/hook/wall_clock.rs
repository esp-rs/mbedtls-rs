use crate::tm;

pub trait MbedtlsWallClock {
    /// Get current wall clock time as broken-down time structure.
    ///
    /// Returns the current calendar time in UTC as a `tm` structure, or `None`
    /// if the wall clock is unavailable or its value cannot be represented (for
    /// example an uninitialized RTC, or a timestamp outside the representable
    /// range). When `None` is returned, MbedTLS X.509 certificate validation
    /// fails closed: the certificate is treated as both expired and not yet
    /// valid, so an unusable clock can never cause a certificate to be accepted.
    ///
    /// The `tm` struct contains the following fields:
    /// - `tm_sec`: seconds after the minute - [0, 60]
    /// - `tm_min`: minutes after the hour - [0, 59]
    /// - `tm_hour`: hours since midnight - [0, 23]
    /// - `tm_mday`: day of the month - [1, 31]
    /// - `tm_mon`: months since January - [0, 11]
    /// - `tm_year`: years since 1900
    /// - `tm_wday`: days since Sunday - [0, 6]
    /// - `tm_yday`: days since January 1 - [0, 365]
    /// - `tm_isdst`: Daylight Saving Time flag
    ///
    /// # Note
    /// This function should return the current wall clock time. The wall clock implementation is
    /// decoupled from the timer implementation (which provides monotonic timing for timeouts).
    /// MbedTLS uses this for X.509 certificate time validation.
    fn instant(&self) -> Option<tm>;
}

/// Hook the wall clock function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that need wall clock time (e.g., X.509 certificate
///   time validation), and ensure that the wall clock implementation is valid
///   for the duration of its use.
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

mod alt {
    use crate::{mbedtls_time_t, tm};
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
    /// - The hooked implementation returned `None` (clock unavailable or
    ///   unrepresentable), in which case MbedTLS certificate validation fails
    ///   closed
    #[no_mangle]
    unsafe extern "C" fn mbedtls_platform_gmtime_r(
        _tt: *const mbedtls_time_t,
        tm_buf: *mut tm,
    ) -> *mut tm {
        if tm_buf.is_null() {
            return ptr::null_mut();
        }

        // Copy the hook pointer out under the lock, then release the critical
        // section BEFORE calling the user's `instant()`: that call may read an
        // RTC over a bus and must not run with interrupts disabled (mirrors
        // `mbedtls_ms_time` in `timer.rs`).
        let wc = critical_section::with(|cs| WALL_CLOCK.borrow(cs).get());

        match wc.and_then(|wc| wc.instant()) {
            Some(now) => {
                *tm_buf = now;
                tm_buf
            }
            None => ptr::null_mut(),
        }
    }
}
