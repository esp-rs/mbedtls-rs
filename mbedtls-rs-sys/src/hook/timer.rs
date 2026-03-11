use crate::mbedtls_ms_time_t;

pub trait MbedtlsTimer {
    /// Get monotonic time in milliseconds.
    ///
    /// This should return a monotonically increasing value representing elapsed
    /// milliseconds since an arbitrary epoch (e.g., system boot). This is used
    /// for duration measurements, not calendar time.
    fn now(&self) -> mbedtls_ms_time_t;
}

/// Hook the timer function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use time-based operations,
///   and ensure that the timer implementation is valid for the duration of its use.
pub unsafe fn hook_timer(timer: Option<&'static (dyn MbedtlsTimer + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if timer.is_some() {
            debug!("TIMER hook: added custom impl");
        } else {
            debug!("TIMER hook: removed");
        }

        alt::TIMER.borrow(cs).set(timer);
    });
}

mod alt {
    use crate::{mbedtls_ms_time_t, mbedtls_time_t};
    use core::cell::Cell;
    use critical_section::Mutex;

    use super::MbedtlsTimer;

    pub(crate) static TIMER: Mutex<Cell<Option<&(dyn MbedtlsTimer + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// Get current time in milliseconds since epoch.
    ///
    /// The time does not need to be correct, only time differences are used by MbedTls
    #[no_mangle]
    unsafe extern "C" fn mbedtls_ms_time() -> mbedtls_ms_time_t {
        if let Some(timer) = critical_section::with(|cs| TIMER.borrow(cs).get()) {
            timer.now()
        } else {
            0
        }
    }

    /// Get current time in seconds since epoch.
    ///
    /// The time does not need to be correct, only time differences are used by MbedTls
    #[no_mangle]
    unsafe extern "C" fn mbedtls_sec_time(timer: *mut mbedtls_time_t) -> mbedtls_time_t {
        let time = if let Some(t) = critical_section::with(|cs| TIMER.borrow(cs).get()) {
            t.now() / 1000
        } else {
            0
        } as mbedtls_time_t;

        if !timer.is_null() {
            *timer = time;
        }
        time
    }
}
