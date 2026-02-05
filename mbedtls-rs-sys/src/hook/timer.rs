pub trait MbedtlsTimer {
    /// Get monotonic time in milliseconds.
    ///
    /// This should return a monotonically increasing value representing elapsed
    /// milliseconds since an arbitrary epoch (e.g., system boot). This is used
    /// for timeouts and duration measurements, not calendar time.
    fn now(&self) -> u64;
}

/// Hook the timer function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use time-based operations (e.g., timeouts,
///   certificate validation), and ensure that the timer implementation is
///   valid for the duration of its use.
#[cfg(not(feature = "nohook-timer"))]
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

#[cfg(not(feature = "nohook-timer"))]
mod alt {
    use core::cell::Cell;
    use critical_section::Mutex;

    use super::MbedtlsTimer;

    pub(crate) static TIMER: Mutex<Cell<Option<&(dyn MbedtlsTimer + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// Get current time in milliseconds since epoch.
    ///
    /// This function is called by MbedTLS for time-based operations.
    #[no_mangle]
    pub unsafe extern "C" fn mbedtls_ms_time() -> i64 {
        if let Some(timer) = critical_section::with(|cs| TIMER.borrow(cs).get()) {
            timer.now() as i64
        } else {
            0
        }
    }

    /// Get current time in seconds since epoch.
    ///
    /// This function is called by MbedTLS for time-based operations.
    /// If `timer` is not null, the time is also stored in `*timer`.
    #[no_mangle]
    pub unsafe extern "C" fn time(timer: *mut i64) -> i64 {
        let time = if let Some(timer) = critical_section::with(|cs| TIMER.borrow(cs).get()) {
            timer.now() / 1000
        } else {
            0
        } as i64;

        if !timer.is_null() {
            *timer = time;
        }

        time
    }
}
