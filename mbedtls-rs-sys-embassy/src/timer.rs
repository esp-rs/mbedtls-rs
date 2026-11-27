//! Monotonic timer over `embassy-time`.

use mbedtls_rs_sys::hook::timer::MbedtlsTimer;
use mbedtls_rs_sys::mbedtls_ms_time_t;

/// Embassy-based timer backend for MbedTLS timeout operations.
///
/// Uses `embassy_time::Instant` to provide monotonic millisecond timing.
///
/// # Usage
/// ```ignore
/// use mbedtls_rs_sys::hook::timer::hook_timer;
/// use mbedtls_rs_sys_embassy::timer::EmbassyTimer;
///
/// static TIMER: EmbassyTimer = EmbassyTimer;
///
/// unsafe {
///     hook_timer(Some(&TIMER));
/// }
/// // ... use MbedTLS ...
/// unsafe {
///     hook_timer(None);
/// }
/// ```
#[derive(Debug, Default)]
pub struct EmbassyTimer;

impl MbedtlsTimer for EmbassyTimer {
    fn now(&self) -> mbedtls_ms_time_t {
        let ms = embassy_time::Instant::now().as_millis();
        mbedtls_ms_time_t::try_from(ms).unwrap_or(mbedtls_ms_time_t::MAX)
    }
}
