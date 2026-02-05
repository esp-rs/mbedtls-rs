use crate::hook::timer::MbedtlsTimer;
use crate::mbedtls_ms_time_t;

/// Embassy-based timer backend for MbedTLS timeout operations.
///
/// Uses `embassy_time::Instant` to provide monotonic millisecond timing.
///
/// # Usage
/// ```no_run
/// use esp_mbedtls_sys::timer::{hook_timer, embassy::EmbassyTimer};
///
/// // Create a static timer instance (using static_cell or similar)
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
