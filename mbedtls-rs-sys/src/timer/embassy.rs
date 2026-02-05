use crate::hook::timer::MbedtlsTimer;

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
    fn now(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}
