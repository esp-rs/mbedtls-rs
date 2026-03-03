extern crate std;

use std::sync::OnceLock;
use std::time::Instant;

use crate::hook::timer::MbedtlsTimer;
use crate::mbedtls_ms_time_t;

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Standard library timer backend for MbedTLS timer operations.
///
/// Uses `std::time::Instant` to provide monotonic time measurements.
/// The first call to `now()` establishes the epoch, and all subsequent
/// calls return milliseconds elapsed since that epoch.
#[derive(Debug, Default)]
pub struct StdTimer;

impl MbedtlsTimer for StdTimer {
    fn now(&self) -> mbedtls_ms_time_t {
        let epoch = EPOCH.get_or_init(|| Instant::now());
        let ms = Instant::now().duration_since(*epoch).as_millis();
        mbedtls_ms_time_t::try_from(ms).unwrap_or(mbedtls_ms_time_t::MAX)
    }
}
