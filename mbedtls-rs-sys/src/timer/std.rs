extern crate std;

use std::sync::OnceLock;
use std::time::Instant;

use crate::hook::timer::MbedtlsTimer;

static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Standard library timer backend for MbedTLS timer operations.
///
/// Uses `std::time::Instant` to provide monotonic time measurements.
/// The first call to `now()` establishes the epoch, and all subsequent
/// calls return milliseconds elapsed since that epoch.
#[derive(Debug, Default)]
pub struct StdTimer;

impl MbedtlsTimer for StdTimer {
    fn now(&self) -> u64 {
        let epoch = EPOCH.get_or_init(|| Instant::now());
        Instant::now().duration_since(*epoch).as_millis() as u64
    }
}
