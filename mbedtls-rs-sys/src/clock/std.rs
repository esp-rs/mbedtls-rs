extern crate std;

use std::time::SystemTime;

use crate::bindings::tm;
use crate::hook::wall_clock::MbedtlsWallClock;

/// Standard library wall clock backend for MbedTLS certificate validation.
///
/// Uses `std::time::SystemTime` to provide calendar time.
#[derive(Debug, Default)]
pub struct StdWallClock;

impl MbedtlsWallClock for StdWallClock {
    /// Returns the current time from the system clock.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The system time is before the Unix epoch (January 1, 1970)
    /// - The system time is out of the valid range for `OffsetDateTime`
    ///
    /// These conditions indicate a serious system clock misconfiguration that would
    /// compromise TLS certificate validation.
    fn instant(&self) -> tm {
        let now = SystemTime::now();
        let duration = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("System time is before Unix epoch");
        let timestamp = i64::try_from(duration.as_secs()).unwrap_or(i64::MAX);

        let datetime = time::OffsetDateTime::from_unix_timestamp(timestamp)
            .expect("System time out of range for OffsetDateTime");

        let date = datetime.date();
        let time = datetime.time();

        tm {
            tm_sec: time.second() as i32,
            tm_min: time.minute() as i32,
            tm_hour: time.hour() as i32,
            tm_mday: date.day() as i32,
            tm_mon: date.month() as i32 - 1, // tm_mon is 0-11
            tm_year: date.year() - 1900,     // tm_year is years since 1900
            tm_wday: date.weekday().number_days_from_sunday() as i32,
            tm_yday: date.ordinal() as i32 - 1, // 0-365
            tm_isdst: 0,
        }
    }
}
