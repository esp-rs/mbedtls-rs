use core::cell::Cell;
use critical_section::Mutex;

use crate::bindings::tm;
use crate::hook::wall_clock::MbedtlsWallClock;

/// ESP RTC-based wall clock backend for MbedTLS certificate validation.
///
/// Uses the ESP RTC peripheral to provide calendar time. The RTC must be
/// initialized with the correct time before use (e.g., via NTP).
///
/// # Usage
/// ```no_run
/// use esp_mbedtls_sys::clock::{hook_wall_clock, esp::EspRtcWallClock};
///
/// // Both RTC and wall clock must be static (using static_cell or similar)
/// static RTC: esp_hal::rtc_cntl::Rtc = /* ... */;
/// static WALL_CLOCK: EspRtcWallClock = EspRtcWallClock::new(&RTC);
///
/// unsafe {
///     hook_wall_clock(Some(&WALL_CLOCK));
/// }
/// // ... use MbedTLS ...
/// unsafe {
///     hook_wall_clock(None);
/// }
/// ```
///
pub struct EspRtcWallClock {
    rtc: Mutex<Cell<&'static esp_hal::rtc_cntl::Rtc<'static>>>,
}

impl EspRtcWallClock {
    pub const fn new(rtc: &'static esp_hal::rtc_cntl::Rtc<'static>) -> Self {
        Self {
            rtc: Mutex::new(Cell::new(rtc)),
        }
    }

    #[inline]
    fn with_rtc<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&esp_hal::rtc_cntl::Rtc<'_>) -> R,
    {
        critical_section::with(|cs| f(self.rtc.borrow(cs).get()))
    }
}

impl MbedtlsWallClock for EspRtcWallClock {
    fn instant(&self) -> tm {
        let rtc_time_secs = self.with_rtc(|rtc| (rtc.current_time_us() / 1_000_000) as i64);

        let datetime = time::OffsetDateTime::from_unix_timestamp(rtc_time_secs)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);

        let date = datetime.date();
        let time = datetime.time();

        tm {
            tm_sec: time.second() as i32,
            tm_min: time.minute() as i32,
            tm_hour: time.hour() as i32,
            tm_mday: date.day() as i32,
            tm_mon: date.month() as i32 - 1, // tm_mon is 0-11, time::Month is 1-12
            tm_year: date.year() - 1900,     // tm_year is years since 1900
            tm_wday: date.weekday().number_days_from_sunday() as i32,
            tm_yday: date.ordinal() as i32 - 1, // MbedTLS uses 0-365
            tm_isdst: 0,
        }
    }
}
