use core::marker::PhantomData;

use crate::bindings::tm;
use crate::hook::wall_clock::MbedtlsWallClock;

/// ESP RTC-based wall clock backend for MbedTLS certificate validation.
///
/// Uses the ESP RTC peripheral to provide calendar time. The RTC must be
/// initialized with the correct time before use (e.g., via NTP).
///
/// # Usage
/// ```no_run
/// use esp_mbedtls_sys::hook::backend::esp::wall_clock::EspRtcWallClock;
/// use esp_mbedtls_sys::hook::wall_clock::hook_wall_clock;
///
/// // The wall clock must be static (using static_cell or similar)
/// let rtc = esp_hal::rtc_cntl::Rtc = /* ... */;
/// static WALL_CLOCK: EspRtcWallClock<esp_hal::rtc_cntl::Rtc<'static>> = EspRtcWallClock::new(rtc);
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
pub struct EspRtcWallClock<'d, T>
where
    T: core::borrow::Borrow<esp_hal::rtc_cntl::Rtc<'d>>,
{
    rtc: T,
    _t: PhantomData<&'d mut ()>,
}

impl<'d, T> EspRtcWallClock<'d, T>
where
    T: core::borrow::Borrow<esp_hal::rtc_cntl::Rtc<'d>>,
{
    pub const fn new(rtc: T) -> Self {
        Self {
            rtc,
            _t: PhantomData,
        }
    }
}

impl<'d, T> MbedtlsWallClock for EspRtcWallClock<'d, T>
where
    T: core::borrow::Borrow<esp_hal::rtc_cntl::Rtc<'d>>,
{
    /// Returns the current time from the RTC, or `None` if the RTC is
    /// uninitialized or its value is outside the representable range (in which
    /// case MbedTLS certificate validation fails closed rather than panicking).
    ///
    /// An uninitialized RTC (for example before the time has been set via NTP)
    /// is the common reason this returns `None`.
    fn instant(&self) -> Option<tm> {
        let rtc_time_secs = i64::try_from(self.rtc.borrow().current_time_us() / 1_000_000).ok()?;

        let datetime = time::OffsetDateTime::from_unix_timestamp(rtc_time_secs).ok()?;

        let date = datetime.date();
        let time = datetime.time();

        Some(tm {
            tm_sec: time.second() as i32,
            tm_min: time.minute() as i32,
            tm_hour: time.hour() as i32,
            tm_mday: date.day() as i32,
            tm_mon: date.month() as i32 - 1, // tm_mon is 0-11, time::Month is 1-12
            tm_year: date.year() - 1900,     // tm_year is years since 1900
            tm_wday: date.weekday().number_days_from_sunday() as i32,
            tm_yday: date.ordinal() as i32 - 1, // MbedTLS uses 0-365
            tm_isdst: 0,
        })
    }
}
