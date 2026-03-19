//! ESP32XX hardware acceleration modules based on the baremetal `esp-hal` crate.

pub mod digest;
#[cfg(not(any(feature = "esp32c2", feature = "nohook-exp-mod")))]
pub mod exp_mod;
#[cfg(feature = "hook-wall-clock")]
pub mod wall_clock;

#[cfg(not(feature = "esp32"))]
pub static SHA1: digest::EspSha1 = digest::EspSha1::new();
#[cfg(not(feature = "esp32"))]
pub static SHA224: digest::EspSha224 = digest::EspSha224::new();
#[cfg(not(feature = "esp32"))]
pub static SHA256: digest::EspSha256 = digest::EspSha256::new();
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub static SHA384: digest::EspSha384 = digest::EspSha384::new();
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub static SHA512: digest::EspSha512 = digest::EspSha512::new();
#[cfg(not(any(feature = "esp32c2", feature = "nohook-exp-mod")))]
pub static EXP_MOD: exp_mod::EspExpMod = exp_mod::EspExpMod::new();

pub struct EspAccel<'d> {
    #[cfg(not(feature = "esp32"))]
    sha: esp_hal::sha::ShaBackend<'d>,
    #[cfg(not(feature = "esp32c2"))]
    rsa: esp_hal::rsa::RsaBackend<'d>,
}

impl<'d> EspAccel<'d> {
    #[cfg(not(any(feature = "esp32", feature = "esp32c2")))]
    pub fn new(sha: esp_hal::peripherals::SHA<'d>, rsa: esp_hal::peripherals::RSA<'d>) -> Self {
        Self {
            sha: esp_hal::sha::ShaBackend::new(sha),
            rsa: esp_hal::rsa::RsaBackend::new(rsa),
        }
    }

    #[cfg(feature = "esp32")]
    pub fn new(rsa: esp_hal::peripherals::RSA<'d>) -> Self {
        Self {
            rsa: esp_hal::rsa::RsaBackend::new(rsa),
        }
    }

    #[cfg(feature = "esp32c2")]
    pub fn new(sha: esp_hal::peripherals::SHA<'d>) -> Self {
        Self {
            sha: esp_hal::sha::ShaBackend::new(sha),
        }
    }

    #[must_use]
    pub fn start(&mut self) -> EspAccelQueue<'_, 'd> {
        EspAccelQueue::new(self)
    }
}

pub struct EspAccelQueue<'a, 'd> {
    #[cfg(not(feature = "esp32"))]
    _sha_queue: esp_hal::sha::ShaWorkQueueDriver<'a, 'd>,
    #[cfg(not(feature = "esp32c2"))]
    _rsa_queue: esp_hal::rsa::RsaWorkQueueDriver<'a, 'd>,
}

impl<'a, 'd> EspAccelQueue<'a, 'd> {
    fn new(accel: &'a mut EspAccel<'d>) -> Self {
        #[cfg(not(feature = "esp32"))]
        let sha_queue = accel.sha.start();
        #[cfg(not(feature = "esp32c2"))]
        let rsa_queue = accel.rsa.start();

        #[cfg(not(any(feature = "esp32", feature = "nohook-sha1")))]
        unsafe {
            crate::hook::digest::hook_sha1(Some(&SHA1));
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha224(Some(&SHA224));
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha256(Some(&SHA256));
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha384(Some(&SHA384));
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha512(Some(&SHA512));
        }
        #[cfg(all(not(feature = "esp32c2"), not(feature = "nohook-exp-mod")))]
        unsafe {
            crate::hook::exp_mod::hook_exp_mod(Some(&EXP_MOD));
        }

        Self {
            #[cfg(not(feature = "esp32"))]
            _sha_queue: sha_queue,
            #[cfg(not(feature = "esp32c2"))]
            _rsa_queue: rsa_queue,
        }
    }
}

impl Drop for EspAccelQueue<'_, '_> {
    fn drop(&mut self) {
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha1")))]
        unsafe {
            crate::hook::digest::hook_sha1(None);
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha224(None);
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha256(None);
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha384(None);
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha512(None);
        }
        #[cfg(all(not(feature = "esp32c2"), not(feature = "nohook-exp-mod")))]
        unsafe {
            crate::hook::exp_mod::hook_exp_mod(None);
        }
    }
}
