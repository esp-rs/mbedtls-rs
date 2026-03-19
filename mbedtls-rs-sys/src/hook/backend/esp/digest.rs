//! Digest implementations using ESP32 hardware acceleration.

/// SHA-1 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha1 impl that implements the RustCrypto `Digest` trait.
#[cfg(not(feature = "esp32"))]
pub type EspSha1 = crate::hook::digest::RustCryptoDigest<esp_hal::sha::Sha1Context>;
/// SHA-224 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha224 impl that implements the RustCrypto `Digest` trait.
#[cfg(not(feature = "esp32"))]
pub type EspSha224 = crate::hook::digest::RustCryptoDigest<esp_hal::sha::Sha224Context>;
/// SHA-256 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha256 impl that implements the RustCrypto `Digest` trait.
#[cfg(not(feature = "esp32"))]
pub type EspSha256 = crate::hook::digest::RustCryptoDigest<esp_hal::sha::Sha256Context>;
/// SHA-384 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha384 impl that implements the RustCrypto `Digest` trait.
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub type EspSha384 = crate::hook::digest::RustCryptoDigest<esp_hal::sha::Sha384Context>;
/// SHA-512 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha512 impl that implements the RustCrypto `Digest` trait.
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub type EspSha512 = crate::hook::digest::RustCryptoDigest<esp_hal::sha::Sha512Context>;

#[cfg(not(feature = "esp32"))]
impl crate::hook::digest::MbedtlsSha1 for EspSha1 {}
#[cfg(not(feature = "esp32"))]
impl crate::hook::digest::MbedtlsSha224 for EspSha224 {}
#[cfg(not(feature = "esp32"))]
impl crate::hook::digest::MbedtlsSha256 for EspSha256 {}
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
impl crate::hook::digest::MbedtlsSha384 for EspSha384 {}
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
impl crate::hook::digest::MbedtlsSha512 for EspSha512 {}
