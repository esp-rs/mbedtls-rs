//! Digest implementations using ESP32 hardware acceleration.
//!
//! The hooks drive the `esp-hal` SHA work-queue contexts (`Sha1Context` & co.)
//! through their native API, so this crate does not depend on the `digest`
//! crate version `esp-hal` happens to implement.

use core::marker::PhantomData;
use core::ptr::drop_in_place;

use mbedtls_rs_sys::hook::digest::MbedtlsDigest;
use mbedtls_rs_sys::hook::{WorkArea, WorkAreaMemory};

/// An `esp-hal` SHA work-queue context, as driven by [`EspDigest`]
pub trait EspShaContext: Clone {
    /// The digest output size, in bytes
    const OUTPUT_SIZE: usize;

    /// Create an empty context
    fn new() -> Self;

    /// Hash `data`, blocking until the work queue has processed it
    fn update(&mut self, data: &[u8]);

    /// Finish hashing, writing the digest to `output` (at least
    /// [`Self::OUTPUT_SIZE`] bytes long) and blocking until it is available
    fn finalize_into(&mut self, output: &mut [u8]);
}

macro_rules! impl_esp_sha_context {
    ($($(#[$meta:meta])* $ctx:ty => $size:literal),* $(,)?) => {
        $(
            $(#[$meta])*
            impl EspShaContext for $ctx {
                const OUTPUT_SIZE: usize = $size;

                fn new() -> Self {
                    <$ctx>::new()
                }

                fn update(&mut self, data: &[u8]) {
                    <$ctx>::update(self, data).wait_blocking();
                }

                fn finalize_into(&mut self, output: &mut [u8]) {
                    <$ctx>::finalize_into_slice(self, output)
                        .unwrap()
                        .wait_blocking();
                }
            }
        )*
    };
}

impl_esp_sha_context! {
    #[cfg(not(feature = "esp32"))]
    esp_hal::sha::Sha1Context => 20,
    #[cfg(not(feature = "esp32"))]
    esp_hal::sha::Sha224Context => 28,
    #[cfg(not(feature = "esp32"))]
    esp_hal::sha::Sha256Context => 32,
    #[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
    esp_hal::sha::Sha384Context => 48,
    #[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
    esp_hal::sha::Sha512Context => 64,
}

/// MbedTLS Digest algorithm implementation that delegates to an `esp-hal`
/// hardware accelerated SHA context.
///
/// The work area holds an `Option<T>`: `None` between `init` and the first
/// `starts`, `Some(context)` while hashing is in progress.
pub struct EspDigest<T>(PhantomData<fn() -> T>);

impl<T> EspDigest<T> {
    /// Create a new `EspDigest` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Default for EspDigest<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MbedtlsDigest for EspDigest<T>
where
    T: EspShaContext,
{
    fn output_size(&self, _memory: &WorkAreaMemory) -> usize {
        T::OUTPUT_SIZE
    }

    fn init(&self, memory: &mut WorkAreaMemory) {
        unsafe { memory.cast_mut_maybe::<Option<T>>() }.write(None);
    }

    fn free(&self, memory: &mut WorkAreaMemory) {
        let ptr = unsafe { memory.cast_mut::<Option<T>>() } as *mut _;

        unsafe {
            drop_in_place(ptr);
        }

        memory.fill(0);
    }

    fn reset(&self, memory: &mut WorkAreaMemory) {
        *unsafe { memory.cast_mut() } = Some(T::new());
    }

    fn update(&self, memory: &mut WorkAreaMemory, data: &[u8]) {
        unsafe { memory.cast_mut::<Option<T>>() }
            .as_mut()
            .unwrap()
            .update(data);
    }

    fn finish(&self, memory: &mut WorkAreaMemory, output: &mut [u8]) {
        unsafe { memory.cast_mut::<Option<T>>() }
            .take()
            .unwrap()
            .finalize_into(output);
    }

    fn clone(&self, src_work_area: &WorkAreaMemory, dst_work_area: &mut WorkAreaMemory) {
        *unsafe { dst_work_area.cast_mut() } = unsafe { src_work_area.cast::<Option<T>>() }.clone();
    }
}

/// SHA-1 digest implementation using ESP32 hardware acceleration
#[cfg(not(feature = "esp32"))]
pub type EspSha1 = EspDigest<esp_hal::sha::Sha1Context>;
/// SHA-224 digest implementation using ESP32 hardware acceleration
#[cfg(not(feature = "esp32"))]
pub type EspSha224 = EspDigest<esp_hal::sha::Sha224Context>;
/// SHA-256 digest implementation using ESP32 hardware acceleration
#[cfg(not(feature = "esp32"))]
pub type EspSha256 = EspDigest<esp_hal::sha::Sha256Context>;
/// SHA-384 digest implementation using ESP32 hardware acceleration
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub type EspSha384 = EspDigest<esp_hal::sha::Sha384Context>;
/// SHA-512 digest implementation using ESP32 hardware acceleration
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub type EspSha512 = EspDigest<esp_hal::sha::Sha512Context>;

#[cfg(not(feature = "esp32"))]
impl mbedtls_rs_sys::hook::digest::MbedtlsSha1 for EspSha1 {}
#[cfg(not(feature = "esp32"))]
impl mbedtls_rs_sys::hook::digest::MbedtlsSha224 for EspSha224 {}
#[cfg(not(feature = "esp32"))]
impl mbedtls_rs_sys::hook::digest::MbedtlsSha256 for EspSha256 {}
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
impl mbedtls_rs_sys::hook::digest::MbedtlsSha384 for EspSha384 {}
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
impl mbedtls_rs_sys::hook::digest::MbedtlsSha512 for EspSha512 {}
