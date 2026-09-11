//! Digest implementations delegating to the `embassy-crypto` hash drivers.

use core::marker::PhantomData;
use core::ptr::drop_in_place;

use crate::hook::digest::MbedtlsDigest;
use crate::hook::{WorkArea, WorkAreaMemory};

/// An `embassy-crypto` hash, as driven by [`EmbassyDigest`]
pub trait EmbassyHash: Clone {
    /// The digest output size, in bytes
    const OUTPUT_SIZE: usize;

    /// The size of the MbedTLS hook work area the hash is emplaced in
    const WORK_AREA_SIZE: usize;

    /// Start a new hash computation
    fn new() -> Self;

    /// Absorb `data`
    fn update(&mut self, data: &[u8]);

    /// Finish the computation, writing the digest to `output` (at least
    /// [`Self::OUTPUT_SIZE`] bytes long)
    fn finalize_into(self, output: &mut [u8]);
}

macro_rules! impl_embassy_hash {
    ($($(#[$meta:meta])* $hash:ty => $work_area_size:expr),* $(,)?) => {
        $(
            $(#[$meta])*
            impl EmbassyHash for $hash {
                const OUTPUT_SIZE: usize = <$hash>::OUTPUT_SIZE;
                const WORK_AREA_SIZE: usize = $work_area_size as usize;

                fn new() -> Self {
                    <$hash>::new()
                }

                fn update(&mut self, data: &[u8]) {
                    <$hash>::update(self, data);
                }

                fn finalize_into(self, output: &mut [u8]) {
                    output[..<$hash>::OUTPUT_SIZE].copy_from_slice(&<$hash>::finalize(self));
                }
            }
        )*
    };
}

impl_embassy_hash! {
    #[cfg(all(feature = "alg-sha1", not(feature = "nohook-sha1")))]
    embassy_crypto::Sha1 => crate::MBEDTLS_SHA1_ALT_WORK_AREA_SIZE,
    #[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
    embassy_crypto::Sha224 => crate::MBEDTLS_SHA256_ALT_WORK_AREA_SIZE,
    #[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
    embassy_crypto::Sha256 => crate::MBEDTLS_SHA256_ALT_WORK_AREA_SIZE,
    #[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
    embassy_crypto::Sha384 => crate::MBEDTLS_SHA512_ALT_WORK_AREA_SIZE,
    #[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
    embassy_crypto::Sha512 => crate::MBEDTLS_SHA512_ALT_WORK_AREA_SIZE,
}

/// MbedTLS Digest algorithm implementation that delegates to an
/// `embassy-crypto` hash driver.
///
/// The work area holds an `Option<T>`: `None` between `init` and the first
/// `starts`, `Some(hash)` while hashing is in progress.
pub struct EmbassyDigest<T>(PhantomData<fn() -> T>);

impl<T> EmbassyDigest<T> {
    /// Create a new `EmbassyDigest` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Default for EmbassyDigest<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MbedtlsDigest for EmbassyDigest<T>
where
    T: EmbassyHash,
{
    fn output_size(&self, _memory: &WorkAreaMemory) -> usize {
        T::OUTPUT_SIZE
    }

    fn init(&self, memory: &mut WorkAreaMemory) {
        // The driver context must fit the work area at any emplacement offset
        // (see the `WorkArea` docs in `src/hook.rs`); the enlarged contexts of
        // the `embassy-crypto` `large-*` features do not. Checked when the
        // implementation is instantiated.
        // `core::assert!`, not the crate `assert!` (whose `defmt` variant is not const-callable)
        const {
            core::assert!(
                core::mem::size_of::<Option<T>>() + 16 <= T::WORK_AREA_SIZE,
                "The embassy-crypto hash context does not fit the MbedTLS hook work area"
            );
            core::assert!(
                core::mem::align_of::<Option<T>>() <= 16,
                "The embassy-crypto hash context is over-aligned for the MbedTLS hook work area"
            );
        }

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

/// SHA-1 digest implementation using the `embassy-crypto` `Sha1` driver
#[cfg(all(feature = "alg-sha1", not(feature = "nohook-sha1")))]
pub type EmbassySha1 = EmbassyDigest<embassy_crypto::Sha1>;
/// SHA-224 digest implementation using the `embassy-crypto` `Sha224` driver
#[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
pub type EmbassySha224 = EmbassyDigest<embassy_crypto::Sha224>;
/// SHA-256 digest implementation using the `embassy-crypto` `Sha256` driver
#[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
pub type EmbassySha256 = EmbassyDigest<embassy_crypto::Sha256>;
/// SHA-384 digest implementation using the `embassy-crypto` `Sha384` driver
#[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
pub type EmbassySha384 = EmbassyDigest<embassy_crypto::Sha384>;
/// SHA-512 digest implementation using the `embassy-crypto` `Sha512` driver
#[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
pub type EmbassySha512 = EmbassyDigest<embassy_crypto::Sha512>;

#[cfg(all(feature = "alg-sha1", not(feature = "nohook-sha1")))]
impl crate::hook::digest::MbedtlsSha1 for EmbassySha1 {}
#[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
impl crate::hook::digest::MbedtlsSha224 for EmbassySha224 {}
#[cfg(all(feature = "alg-sha256", not(feature = "nohook-sha256")))]
impl crate::hook::digest::MbedtlsSha256 for EmbassySha256 {}
#[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
impl crate::hook::digest::MbedtlsSha384 for EmbassySha384 {}
#[cfg(all(feature = "alg-sha512", not(feature = "nohook-sha512")))]
impl crate::hook::digest::MbedtlsSha512 for EmbassySha512 {}
