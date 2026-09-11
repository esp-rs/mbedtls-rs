//! AES implementation delegating to the `embassy-crypto` AES (ECB) drivers.
//!
//! The work area holds the raw key only, and the `embassy-crypto` cipher is
//! keyed anew for each MbedTLS operation - as a hardware AES peripheral is
//! anyway. The driver contexts cannot live in the work area: they are larger
//! than it (up to 512 bytes on 32-bit targets, 1 KiB on 64-bit ones) and they
//! are not plain-old-data (they have drop glue), which the AES hook requires
//! of the state in its work area (see [`crate::hook::aes`]).

use core::marker::PhantomData;

use crate::hook::aes::{AesBlock, MbedtlsAes, SoftAesState};
use crate::hook::{WorkArea, WorkAreaMemory};
use crate::{MbedtlsError, MBEDTLS_ERR_AES_BAD_INPUT_DATA, MBEDTLS_ERR_AES_INVALID_KEY_LENGTH};

/// A set of AES key sizes served by `embassy-crypto` drivers, as used by
/// [`EmbassyAes`].
///
/// Implemented by [`embassy_crypto::Aes128`] (the `Aes128Ecb` driver) and
/// [`embassy_crypto::Aes256`] (the `Aes256Ecb` driver), and by pairs of sets:
/// `(Aes128, Aes256)` serves both key sizes.
pub trait EmbassyAesKeys {
    /// Whether keys of `key_len` bytes are served
    fn serves(key_len: usize) -> bool;

    /// Encrypt (or, with `dec`, decrypt) `block` in place with `key`, whose
    /// length is served
    fn crypt(key: &[u8], dec: bool, block: &mut AesBlock);
}

macro_rules! impl_embassy_aes_keys {
    ($($cipher:ty => $key_len:literal),* $(,)?) => {
        $(
            impl EmbassyAesKeys for $cipher {
                fn serves(key_len: usize) -> bool {
                    key_len == $key_len
                }

                fn crypt(key: &[u8], dec: bool, block: &mut AesBlock) {
                    let cipher = <$cipher>::new(key.try_into().unwrap());

                    if dec {
                        cipher.decrypt_block(block);
                    } else {
                        cipher.encrypt_block(block);
                    }
                }
            }
        )*
    };
}

impl_embassy_aes_keys! {
    embassy_crypto::Aes128 => 16,
    embassy_crypto::Aes256 => 32,
}

impl<A, B> EmbassyAesKeys for (A, B)
where
    A: EmbassyAesKeys,
    B: EmbassyAesKeys,
{
    fn serves(key_len: usize) -> bool {
        A::serves(key_len) || B::serves(key_len)
    }

    fn crypt(key: &[u8], dec: bool, block: &mut AesBlock) {
        if A::serves(key.len()) {
            A::crypt(key, dec, block);
        } else {
            B::crypt(key, dec, block);
        }
    }
}

/// The AES state emplaced in the MbedTLS AES context work area.
///
/// Plain-old-data only (the MbedTLS cipher layer memcpy-clones contexts).
// The size difference between the variants is irrelevant: the state is
// emplaced in the fixed-size work area, which must fit the large (software
// fallback) variant anyway - and being plain-old-data, it cannot be boxed.
#[allow(clippy::large_enum_variant)]
enum EmbassyAesState {
    /// The key is scheduled by the `embassy-crypto` driver for each operation
    Driver {
        key: [u8; 32],
        key_len: u8,
        dec: bool,
    },
    /// Software fallback for key sizes not served by the drivers
    Soft(SoftAesState),
}

impl EmbassyAesState {
    fn new<K: EmbassyAesKeys>(key: &[u8], dec: bool) -> Result<Self, MbedtlsError> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH));
        }

        let state = if K::serves(key.len()) {
            let mut key_buf = [0; 32];
            key_buf[..key.len()].copy_from_slice(key);

            Self::Driver {
                key: key_buf,
                key_len: key.len() as _,
                dec,
            }
        } else if dec {
            Self::Soft(SoftAesState::new_dec(key)?)
        } else {
            Self::Soft(SoftAesState::new_enc(key)?)
        };

        Ok(state)
    }

    fn crypt_block<K: EmbassyAesKeys>(
        &mut self,
        dec: bool,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        match self {
            Self::Driver {
                key,
                key_len,
                dec: key_dec,
            } => {
                // Mirror the software fallback: using a context keyed for the
                // opposite direction is an input error
                if *key_dec != dec {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
                }

                K::crypt(&key[..*key_len as usize], dec, block);

                Ok(())
            }
            Self::Soft(state) => {
                if dec {
                    state.decrypt(block)
                } else {
                    state.encrypt(block)
                }
            }
        }
    }
}

/// AES implementation delegating to the `embassy-crypto` AES drivers of the
/// key sizes in `K` - by default AES-128 and AES-256, e.g.
/// `EmbassyAes<embassy_crypto::Aes128>` needs the AES-128 driver only - and
/// to the MbedTLS software AES for the other key sizes (always for 192-bit
/// keys, which `embassy-crypto` has no driver for).
pub struct EmbassyAes<K = (embassy_crypto::Aes128, embassy_crypto::Aes256)>(PhantomData<fn() -> K>);

impl<K> EmbassyAes<K> {
    /// Create a new `EmbassyAes` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<K> Default for EmbassyAes<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> MbedtlsAes for EmbassyAes<K>
where
    K: EmbassyAesKeys,
{
    fn init(&self, memory: &mut WorkAreaMemory) {
        unsafe { memory.cast_mut_maybe::<Option<EmbassyAesState>>() }.write(None);
    }

    fn free(&self, memory: &mut WorkAreaMemory) {
        let ptr = unsafe { memory.cast_mut::<Option<EmbassyAesState>>() } as *mut _;

        unsafe {
            core::ptr::drop_in_place(ptr);
        }

        memory.fill(0);
    }

    fn set_enc_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        *unsafe { memory.cast_mut() } = Some(EmbassyAesState::new::<K>(key, false)?);

        Ok(())
    }

    fn set_dec_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        *unsafe { memory.cast_mut() } = Some(EmbassyAesState::new::<K>(key, true)?);

        Ok(())
    }

    fn encrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        state(memory)?.crypt_block::<K>(false, block)
    }

    fn decrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        state(memory)?.crypt_block::<K>(true, block)
    }
}

#[inline(always)]
fn state(memory: &mut WorkAreaMemory) -> Result<&mut EmbassyAesState, MbedtlsError> {
    unsafe { memory.cast_mut::<Option<EmbassyAesState>>() }
        .as_mut()
        .ok_or(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))
}
