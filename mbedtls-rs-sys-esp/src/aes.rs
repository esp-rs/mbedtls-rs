//! AES implementation using ESP32XX hardware acceleration.
//!
//! Ops are posted to the `esp-hal` AES work queue (see
//! `esp_hal::aes::AesBackend`), whose driver must be running for the
//! duration of use - this is ensured by `EspAccel`/`EspAccelQueue`.

use esp_hal::aes::{cipher_modes, AesContext, Key, Operation};

use mbedtls_rs_sys::hook::aes::{AesBlock, MbedtlsAes, SoftAesState, AES_BLOCK_SIZE};
use mbedtls_rs_sys::hook::{WorkArea, WorkAreaMemory};
use mbedtls_rs_sys::{
    MbedtlsError, MBEDTLS_ERR_AES_BAD_INPUT_DATA, MBEDTLS_ERR_AES_INVALID_KEY_LENGTH,
};

/// Whether the AES peripheral supports 192-bit keys.
///
/// The ESP32-S3/C3/C5/C6/H2 AES peripherals only support 128- and 256-bit
/// keys; 192-bit keys are handled with the MbedTLS software implementation
/// there.
const HW_192: bool = cfg!(any(feature = "esp32", feature = "esp32s2"));

/// The AES state emplaced in the MbedTLS AES context work area.
///
/// Plain-old-data only (the MbedTLS cipher layer memcpy-clones contexts).
// The size difference between the variants is irrelevant: the state is
// emplaced in the fixed-size work area, which must fit the large (software
// fallback) variant anyway - and being plain-old-data, it cannot be boxed.
#[allow(clippy::large_enum_variant)]
enum EspAesState {
    /// The key is scheduled on the AES peripheral for each operation
    Hw {
        key: [u8; 32],
        key_len: u8,
        dec: bool,
    },
    /// Software fallback for key sizes the peripheral does not support
    Soft(SoftAesState),
}

impl EspAesState {
    fn new(key: &[u8], dec: bool) -> Result<Self, MbedtlsError> {
        let state = match key.len() {
            16 | 32 => Self::new_hw(key, dec),
            24 => {
                if HW_192 {
                    Self::new_hw(key, dec)
                } else if dec {
                    Self::Soft(SoftAesState::new_dec(key)?)
                } else {
                    Self::Soft(SoftAesState::new_enc(key)?)
                }
            }
            _ => return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH)),
        };

        Ok(state)
    }

    fn new_hw(key: &[u8], dec: bool) -> Self {
        let mut key_buf = [0; 32];
        key_buf[..key.len()].copy_from_slice(key);

        Self::Hw {
            key: key_buf,
            key_len: key.len() as _,
            dec,
        }
    }

    fn hw_key(key: &[u8; 32], key_len: u8) -> Key {
        match key_len {
            16 => Key::from(<[u8; 16]>::try_from(&key[..16]).unwrap()),
            #[cfg(any(feature = "esp32", feature = "esp32s2"))]
            24 => Key::from(<[u8; 24]>::try_from(&key[..24]).unwrap()),
            32 => Key::from(*key),
            _ => unreachable!(),
        }
    }

    /// Run a work-queue operation over `data` in-place with the given cipher
    /// mode
    fn process_hw(
        key: &[u8; 32],
        key_len: u8,
        dec: bool,
        cipher_mode: impl Into<esp_hal::aes::CipherState>,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        let operation = if dec {
            Operation::Decrypt
        } else {
            Operation::Encrypt
        };

        let mut ctx = AesContext::new(cipher_mode, operation, Self::hw_key(key, key_len));

        ctx.process_in_place(data)
            .map_err(|_| MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))?
            .wait_blocking();

        Ok(())
    }

    fn crypt_block(&mut self, dec: bool, block: &mut AesBlock) -> Result<(), MbedtlsError> {
        match self {
            Self::Hw {
                key,
                key_len,
                dec: key_dec,
            } => {
                // Mirror the software fallback: using a context keyed for the
                // opposite direction is an input error
                if *key_dec != dec {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
                }

                Self::process_hw(key, *key_len, dec, cipher_modes::Ecb, block)
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

/// AES implementation using the ESP32XX AES peripheral (via the `esp-hal`
/// AES work queue), with the MbedTLS software AES as fallback for key sizes the
/// peripheral does not support (192-bit keys on ESP32-C3/C5/C6/H2).
pub struct EspAes(());

impl EspAes {
    /// Create a new `EspAes` instance
    pub const fn new() -> Self {
        Self(())
    }
}

impl Default for EspAes {
    fn default() -> Self {
        Self::new()
    }
}

impl MbedtlsAes for EspAes {
    fn init(&self, memory: &mut WorkAreaMemory) {
        unsafe { memory.cast_mut_maybe::<Option<EspAesState>>() }.write(None);
    }

    fn free(&self, memory: &mut WorkAreaMemory) {
        let ptr = unsafe { memory.cast_mut::<Option<EspAesState>>() } as *mut _;

        unsafe {
            core::ptr::drop_in_place(ptr);
        }

        memory.fill(0);
    }

    fn set_enc_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        *unsafe { memory.cast_mut() } = Some(EspAesState::new(key, false)?);

        Ok(())
    }

    fn set_dec_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        *unsafe { memory.cast_mut() } = Some(EspAesState::new(key, true)?);

        Ok(())
    }

    fn encrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        state(memory)?.crypt_block(false, block)
    }

    fn decrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        state(memory)?.crypt_block(true, block)
    }

    fn encrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        match state(memory)? {
            EspAesState::Hw { key, key_len, dec } => {
                if *dec {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
                }

                EspAesState::process_hw(key, *key_len, false, cipher_modes::Cbc::new(*iv), data)?;

                // MbedTLS chaining semantics: the IV becomes the last
                // ciphertext block
                iv.copy_from_slice(&data[data.len() - AES_BLOCK_SIZE..]);

                Ok(())
            }
            EspAesState::Soft(soft) => {
                for block in data.as_chunks_mut::<AES_BLOCK_SIZE>().0 {
                    for (b, i) in block.iter_mut().zip(iv.iter()) {
                        *b ^= *i;
                    }
                    soft.encrypt(block)?;

                    *iv = *block;
                }

                Ok(())
            }
        }
    }

    fn decrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        match state(memory)? {
            EspAesState::Hw { key, key_len, dec } => {
                if !*dec {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
                }

                // MbedTLS chaining semantics: the IV becomes the last input
                // ciphertext block; save it before it is overwritten
                let mut next_iv = AesBlock::default();
                next_iv.copy_from_slice(&data[data.len() - AES_BLOCK_SIZE..]);

                EspAesState::process_hw(key, *key_len, true, cipher_modes::Cbc::new(*iv), data)?;

                *iv = next_iv;

                Ok(())
            }
            EspAesState::Soft(soft) => {
                for block in data.as_chunks_mut::<AES_BLOCK_SIZE>().0 {
                    let ct = *block;
                    soft.decrypt(block)?;
                    for (b, i) in block.iter_mut().zip(iv.iter()) {
                        *b ^= *i;
                    }

                    *iv = ct;
                }

                Ok(())
            }
        }
    }
}

#[inline(always)]
fn state(memory: &mut WorkAreaMemory) -> Result<&mut EspAesState, MbedtlsError> {
    unsafe { memory.cast_mut::<Option<EspAesState>>() }
        .as_mut()
        .ok_or(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))
}
