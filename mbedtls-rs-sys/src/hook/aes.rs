//! Hooking for the MbedTLS AES block cipher.
//!
//! Unlike the granular `MBEDTLS_AES_*_ALT` options (which keep the upstream
//! key-schedule context layout and therefore cannot host a hardware backend's
//! state), this hook replaces the AES module wholesale (`MBEDTLS_AES_ALT`):
//! `mbedtls_aes_context` becomes an opaque, 16-byte-aligned work area (see
//! `gen/hook/aes_alt.h`) and every `mbedtls_aes_*` entry point is provided in
//! Rust, dispatching through the [`MbedtlsAes`] trait. When nothing is
//! hooked, the entry points fall back to MbedTLS's own software AES, which
//! the library keeps compiled under `mbedtls_aes_soft_*` names (see
//! [`SoftAes`]).
//!
//! Since every MbedTLS AES consumer funnels through these entry points -
//! CCM/GCM (via the block-cipher/cipher layers), CMAC (via the cipher layer),
//! CTR-DRBG (directly), and the raw cipher-mode functions - hooking the block
//! cipher accelerates all of them at once.
//!
//! IMPORTANT: MbedTLS's generic cipher layer clones AES contexts with a raw
//! `memcpy` and never notifies this module. Implementations MUST therefore
//! keep only plain-old-data state (no heap pointers, no self-references) in
//! the work area.

use core::ops::Deref;

use crate::hook::WorkAreaMemory;
use crate::MbedtlsError;
#[cfg(mbedtls_hook = "aes")]
use crate::{MBEDTLS_ERR_AES_BAD_INPUT_DATA, MBEDTLS_ERR_AES_INVALID_KEY_LENGTH};

#[cfg(mbedtls_hook = "aes")]
use super::WorkArea;

/// The AES block size, in bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// An AES block
pub type AesBlock = [u8; AES_BLOCK_SIZE];

/// Trait representing a custom (hooked) MbedTLS AES implementation.
///
/// All block operations work in-place on 16-byte blocks. The bulk CBC helpers
/// have default implementations that chain the single-block operations;
/// hardware implementations may override them with multi-block operations.
///
/// IMPORTANT: the state emplaced in the work area MUST be plain-old-data:
/// MbedTLS's cipher layer clones AES contexts with a raw `memcpy` (there is
/// no clone callback in the AES API), and contexts may be moved in memory.
pub trait MbedtlsAes {
    /// Initialize the work area (i.e. emplace an empty, un-keyed state)
    fn init(&self, memory: &mut WorkAreaMemory);

    /// Free the work area (i.e. execute drop-in-place and wipe)
    fn free(&self, memory: &mut WorkAreaMemory);

    /// Schedule an encryption key.
    ///
    /// `key` is 16, 24 or 32 bytes long.
    fn set_enc_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError>;

    /// Schedule a decryption key.
    ///
    /// `key` is 16, 24 or 32 bytes long.
    fn set_dec_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError>;

    /// Encrypt a single block in-place. The state must have been keyed with
    /// [`MbedtlsAes::set_enc_key`].
    fn encrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError>;

    /// Decrypt a single block in-place. The state must have been keyed with
    /// [`MbedtlsAes::set_dec_key`].
    fn decrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError>;

    /// Bulk in-place CBC encryption.
    ///
    /// `data.len()` is a non-zero multiple of 16. On return, `iv` holds the
    /// last ciphertext block (ready for chaining the next call).
    fn encrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        for block in data.chunks_exact_mut(AES_BLOCK_SIZE) {
            let block: &mut AesBlock = block.try_into().unwrap();

            xor_in_place(block, iv);
            self.encrypt(memory, block)?;

            *iv = *block;
        }

        Ok(())
    }

    /// Bulk in-place CBC decryption.
    ///
    /// `data.len()` is a non-zero multiple of 16. On return, `iv` holds the
    /// last input ciphertext block (ready for chaining the next call).
    fn decrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        for block in data.chunks_exact_mut(AES_BLOCK_SIZE) {
            let block: &mut AesBlock = block.try_into().unwrap();

            let ct = *block;
            self.decrypt(memory, block)?;
            xor_in_place(block, iv);

            *iv = ct;
        }

        Ok(())
    }
}

impl<T: Deref> MbedtlsAes for T
where
    T::Target: MbedtlsAes,
{
    fn init(&self, memory: &mut WorkAreaMemory) {
        self.deref().init(memory);
    }

    fn free(&self, memory: &mut WorkAreaMemory) {
        self.deref().free(memory);
    }

    fn set_enc_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        self.deref().set_enc_key(memory, key)
    }

    fn set_dec_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        self.deref().set_dec_key(memory, key)
    }

    fn encrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        self.deref().encrypt(memory, block)
    }

    fn decrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        self.deref().decrypt(memory, block)
    }

    fn encrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        self.deref().encrypt_cbc(memory, iv, data)
    }

    fn decrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        self.deref().decrypt_cbc(memory, iv, data)
    }
}

#[inline(always)]
fn xor_in_place(block: &mut AesBlock, other: &AesBlock) {
    for (b, o) in block.iter_mut().zip(other.iter()) {
        *b ^= *o;
    }
}

/// A keyed AES cipher state based on the MbedTLS software AES implementation.
///
/// The library compiles that implementation under `mbedtls_aes_soft_*` names
/// next to the hooked (`_ALT`) entry points (see `SoftFallback` in
/// `gen/builder.rs`). This is the state of the [`SoftAes`] fallback, and is
/// reusable by hardware backends that need a software escape hatch (e.g. for
/// key sizes their AES peripheral does not support).
///
/// Plain-old-data: just the MbedTLS key schedule plus the direction the key
/// was scheduled for.
#[cfg(mbedtls_hook = "aes")]
pub struct SoftAesState {
    ctx: crate::mbedtls_aes_soft_context,
    dec: bool,
}

#[cfg(mbedtls_hook = "aes")]
impl SoftAesState {
    /// Create a new encryption state by scheduling `key` (16, 24 or 32 bytes)
    pub fn new_enc(key: &[u8]) -> Result<Self, MbedtlsError> {
        Self::new(key, false)
    }

    /// Create a new decryption state by scheduling `key` (16, 24 or 32 bytes)
    pub fn new_dec(key: &[u8]) -> Result<Self, MbedtlsError> {
        Self::new(key, true)
    }

    fn new(key: &[u8], dec: bool) -> Result<Self, MbedtlsError> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH));
        }

        let mut ctx = core::mem::MaybeUninit::<crate::mbedtls_aes_soft_context>::uninit();

        // `mbedtls_aes_soft_init` zeroes the context, i.e. fully initializes it
        let ctx = unsafe {
            crate::mbedtls_aes_soft_init(ctx.as_mut_ptr());
            ctx.assume_init()
        };

        let mut this = Self { ctx, dec };

        let keybits = key.len() as u32 * 8;
        let ret = if dec {
            unsafe { crate::mbedtls_aes_soft_setkey_dec(&mut this.ctx, key.as_ptr(), keybits) }
        } else {
            unsafe { crate::mbedtls_aes_soft_setkey_enc(&mut this.ctx, key.as_ptr(), keybits) }
        };
        crate::merr!(ret)?;

        Ok(this)
    }

    /// Encrypt a single block in-place (state must be an encryption state)
    pub fn encrypt(&mut self, block: &mut AesBlock) -> Result<(), MbedtlsError> {
        if self.dec {
            return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
        }

        crate::merr!(unsafe {
            crate::mbedtls_internal_aes_soft_encrypt(
                &mut self.ctx,
                block.as_ptr(),
                block.as_mut_ptr(),
            )
        })?;

        Ok(())
    }

    /// Decrypt a single block in-place (state must be a decryption state)
    pub fn decrypt(&mut self, block: &mut AesBlock) -> Result<(), MbedtlsError> {
        if !self.dec {
            return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
        }

        crate::merr!(unsafe {
            crate::mbedtls_internal_aes_soft_decrypt(
                &mut self.ctx,
                block.as_ptr(),
                block.as_mut_ptr(),
            )
        })?;

        Ok(())
    }

    /// Bulk in-place CBC en/decryption via the MbedTLS software CBC mode,
    /// with the [`MbedtlsAes::encrypt_cbc`] / [`MbedtlsAes::decrypt_cbc`] IV
    /// chaining semantics
    #[cfg(feature = "cipher-mode-cbc")]
    pub fn crypt_cbc(
        &mut self,
        dec: bool,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        if self.dec != dec {
            return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA));
        }

        let mode = if dec {
            crate::MBEDTLS_AES_DECRYPT
        } else {
            crate::MBEDTLS_AES_ENCRYPT
        };

        crate::merr!(unsafe {
            crate::mbedtls_aes_soft_crypt_cbc(
                &mut self.ctx,
                mode as _,
                data.len(),
                iv.as_mut_ptr(),
                data.as_ptr(),
                data.as_mut_ptr(),
            )
        })?;

        Ok(())
    }
}

/// MbedTLS AES implementation that delegates to the MbedTLS software AES
/// implementation; the fallback when no custom implementation is hooked
#[cfg(mbedtls_hook = "aes")]
pub struct SoftAes(());

#[cfg(mbedtls_hook = "aes")]
impl SoftAes {
    /// Create a new `SoftAes` instance
    pub const fn new() -> Self {
        Self(())
    }
}

#[cfg(mbedtls_hook = "aes")]
impl Default for SoftAes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(mbedtls_hook = "aes")]
impl MbedtlsAes for SoftAes {
    fn init(&self, memory: &mut WorkAreaMemory) {
        unsafe { memory.cast_mut_maybe::<Option<SoftAesState>>() }.write(None);
    }

    fn free(&self, memory: &mut WorkAreaMemory) {
        // Plain-old-data: nothing to drop, wiping the work area frees (and
        // zeroizes) the state
        memory.fill(0);
    }

    fn set_enc_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        *unsafe { memory.cast_mut() } = Some(SoftAesState::new_enc(key)?);

        Ok(())
    }

    fn set_dec_key(&self, memory: &mut WorkAreaMemory, key: &[u8]) -> Result<(), MbedtlsError> {
        *unsafe { memory.cast_mut() } = Some(SoftAesState::new_dec(key)?);

        Ok(())
    }

    fn encrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        unsafe { memory.cast_mut::<Option<SoftAesState>>() }
            .as_mut()
            .ok_or(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))?
            .encrypt(block)
    }

    fn decrypt(
        &self,
        memory: &mut WorkAreaMemory,
        block: &mut AesBlock,
    ) -> Result<(), MbedtlsError> {
        unsafe { memory.cast_mut::<Option<SoftAesState>>() }
            .as_mut()
            .ok_or(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))?
            .decrypt(block)
    }

    #[cfg(feature = "cipher-mode-cbc")]
    fn encrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        unsafe { memory.cast_mut::<Option<SoftAesState>>() }
            .as_mut()
            .ok_or(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))?
            .crypt_cbc(false, iv, data)
    }

    #[cfg(feature = "cipher-mode-cbc")]
    fn decrypt_cbc(
        &self,
        memory: &mut WorkAreaMemory,
        iv: &mut AesBlock,
        data: &mut [u8],
    ) -> Result<(), MbedtlsError> {
        unsafe { memory.cast_mut::<Option<SoftAesState>>() }
            .as_mut()
            .ok_or(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA))?
            .crypt_cbc(true, iv, data)
    }
}

/// Hook the AES implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use AES (including any that were only
///   initialized earlier, such as a CTR-DRBG instance), and ensure that the
///   `aes` implementation is valid for the duration of its use.
#[cfg(mbedtls_hook = "aes")]
pub unsafe fn hook_aes(aes: Option<&'static (dyn MbedtlsAes + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if aes.is_some() {
            debug!("AES hook: added custom/HW accelerated impl");
        } else {
            debug!("AES hook: removed");
        }

        alt::AES.borrow(cs).set(aes);
    });
}

#[cfg(mbedtls_hook = "aes")]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar, c_uint};

    use critical_section::Mutex;

    use crate::hook::{RawWorkArea, WorkAreaMemory};
    use crate::{
        mbedtls_aes_context, MbedtlsError, MBEDTLS_AES_DECRYPT, MBEDTLS_AES_ENCRYPT,
        MBEDTLS_ERR_AES_BAD_INPUT_DATA, MBEDTLS_ERR_AES_INVALID_KEY_LENGTH,
    };

    use super::{AesBlock, MbedtlsAes, SoftAes, SoftAesState, AES_BLOCK_SIZE};

    // The work area must be able to host the largest state used by the
    // fallback, plus emplacement slack for under-aligned opaque storage (see
    // the `WorkArea` docs in `src/hook.rs`); hardware backends embedding
    // `SoftAesState` as a software escape hatch are covered by the same bound
    // as long as their own state is not larger.
    // `core::assert!`, not the crate `assert!` (whose `defmt` variant is not const-callable)
    const _: () = core::assert!(
        core::mem::size_of::<Option<SoftAesState>>() + 16
            <= crate::MBEDTLS_AES_ALT_WORK_AREA_SIZE as usize,
        "The MbedTLS software AES state does not fit the AES hook work area"
    );
    const _: () = core::assert!(
        core::mem::align_of::<Option<SoftAesState>>() <= 16,
        "The MbedTLS software AES state is over-aligned for the work area"
    );

    const ENCRYPT: c_int = MBEDTLS_AES_ENCRYPT as c_int;
    const DECRYPT: c_int = MBEDTLS_AES_DECRYPT as c_int;

    pub(crate) static AES: Mutex<Cell<Option<&(dyn MbedtlsAes + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static AES_SOFT: SoftAes = SoftAes::new();

    #[inline(always)]
    fn algo<'a>() -> &'a dyn MbedtlsAes {
        if let Some(aes) = critical_section::with(|cs| AES.borrow(cs).get()) {
            aes
        } else {
            &AES_SOFT
        }
    }

    impl RawWorkArea for mbedtls_aes_context {
        unsafe fn work_area<'a>(ctx: *const Self) -> &'a WorkAreaMemory {
            unsafe { &*core::ptr::addr_of!((*ctx).work_area) }
        }

        unsafe fn work_area_mut<'a>(ctx: *mut Self) -> &'a mut WorkAreaMemory {
            unsafe { &mut *core::ptr::addr_of_mut!((*ctx).work_area) }
        }
    }

    #[inline(always)]
    fn result(result: Result<(), MbedtlsError>) -> c_int {
        result.map_or_else(|e| e.code(), |_| 0)
    }

    /// Validate `keybits` and return the key as a slice
    #[inline(always)]
    unsafe fn key_slice<'a>(
        key: *const c_uchar,
        keybits: c_uint,
    ) -> Result<&'a [u8], MbedtlsError> {
        if !matches!(keybits, 128 | 192 | 256) {
            return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH));
        }

        Ok(unsafe { core::slice::from_raw_parts(key, keybits as usize / 8) })
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_init(ctx: *mut mbedtls_aes_context) {
        algo().init(unsafe { mbedtls_aes_context::work_area_mut(ctx) });
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_free(ctx: *mut mbedtls_aes_context) {
        // MbedTLS contract: `mbedtls_aes_free(NULL)` is documented as valid
        if ctx.is_null() {
            return;
        }

        algo().free(unsafe { mbedtls_aes_context::work_area_mut(ctx) });
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_setkey_enc(
        ctx: *mut mbedtls_aes_context,
        key: *const c_uchar,
        keybits: c_uint,
    ) -> c_int {
        result(unsafe { key_slice(key, keybits) }.and_then(|key| {
            algo().set_enc_key(unsafe { mbedtls_aes_context::work_area_mut(ctx) }, key)
        }))
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_setkey_dec(
        ctx: *mut mbedtls_aes_context,
        key: *const c_uchar,
        keybits: c_uint,
    ) -> c_int {
        result(unsafe { key_slice(key, keybits) }.and_then(|key| {
            algo().set_dec_key(unsafe { mbedtls_aes_context::work_area_mut(ctx) }, key)
        }))
    }

    #[inline(always)]
    unsafe fn crypt_block(
        algo: &dyn MbedtlsAes,
        ctx: *mut mbedtls_aes_context,
        mode: c_int,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> Result<(), MbedtlsError> {
        // Copy through a local block so that `input` and `output` may alias
        // in any way (MbedTLS allows in-place operation)
        let mut block = AesBlock::default();
        unsafe {
            core::ptr::copy_nonoverlapping(input, block.as_mut_ptr(), AES_BLOCK_SIZE);
        }

        let memory = unsafe { mbedtls_aes_context::work_area_mut(ctx) };

        match mode {
            ENCRYPT => algo.encrypt(memory, &mut block)?,
            DECRYPT => algo.decrypt(memory, &mut block)?,
            _ => return Err(MbedtlsError::new(MBEDTLS_ERR_AES_BAD_INPUT_DATA)),
        }

        unsafe {
            core::ptr::copy_nonoverlapping(block.as_ptr(), output, AES_BLOCK_SIZE);
        }

        Ok(())
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_crypt_ecb(
        ctx: *mut mbedtls_aes_context,
        mode: c_int,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        result(unsafe { crypt_block(algo(), ctx, mode, input, output) })
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_internal_aes_encrypt(
        ctx: *mut mbedtls_aes_context,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        result(unsafe { crypt_block(algo(), ctx, ENCRYPT, input, output) })
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_internal_aes_decrypt(
        ctx: *mut mbedtls_aes_context,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        result(unsafe { crypt_block(algo(), ctx, DECRYPT, input, output) })
    }

    #[cfg(feature = "cipher-mode-cbc")]
    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_crypt_cbc(
        ctx: *mut mbedtls_aes_context,
        mode: c_int,
        length: usize,
        iv: *mut c_uchar,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        use crate::MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

        let algo = algo();

        if mode != ENCRYPT && mode != DECRYPT {
            return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        }

        if length == 0 {
            return 0;
        }

        if length % AES_BLOCK_SIZE != 0 {
            return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
        }

        // `input` and `output` may alias (in-place operation); shift the data
        // into the output buffer first (`copy` has `memmove` semantics) and
        // then operate in-place on the output buffer only.
        unsafe {
            core::ptr::copy(input, output, length);
        }

        let data = unsafe { core::slice::from_raw_parts_mut(output, length) };
        let iv = unsafe { &mut *(iv as *mut AesBlock) };
        let memory = unsafe { mbedtls_aes_context::work_area_mut(ctx) };

        result(if mode == DECRYPT {
            algo.decrypt_cbc(memory, iv, data)
        } else {
            algo.encrypt_cbc(memory, iv, data)
        })
    }

    #[cfg(feature = "cipher-mode-cfb")]
    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_crypt_cfb128(
        ctx: *mut mbedtls_aes_context,
        mode: c_int,
        length: usize,
        iv_off: *mut usize,
        iv: *mut c_uchar,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        let algo = algo();

        if mode != ENCRYPT && mode != DECRYPT {
            return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        }

        let mut n = unsafe { *iv_off };

        if n > 15 {
            return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        }

        let iv = unsafe { &mut *(iv as *mut AesBlock) };
        let memory = unsafe { mbedtls_aes_context::work_area_mut(ctx) };

        for i in 0..length {
            if n == 0 {
                if let Err(e) = algo.encrypt(memory, iv) {
                    return e.code();
                }
            }

            let c = unsafe { input.add(i).read() };

            if mode == DECRYPT {
                unsafe {
                    output.add(i).write(c ^ iv[n]);
                }
                iv[n] = c;
            } else {
                let o = iv[n] ^ c;
                iv[n] = o;
                unsafe {
                    output.add(i).write(o);
                }
            }

            n = (n + 1) & 0x0f;
        }

        unsafe {
            *iv_off = n;
        }

        0
    }

    #[cfg(feature = "cipher-mode-cfb")]
    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_crypt_cfb8(
        ctx: *mut mbedtls_aes_context,
        mode: c_int,
        length: usize,
        iv: *mut c_uchar,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        let algo = algo();

        if mode != ENCRYPT && mode != DECRYPT {
            return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        }

        let iv = unsafe { &mut *(iv as *mut AesBlock) };
        let memory = unsafe { mbedtls_aes_context::work_area_mut(ctx) };

        for i in 0..length {
            let ov = *iv;

            if let Err(e) = algo.encrypt(memory, iv) {
                return e.code();
            }

            let inp = unsafe { input.add(i).read() };
            let c = iv[0] ^ inp;
            unsafe {
                output.add(i).write(c);
            }

            let feedback = if mode == DECRYPT { inp } else { c };

            iv[..15].copy_from_slice(&ov[1..]);
            iv[15] = feedback;
        }

        0
    }

    #[cfg(feature = "cipher-mode-ofb")]
    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_crypt_ofb(
        ctx: *mut mbedtls_aes_context,
        length: usize,
        iv_off: *mut usize,
        iv: *mut c_uchar,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        let algo = algo();

        let mut n = unsafe { *iv_off };

        if n > 15 {
            return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        }

        let iv = unsafe { &mut *(iv as *mut AesBlock) };
        let memory = unsafe { mbedtls_aes_context::work_area_mut(ctx) };

        for i in 0..length {
            if n == 0 {
                if let Err(e) = algo.encrypt(memory, iv) {
                    return e.code();
                }
            }

            unsafe {
                output.add(i).write(input.add(i).read() ^ iv[n]);
            }

            n = (n + 1) & 0x0f;
        }

        unsafe {
            *iv_off = n;
        }

        0
    }

    #[cfg(feature = "cipher-mode-ctr")]
    #[no_mangle]
    unsafe extern "C" fn mbedtls_aes_crypt_ctr(
        ctx: *mut mbedtls_aes_context,
        length: usize,
        nc_off: *mut usize,
        nonce_counter: *mut c_uchar,
        stream_block: *mut c_uchar,
        input: *const c_uchar,
        output: *mut c_uchar,
    ) -> c_int {
        let algo = algo();

        let mut offset = unsafe { *nc_off };

        if offset > 0x0f {
            return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
        }

        let nonce_counter = unsafe { &mut *(nonce_counter as *mut AesBlock) };
        let stream_block = unsafe { &mut *(stream_block as *mut AesBlock) };
        let memory = unsafe { mbedtls_aes_context::work_area_mut(ctx) };

        let mut i = 0;
        while i < length {
            let mut n = AES_BLOCK_SIZE;

            if offset == 0 {
                *stream_block = *nonce_counter;
                if let Err(e) = algo.encrypt(memory, stream_block) {
                    return e.code();
                }

                // Increment the 128-bit big-endian counter
                for b in nonce_counter.iter_mut().rev() {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
            } else {
                n -= offset;
            }

            if n > length - i {
                n = length - i;
            }

            for j in 0..n {
                unsafe {
                    output
                        .add(i + j)
                        .write(input.add(i + j).read() ^ stream_block[offset + j]);
                }
            }

            offset = 0;
            i += n;
        }

        unsafe {
            *nc_off = (*nc_off + length) % AES_BLOCK_SIZE;
        }

        0
    }

    #[cfg(feature = "cipher-mode-xts")]
    mod xts {
        use core::ffi::{c_int, c_uchar, c_uint};

        use crate::hook::{RawWorkArea, WorkAreaMemory};
        use crate::{
            mbedtls_aes_context, mbedtls_aes_xts_context, MbedtlsError,
            MBEDTLS_ERR_AES_BAD_INPUT_DATA, MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH,
            MBEDTLS_ERR_AES_INVALID_KEY_LENGTH,
        };

        use super::super::{xor_in_place, AesBlock, AES_BLOCK_SIZE};
        use super::{algo, result, DECRYPT, ENCRYPT};

        /// Multiply a GF(2^128) field element (little-endian block
        /// representation) by the polynomial `x`
        fn gf128mul_x_ble(block: &mut AesBlock) {
            let a = u64::from_le_bytes(block[..8].try_into().unwrap());
            let b = u64::from_le_bytes(block[8..].try_into().unwrap());

            let ra = (a << 1) ^ if b >> 63 != 0 { 0x0087 } else { 0 };
            let rb = (a >> 63) | (b << 1);

            block[..8].copy_from_slice(&ra.to_le_bytes());
            block[8..].copy_from_slice(&rb.to_le_bytes());
        }

        /// Split an XTS key into the data (first half) and tweak (second
        /// half) sub-keys
        fn split_key(key: &[u8]) -> Result<(&[u8], &[u8]), MbedtlsError> {
            if key.len() != 32 && key.len() != 64 {
                return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH));
            }

            Ok(key.split_at(key.len() / 2))
        }

        /// Raw projections to the two embedded AES contexts' work areas (no
        /// reference to the XTS struct may be formed — see `RawWorkArea`).
        ///
        /// # Safety
        /// `ctx` must be non-null and valid for reads/writes; the two helpers
        /// borrow disjoint fields, so their results may coexist.
        #[inline(always)]
        unsafe fn crypt_wa<'a>(ctx: *mut mbedtls_aes_xts_context) -> &'a mut WorkAreaMemory {
            unsafe { mbedtls_aes_context::work_area_mut(core::ptr::addr_of_mut!((*ctx).crypt)) }
        }

        /// See [`crypt_wa`].
        #[inline(always)]
        unsafe fn tweak_wa<'a>(ctx: *mut mbedtls_aes_xts_context) -> &'a mut WorkAreaMemory {
            unsafe { mbedtls_aes_context::work_area_mut(core::ptr::addr_of_mut!((*ctx).tweak)) }
        }

        #[no_mangle]
        unsafe extern "C" fn mbedtls_aes_xts_init(ctx: *mut mbedtls_aes_xts_context) {
            let algo = algo();

            algo.init(unsafe { crypt_wa(ctx) });
            algo.init(unsafe { tweak_wa(ctx) });
        }

        #[no_mangle]
        unsafe extern "C" fn mbedtls_aes_xts_free(ctx: *mut mbedtls_aes_xts_context) {
            // MbedTLS contract: freeing NULL is valid
            if ctx.is_null() {
                return;
            }

            let algo = algo();

            algo.free(unsafe { crypt_wa(ctx) });
            algo.free(unsafe { tweak_wa(ctx) });
        }

        #[no_mangle]
        unsafe extern "C" fn mbedtls_aes_xts_setkey_enc(
            ctx: *mut mbedtls_aes_xts_context,
            key: *const c_uchar,
            keybits: c_uint,
        ) -> c_int {
            let algo = algo();

            result((|| {
                if keybits % 8 != 0 {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH));
                }

                let key = unsafe { core::slice::from_raw_parts(key, keybits as usize / 8) };
                let (crypt_key, tweak_key) = split_key(key)?;

                algo.set_enc_key(unsafe { crypt_wa(ctx) }, crypt_key)?;
                algo.set_enc_key(unsafe { tweak_wa(ctx) }, tweak_key)
            })())
        }

        #[no_mangle]
        unsafe extern "C" fn mbedtls_aes_xts_setkey_dec(
            ctx: *mut mbedtls_aes_xts_context,
            key: *const c_uchar,
            keybits: c_uint,
        ) -> c_int {
            let algo = algo();

            result((|| {
                if keybits % 8 != 0 {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_AES_INVALID_KEY_LENGTH));
                }

                let key = unsafe { core::slice::from_raw_parts(key, keybits as usize / 8) };
                let (crypt_key, tweak_key) = split_key(key)?;

                algo.set_dec_key(unsafe { crypt_wa(ctx) }, crypt_key)?;
                // The tweak is always computed with the encryption schedule
                algo.set_enc_key(unsafe { tweak_wa(ctx) }, tweak_key)
            })())
        }

        #[no_mangle]
        unsafe extern "C" fn mbedtls_aes_crypt_xts(
            ctx: *mut mbedtls_aes_xts_context,
            mode: c_int,
            length: usize,
            data_unit: *const c_uchar,
            mut input: *const c_uchar,
            mut output: *mut c_uchar,
        ) -> c_int {
            let algo = algo();
            // Disjoint raw projections into the two embedded contexts.
            let crypt_memory = unsafe { crypt_wa(ctx) };
            let tweak_memory = unsafe { tweak_wa(ctx) };

            if mode != ENCRYPT && mode != DECRYPT {
                return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
            }

            // Data units must be at least one block long,
            // and (NIST SP 800-38E) at most 2**20 blocks
            if !(AES_BLOCK_SIZE..=(1 << 20) * AES_BLOCK_SIZE).contains(&length) {
                return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
            }

            let blocks = length / AES_BLOCK_SIZE;
            let leftover = length % AES_BLOCK_SIZE;

            // Compute the initial tweak
            let mut tweak = AesBlock::default();
            unsafe {
                core::ptr::copy_nonoverlapping(data_unit, tweak.as_mut_ptr(), AES_BLOCK_SIZE);
            }
            if let Err(e) = algo.encrypt(tweak_memory, &mut tweak) {
                return e.code();
            }

            let mut prev_tweak = AesBlock::default();
            let mut tmp = AesBlock::default();

            for block in (0..blocks).rev() {
                if leftover != 0 && mode == DECRYPT && block == 0 {
                    // The last full block of a decrypt operation with leftover
                    // bytes uses the *next* tweak; the current tweak is saved
                    // for the leftover bytes (ciphertext stealing)
                    prev_tweak = tweak;
                    gf128mul_x_ble(&mut tweak);
                }

                unsafe {
                    core::ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), AES_BLOCK_SIZE);
                }
                xor_in_place(&mut tmp, &tweak);

                let crypted = if mode == DECRYPT {
                    algo.decrypt(crypt_memory, &mut tmp)
                } else {
                    algo.encrypt(crypt_memory, &mut tmp)
                };
                if let Err(e) = crypted {
                    return e.code();
                }

                xor_in_place(&mut tmp, &tweak);
                unsafe {
                    core::ptr::copy_nonoverlapping(tmp.as_ptr(), output, AES_BLOCK_SIZE);
                }

                gf128mul_x_ble(&mut tweak);

                unsafe {
                    input = input.add(AES_BLOCK_SIZE);
                    output = output.add(AES_BLOCK_SIZE);
                }
            }

            if leftover != 0 {
                // Ciphertext stealing for the final partial block
                let t = if mode == DECRYPT { &prev_tweak } else { &tweak };
                let prev_output = unsafe { output.sub(AES_BLOCK_SIZE) };

                // Publish the ciphertext bytes of the previous block that are
                // not stolen, reading the input bytes first (mirrors the
                // upstream operation order, incl. for in-place operation)
                for i in 0..leftover {
                    tmp[i] = unsafe { input.add(i).read() } ^ t[i];
                    unsafe {
                        output.add(i).write(prev_output.add(i).read());
                    }
                }

                // Steal the remaining ciphertext bytes of the previous block
                for i in leftover..AES_BLOCK_SIZE {
                    tmp[i] = unsafe { prev_output.add(i).read() } ^ t[i];
                }

                let crypted = if mode == DECRYPT {
                    algo.decrypt(crypt_memory, &mut tmp)
                } else {
                    algo.encrypt(crypt_memory, &mut tmp)
                };
                if let Err(e) = crypted {
                    return e.code();
                }

                xor_in_place(&mut tmp, t);
                unsafe {
                    core::ptr::copy_nonoverlapping(tmp.as_ptr(), prev_output, AES_BLOCK_SIZE);
                }
            }

            0
        }
    }
}
