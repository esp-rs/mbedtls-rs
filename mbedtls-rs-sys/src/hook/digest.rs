//! Hooking for MbedTLS Digest algorithms

use core::ffi::{c_int, c_uchar};
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::drop_in_place;

use digest::Digest;

use crate::hook::WorkAreaMemory;

use super::WorkArea;

pub use sha1::*;
pub use sha256::*;
pub use sha512::*;

pub mod sha1;
pub mod sha256;
pub mod sha512;

/// Trait representing a custom (hooked) MbedTLS Digest algorithm
pub trait MbedtlsDigest {
    /// Get the output size of the digest algorithm
    ///
    /// # Arguments
    /// - `memory` - The work area used by the digest algorithm
    ///
    /// # Returns
    /// - The output size in bytes
    fn output_size(&self, memory: &WorkAreaMemory) -> usize;

    /// Initialize the digest algorithm
    ///
    /// # Arguments
    /// - `memory` - The work area used by the digest algorithm
    fn init(&self, memory: &mut WorkAreaMemory);

    /// Free the digest algorithm (i.e. execute drop-in-place)
    ///
    /// # Arguments
    /// - `memory` - The work area used by the digest algorithm
    fn free(&self, memory: &mut WorkAreaMemory);

    /// Reset the digest algorithm
    ///
    /// # Arguments
    /// - `memory` - The work area used by the digest algorithm
    fn reset(&self, memory: &mut WorkAreaMemory);

    /// Update the digest algorithm with data
    ///
    /// # Arguments
    /// - `memory` - The work area used by the digest algorithm
    /// - `data` - The data to update the digest with
    fn update(&self, memory: &mut WorkAreaMemory, data: &[u8]);

    /// Finish the digest algorithm and produce the output
    ///
    /// # Arguments
    /// - `memory` - The work area used by the digest algorithm
    /// - `output` - The output buffer to write the digest to
    fn finish(&self, memory: &mut WorkAreaMemory, output: &mut [u8]);

    /// Clone the digest state from one work area to another
    ///
    /// # Arguments
    /// - `src_work_area` - The source work area to clone from
    /// - `dst_workarea` - The destination work area to clone to
    fn clone(&self, src_work_area: &WorkAreaMemory, dst_workarea: &mut WorkAreaMemory);
}

impl<T: Deref> MbedtlsDigest for T
where
    T::Target: MbedtlsDigest,
{
    fn output_size(&self, memory: &WorkAreaMemory) -> usize {
        self.deref().output_size(memory)
    }

    fn init(&self, memory: &mut WorkAreaMemory) {
        self.deref().init(memory);
    }

    fn free(&self, memory: &mut WorkAreaMemory) {
        self.deref().free(memory);
    }

    fn reset(&self, memory: &mut WorkAreaMemory) {
        self.deref().reset(memory);
    }

    fn update(&self, memory: &mut WorkAreaMemory, data: &[u8]) {
        self.deref().update(memory, data);
    }

    fn finish(&self, memory: &mut WorkAreaMemory, output: &mut [u8]) {
        self.deref().finish(memory, output);
    }

    fn clone(&self, src_work_area: &WorkAreaMemory, dst_workarea: &mut WorkAreaMemory) {
        self.deref().clone(src_work_area, dst_workarea);
    }
}

/// MbedTLS Digest algorithm implementation that delegates
/// to implementations based on the RustCrypto `Digest` trait
pub struct RustCryptoDigest<T>(PhantomData<fn() -> T>);

impl<T> RustCryptoDigest<T> {
    /// Create a new `RustCryptoDigest` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Default for RustCryptoDigest<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MbedtlsDigest for RustCryptoDigest<T>
where
    T: Digest + Clone,
{
    fn output_size(&self, _work_area: &WorkAreaMemory) -> usize {
        <T as Digest>::output_size()
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
        Digest::update(
            unsafe { memory.cast_mut::<Option<T>>() }.as_mut().unwrap(),
            data,
        );
    }

    fn finish(&self, memory: &mut WorkAreaMemory, output: &mut [u8]) {
        output.copy_from_slice(
            &unsafe { memory.cast_mut::<Option<T>>() }
                .take()
                .unwrap()
                .finalize(),
        );
    }

    fn clone(&self, src_work_area: &WorkAreaMemory, dst_work_area: &mut WorkAreaMemory) {
        *unsafe { dst_work_area.cast_mut() } = unsafe { src_work_area.cast::<Option<T>>() }.clone();
    }
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_init<T: WorkArea>(algo: &dyn MbedtlsDigest, memory: *mut T) {
    algo.init(memory.as_mut().unwrap().memory_mut());
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_free<T: WorkArea>(algo: &dyn MbedtlsDigest, memory: *mut T) {
    // MbedTLS upstream contract: `mbedtls_*_free(NULL)` is explicitly documented
    // as valid (sha1.h:76-82, sha256.h, sha512.h: "ctx ... may be NULL, in which
    // case this function returns immediately"). No current caller in MbedTLS 3.x
    // actually passes NULL: `mbedtls_md_free` (md.c:282) NULL-checks `ctx->md_ctx`
    // before dispatch, PSA hash code passes `&operation->ctx` (struct field), and
    // the SHA self-tests pass `&ctx` (stack variable). The contract is forward-
    // compatible / defensive: when our `MBEDTLS_SHA*_ALT` hook replaces the
    // upstream implementation, any future caller that elects to pass NULL through
    // would land here, and panicking across the FFI boundary is strictly worse
    // than the documented no-op.
    let Some(memory) = memory.as_mut() else {
        return;
    };
    algo.free(memory.memory_mut());
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_clone<T: WorkArea>(
    algo: &dyn MbedtlsDigest,
    src_work_area: *const T,
    dst_work_area: *mut T,
) {
    algo.clone(
        src_work_area.as_ref().unwrap().memory(),
        dst_work_area.as_mut().unwrap().memory_mut(),
    );
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_starts<T: WorkArea>(algo: &dyn MbedtlsDigest, memory: *mut T) -> c_int {
    algo.reset(memory.as_mut().unwrap().memory_mut());

    0
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_update<T: WorkArea>(
    algo: &dyn MbedtlsDigest,
    memory: *mut T,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    if ilen > 0 {
        let data = unsafe { core::slice::from_raw_parts(input, ilen) };

        algo.update(memory.as_mut().unwrap().memory_mut(), data);
    }

    0
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_finish<T: WorkArea>(
    algo: &dyn MbedtlsDigest,
    memory: *mut T,
    output: *mut c_uchar,
) -> c_int {
    let output_slice = unsafe {
        core::slice::from_raw_parts_mut(output, algo.output_size(memory.as_ref().unwrap().memory()))
    };

    algo.finish(memory.as_mut().unwrap().memory_mut(), output_slice);

    0
}
