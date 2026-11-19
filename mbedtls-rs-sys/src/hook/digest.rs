//! Hooking for MbedTLS Digest algorithms

use core::ffi::{c_int, c_uchar};
use core::ops::Deref;

use crate::hook::WorkAreaMemory;

use super::RawWorkArea;

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

/// Defines an [`MbedtlsDigest`] implementation over one of the MbedTLS
/// software digest implementations.
///
/// The library compiles those under `mbedtls_*_soft_*` names next to the
/// hooked (`_ALT`) entry points (see `SoftFallback` in `gen/builder.rs`), and
/// they are the fallback used when no custom implementation is hooked.
///
/// The (plain-old-data) `mbedtls_*_soft_context` is emplaced in the work area
/// and driven through the `*_soft` functions. Those only fail on invalid
/// arguments, which the hook entry points never pass, so their results are
/// not checked.
///
/// `starts` is a `fn(*mut ctx) -> c_int` (typically a closure) so that the
/// SHA-224/384 variants can bind the variant flag of the shared `*_starts`.
#[cfg(any(
    mbedtls_hook = "sha1",
    mbedtls_hook = "sha256",
    mbedtls_hook = "sha512",
))]
macro_rules! soft_digest {
    (
        $(#[$meta:meta])*
        $name:ident: $ctx:ty, output_size = $output_size:expr,
        init = $init:path, free = $free:path, clone = $clone:path,
        starts = $starts:expr, update = $update:path, finish = $finish:path $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name(());

        impl $name {
            /// Create a new instance
            pub const fn new() -> Self {
                Self(())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::hook::digest::MbedtlsDigest for $name {
            fn output_size(&self, _memory: &$crate::hook::WorkAreaMemory) -> usize {
                $output_size
            }

            fn init(&self, memory: &mut $crate::hook::WorkAreaMemory) {
                use $crate::hook::WorkArea;

                // `*_init` zeroes the context, i.e. fully initializes it
                let ctx = unsafe { memory.cast_mut_maybe::<$ctx>() }.as_mut_ptr();
                unsafe { $init(ctx) };
            }

            fn free(&self, memory: &mut $crate::hook::WorkAreaMemory) {
                use $crate::hook::WorkArea;

                let ctx: *mut $ctx = unsafe { memory.cast_mut::<$ctx>() };
                unsafe { $free(ctx) };

                memory.fill(0);
            }

            fn reset(&self, memory: &mut $crate::hook::WorkAreaMemory) {
                use $crate::hook::WorkArea;

                let starts: fn(*mut $ctx) -> ::core::ffi::c_int = $starts;

                let ctx: *mut $ctx = unsafe { memory.cast_mut::<$ctx>() };
                starts(ctx);
            }

            fn update(&self, memory: &mut $crate::hook::WorkAreaMemory, data: &[u8]) {
                use $crate::hook::WorkArea;

                let ctx: *mut $ctx = unsafe { memory.cast_mut::<$ctx>() };
                unsafe { $update(ctx, data.as_ptr(), data.len()) };
            }

            fn finish(&self, memory: &mut $crate::hook::WorkAreaMemory, output: &mut [u8]) {
                use $crate::hook::WorkArea;

                assert!(output.len() >= $output_size);

                let ctx: *mut $ctx = unsafe { memory.cast_mut::<$ctx>() };
                unsafe { $finish(ctx, output.as_mut_ptr()) };
            }

            fn clone(
                &self,
                src_work_area: &$crate::hook::WorkAreaMemory,
                dst_work_area: &mut $crate::hook::WorkAreaMemory,
            ) {
                use $crate::hook::WorkArea;

                let src: *const $ctx = unsafe { src_work_area.cast::<$ctx>() };
                let dst: *mut $ctx = unsafe { dst_work_area.cast_mut::<$ctx>() };
                unsafe { $clone(dst, src) };
            }
        }
    };
}

#[cfg(any(
    mbedtls_hook = "sha1",
    mbedtls_hook = "sha256",
    mbedtls_hook = "sha512",
))]
pub(crate) use soft_digest;

#[allow(unused)]
#[inline(always)]
unsafe fn digest_init<T: RawWorkArea>(algo: &dyn MbedtlsDigest, memory: *mut T) {
    algo.init(unsafe { T::work_area_mut(memory) });
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_free<T: RawWorkArea>(algo: &dyn MbedtlsDigest, memory: *mut T) {
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
    if memory.is_null() {
        return;
    }
    algo.free(unsafe { T::work_area_mut(memory) });
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_clone<T: RawWorkArea>(
    algo: &dyn MbedtlsDigest,
    src_work_area: *const T,
    dst_work_area: *mut T,
) {
    algo.clone(unsafe { T::work_area(src_work_area) }, unsafe {
        T::work_area_mut(dst_work_area)
    });
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_starts<T: RawWorkArea>(algo: &dyn MbedtlsDigest, memory: *mut T) -> c_int {
    algo.reset(unsafe { T::work_area_mut(memory) });

    0
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_update<T: RawWorkArea>(
    algo: &dyn MbedtlsDigest,
    memory: *mut T,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    if ilen > 0 {
        let data = unsafe { core::slice::from_raw_parts(input, ilen) };

        algo.update(unsafe { T::work_area_mut(memory) }, data);
    }

    0
}

#[allow(unused)]
#[inline(always)]
unsafe fn digest_finish<T: RawWorkArea>(
    algo: &dyn MbedtlsDigest,
    memory: *mut T,
    output: *mut c_uchar,
) -> c_int {
    let output_slice =
        unsafe { core::slice::from_raw_parts_mut(output, algo.output_size(T::work_area(memory))) };

    algo.finish(unsafe { T::work_area_mut(memory) }, output_slice);

    0
}
