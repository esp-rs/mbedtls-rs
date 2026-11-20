//! SHA-1 digest algorithm hook for mbedtls

use core::ops::Deref;

use super::MbedtlsDigest;

/// Trait representing a custom (hooked) MbedTLS SHA-1 algorithm
pub trait MbedtlsSha1: MbedtlsDigest {}

impl<T: Deref> MbedtlsSha1 for T where T::Target: MbedtlsSha1 {}

/// Hook the SHA-1 algorithm
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use SHA-1, and ensure that the
///   `sha1` implementation is valid for the duration of its use.
#[cfg(mbedtls_hook = "sha1")]
pub unsafe fn hook_sha1(sha1: Option<&'static (dyn MbedtlsSha1 + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if sha1.is_some() {
            debug!("SHA-1 hook: added custom/HW accelerated impl");
        } else {
            debug!("SHA-1 hook: removed");
        }

        alt::SHA1.borrow(cs).set(sha1);
    });
}

#[cfg(mbedtls_hook = "sha1")]
pub use alt::SoftSha1;

#[cfg(mbedtls_hook = "sha1")]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar};

    use critical_section::Mutex;

    use crate::hook::digest::{
        digest_clone, digest_finish, digest_free, digest_init, digest_starts, digest_update,
        soft_digest, MbedtlsDigest,
    };
    use crate::hook::{RawWorkArea, WorkAreaMemory};
    use crate::{
        mbedtls_sha1_context, mbedtls_sha1_soft_clone, mbedtls_sha1_soft_context,
        mbedtls_sha1_soft_finish, mbedtls_sha1_soft_free, mbedtls_sha1_soft_init,
        mbedtls_sha1_soft_starts, mbedtls_sha1_soft_update,
    };

    use super::MbedtlsSha1;

    soft_digest! {
        /// The MbedTLS software SHA-1 implementation; the fallback when no
        /// custom implementation is hooked
        SoftSha1: mbedtls_sha1_soft_context, output_size = 20,
        init = mbedtls_sha1_soft_init,
        free = mbedtls_sha1_soft_free,
        clone = mbedtls_sha1_soft_clone,
        starts = |ctx| unsafe { mbedtls_sha1_soft_starts(ctx) },
        update = mbedtls_sha1_soft_update,
        finish = mbedtls_sha1_soft_finish,
    }

    impl MbedtlsSha1 for SoftSha1 {}

    // The work area must be able to host the fallback's state at *any* runtime
    // offset (up to 15 bytes of emplacement waste at under-aligned opaque
    // storage — see `sha256.rs` for the
    // full rationale).
    // `core::assert!`, not the crate `assert!` (whose `defmt` variant is not const-callable)
    const _: () = core::assert!(
        core::mem::size_of::<mbedtls_sha1_soft_context>() + 16
            <= crate::MBEDTLS_SHA1_ALT_WORK_AREA_SIZE as usize,
        "The MbedTLS software SHA-1 context does not fit the SHA-1 hook work area"
    );
    const _: () = core::assert!(
        core::mem::align_of::<mbedtls_sha1_soft_context>() <= 16,
        "The MbedTLS software SHA-1 context is over-aligned for the work area"
    );

    pub(crate) static SHA1: Mutex<Cell<Option<&(dyn MbedtlsSha1 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA1_SOFT: SoftSha1 = SoftSha1::new();

    #[inline(always)]
    fn algo<'a>() -> &'a dyn MbedtlsDigest {
        if let Some(sha1) = critical_section::with(|cs| SHA1.borrow(cs).get()) {
            sha1
        } else {
            &SHA1_SOFT
        }
    }

    impl RawWorkArea for mbedtls_sha1_context {
        unsafe fn work_area<'a>(ctx: *const Self) -> &'a WorkAreaMemory {
            unsafe { &*core::ptr::addr_of!((*ctx).work_area) }
        }

        unsafe fn work_area_mut<'a>(ctx: *mut Self) -> &'a mut WorkAreaMemory {
            unsafe { &mut *core::ptr::addr_of_mut!((*ctx).work_area) }
        }
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_init(ctx: *mut mbedtls_sha1_context) {
        digest_init(algo(), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_free(ctx: *mut mbedtls_sha1_context) {
        digest_free(algo(), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_clone(
        dst: *mut mbedtls_sha1_context,
        src: *const mbedtls_sha1_context,
    ) {
        digest_clone(algo(), src, dst);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_starts(ctx: *mut mbedtls_sha1_context) -> c_int {
        digest_starts(algo(), ctx)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_update(
        ctx: *mut mbedtls_sha1_context,
        input: *const c_uchar,
        ilen: usize,
    ) -> c_int {
        digest_update(algo(), ctx, input, ilen)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_finish(
        ctx: *mut mbedtls_sha1_context,
        output: *mut c_uchar,
    ) -> c_int {
        digest_finish(algo(), ctx, output)
    }
}
