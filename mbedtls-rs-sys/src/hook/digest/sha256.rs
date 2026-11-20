use core::ops::Deref;

use super::MbedtlsDigest;

/// Trait representing a custom (hooked) MbedTLS SHA-256 algorithm
pub trait MbedtlsSha256: MbedtlsDigest {}
/// Trait representing a custom (hooked) MbedTLS SHA-224 algorithm
pub trait MbedtlsSha224: MbedtlsDigest {}

impl<T: Deref> MbedtlsSha256 for T where T::Target: MbedtlsSha256 {}
impl<T: Deref> MbedtlsSha224 for T where T::Target: MbedtlsSha224 {}

/// Hook the SHA-256 implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use SHA-256 or SHA-224, and ensure that the
///   `sha256` or `sha224` implementation is valid for the duration of its use.
#[cfg(mbedtls_hook = "sha256")]
pub unsafe fn hook_sha256(sha256: Option<&'static (dyn MbedtlsSha256 + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if sha256.is_some() {
            debug!("SHA-256 hook: added custom/HW accelerated impl");
        } else {
            debug!("SHA-256 hook: removed");
        }

        alt::SHA256.borrow(cs).set(sha256);
    });
}

/// Hook the SHA224 implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use SHA-224, and ensure that the
///   `sha224` implementation is valid for the duration of its use.
#[cfg(mbedtls_hook = "sha256")]
pub unsafe fn hook_sha224(sha224: Option<&'static (dyn MbedtlsSha224 + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if sha224.is_some() {
            debug!("SHA-224 hook: added custom/HW accelerated impl");
        } else {
            debug!("SHA-224 hook: removed");
        }

        alt::SHA224.borrow(cs).set(sha224);
    });
}

#[cfg(mbedtls_hook = "sha256")]
pub use alt::{SoftSha224, SoftSha256};

#[cfg(mbedtls_hook = "sha256")]
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
        mbedtls_sha256_context, mbedtls_sha256_soft_clone, mbedtls_sha256_soft_context,
        mbedtls_sha256_soft_finish, mbedtls_sha256_soft_free, mbedtls_sha256_soft_init,
        mbedtls_sha256_soft_starts, mbedtls_sha256_soft_update,
    };

    use super::{MbedtlsSha224, MbedtlsSha256};

    soft_digest! {
        /// The MbedTLS software SHA-256 implementation; the fallback when no
        /// custom implementation is hooked
        SoftSha256: mbedtls_sha256_soft_context, output_size = 32,
        init = mbedtls_sha256_soft_init,
        free = mbedtls_sha256_soft_free,
        clone = mbedtls_sha256_soft_clone,
        starts = |ctx| unsafe { mbedtls_sha256_soft_starts(ctx, 0) },
        update = mbedtls_sha256_soft_update,
        finish = mbedtls_sha256_soft_finish,
    }

    soft_digest! {
        /// The MbedTLS software SHA-224 implementation; the fallback when no
        /// custom implementation is hooked
        SoftSha224: mbedtls_sha256_soft_context, output_size = 28,
        init = mbedtls_sha256_soft_init,
        free = mbedtls_sha256_soft_free,
        clone = mbedtls_sha256_soft_clone,
        starts = |ctx| unsafe { mbedtls_sha256_soft_starts(ctx, 1) },
        update = mbedtls_sha256_soft_update,
        finish = mbedtls_sha256_soft_finish,
    }

    impl MbedtlsSha256 for SoftSha256 {}
    impl MbedtlsSha224 for SoftSha224 {}

    // The work area must be able to host the fallback's state at *any* runtime
    // offset: opaque external storage may under-align the context (see the
    // `WorkArea` docs in `src/hook.rs`), so emplacement may lose up to
    // `align_of - 1` bytes (bounded by 16, the max alignment the `WorkArea`
    // casts support) — hence the `+ 16`. Registered hardware backends emplace
    // their own types and are covered by the runtime fit check in
    // `WorkArea::cast_mut_maybe`.
    // `core::assert!`, not the crate `assert!` (whose `defmt` variant is not const-callable)
    const _: () = core::assert!(
        core::mem::size_of::<mbedtls_sha256_soft_context>() + 16
            <= crate::MBEDTLS_SHA256_ALT_WORK_AREA_SIZE as usize,
        "The MbedTLS software SHA-256 context does not fit the SHA-256 hook work area"
    );
    const _: () = core::assert!(
        core::mem::align_of::<mbedtls_sha256_soft_context>() <= 16,
        "The MbedTLS software SHA-256 context is over-aligned for the work area"
    );

    pub(crate) static SHA256: Mutex<Cell<Option<&(dyn MbedtlsSha256 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA256_SOFT: SoftSha256 = SoftSha256::new();

    pub(crate) static SHA224: Mutex<Cell<Option<&(dyn MbedtlsSha224 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA224_SOFT: SoftSha224 = SoftSha224::new();

    /// Read `is224` via raw field projection — `ctx` may be under-aligned
    /// (see `RawWorkArea`), so no reference to the struct may be formed; the
    /// `u8` field itself is loadable at any address.
    #[inline(always)]
    fn is224(ctx: *const mbedtls_sha256_context) -> u8 {
        unsafe { core::ptr::addr_of!((*ctx).is224).read() }
    }

    #[inline(always)]
    fn set_is224(ctx: *mut mbedtls_sha256_context, value: u8) {
        unsafe { core::ptr::addr_of_mut!((*ctx).is224).write(value) }
    }

    #[inline(always)]
    fn algo<'a>(ctx: *const mbedtls_sha256_context) -> &'a dyn MbedtlsDigest {
        if is224(ctx) != 0 {
            if let Some(sha) = critical_section::with(|cs| SHA224.borrow(cs).get()) {
                sha
            } else {
                &SHA224_SOFT
            }
        } else if let Some(sha) = critical_section::with(|cs| SHA256.borrow(cs).get()) {
            sha
        } else {
            &SHA256_SOFT
        }
    }

    impl RawWorkArea for mbedtls_sha256_context {
        unsafe fn work_area<'a>(ctx: *const Self) -> &'a WorkAreaMemory {
            unsafe { &*core::ptr::addr_of!((*ctx).work_area) }
        }

        unsafe fn work_area_mut<'a>(ctx: *mut Self) -> &'a mut WorkAreaMemory {
            unsafe { &mut *core::ptr::addr_of_mut!((*ctx).work_area) }
        }
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_init(ctx: *mut mbedtls_sha256_context) {
        set_is224(ctx, 0);

        digest_init(algo(ctx), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_free(ctx: *mut mbedtls_sha256_context) {
        // MbedTLS contract: `mbedtls_sha256_free(NULL)` is documented as valid
        // (see `digest_free` in `mbedtls-rs-sys/src/hook/digest.rs` for the
        // full call-path rationale). Null-check before `algo(ctx)` because that
        // helper dereferences `ctx` to read `is224`.
        if ctx.is_null() {
            return;
        }
        digest_free(algo(ctx), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_clone(
        dst: *mut mbedtls_sha256_context,
        src: *const mbedtls_sha256_context,
    ) {
        if is224(src) != is224(dst) {
            digest_free(algo(dst), dst);

            set_is224(dst, is224(src));
            digest_init(algo(dst), dst);
        }

        digest_clone(algo(src), src, dst);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_starts(
        ctx: *mut mbedtls_sha256_context,
        is224: c_int,
    ) -> c_int {
        if is224 != self::is224(ctx) as _ {
            digest_free(algo(ctx), ctx);

            set_is224(ctx, is224 as _);
            digest_init(algo(ctx), ctx);
        }

        digest_starts(algo(ctx), ctx)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_update(
        ctx: *mut mbedtls_sha256_context,
        input: *const c_uchar,
        ilen: usize,
    ) -> c_int {
        digest_update(algo(ctx), ctx, input, ilen)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_finish(
        ctx: *mut mbedtls_sha256_context,
        output: *mut c_uchar,
    ) -> c_int {
        digest_finish(algo(ctx), ctx, output)
    }
}
