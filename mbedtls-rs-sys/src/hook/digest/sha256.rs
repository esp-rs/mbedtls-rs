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
#[cfg(not(feature = "nohook-sha256"))]
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
#[cfg(not(feature = "nohook-sha256"))]
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

#[cfg(not(feature = "nohook-sha256"))]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar};

    use critical_section::Mutex;

    use crate::hook::digest::{
        digest_clone, digest_finish, digest_free, digest_init, digest_starts, digest_update,
        MbedtlsDigest, RustCryptoDigest,
    };
    use crate::hook::{WorkArea, WorkAreaMemory};
    use crate::mbedtls_sha256_context;

    use super::{MbedtlsSha224, MbedtlsSha256};

    type RustCryptoSha256 = RustCryptoDigest<sha2::Sha256>;
    type RustCryptoSha224 = RustCryptoDigest<sha2::Sha224>;

    impl MbedtlsSha256 for RustCryptoSha256 {}
    impl MbedtlsSha224 for RustCryptoSha224 {}

    pub(crate) static SHA256: Mutex<Cell<Option<&(dyn MbedtlsSha256 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA256_RUST_CRYPTO: RustCryptoSha256 = RustCryptoSha256::new();

    pub(crate) static SHA224: Mutex<Cell<Option<&(dyn MbedtlsSha224 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA224_RUST_CRYPTO: RustCryptoSha224 = RustCryptoSha224::new();

    #[inline(always)]
    fn algo<'a>(ctx: *const mbedtls_sha256_context) -> &'a dyn MbedtlsDigest {
        if unsafe { (*ctx).is224 } != 0 {
            if let Some(sha) = critical_section::with(|cs| SHA224.borrow(cs).get()) {
                sha
            } else {
                &SHA224_RUST_CRYPTO
            }
        } else if let Some(sha) = critical_section::with(|cs| SHA256.borrow(cs).get()) {
            sha
        } else {
            &SHA256_RUST_CRYPTO
        }
    }

    impl WorkArea for mbedtls_sha256_context {
        fn memory(&self) -> &WorkAreaMemory {
            &self.work_area
        }

        fn memory_mut(&mut self) -> &mut WorkAreaMemory {
            &mut self.work_area
        }
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_init(ctx: *mut mbedtls_sha256_context) {
        let ctx = unsafe { &mut *ctx };
        ctx.is224 = 0;

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
        let dst = unsafe { &mut *dst };
        let src = unsafe { &*src };

        if src.is224 != dst.is224 {
            digest_free(algo(dst), dst);

            dst.is224 = src.is224;
            digest_init(algo(dst), dst);
        }

        digest_clone(algo(src), src, dst);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha256_starts(
        ctx: *mut mbedtls_sha256_context,
        is224: c_int,
    ) -> c_int {
        let ctx = unsafe { &mut *ctx };

        if is224 != ctx.is224 as _ {
            digest_free(algo(ctx), ctx);

            ctx.is224 = is224 as _;
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
