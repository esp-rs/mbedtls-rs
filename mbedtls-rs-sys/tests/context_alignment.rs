//! Regression tests for the two context-storage worlds the hooks must serve
//! (see the `WorkArea` docs in `src/hook.rs`):
//!
//! - **Relocation** (compiler-managed storage): a context is a plain value
//!   that Rust may move — an untracked bitwise copy. The `aligned(16)` on the
//!   C structs makes every compiler-chosen location uniformly aligned, so the
//!   runtime-emplaced hook state keeps its offset across moves. If that
//!   attribute is ever dropped, `moved_context_keeps_state` fails (or worse,
//!   silently corrupts).
//!
//! - **Under-aligned opaque storage** (OpenThread-style): contexts cast out
//!   of 8-aligned byte buffers. The hook entry points must not form
//!   references to the whole struct (that would assert the declared 16-byte
//!   alignment); they use raw field projection and align the state at
//!   runtime. If an entry point regresses to `&mut *ctx`, the under-aligned
//!   tests abort with a misaligned-reference panic in debug builds.

use core::mem::MaybeUninit;

use mbedtls_rs_sys::{
    mbedtls_aes_context, mbedtls_aes_crypt_ecb, mbedtls_aes_free, mbedtls_aes_init,
    mbedtls_aes_setkey_enc, mbedtls_sha256_clone, mbedtls_sha256_context, mbedtls_sha256_finish,
    mbedtls_sha256_free, mbedtls_sha256_init, mbedtls_sha256_starts, mbedtls_sha256_update,
    MBEDTLS_AES_ENCRYPT,
};

#[path = "support/psa_random.rs"]
mod psa_random;

/// SHA-256("abc"), FIPS 180-2 test vector.
const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

/// An over-aligned slab from which deliberately under-aligned (8 mod 16)
/// context locations are carved, mimicking OpenThread's
/// `OT_DEFINE_ALIGNED_VAR(..., uint64_t)` opaque context storage.
#[repr(C, align(16))]
struct Slab([u8; 4096]);

impl Slab {
    fn new() -> Self {
        Self([0; 4096])
    }

    /// A pointer into the slab that is 8-aligned but NOT 16-aligned.
    fn under_aligned_ptr<T>(&mut self) -> *mut T {
        assert!(size_of::<T>() + 8 <= size_of_val(&self.0));

        let p = unsafe { self.0.as_mut_ptr().add(8) };
        assert_eq!(p as usize % 16, 8);

        p.cast()
    }
}

/// A context relocated mid-hash (stack → heap → a fresh stack slot) must keep
/// its state: the `aligned(16)` struct attribute guarantees every location
/// the compiler picks has the same alignment, and with it the same runtime
/// emplacement offset.
#[test]
fn moved_context_keeps_state() {
    unsafe {
        let mut ctx = MaybeUninit::<mbedtls_sha256_context>::uninit();
        mbedtls_sha256_init(ctx.as_mut_ptr());
        assert_eq!(mbedtls_sha256_starts(ctx.as_mut_ptr(), 0), 0);
        assert_eq!(
            mbedtls_sha256_update(ctx.as_mut_ptr(), b"ab".as_ptr(), 2),
            0
        );

        // Move to the heap mid-hash...
        let mut boxed = Box::new(ctx.assume_init());
        assert_eq!(mbedtls_sha256_update(&mut *boxed, b"c".as_ptr(), 1), 0);

        // ... and back out to a (different) stack slot.
        let mut back = *boxed;

        let mut out = [0u8; 32];
        assert_eq!(mbedtls_sha256_finish(&mut back, out.as_mut_ptr()), 0);
        mbedtls_sha256_free(&mut back);

        assert_eq!(out, ABC_SHA256);
    }
}

/// A context living at an 8-aligned (not 16-aligned) address — the
/// OpenThread storage pattern — must work end to end: the entry points use
/// raw field projection, and the state is aligned at runtime within the work
/// area.
#[test]
fn under_aligned_sha256_context_works() {
    let mut slab = Slab::new();
    let ctx: *mut mbedtls_sha256_context = slab.under_aligned_ptr();

    unsafe {
        mbedtls_sha256_init(ctx);
        assert_eq!(mbedtls_sha256_starts(ctx, 0), 0);
        assert_eq!(mbedtls_sha256_update(ctx, b"abc".as_ptr(), 3), 0);

        let mut out = [0u8; 32];
        assert_eq!(mbedtls_sha256_finish(ctx, out.as_mut_ptr()), 0);
        mbedtls_sha256_free(ctx);

        assert_eq!(out, ABC_SHA256);
    }
}

/// The module clone API is a *typed* clone (read at the source's offset,
/// re-emplace at the destination's), so cloning between differently-aligned
/// locations must transfer the mid-hash state faithfully.
#[test]
fn clone_across_alignments_transfers_state() {
    let mut slab = Slab::new();
    let dst: *mut mbedtls_sha256_context = slab.under_aligned_ptr();

    unsafe {
        // Properly aligned source, hashed halfway.
        let mut src = MaybeUninit::<mbedtls_sha256_context>::uninit();
        mbedtls_sha256_init(src.as_mut_ptr());
        assert_eq!(mbedtls_sha256_starts(src.as_mut_ptr(), 0), 0);
        assert_eq!(
            mbedtls_sha256_update(src.as_mut_ptr(), b"ab".as_ptr(), 2),
            0
        );

        // Clone into the under-aligned destination (initialized first, per
        // the MbedTLS clone contract).
        mbedtls_sha256_init(dst);
        mbedtls_sha256_clone(dst, src.as_ptr());

        // Finish both independently; both must produce the reference digest.
        let mut out_src = [0u8; 32];
        let mut out_dst = [0u8; 32];
        assert_eq!(mbedtls_sha256_update(src.as_mut_ptr(), b"c".as_ptr(), 1), 0);
        assert_eq!(mbedtls_sha256_update(dst, b"c".as_ptr(), 1), 0);
        assert_eq!(
            mbedtls_sha256_finish(src.as_mut_ptr(), out_src.as_mut_ptr()),
            0
        );
        assert_eq!(mbedtls_sha256_finish(dst, out_dst.as_mut_ptr()), 0);
        mbedtls_sha256_free(src.as_mut_ptr());
        mbedtls_sha256_free(dst);

        assert_eq!(out_src, ABC_SHA256);
        assert_eq!(out_dst, ABC_SHA256);
    }
}

/// Same as [`under_aligned_sha256_context_works`], for the AES hook (whose
/// work area hosts the largest states): FIPS-197 AES-128 known answer from an
/// 8-aligned context.
#[test]
fn under_aligned_aes_context_works() {
    // FIPS-197 appendix C.1.
    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const PLAIN: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const CIPHER: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    let mut slab = Slab::new();
    let ctx: *mut mbedtls_aes_context = slab.under_aligned_ptr();

    unsafe {
        mbedtls_aes_init(ctx);
        assert_eq!(mbedtls_aes_setkey_enc(ctx, KEY.as_ptr(), 128), 0);

        let mut out = [0u8; 16];
        assert_eq!(
            mbedtls_aes_crypt_ecb(
                ctx,
                MBEDTLS_AES_ENCRYPT as _,
                PLAIN.as_ptr(),
                out.as_mut_ptr()
            ),
            0
        );
        mbedtls_aes_free(ctx);

        assert_eq!(out, CIPHER);
    }
}
