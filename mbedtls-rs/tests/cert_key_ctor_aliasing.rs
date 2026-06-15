//! Standalone aliasing model for the F-32 cert/key constructor provenance fix.
//!
//! The real `MRc`/`Certificate`/`PrivateKey` constructors call MbedTLS C and
//! cannot run under Miri, so (mirroring `async_split_aliasing.rs`) this test
//! re-creates the exact pointer pattern the fix relies on: an `MRc`-shaped
//! `NonNull<(T, usize)>` allocation whose inner `T` is mutated through a `*mut`
//! projected from the allocation pointer via `addr_of_mut!`, by a fake "FFI"
//! function that actually WRITES (a no-op stub would not exercise the access).
//!
//! What it validates under Tree Borrows:
//! - Writing through a `*mut T` whose provenance is the unique allocation
//!   pointer (not a shared `&`) is sound - this is what `MRc::as_mut_ptr` now
//!   does. The old `&*mrc as *const _ as *mut _` shared-deref write that the fix
//!   removes would fail here ("Frozen forbids child write").
//! - The field projection targets `.0` (the inner value) and leaves `.1` (the
//!   refcount) untouched, which is the `MRc`-tuple-specific property that makes
//!   `addr_of_mut!((*ptr).0)` correct where `ptr.cast::<T>()` would be a
//!   layout-assumption bug.

use core::ptr::NonNull;

// A stand-in for the hooked MbedTLS context (e.g. `mbedtls_x509_crt`): a struct
// that C parses INTO, i.e. writes through the pointer we hand it.
struct FakeCtx {
    parsed: u32,
    tag: u8,
}

// Fake "FFI": mutates THROUGH the raw pointer, exactly like
// `mbedtls_x509_crt_parse`/`mbedtls_pk_parse_key` write into the context.
unsafe fn fake_parse(ctx: *mut FakeCtx) -> i32 {
    (*ctx).parsed = 0xC0FFEE;
    (*ctx).tag = 7;
    0
}

// An `MRc`-shaped owner: a `NonNull<(T, refcount)>` where the inner value is
// field `.0` and the refcount is `.1`, mirroring `MRc<T>(NonNull<(T, usize)>)`.
struct FakeMRc {
    ptr: NonNull<(FakeCtx, usize)>,
}

impl FakeMRc {
    fn new() -> Self {
        // Heap-allocate the tuple, init the inner value, set refcount = 1 -
        // mirroring `MRc::new`'s `mbedtls_calloc` + `init` + `.1 = 1`.
        let boxed = Box::new((FakeCtx { parsed: 0, tag: 0 }, 1usize));
        let ptr = NonNull::new(Box::into_raw(boxed)).unwrap();
        Self { ptr }
    }

    // Mirror of `MRc::as_mut_ptr`: project `.0` from the allocation pointer with
    // `addr_of_mut!`, never forming an intermediate reference, never casting.
    fn as_mut_ptr(&mut self) -> *mut FakeCtx {
        unsafe { core::ptr::addr_of_mut!((*self.ptr.as_ptr()).0) }
    }

    fn refcount(&self) -> usize {
        unsafe { (*self.ptr.as_ptr()).1 }
    }

    fn parsed(&self) -> u32 {
        unsafe { (*self.ptr.as_ptr()).0.parsed }
    }
}

impl Drop for FakeMRc {
    fn drop(&mut self) {
        drop(unsafe { Box::from_raw(self.ptr.as_ptr()) });
    }
}

#[test]
fn write_through_unique_provenance_pointer_is_sound() {
    let mut mrc = FakeMRc::new();
    assert_eq!(mrc.refcount(), 1);

    // Hand the projected `*mut` to the fake FFI, which writes through it -
    // exactly the construction-time pattern in `Certificate::new` etc.
    let rc = unsafe { fake_parse(mrc.as_mut_ptr()) };
    assert_eq!(rc, 0);

    // The write landed in the inner value (`.0`)...
    assert_eq!(mrc.parsed(), 0xC0FFEE);
    // ...and the refcount (`.1`) is untouched by the `.0` projection - proving
    // the field projection does not disturb the tuple's second field.
    assert_eq!(mrc.refcount(), 1);
}
