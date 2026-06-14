//! Standalone aliasing model for the async split-session provenance fix.
//!
//! The real `MBio`/`SessionRead`/`SessionWrite` internals are private, and
//! constructing a real `Session` needs the MbedTLS C library and a live
//! handshake, so they can't run under miri here. Instead this test re-creates
//! the exact pointer pattern the fix relies on - a context owned behind a
//! `NonNull` derived from a unique borrow (mirroring `MBox::as_mut_ptr`), shared
//! by two halves, with fake "FFI" functions that actually WRITE through the
//! `*mut` - so `cargo +nightly miri test` can prove the Rust-side provenance is
//! sound.
//!
//! What it validates: writing through a `*mut` whose provenance is a unique
//! `&mut` (not a shared `&`) is Stacked/Tree-Borrows clean, including when two
//! halves hold copies of the same pointer (the write-through-shared-ref bug
//! this fix removes would fail here).

use core::ptr::NonNull;

// --- A stand-in for `mbedtls_ssl_context`: a struct C would mutate.
struct FakeCtx {
    counter: u64,
    last_op: u8,
}

// --- Fake "FFI": these mutate THROUGH the raw pointer, exactly like MbedTLS C
// writes through the pointer the real code hands it. A no-op stub would not
// exercise the write, so these deliberately write.
unsafe fn fake_ssl_handshake(ctx: *mut FakeCtx) -> i32 {
    (*ctx).counter += 1;
    (*ctx).last_op = 1;
    0
}
unsafe fn fake_ssl_read(ctx: *mut FakeCtx) -> i32 {
    (*ctx).counter += 1;
    (*ctx).last_op = 2;
    0
}
unsafe fn fake_ssl_write(ctx: *mut FakeCtx) -> i32 {
    (*ctx).counter += 1;
    (*ctx).last_op = 3;
    0
}

// --- Owner that hands out a write-provenance pointer from a unique borrow,
// mirroring `MBox::as_mut_ptr(&mut self) -> *mut T`.
struct Owner {
    ctx: FakeCtx,
}
impl Owner {
    fn as_mut_ptr(&mut self) -> *mut FakeCtx {
        &mut self.ctx as *mut FakeCtx
    }
}

// --- The two halves, each holding a COPY of the same NonNull (as `split` does).
struct ReadHalf {
    ctx: NonNull<FakeCtx>,
}
struct WriteHalf {
    ctx: NonNull<FakeCtx>,
}

impl ReadHalf {
    fn read(&mut self) -> i32 {
        unsafe { fake_ssl_read(self.ctx.as_ptr()) }
    }
}
impl WriteHalf {
    fn write(&mut self) -> i32 {
        unsafe { fake_ssl_write(self.ctx.as_ptr()) }
    }
}

#[test]
fn write_through_unique_provenance_pointer_is_sound() {
    let mut owner = Owner {
        ctx: FakeCtx {
            counter: 0,
            last_op: 0,
        },
    };

    // Derive ONE pointer from a unique borrow and share it with both halves,
    // exactly as `split` does. Under Stacked/Tree Borrows this is only sound
    // because the pointer carries write provenance from `&mut`, not from `&`.
    let ctx = unsafe { NonNull::new_unchecked(owner.as_mut_ptr()) };
    let mut read = ReadHalf { ctx };
    let mut write = WriteHalf { ctx };

    // Handshake, then a read and a write, each mutating through the pointer.
    unsafe { fake_ssl_handshake(ctx.as_ptr()) };
    assert_eq!(read.read(), 0);
    assert_eq!(write.write(), 0);

    // The fake FFI wrote through the pointer each time (handshake + read + write).
    assert_eq!(owner.ctx.counter, 3);
    assert_eq!(owner.ctx.last_op, 3);
}
