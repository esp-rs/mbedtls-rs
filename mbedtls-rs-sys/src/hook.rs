//! This module allows for replacing (hooking) some crypto algorithms and timer/clock
//! functionality in MbedTLS with custom implementations.
//!
//! This enables providing hardware-accelerated crypto or platform-specific time sources
//! on platforms that support it.
//!
//! Crypto algorithms that remain "un-hooked" by the user fall back to the software
//! implementations of MbedTLS itself. For the `_ALT` hooks (the digests, AES, ECDSA and
//! ECDH), MbedTLS would normally compile its own implementation out; the crate keeps it by
//! compiling those modules a second time under `mbedtls_*_soft_*` symbol names (see
//! `SoftFallback` in `gen/builder.rs`) and forwarding to them.

pub mod aes;
pub mod backend;
pub mod digest;
pub mod ecdh;
pub mod ecdsa;
pub mod ecp;
pub mod exp_mod;
#[cfg(feature = "hook-timer")]
pub mod timer;
#[cfg(feature = "hook-wall-clock")]
pub mod wall_clock;

/// The work area memory type used by MbedTLS algorithms' hooks
pub type WorkAreaMemory = [u8];

/// Trait representing a work area used by MbedTLS algorithms' hooks.
///
/// The work area is just a sequence of bytes, which is fixed size and pre-allocated (so to say)
/// by MbedTLS, and hopefully big enough for all types of hooks to be able to emplace their
/// state within it.
///
/// For emplacing the state, this trait provides some helper methods to cast the work area
/// to/from the desired types by following Rust emplacement rules (i.e. proper memory alignment
/// of the emplaced type).
///
/// Typically, mult-stage algorithms (e.g., digests) will use this work area to store their
/// intermediate state between calls (as in, between init/reset/update/finish).
///
/// # Context alignment: why `aligned(16)` on the C struct AND runtime alignment here
///
/// The emplaced state's offset within the work area is computed *at runtime* from the work
/// area's address (see [`WorkArea::cast_mut_maybe`]). Two storage worlds have to coexist:
///
/// - **Compiler-managed storage relocates contexts.** A context that lives in a Rust local,
///   a `Box`, or as a field of a moved struct (e.g. `mbedtls_entropy_context` embeds a SHA
///   context) is relocated by plain bitwise copies that no hook observes — **Rust move
///   semantics** most of all, and C struct assignment. Such a copy is only safe if the new
///   location has the same alignment (mod 16) as the old one, so that the stored state sits
///   at the same offset. This is what the `aligned(16)` attribute on the C structs (see
///   `gen/hook/*_alt.h`) guarantees: every compiler-chosen location is uniformly 16-aligned,
///   the runtime offset is always the same (zero), and bitwise relocation is safe.
///
/// - **Opaque external storage under-aligns contexts — but never moves them.** OpenThread
///   casts its contexts out of `OT_DEFINE_ALIGNED_VAR(..., uint64_t)` byte arrays (8-aligned),
///   and some heaps return 4-aligned memory. There the runtime offset is nonzero but *stable*
///   (heap allocations and OT's in-place storage do not relocate), so runtime alignment makes
///   them work — provided the hooks never create a `&`/`&mut` to the whole context struct,
///   which would assert the declared 16-byte alignment and be instant UB. Hook entry points
///   therefore use raw field projection only — see [`RawWorkArea`]. The `*_WORK_AREA_SIZE`
///   values include slack for the worst-case emplacement offset (see `Hook::work_area_size`
///   in `gen/builder.rs`).
///
/// Duplication through the module clone APIs (`mbedtls_shaX_clone`) is implemented as a
/// *typed* clone (read at the source's offset, re-emplace at the destination's), so it is
/// correct even between differently-aligned locations.
pub trait WorkArea {
    /// Get a reference to the work area memory as a slice
    fn memory(&self) -> &WorkAreaMemory;

    /// Get a mutable reference to the work area memory as a slice
    fn memory_mut(&mut self) -> &mut WorkAreaMemory;

    /// Cast the work area memory to a mutable `MaybeUninit<T>` reference of the specified type `T`.
    ///
    /// IMPORTANT: This cast would only work for types `T` that have alignment requirement <= 16 bytes!
    ///
    /// # Safety
    /// - The caller MUST ensure that the type `T` needs an alignment <= 16 bytes
    /// - The caller MUST ensure that the memory does NOT contain data which is currently
    ///   initialized as type `T` or another initialized type.
    ///   Violating this rule results in undefined behavior in that the drop implementation of
    ///   the currently initialized type (if any) will not be called when the work area is
    ///   reused.
    unsafe fn cast_mut_maybe<T>(&mut self) -> &mut core::mem::MaybeUninit<T> {
        let (_start, array, _) = unsafe {
            self.memory_mut()
                .align_to_mut::<core::mem::MaybeUninit<T>>()
        };

        // Unfortunately this assert cannot be enabled for the following reason:
        //
        // It might be, that the work area is allocated on-heap - via `mbedtls_calloc`/`calloc`
        // Now, there are implementations of `malloc`/`calloc` that return memory aligned
        // to 4 bytes only. (E.g. `esp-alloc`'s "malloc-on-top-of-Rust-heap" implementation)
        //
        // In such cases, if the target type `T` has alignment requirement of 8 or 16 bytes,
        // the `start` slice will not be empty, and the assert will fail.
        //
        // The one good thing is that heap-allocated structs **don't** move. So whatever
        // the start slice is, it will remain the same for the lifetime of the work area.
        //
        // assert!(
        //     _start.is_empty(),
        //     "Cannot align target type {} in the work area. The type likely requires alignment > 16, which is not supported.",
        //     core::any::type_name::<T>()
        // );

        if array.is_empty() {
            panic!(
                "work area cannot fit target type {}",
                core::any::type_name::<T>()
            );
        }

        &mut array[0]
    }

    /// Cast the work area to a reference of the specified type `T`
    ///
    /// # Safety
    /// - The caller MUST ensure that the type `T` needs an alignment <= 16 bytes
    /// - The caller MUST ensure that the work area contains data which is properly
    ///   initialized as type `T`.
    unsafe fn cast<T>(&self) -> &T {
        let (_start, array, _) = unsafe { self.memory().align_to::<T>() };

        // See above why this assert is commented out.
        // assert!(
        //     _start.is_empty(),
        //     "Cannot align target type {} in the work area. The type likely requires alignment > 16, which is not supported.",
        //     core::any::type_name::<T>()
        // );

        if array.is_empty() {
            panic!(
                "work area cannot fit target type {}",
                core::any::type_name::<T>()
            );
        }

        &array[0]
    }

    /// Cast the work area to a mutable reference of the specified type `T`
    ///
    /// # Safety
    /// - The caller MUST ensure that the type `T` needs an alignment <= 16 bytes
    /// - The caller MUST ensure that the work area contains data which is properly
    ///   initialized as type `T`.
    unsafe fn cast_mut<T>(&mut self) -> &mut T {
        let t = self.cast_mut_maybe();

        unsafe { t.assume_init_mut() }
    }
}

impl WorkArea for WorkAreaMemory {
    fn memory(&self) -> &WorkAreaMemory {
        self
    }

    fn memory_mut(&mut self) -> &mut WorkAreaMemory {
        self
    }
}

/// Raw, alignment-agnostic access to a hook context's `work_area` bytes,
/// implemented by the C context structs (`mbedtls_sha256_context`, ...).
///
/// Hook entry points receive `*mut ctx` pointers whose declared 16-byte
/// alignment may be violated by opaque external storage (see the [`WorkArea`]
/// docs), so they must never do `&mut *ctx` — a reference to the whole struct
/// asserts the declared alignment. These accessors use raw field projection
/// (`&raw mut (*ctx).work_area`, legal at any address) and hand out slices of
/// the byte array, which has alignment 1 and is therefore referenceable
/// anywhere.
pub trait RawWorkArea {
    /// Borrow the context's work-area bytes.
    ///
    /// # Safety
    /// `ctx` must be non-null and valid for reads of `Self`, and the borrow
    /// must not outlive the context or overlap a mutable one.
    unsafe fn work_area<'a>(ctx: *const Self) -> &'a WorkAreaMemory;

    /// Mutably borrow the context's work-area bytes.
    ///
    /// # Safety
    /// `ctx` must be non-null and valid for reads and writes of `Self`, and
    /// the borrow must not overlap any other borrow of the context.
    unsafe fn work_area_mut<'a>(ctx: *mut Self) -> &'a mut WorkAreaMemory;
}
