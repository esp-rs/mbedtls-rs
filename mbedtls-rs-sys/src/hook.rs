//! Custom implementations for MbedTLS hooks.
//!
//! Supports replacing:
//! - Crypto algorithms (digest, exp_mod) with hardware-accelerated or custom implementations
//! - Timer functions for timeout operations
//! - Wall clock functions for certificate time validation
//!
//! # Note
//! Un-hooked crypto algorithms use RustCrypto implementations, not MbedTLS software fallbacks.

pub mod digest;
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
