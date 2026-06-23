#![no_std]
#![allow(clippy::uninlined_format_args)]

use core::cell::RefCell;
use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use critical_section::Mutex;

#[cfg(not(target_os = "espidf"))]
pub(crate) use crate::sys::{mbedtls_calloc, mbedtls_free};
use crate::sys::{
    mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_free, mbedtls_ctr_drbg_init, mbedtls_pk_context,
    mbedtls_pk_free, mbedtls_pk_init, mbedtls_ssl_conf_dbg, mbedtls_ssl_config,
    mbedtls_ssl_config_free, mbedtls_ssl_config_init, mbedtls_ssl_context, mbedtls_ssl_free,
    mbedtls_ssl_init, mbedtls_ssl_protocol_version,
    mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_2,
    mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_3, mbedtls_ssl_session,
    mbedtls_ssl_session_free, mbedtls_ssl_session_init, mbedtls_x509_crt, mbedtls_x509_crt_free,
    mbedtls_x509_crt_init,
};

use rand_core::CryptoRng;

pub use cert::*;
pub use session::*;

pub(crate) mod fmt; // MUST be the first so that the other modules can see it

mod cert;
mod session;

/// Re-export of the mbedtls-rs-sys crate so that users do not have to
/// explicitly depend on it if they want to use the raw MbedTLS bindings.
pub mod sys {
    pub use mbedtls_rs_sys::*;
}

/// An erased pointer to the user-provided RNG, stored in the global [`RNG`].
///
/// The RNG is stored as a raw `NonNull` rather than a reference: a pointer
/// makes no aliasing/validity claim, and the `&mut` is materialized only inside
/// the `mbedtls_rng` callback. [`Tls::new`] takes a `&'static mut`, so its
/// stored pointer is always valid. [`Tls::new_local_borrows`] takes a shorter
/// `&'d mut` and is `unsafe` precisely because of this slot: if that borrow ends
/// while the pointer is still installed (only reachable by leaking the `Tls`),
/// a later callback dereference would be UB. See `new_local_borrows`' safety
/// contract.
struct RngPtr(NonNull<dyn CryptoRng + Send>);

// SAFETY: the pointee is `Send` (the trait object bound), and all access is
// serialized through the `critical_section` `Mutex` below. The pointer is set
// from a live `&mut` in a `Tls` constructor and cleared in `Tls::drop`.
unsafe impl Send for RngPtr {}

static RNG: Mutex<RefCell<Option<RngPtr>>> = Mutex::new(RefCell::new(None));

/// An error returned when creating a `Tls` instance
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsError {
    AlreadyCreated,
}

/// A TLS instance
///
/// Represents an instance of the MbedTLS library.
/// Only one such instance can be active at any point in time.
pub struct Tls<'d>(PhantomData<&'d mut ()>);

impl Tls<'static> {
    /// Create a new instance of the `Tls` type from a `'static` RNG.
    ///
    /// Note that there could be only one active `Tls` instance at any point in
    /// time, and the function will return an error if there is already an active
    /// instance.
    ///
    /// This is safe because the RNG borrow is `'static`: it stays valid for the
    /// rest of the program, so even leaking the returned `Tls` (e.g. via
    /// `core::mem::forget`) cannot leave the global RNG slot dangling. For a
    /// shorter-lived borrow, see [`Tls::new_local_borrows`].
    pub fn new(rng: &'static mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        // No `unsafe`: a `&'static mut` is already valid for the program's
        // lifetime, so `NonNull::from` erases nothing the caller could invalidate.
        Self::store_rng(NonNull::from(rng))
    }
}

impl<'d> Tls<'d> {
    /// Create a new instance of the `Tls` type from a non-`'static` RNG.
    ///
    /// Note that there could be only one active `Tls` instance at any point in
    /// time, and the function will return an error if there is already an active
    /// instance.
    ///
    /// Prefer [`Tls::new`] with a `'static` RNG where possible; this variant
    /// exists for borrowed RNGs (e.g. a hardware TRNG peripheral) that cannot be
    /// `'static`.
    ///
    /// # Safety
    /// The RNG is stored behind a lifetime-erased pointer for as long as the
    /// global RNG slot is installed (until this `Tls` is dropped). The caller
    /// must ensure the returned `Tls` is dropped - NOT leaked via
    /// `core::mem::forget` / `ManuallyDrop` - before `rng`'s borrow ends, and
    /// must not combine a leaked `Tls` with direct calls into the raw
    /// `mbedtls-rs-sys` RNG/PSA bindings; otherwise a later callback may
    /// dereference a dangling pointer. Using only the safe `Session` API upholds
    /// this automatically (a `Session` keeps the `Tls` alive via `TlsReference`).
    pub unsafe fn new_local_borrows(rng: &'d mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        // SAFETY: erase only the pointee lifetime on a *pointer* (ptr -> ptr, no
        // validity claim); the caller upholds the no-leak contract documented
        // above. The transmute preserves the data pointer and vtable.
        let rng = unsafe {
            core::mem::transmute::<NonNull<dyn CryptoRng + Send + '_>, NonNull<dyn CryptoRng + Send>>(
                NonNull::from(rng),
            )
        };
        Self::store_rng(rng)
    }
}

impl<'d> Tls<'d> {
    /// Install the erased RNG pointer into the global slot, enforcing the
    /// single-active-instance invariant. Safe: storing a `NonNull` asserts
    /// nothing about the pointee; validity is the contract of whichever
    /// constructor produced the pointer.
    fn store_rng(rng: NonNull<dyn CryptoRng + Send>) -> Result<Self, TlsError> {
        critical_section::with(|cs| {
            if RNG.borrow(cs).borrow().is_some() {
                return Err(TlsError::AlreadyCreated);
            }

            *RNG.borrow(cs).borrow_mut() = Some(RngPtr(rng));

            Ok(Self(PhantomData))
        })
    }

    pub(crate) fn release(&mut self) {
        critical_section::with(|cs| {
            *RNG.borrow(cs).borrow_mut() = None;
        });
    }

    /// Set the MbedTLS debug level (0 - 5).
    ///
    /// No-op unless the `tls-debug` feature is enabled (the `tls`/`openthread`
    /// bundles enable it) so `MBEDTLS_DEBUG_C` is compiled in; also a no-op on
    /// ESP-IDF.
    #[allow(unused)]
    pub fn set_debug(&mut self, level: u32) {
        #[cfg(all(not(target_os = "espidf"), feature = "tls-debug"))]
        // SAFETY: this block is compiled only when `tls-debug` is enabled, which turns on
        // `mbedtls-rs-sys/tls-debug` (MBEDTLS_DEBUG_C) so `mbedtls_debug_set_threshold` is
        // defined and linked; the call passes one `c_int` by value (no pointers/aliasing).
        unsafe {
            use crate::sys::mbedtls_debug_set_threshold;

            mbedtls_debug_set_threshold(level as c_int);
        }
    }

    /// Get a reference to the `Tls` instance
    ///
    /// Each `Session` needs a reference to (the) active `Tls` instance
    /// throughout its lifetime.
    pub fn reference(&self) -> TlsReference<'_> {
        TlsReference(PhantomData)
    }

    /// Hook MbedTLS SSL debug logging into the Rust log system
    ///
    /// # Arguments
    /// - `ssl_config`: The MbedTLS SSL configuration to hook the debug logging into
    pub(crate) fn hook_debug_logs(ssl_config: &mut mbedtls_ssl_config) {
        /// Output the MbedTLS debug messages to the log
        #[no_mangle]
        unsafe extern "C" fn mbedtls_dbg_print(
            _arg: *mut c_void,
            lvl: i32,
            file: *const c_char,
            line: i32,
            msg: *const c_char,
        ) {
            let file = CStr::from_ptr(file);
            let msg = CStr::from_ptr(msg);

            let file = file.to_str().unwrap_or("???").trim();
            let msg = msg.to_str().unwrap_or("???").trim();

            match lvl {
                0 => warn!("(MbedTLS) {} (at {}:{})", msg, file, line),
                1 => info!("(MbedTLS) {} (at {}:{})", msg, file, line),
                2 => debug!("(MbedTLS) {} (at {}:{})", msg, file, line),
                _ => trace!("(MbedTLS) {} (at {}:{})", msg, file, line),
            }
        }

        unsafe {
            mbedtls_ssl_conf_dbg(
                &mut *ssl_config,
                Some(mbedtls_dbg_print),
                core::ptr::null_mut(),
            );
        }
    }
}

impl<'d> Drop for Tls<'d> {
    fn drop(&mut self) {
        self.release();
    }
}

/// A reference to (the) active `Tls` instance
///
/// Used instead of just `&'a Tls` so that the invariant `'d` lifetime of the `Tls` instance
/// is not exposed in the `Session` type.
#[allow(unused)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsReference<'a>(PhantomData<&'a ()>);

/// The minimum TLS version that will be supported by a particular `Session` instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsVersion {
    /// TLS 1.2
    Tls1_2,
    /// TLS 1.3
    Tls1_3,
}

impl TlsVersion {
    fn mbed_tls_version(&self) -> mbedtls_ssl_protocol_version {
        match self {
            TlsVersion::Tls1_2 => mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_2,
            TlsVersion::Tls1_3 => mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_3,
        }
    }
}

/// An internal trait to be implemented on MbedTLS structures.
///
/// The trait models the initialization and deinitialization
/// sequence available on a number of MBedTLS structures.
trait MInit {
    /// Initialize the structure
    fn init(&mut self) {}

    /// Deinitialize the structure
    fn deinit(&mut self) {}
}

impl MInit for mbedtls_ctr_drbg_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_ctr_drbg_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ctr_drbg_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_config {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_config_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_config_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_session {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_session_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_session_free(self);
        }
    }
}

impl MInit for mbedtls_x509_crt {
    fn init(&mut self) {
        unsafe {
            mbedtls_x509_crt_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_x509_crt_free(self);
        }
    }
}

impl MInit for mbedtls_pk_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_pk_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_pk_free(self);
        }
    }
}

/// A uniquely-owned box-like wrapper type for MbedTLS structures that need to be allocated/deallocated
/// using `mbedtls_calloc`/`mbedtls_free`, and initialized/deinitialized using the `MInit` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MBox<T>(NonNull<T>)
where
    T: MInit;

impl<T> MBox<T>
where
    T: MInit,
{
    /// Create a new MBox
    ///
    /// # Returns
    /// - Ok(MBox<T>) if the allocation was successful
    /// - Err(TlsError::OutOfMemory) if the allocation failed
    fn new() -> Option<Self> {
        NonNull::new(unsafe { mbedtls_calloc(1, size_of::<T>()) }.cast::<T>()).map(|mut ptr| {
            unsafe { ptr.as_mut() }.init();

            Self(ptr)
        })
    }

    /// Get a reference to the inner value
    fn as_ref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }

    /// Get a mutable reference to the inner value
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }

    /// Get the raw pointer to the inner value.
    ///
    /// The pointer is the original allocation pointer preserved in the
    /// `NonNull` (not derived from a Rust reference), so writing through it
    /// (e.g. by C code via FFI) is sound. Taking `&mut self` ensures the caller
    /// is not simultaneously holding a shared reference to the same object via
    /// `Deref`. Used by the async session path, which must hand MbedTLS a `*mut`
    /// it can write through.
    fn as_mut_ptr(&mut self) -> *mut T {
        self.0.as_ptr()
    }
}

impl<T> Deref for MBox<T>
where
    T: MInit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> DerefMut for MBox<T>
where
    T: MInit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T> Drop for MBox<T>
where
    T: MInit,
{
    fn drop(&mut self) {
        self.as_mut().deinit();

        unsafe {
            mbedtls_free(self.0.as_ptr() as *mut c_void);
        }
    }
}

/// A reference-counted `Rc`-like wrapper type for MbedTLS structures that need to be allocated/deallocated
/// using `mbedtls_calloc`/`mbedtls_free`, and initialized/deinitialized using the `MInit` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MRc<T>(NonNull<(T, usize)>)
where
    T: MInit;

impl<T> MRc<T>
where
    T: MInit,
{
    /// Create a new MRc
    fn new() -> Option<Self> {
        NonNull::new(unsafe { mbedtls_calloc(1, size_of::<(T, usize)>()) }.cast::<(T, usize)>())
            .map(|mut ptr| {
                let this = unsafe { ptr.as_mut() };

                this.0.init();
                this.1 = 1;

                Self(ptr)
            })
    }

    /// Get a reference to the inner value
    fn as_ref(&self) -> &T {
        &unsafe { self.0.as_ref() }.0
    }

    /// Get a raw pointer to the inner value, with write provenance.
    ///
    /// The pointer is projected from the original `(T, usize)` allocation
    /// pointer in the `NonNull` (not derived from a Rust reference), so writing
    /// through it (e.g. by C code via FFI) is sound. `addr_of_mut!` projects the
    /// `.0` field without ever forming an intermediate reference, and must be
    /// used rather than `self.0.as_ptr().cast::<T>()` because the field order of
    /// the `(T, usize)` tuple is not guaranteed.
    ///
    /// SAFETY: unlike `MBox`, `MRc` is `Clone`, so `&mut self` alone does not
    /// guarantee unique access to the inner `T` (a clone could be reading it).
    /// The caller must ensure no other live reference to the inner `T` exists
    /// for the duration of the write. This holds at construction, where the
    /// `MRc` is freshly allocated, has refcount 1 and has not yet been cloned -
    /// which is the only context this is used in. Writing through this pointer
    /// while a clone concurrently dereferences the value would be UB.
    fn as_mut_ptr(&mut self) -> *mut T {
        unsafe { core::ptr::addr_of_mut!((*self.0.as_ptr()).0) }
    }
}

impl<T> Clone for MRc<T>
where
    T: MInit,
{
    fn clone(&self) -> Self {
        let mut ptr = self.0;

        unsafe { ptr.as_mut() }.1 += 1;

        Self(ptr)
    }
}

impl<T> Deref for MRc<T>
where
    T: MInit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> Drop for MRc<T>
where
    T: MInit,
{
    fn drop(&mut self) {
        unsafe { self.0.as_mut() }.1 -= 1;

        if unsafe { self.0.as_mut() }.1 == 0 {
            unsafe { self.0.as_mut() }.0.deinit();

            unsafe {
                mbedtls_free(self.0.as_ptr() as *mut c_void);
            }
        }
    }
}

pub(crate) unsafe extern "C" fn mbedtls_rng(
    _param: *mut c_void,
    buf: *mut c_uchar,
    len: usize,
) -> c_int {
    use crate::sys::MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;

    if len == 0 {
        return 0;
    }
    if buf.is_null() {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }

    let buf = core::slice::from_raw_parts_mut(buf, len);

    critical_section::with(|cs| {
        match RNG.borrow(cs).borrow_mut().as_mut() {
            // SAFETY: the pointer was set from a live `&mut` in a `Tls`
            // constructor (`store_rng`) and is cleared in `Tls::drop`, so on the
            // normal path (a live `Tls`) it is valid; access is serialized by the
            // surrounding `Mutex`. The one unsound path is a leaked `Tls` created
            // via `new_local_borrows` (see `RngPtr`): if the owner did
            // `mem::forget` and dropped the RNG, this slot is stale. That is a
            // caller contract, not something this callback can detect.
            Some(rng) => {
                rng.0.as_mut().fill_bytes(buf);
                0
            }
            // No `Tls` is active: report an entropy failure rather than panicking
            // (the old `unwrap()` aborted out of this `extern "C"` callback). This
            // path is reachable via `mbedtls_psa_external_get_random`, which the
            // PSA layer can call with no live `Session`.
            None => MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
        }
    })
}

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    output: *mut c_uchar,
    out_size: usize,
    output_len: *mut usize,
) -> c_int {
    // PSA status codes (`psa_status_t`). MbedTLS treats this hook's return as a
    // PSA status, not an `MBEDTLS_ERR_*` code, and the generated bindings do not
    // expose the `PSA_*` macros, so they are defined locally here.
    const PSA_SUCCESS: c_int = 0;
    const PSA_ERROR_INSUFFICIENT_ENTROPY: c_int = -148;
    const PSA_ERROR_INVALID_ARGUMENT: c_int = -135;

    if output_len.is_null() {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    // A zero-size request may legitimately pass a null `output`.
    if output.is_null() && out_size != 0 {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if out_size == 0 {
        *output_len = 0;
        return PSA_SUCCESS;
    }

    if mbedtls_rng(core::ptr::null_mut(), output, out_size) == 0 {
        *output_len = out_size;
        PSA_SUCCESS
    } else {
        PSA_ERROR_INSUFFICIENT_ENTROPY
    }
}

#[cfg(target_os = "espidf")]
extern "C" {
    #[link_name = "calloc"]
    pub(crate) fn mbedtls_calloc(num: usize, size: usize) -> *mut c_void;
    #[link_name = "free"]
    pub(crate) fn mbedtls_free(ptr: *mut c_void);
}
