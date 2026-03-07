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
use crate::sys::{mbedtls_calloc, mbedtls_free};
use crate::sys::{
    mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_free, mbedtls_ctr_drbg_init, mbedtls_pk_context,
    mbedtls_pk_free, mbedtls_pk_init, mbedtls_ssl_conf_dbg, mbedtls_ssl_config,
    mbedtls_ssl_config_free, mbedtls_ssl_config_init, mbedtls_ssl_context, mbedtls_ssl_free,
    mbedtls_ssl_init, mbedtls_ssl_protocol_version,
    mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_2,
    mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_3, mbedtls_x509_crt,
    mbedtls_x509_crt_free, mbedtls_x509_crt_init,
};

use rand_core::CryptoRng;

pub use cert::*;
#[cfg(feature = "edge-nal")]
pub use edge_nal::*;
pub use session::*;

pub(crate) mod fmt; // MUST be the first so that the other modules can see it

mod cert;
#[cfg(feature = "edge-nal")]
mod edge_nal;
mod session;

/// Re-export of the mbedtls-rs-sys crate so that users do not have to
/// explicitly depend on it if they want to use the raw MbedTLS bindings.
pub mod sys {
    pub use mbedtls_rs_sys::*;
}

static RNG: Mutex<RefCell<Option<&mut (dyn CryptoRng + Send)>>> = Mutex::new(RefCell::new(None));

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

impl<'d> Tls<'d> {
    /// Create a new instance of the `Tls` type.
    ///
    /// Note that there could be only one active `Tls` instance at any point in time,
    /// and the function will return an error if there is already an active instance.
    pub fn new(rng: &'d mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        critical_section::with(|cs| {
            let created = RNG.borrow(cs).borrow().is_some();

            if created {
                return Err(TlsError::AlreadyCreated);
            }

            *RNG.borrow(cs).borrow_mut() = Some(unsafe {
                core::mem::transmute::<
                    &'d mut (dyn CryptoRng + Send),
                    &'static mut (dyn CryptoRng + Send),
                >(rng)
            });

            Ok(Self(PhantomData))
        })
    }

    pub(crate) fn release(&mut self) {
        critical_section::with(|cs| {
            *RNG.borrow(cs).borrow_mut() = None;
        });
    }

    /// Set the MbedTLS debug level (0 - 5)
    #[allow(unused)]
    pub fn set_debug(&mut self, level: u32) {
        #[cfg(not(target_os = "espidf"))]
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
    let buf = core::slice::from_raw_parts_mut(buf, len as _);

    critical_section::with(|cs| {
        let mut rng = RNG.borrow(cs).borrow_mut();

        rng.as_mut().unwrap().fill_bytes(buf);
    });

    0
}

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    output: *mut c_uchar,
    out_size: usize,
    output_len: *mut usize,
) -> c_int {
    *output_len = out_size;
    mbedtls_rng(core::ptr::null_mut(), output, out_size)
}

#[cfg(not(target_os = "espidf"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut c_uchar, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}

#[cfg(target_os = "espidf")]
extern "C" {
    #[link_name = "calloc"]
    fn mbedtls_calloc(num: usize, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn mbedtls_free(ptr: *mut c_void);
}
