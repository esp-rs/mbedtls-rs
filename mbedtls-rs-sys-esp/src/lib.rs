//! Hardware acceleration of MbedTLS for the ESP32 chips, based on the baremetal
//! `esp-hal` crate.
//!
//! The chip feature (`esp32`, `esp32c6`, ...) enables the `mbedtls-rs-sys`
//! hooks of the accelerators the chip has. A hook is only installed if its
//! algorithm is compiled into MbedTLS as well; for algorithms that are not,
//! nothing is accelerated.
//!
//! Hardware acceleration involves two *independent* concerns, mirroring the
//! `esp-hal` work-queue design:
//!
//! 1. **Servicing** — instantiating an `esp-hal` crypto backend (`ShaBackend`,
//!    `RsaBackend`, `AesBackend`, `EccBackend`) over its peripheral and
//!    *starting* it, so that it services the corresponding global `esp-hal`
//!    work queue. [`EspAccel`] is an optional convenience for this: users are
//!    equally free to instantiate and start the `esp-hal` backends themselves
//!    (e.g. when other, non-MbedTLS parts of the firmware also use them).
//!
//! 2. **Hooking** — registering this crate's MbedTLS hooks so that MbedTLS
//!    algorithms are routed to the work-queue *clients* (the statics below).
//!    [`EspHooks`] is the utility for this.
//!
//! The two must be paired with care: a hooked algorithm whose work queue no
//! one services makes the next MbedTLS call on that algorithm **block
//! forever** (the work item is queued, but no backend ever picks it up). When
//! [`EspAccel`] is used for servicing, [`EspAccelQueue::hook`] pairs the two
//! safely by construction: it hooks exactly the algorithms whose queues are
//! being serviced, and the returned guard cannot outlive them.

#![no_std]

// On the host, the crate is empty without a chip, so that the workspace and the publish check build
#[cfg(all(
    target_os = "none",
    not(any(
        feature = "esp32",
        feature = "esp32c2",
        feature = "esp32c3",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2",
        feature = "esp32s2",
        feature = "esp32s3"
    ))
))]
compile_error!(
    "mbedtls-rs-sys-esp: select the chip with one of the features esp32, esp32c2, esp32c3, \
     esp32c5, esp32c6, esp32h2, esp32s2, esp32s3"
);

#[cfg(all(feature = "esp-hal", not(feature = "esp32c2"), mbedtls_hook = "aes"))]
pub mod aes;
#[cfg(feature = "esp-hal")]
pub mod digest;
#[cfg(all(
    any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ),
    any(mbedtls_hook = "ecp_mul", mbedtls_hook = "ecp_verify")
))]
pub mod ecc;
#[cfg(all(
    feature = "esp-hal",
    not(feature = "esp32c2"),
    mbedtls_hook = "exp_mod"
))]
pub mod exp_mod;
// Pure routing logic (no `esp-hal` dependency). Mounted `pub` on the host
// under the internal `_route-test` feature so `tests/exp_mod_route.rs` can
// exercise it without an ESP target; `pub(crate)` in production builds.
#[cfg(all(
    feature = "esp-hal",
    not(feature = "esp32c2"),
    mbedtls_hook = "exp_mod"
))]
pub(crate) mod exp_mod_route;
#[cfg(all(not(feature = "esp-hal"), feature = "_route-test"))]
pub mod exp_mod_route;
// esp32c5: LP_TIMER driver not yet wired in esp-hal v1.1, so `Rtc::current_time_us`
// and `Rtc::set_current_time_us` are unavailable. Re-enable once esp-hal lands the
// c5 LP_TIMER driver.
#[cfg(all(
    feature = "esp-hal",
    mbedtls_hook = "wall_clock",
    not(feature = "esp32c5")
))]
pub mod wall_clock;

#[cfg(all(feature = "esp-hal", not(feature = "esp32")))]
pub static SHA1: digest::EspSha1 = digest::EspSha1::new();
#[cfg(all(feature = "esp-hal", not(feature = "esp32")))]
pub static SHA224: digest::EspSha224 = digest::EspSha224::new();
#[cfg(all(feature = "esp-hal", not(feature = "esp32")))]
pub static SHA256: digest::EspSha256 = digest::EspSha256::new();
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub static SHA384: digest::EspSha384 = digest::EspSha384::new();
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub static SHA512: digest::EspSha512 = digest::EspSha512::new();
#[cfg(all(
    feature = "esp-hal",
    not(feature = "esp32c2"),
    mbedtls_hook = "exp_mod"
))]
pub static EXP_MOD: exp_mod::EspExpMod = exp_mod::EspExpMod::new();
#[cfg(all(feature = "esp-hal", not(feature = "esp32c2"), mbedtls_hook = "aes"))]
pub static AES: aes::EspAes = aes::EspAes::new();
#[cfg(all(
    any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ),
    any(mbedtls_hook = "ecp_mul", mbedtls_hook = "ecp_verify")
))]
pub static ECC: ecc::EspEcc = ecc::EspEcc::new();

/// An optional convenience utility for instantiating and starting the
/// `esp-hal` crypto **backends** (the work-queue *servicing* side).
///
/// Built with the `with_*` methods, so any subset of the chip's accelerators
/// can be used — each `with_*` method exists only on the chips that have the
/// corresponding peripheral (see the table below). [`EspAccel::start`] starts
/// the configured backends' work-queue drivers; it does **not** register any
/// MbedTLS hooks — see [`EspHooks`] and [`EspAccelQueue::hook`] for that.
///
/// This type is pure convenience over `esp-hal`: users with other (non-MbedTLS)
/// consumers of the `esp-hal` crypto work queues can skip it entirely and
/// instantiate/start the `esp-hal` backends themselves; the MbedTLS hooks are
/// mere work-queue clients and do not care who services the queues.
///
/// Per-chip peripheral sets:
///
/// | Chip     | SHA | RSA | AES | ECC |
/// |----------|-----|-----|-----|-----|
/// | esp32    |  -  |  x  |  x  |  -  |
/// | esp32s2  |  x  |  x  |  x  |  -  |
/// | esp32s3  |  x  |  x  |  x  |  -  |
/// | esp32c2  |  x  |  -  |  -  |  x  |
/// | esp32c3  |  x  |  x  |  x  |  -  |
/// | esp32c5  |  x  |  x  |  x  |  x  |
/// | esp32c6  |  x  |  x  |  x  |  x  |
/// | esp32h2  |  x  |  x  |  x  |  x  |
///
/// (SHA is present on the esp32 too, but its peripheral is not supported by
/// the `esp-hal` SHA work-queue backend.)
#[cfg(feature = "esp-hal")]
pub struct EspAccel<'d> {
    #[cfg(not(feature = "esp32"))]
    sha: Option<esp_hal::sha::ShaBackend<'d>>,
    #[cfg(not(feature = "esp32c2"))]
    rsa: Option<esp_hal::rsa::RsaBackend<'d>>,
    #[cfg(not(feature = "esp32c2"))]
    aes: Option<esp_hal::aes::AesBackend<'d>>,
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    ecc: Option<esp_hal::ecc::EccBackend<'d>>,
}

#[cfg(feature = "esp-hal")]
impl<'d> EspAccel<'d> {
    /// Create an empty `EspAccel` — no backends configured yet; add them with
    /// the `with_*` methods.
    pub const fn new() -> Self {
        Self {
            #[cfg(not(feature = "esp32"))]
            sha: None,
            #[cfg(not(feature = "esp32c2"))]
            rsa: None,
            #[cfg(not(feature = "esp32c2"))]
            aes: None,
            #[cfg(any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ))]
            ecc: None,
        }
    }

    /// Configure the SHA backend over the `SHA` peripheral.
    #[cfg(not(feature = "esp32"))]
    pub fn with_sha(mut self, sha: esp_hal::peripherals::SHA<'d>) -> Self {
        self.sha = Some(esp_hal::sha::ShaBackend::new(sha));
        self
    }

    /// Configure the RSA backend over the `RSA` peripheral (services the
    /// modular-exponentiation work queue).
    #[cfg(not(feature = "esp32c2"))]
    pub fn with_rsa(mut self, rsa: esp_hal::peripherals::RSA<'d>) -> Self {
        self.rsa = Some(esp_hal::rsa::RsaBackend::new(rsa));
        self
    }

    /// Configure the AES backend over the `AES` peripheral.
    #[cfg(not(feature = "esp32c2"))]
    pub fn with_aes(mut self, aes: esp_hal::peripherals::AES<'d>) -> Self {
        self.aes = Some(esp_hal::aes::AesBackend::new(aes));
        self
    }

    /// Configure the ECC backend over the `ECC` peripheral.
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    pub fn with_ecc(mut self, ecc: esp_hal::peripherals::ECC<'d>) -> Self {
        self.ecc = Some(esp_hal::ecc::EccBackend::new(
            ecc,
            esp_hal::ecc::Config::default(),
        ));
        self
    }

    /// Start the configured backends' work-queue drivers.
    ///
    /// The returned [`EspAccelQueue`] services the corresponding `esp-hal`
    /// work queues for as long as it lives. This registers **no** MbedTLS
    /// hooks — call [`EspAccelQueue::hook`] (or use [`EspHooks`] directly)
    /// for that.
    pub fn start(&mut self) -> EspAccelQueue<'_, 'd> {
        EspAccelQueue {
            #[cfg(not(feature = "esp32"))]
            sha: self.sha.as_mut().map(esp_hal::sha::ShaBackend::start),
            #[cfg(not(feature = "esp32c2"))]
            rsa: self.rsa.as_mut().map(esp_hal::rsa::RsaBackend::start),
            #[cfg(not(feature = "esp32c2"))]
            aes: self.aes.as_mut().map(esp_hal::aes::AesBackend::start),
            #[cfg(any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ))]
            ecc: self.ecc.as_mut().map(esp_hal::ecc::EccBackend::start),
        }
    }
}

#[cfg(feature = "esp-hal")]
impl Default for EspAccel<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// The running work-queue drivers of the backends configured on an
/// [`EspAccel`] — the queues are serviced for as long as this guard lives.
///
/// Registering the MbedTLS hooks is a separate step: [`EspAccelQueue::hook`]
/// does it for exactly the algorithms serviced here (the safe pairing), or
/// use [`EspHooks`] directly for a custom subset.
#[cfg(feature = "esp-hal")]
#[must_use]
pub struct EspAccelQueue<'a, 'd> {
    #[cfg(not(feature = "esp32"))]
    sha: Option<esp_hal::sha::ShaWorkQueueDriver<'a, 'd>>,
    #[cfg(not(feature = "esp32c2"))]
    rsa: Option<esp_hal::rsa::RsaWorkQueueDriver<'a, 'd>>,
    #[cfg(not(feature = "esp32c2"))]
    aes: Option<esp_hal::aes::AesWorkQueueDriver<'a, 'd>>,
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    ecc: Option<esp_hal::ecc::EccWorkQueueDriver<'a, 'd>>,
}

#[cfg(feature = "esp-hal")]
impl EspAccelQueue<'_, '_> {
    /// Register the MbedTLS hooks for **exactly** the algorithms whose work
    /// queues this guard is servicing.
    ///
    /// This is the safe-by-construction pairing of hooking and servicing: an
    /// algorithm gets hooked only if its queue is running, and the returned
    /// [`EspHooksGuard`] borrows this guard, so the hooks are compile-time
    /// guaranteed to be unregistered (falling back to software) before the
    /// queues stop.
    ///
    /// # Safety
    /// - This registers global hooks that affect the behavior of MbedTLS: it
    ///   MUST be called BEFORE any MbedTLS functions that use the hooked
    ///   algorithms (including any state initialized earlier, such as a
    ///   CTR-DRBG instance).
    /// - The returned guard must not be dropped while MbedTLS state
    ///   initialized under the hooks is still alive (the hook backends'
    ///   in-context state is not interchangeable with the software fallback's).
    pub unsafe fn hook(&self) -> EspHooksGuard<'_> {
        #[allow(unused_mut)]
        let mut hooks = EspHooks::new();

        #[cfg(not(feature = "esp32"))]
        if self.sha.is_some() {
            hooks = hooks.with_sha();
        }
        #[cfg(not(feature = "esp32c2"))]
        if self.rsa.is_some() {
            hooks = hooks.with_exp_mod();
        }
        #[cfg(not(feature = "esp32c2"))]
        if self.aes.is_some() {
            hooks = hooks.with_aes();
        }
        #[cfg(any(
            feature = "esp32c2",
            feature = "esp32c5",
            feature = "esp32c6",
            feature = "esp32h2"
        ))]
        if self.ecc.is_some() {
            hooks = hooks.with_ecc();
        }

        unsafe { hooks.apply() };

        EspHooksGuard {
            hooks,
            _scope: core::marker::PhantomData,
        }
    }
}

/// A builder selecting which MbedTLS algorithms to **hook** to the ESP
/// hardware-acceleration work-queue clients (the *usage* side; the statics in
/// this module).
///
/// Granularity is the hardware unit: [`with_sha`](EspHooks::with_sha) covers
/// every SHA digest the chip accelerates, [`with_ecc`](EspHooks::with_ecc)
/// covers both the ECP-mul and ECP-verify hooks, etc. Algorithms that are
/// not compiled into MbedTLS are skipped, so for a unit without any of them
/// `with_*` does nothing.
///
/// This registers work-queue *clients* only — someone must **service** those
/// queues: either an [`EspAccel`]/[`EspAccelQueue`] or `esp-hal` crypto
/// backends instantiated and started by user code. A hooked algorithm with no
/// running backend makes the next MbedTLS call on it **block forever**. When
/// servicing via [`EspAccel`], prefer [`EspAccelQueue::hook`], which rules
/// that hazard out by construction.
#[cfg(feature = "esp-hal")]
#[derive(Clone, Copy)]
pub struct EspHooks {
    #[cfg(not(feature = "esp32"))]
    sha: bool,
    #[cfg(not(feature = "esp32c2"))]
    exp_mod: bool,
    #[cfg(not(feature = "esp32c2"))]
    aes: bool,
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    ecc: bool,
}

#[cfg(feature = "esp-hal")]
impl EspHooks {
    /// Create an empty selection — no algorithms; add them with the `with_*`
    /// methods.
    pub const fn new() -> Self {
        Self {
            #[cfg(not(feature = "esp32"))]
            sha: false,
            #[cfg(not(feature = "esp32c2"))]
            exp_mod: false,
            #[cfg(not(feature = "esp32c2"))]
            aes: false,
            #[cfg(any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ))]
            ecc: false,
        }
    }

    /// Select the SHA digests (SHA-1/224/256, plus SHA-384/512 on chips whose
    /// SHA peripheral accelerates them).
    #[cfg(not(feature = "esp32"))]
    pub const fn with_sha(mut self) -> Self {
        self.sha = true;
        self
    }

    /// Select modular exponentiation (RSA/DHM), backed by the RSA peripheral.
    #[cfg(not(feature = "esp32c2"))]
    pub const fn with_exp_mod(mut self) -> Self {
        self.exp_mod = true;
        self
    }

    /// Select AES.
    #[cfg(not(feature = "esp32c2"))]
    pub const fn with_aes(mut self) -> Self {
        self.aes = true;
        self
    }

    /// Select the ECP operations (mul + verify), backed by the ECC peripheral.
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    pub const fn with_ecc(mut self) -> Self {
        self.ecc = true;
        self
    }

    /// Register the selected hooks, returning a guard that unregisters them
    /// (falling back to the software implementations) on drop.
    ///
    /// # Safety
    /// - This registers global hooks that affect the behavior of MbedTLS: it
    ///   MUST be called BEFORE any MbedTLS functions that use the hooked
    ///   algorithms (including any state initialized earlier, such as a
    ///   CTR-DRBG instance).
    /// - Every selected algorithm's `esp-hal` work queue MUST be serviced (by
    ///   an [`EspAccelQueue`] or a user-started `esp-hal` backend) for as long
    ///   as MbedTLS may call it — a hooked algorithm with no running backend
    ///   blocks forever. [`EspAccelQueue::hook`] discharges this obligation
    ///   by construction.
    /// - The returned guard must not be dropped while MbedTLS state
    ///   initialized under the hooks is still alive (the hook backends'
    ///   in-context state is not interchangeable with the software fallback's).
    pub unsafe fn hook(self) -> EspHooksGuard<'static> {
        unsafe { self.apply() };

        EspHooksGuard {
            hooks: self,
            _scope: core::marker::PhantomData,
        }
    }

    /// Register the selected hooks.
    ///
    /// # Safety
    /// See [`EspHooks::hook`].
    unsafe fn apply(&self) {
        #[cfg(not(feature = "esp32"))]
        if self.sha {
            #[cfg(mbedtls_hook = "sha1")]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha1(Some(&SHA1));
            }
            #[cfg(mbedtls_hook = "sha256")]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha224(Some(&SHA224));
            }
            #[cfg(mbedtls_hook = "sha256")]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha256(Some(&SHA256));
            }
            #[cfg(all(any(feature = "esp32s2", feature = "esp32s3"), mbedtls_hook = "sha512"))]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha384(Some(&SHA384));
            }
            #[cfg(all(any(feature = "esp32s2", feature = "esp32s3"), mbedtls_hook = "sha512"))]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha512(Some(&SHA512));
            }
        }

        #[cfg(all(not(feature = "esp32c2"), mbedtls_hook = "exp_mod"))]
        if self.exp_mod {
            unsafe {
                mbedtls_rs_sys::hook::exp_mod::hook_exp_mod(Some(&EXP_MOD));
            }
        }

        #[cfg(all(not(feature = "esp32c2"), mbedtls_hook = "aes"))]
        if self.aes {
            unsafe {
                mbedtls_rs_sys::hook::aes::hook_aes(Some(&AES));
            }
        }

        #[cfg(any(
            feature = "esp32c2",
            feature = "esp32c5",
            feature = "esp32c6",
            feature = "esp32h2"
        ))]
        if self.ecc {
            #[cfg(mbedtls_hook = "ecp_mul")]
            unsafe {
                mbedtls_rs_sys::hook::ecp::hook_ecp_mul(Some(&ECC));
            }
            #[cfg(mbedtls_hook = "ecp_verify")]
            unsafe {
                mbedtls_rs_sys::hook::ecp::hook_ecp_verify(Some(&ECC));
            }
        }
    }

    /// Unregister the selected hooks (fall back to software).
    ///
    /// # Safety
    /// See [`EspHooks::hook`] — no MbedTLS state initialized under the hooks
    /// may still be alive.
    unsafe fn unapply(&self) {
        #[cfg(not(feature = "esp32"))]
        if self.sha {
            #[cfg(mbedtls_hook = "sha1")]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha1(None);
            }
            #[cfg(mbedtls_hook = "sha256")]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha224(None);
            }
            #[cfg(mbedtls_hook = "sha256")]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha256(None);
            }
            #[cfg(all(any(feature = "esp32s2", feature = "esp32s3"), mbedtls_hook = "sha512"))]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha384(None);
            }
            #[cfg(all(any(feature = "esp32s2", feature = "esp32s3"), mbedtls_hook = "sha512"))]
            unsafe {
                mbedtls_rs_sys::hook::digest::hook_sha512(None);
            }
        }

        #[cfg(all(not(feature = "esp32c2"), mbedtls_hook = "exp_mod"))]
        if self.exp_mod {
            unsafe {
                mbedtls_rs_sys::hook::exp_mod::hook_exp_mod(None);
            }
        }

        #[cfg(all(not(feature = "esp32c2"), mbedtls_hook = "aes"))]
        if self.aes {
            unsafe {
                mbedtls_rs_sys::hook::aes::hook_aes(None);
            }
        }

        #[cfg(any(
            feature = "esp32c2",
            feature = "esp32c5",
            feature = "esp32c6",
            feature = "esp32h2"
        ))]
        if self.ecc {
            #[cfg(mbedtls_hook = "ecp_mul")]
            unsafe {
                mbedtls_rs_sys::hook::ecp::hook_ecp_mul(None);
            }
            #[cfg(mbedtls_hook = "ecp_verify")]
            unsafe {
                mbedtls_rs_sys::hook::ecp::hook_ecp_verify(None);
            }
        }
    }
}

#[cfg(feature = "esp-hal")]
impl Default for EspHooks {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard for registered [`EspHooks`]: unregisters the hooks (falling back to
/// the software implementations) on drop.
///
/// The lifetime ties the guard to whatever services the hooked work queues
/// when obtained via [`EspAccelQueue::hook`] (`'static` when obtained via
/// [`EspHooks::hook`], where servicing is the user's responsibility).
///
/// Dropping the guard while MbedTLS state initialized under the hooks is
/// still alive is undefined behavior — see [`EspHooks::hook`].
#[cfg(feature = "esp-hal")]
#[must_use]
pub struct EspHooksGuard<'s> {
    hooks: EspHooks,
    _scope: core::marker::PhantomData<&'s ()>,
}

#[cfg(feature = "esp-hal")]
impl Drop for EspHooksGuard<'_> {
    fn drop(&mut self) {
        unsafe { self.hooks.unapply() }
    }
}
