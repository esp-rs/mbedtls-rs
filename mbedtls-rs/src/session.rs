use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::marker::PhantomData;
use core::ptr::NonNull;

use embedded_io::{Error, ErrorKind};

use super::sys::*;
use super::{
    mbedtls_calloc, mbedtls_free, mbedtls_rng, Certificate, MBox, PrivateKey, Tls, TlsReference,
    TlsVersion,
};

pub use asynch::*;

mod asynch;
pub mod blocking;
#[cfg(any(
    all(not(target_os = "espidf"), feature = "tls-proto-dtls"),
    esp_idf_mbedtls_ssl_proto_dtls
))]
pub mod dtls;

/// An owned, nul-terminated server name allocated through MbedTLS's allocator
/// (`mbedtls_calloc`/`mbedtls_free`), so it honours a user-overridden MbedTLS
/// heap instead of the Rust global allocator. Used to bind a saved session to a
/// peer identity (see [`SavedSession`]).
pub(crate) struct ServerName {
    ptr: NonNull<u8>,
}

impl ServerName {
    /// Copy a `&CStr`'s bytes (including the nul) into a fresh MbedTLS-allocated
    /// buffer. Returns `None` if the allocation fails.
    fn from_cstr(name: &CStr) -> Option<Self> {
        Self::from_bytes_with_nul(name.to_bytes_with_nul())
    }

    fn from_bytes_with_nul(bytes: &[u8]) -> Option<Self> {
        // SAFETY: `mbedtls_calloc` is the MbedTLS allocator entry point; requesting
        // `bytes.len()` elements of one byte each yields a `bytes.len()`-byte (or
        // null) allocation, which `NonNull::new` checks before we treat it as owned.
        let ptr =
            NonNull::new(unsafe { mbedtls_calloc(bytes.len(), size_of::<u8>()) }.cast::<u8>())?;

        // SAFETY: `ptr` points to a fresh `bytes.len()`-byte allocation, and the
        // source slice is independent of it.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.as_ptr(), bytes.len());
        }

        Some(Self { ptr })
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `ptr` was constructed from a nul-terminated source slice in
        // `from_bytes_with_nul` and is never mutated after construction.
        unsafe { CStr::from_ptr(self.ptr.as_ptr().cast::<c_char>()) }.to_bytes_with_nul()
    }
}

impl Drop for ServerName {
    fn drop(&mut self) {
        // SAFETY: `ptr` was allocated by `mbedtls_calloc` in `from_bytes_with_nul`,
        // is owned solely by this `ServerName`, and is freed exactly once here.
        unsafe {
            mbedtls_free(self.ptr.as_ptr() as *mut c_void);
        }
    }
}

/// A reusable TLS session state captured from a connected session.
///
/// A saved session is bound to the server name that was configured when it was
/// captured, and [`Session::connect_with_session`] refuses to resume it against
/// a different server name (see that method). A session captured without a
/// server name carries no peer binding and may only be resumed into an equally
/// nameless session.
pub struct SavedSession {
    pub(crate) mbedtls_session: MBox<mbedtls_ssl_session>,
    /// The server name the originating session was configured with, used to
    /// reject cross-host resume. `None` if the session had no server name.
    pub(crate) server_name: Option<ServerName>,
}

/// Reject reusing a saved session against a different peer identity.
///
/// TLS 1.2 resume acceptance does not re-validate the server certificate, so a
/// session saved for host A presented to a server B that accepts it would skip
/// verifying B's certificate. We enforce the binding in the wrapper for both TLS
/// 1.2 and 1.3 (1.3 also checks in C). `None`/`Some` are treated as distinct, so
/// a nameless saved session only resumes into a nameless session.
pub(crate) fn check_saved_session_server_name(
    saved: &Option<ServerName>,
    current: *const c_char,
) -> Result<(), SessionError> {
    let current_bytes: Option<&[u8]> = if current.is_null() {
        None
    } else {
        // SAFETY: a non-null hostname pointer read from `mbedtls_ssl_context`
        // is a heap-allocated, nul-terminated string owned by the SSL context.
        // The borrow only lives for the synchronous byte comparison below.
        Some(unsafe { CStr::from_ptr(current) }.to_bytes_with_nul())
    };
    let saved_bytes = saved.as_ref().map(|n| n.as_bytes());

    if current_bytes == saved_bytes {
        Ok(())
    } else {
        Err(SessionError::MbedTls(MbedtlsError::new(
            MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
        )))
    }
}

/// Certificate verification mode used for a session
///
/// # Certificate validity dates are not checked by default
///
/// `MBEDTLS_HAVE_TIME_DATE` is off unless the `hook-wall-clock` feature is
/// enabled, so the `notBefore` / `notAfter` window is **not** verified: an
/// expired or not-yet-valid peer certificate is accepted even under
/// [`AuthMode::Required`]. Chain, signature and hostname verification are
/// unaffected.
///
/// This is the default because a `no_std` target has no wall clock unless the
/// consumer supplies one. To enable the checks, turn on `hook-wall-clock` and
/// install an `MbedtlsWallClock` implementation (plus an `MbedtlsTimer`, which
/// `hook-wall-clock` pulls in) before any X.509 use. With the feature enabled
/// and no clock installed, verification fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AuthMode {
    /// Peer certificate is not checked (default on server) (insecure on client)
    None,
    /// Peer certificate is checked, however the handshake continues even if verification failed;
    /// [mbedtls_ssl_get_verify_result()] can be called after the handshake is complete.
    Optional,
    /// Peer *must* present a valid certificate, handshake is aborted if verification failed. (default on client)
    Required,
    /// Used only for sni_authmode
    Unset,
}

impl AuthMode {
    fn mbedtls_authmode(&self) -> i32 {
        (match self {
            AuthMode::None => MBEDTLS_SSL_VERIFY_NONE,
            AuthMode::Optional => MBEDTLS_SSL_VERIFY_OPTIONAL,
            AuthMode::Required => MBEDTLS_SSL_VERIFY_REQUIRED,
            AuthMode::Unset => MBEDTLS_SSL_VERIFY_UNSET,
        }) as i32
    }
}

/// The credentials (certificate and private key)
/// used for client or server authentication
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Credentials<'a> {
    /// Certificate (chain)
    pub certificate: Certificate<'a>,
    /// Private key paired with the certificate.
    pub private_key: PrivateKey,
}

/// How a session proves to its peer who it is.
///
/// Its `Debug` output leaves the secrets out.
#[derive(Clone)]
pub enum Authentication<'a> {
    /// A certificate (chain) and its private key.
    Certificate(Credentials<'a>),
    /// The password of an EC J-PAKE handshake, shared with the peer, as in
    /// Thread commissioning. The session then offers only
    /// `TLS_ECJPAKE_WITH_AES_128_CCM_8`, with TLS 1.2: the peers authenticate
    /// each other with the password, without certificates.
    ///
    /// With the `kex-ecjpake` feature; on ESP-IDF, with
    /// `CONFIG_MBEDTLS_KEY_EXCHANGE_ECJPAKE`.
    #[cfg(any(
        all(not(target_os = "espidf"), feature = "kex-ecjpake"),
        esp_idf_mbedtls_key_exchange_ecjpake
    ))]
    EcJpake(&'a [u8]),
    /// A pre-shared key, and the identity that names it. The session then
    /// offers only the cipher suites of pre-shared keys: ECDHE-PSK, which has
    /// forward secrecy, then DHE-PSK, then plain PSK; and with TLS 1.3, its
    /// PSK modes. A server takes only a client that sends `identity`.
    ///
    /// The key must be random, not a password: a recorded handshake lets
    /// anyone test guesses of it offline. For passwords, see `EcJpake`.
    ///
    /// TLS 1.2 and DTLS need the `kex-ecdhe-psk` or `kex-psk` feature (the
    /// `tls` bundle has both). On ESP-IDF, PSK needs
    /// `CONFIG_MBEDTLS_PSK_MODES`.
    #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
    Psk {
        /// The name of the key, which the client sends in the clear.
        identity: &'a [u8],
        /// The key.
        key: &'a [u8],
    },
    /// Server only: pre-shared keys, one for each client, looked up by the
    /// identity that the client sends; see [`PskCallback`]. As with `Psk`,
    /// the session offers only the cipher suites of pre-shared keys.
    #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
    PskLookup(PskCallback),
}

impl<'a> From<Credentials<'a>> for Authentication<'a> {
    fn from(creds: Credentials<'a>) -> Self {
        Self::Certificate(creds)
    }
}

impl core::fmt::Debug for Authentication<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Certificate(creds) => f.debug_tuple("Certificate").field(creds).finish(),
            #[cfg(any(
                all(not(target_os = "espidf"), feature = "kex-ecjpake"),
                esp_idf_mbedtls_key_exchange_ecjpake
            ))]
            Self::EcJpake(_) => f.write_str("EcJpake(..)"),
            #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
            Self::Psk { identity, .. } => f
                .debug_struct("Psk")
                .field("identity", identity)
                .finish_non_exhaustive(),
            #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
            Self::PskLookup(callback) => f.debug_tuple("PskLookup").field(callback).finish(),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Authentication<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::Certificate(creds) => defmt::write!(f, "Certificate({})", creds),
            #[cfg(any(
                all(not(target_os = "espidf"), feature = "kex-ecjpake"),
                esp_idf_mbedtls_key_exchange_ecjpake
            ))]
            Self::EcJpake(_) => defmt::write!(f, "EcJpake(..)"),
            #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
            Self::Psk { identity, .. } => defmt::write!(f, "Psk {{ identity: {}, .. }}", identity),
            #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
            Self::PskLookup(callback) => defmt::write!(f, "PskLookup({})", callback),
        }
    }
}

/// A raw verification callback registered through `mbedtls_ssl_conf_verify`,
/// for callers that supply their own trust store instead of a parsed CA
/// chain — for example a CA bundle kept in flash and searched on demand —
/// or that examine the peer chain in addition to a parsed CA chain.
///
/// `f` is called by MbedTLS after the standard verification pass for every
/// certificate of the verified chain, from the top down to the leaf at depth
/// 0, with the accumulated `flags` for that certificate. With `ca_chain`, the
/// top certificate can be the trusted root from `ca_chain`, even if the peer
/// did not send it. Returning `0` keeps the verdict that `*flags` holds after
/// the call: with [AuthMode::Required], the handshake fails if a flag is
/// left set on any certificate of the chain. Any non-zero return value
/// aborts the handshake. `p_ctx` is passed back unchanged and must stay
/// valid (and unmutated from other contexts) for the whole session
/// lifetime.
///
/// After the callback, the TLS layer also checks the key usage extensions of
/// the leaf and, with TLS 1.2, the curve of its EC key. The callback does not
/// see the flags of these checks and cannot clear them.
///
/// With the `hook-wall-clock` feature, if the wall clock gives no time,
/// MbedTLS aborts the chain verification with `MBEDTLS_ERR_X509_FATAL_ERROR`
/// before it calls `f`. Thus, without a clock, the callback cannot accept a
/// certificate.
///
/// Without `ca_chain`, setting this installs a zero-initialized placeholder
/// CA chain, and the callback is the only source of trust. With `ca_chain`,
/// MbedTLS verifies the peer chain against it as usual, and the callback
/// gets the result of that verification in `flags`.
///
/// On the client it applies to the server's certificate chain and is
/// mutually exclusive with `skip_hostname_verification`, which uses the same
/// configuration slot (clear `MBEDTLS_X509_BADCERT_CN_MISMATCH` in the
/// callback instead). On the server it applies to the client's certificate
/// chain (mutual TLS).
#[derive(Debug, Clone, Copy)]
pub struct VerifyCallback {
    /// The callback passed to `mbedtls_ssl_conf_verify`.
    pub f: unsafe extern "C" fn(
        p_ctx: *mut c_void,
        crt: *mut mbedtls_x509_crt,
        depth: c_int,
        flags: *mut u32,
    ) -> c_int,
    /// Opaque context pointer handed back to `f` on every call.
    pub p_ctx: *mut c_void,
}

// The raw pointers are opaque to defmt; format only the type name.
#[cfg(feature = "defmt")]
impl defmt::Format for VerifyCallback {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "VerifyCallback");
    }
}

/// A raw lookup of pre-shared keys registered through
/// `mbedtls_ssl_conf_psk_cb`, for a server with a key for each client (see
/// [`Authentication::PskLookup`]).
///
/// `f` is called by MbedTLS during the handshake, with the identity that the
/// client sent. If it knows the identity, it sets the identity's key with
/// `mbedtls_ssl_set_hs_psk(ssl, key, key_len)` and returns `0`. Any other
/// return value ends the handshake: an unknown identity. `p_ctx` is passed
/// back unchanged and must stay valid (and unmutated from other contexts)
/// for the whole session lifetime.
#[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
#[derive(Debug, Clone, Copy)]
pub struct PskCallback {
    /// The callback passed to `mbedtls_ssl_conf_psk_cb`.
    pub f: unsafe extern "C" fn(
        p_ctx: *mut c_void,
        ssl: *mut mbedtls_ssl_context,
        identity: *const c_uchar,
        identity_len: usize,
    ) -> c_int,
    /// Opaque context pointer handed back to `f` on every call.
    pub p_ctx: *mut c_void,
}

// The raw pointers are opaque to defmt; format only the type name.
#[cfg(all(
    feature = "defmt",
    any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes)
))]
impl defmt::Format for PskCallback {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "PskCallback");
    }
}

/// Configuration for a TLS session
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientSessionConfig<'a> {
    /// Trusted CA (Certificate Authority) chain to be used for certificate
    /// verification during the SSL/TLS handshake.
    ///
    /// The CA chain should contain the trusted CA certificates
    /// that will be used to verify the server's certificate by the client during the handshake.
    pub ca_chain: Option<Certificate<'a>>,
    /// How the client proves to the server who it is: `None` (the usual TLS
    /// client), a certificate (mutual TLS) or an EC J-PAKE password. With
    /// EC J-PAKE, the fields that verify the server's certificate do not
    /// apply.
    pub authentication: Option<Authentication<'a>>,
    /// The server name to verify in the certificate provided by the server
    /// Optional, because it can also be provided later
    pub server_name: Option<&'a CStr>,
    /// Certificate verification mode. Can be overriden.
    /// By default, [AuthMode::Required] will be used
    pub auth_mode: AuthMode,
    /// The minimum TLS version that will be supported by a particular `Session` instance
    pub min_version: TlsVersion,
    /// The maximum TLS version that will be supported by a particular `Session` instance.
    /// `None` keeps Mbed TLS's default maximum.
    pub max_version: Option<TlsVersion>,
    /// ALPN protocols
    pub alpn_protocols: Option<&'a [&'a CStr]>,
    /// Skip the certificate hostname (CN/SAN) match check while still sending
    /// SNI (`server_name`) and verifying the rest of the certificate chain.
    ///
    /// Equivalent to esp-idf's `skip_cert_common_name_check`: use this when
    /// the server certificate does not match the hostname used to reach the
    /// server (e.g. pinned or self-signed certificates served behind a
    /// different domain).
    pub skip_hostname_verification: bool,
    /// Ordered key-exchange groups to offer. `None` keeps Mbed TLS's defaults.
    pub key_exchange_groups: Option<&'a [TlsGroup]>,
    /// Raw verification callback, see [VerifyCallback]. Without `ca_chain`
    /// it is the trust store: it lets the caller keep trusted roots in flash
    /// (for example an esp-idf-style CA bundle) and only materialize the
    /// root the peer chain actually needs. With `ca_chain` it gets the
    /// verdict of the standard verification, for example to record or pin
    /// the server's public key.
    ///
    /// Mutually exclusive with `skip_hostname_verification` (both feed the
    /// same slot).
    pub verify_callback: Option<VerifyCallback>,
}

impl<'a> Default for ClientSessionConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ClientSessionConfig<'a> {
    pub const fn new() -> Self {
        Self {
            ca_chain: None,
            authentication: None,
            server_name: None,
            auth_mode: AuthMode::Required,
            min_version: TlsVersion::Tls1_2,
            max_version: None,
            alpn_protocols: None,
            skip_hostname_verification: false,
            key_exchange_groups: None,
            verify_callback: None,
        }
    }
}

/// A named group that can be offered during TLS key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum TlsGroup {
    Secp192k1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP192K1 as u16,
    Secp192r1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1 as u16,
    Secp224k1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP224K1 as u16,
    Secp224r1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1 as u16,
    Secp256k1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1 as u16,
    Secp256r1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 as u16,
    Secp384r1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 as u16,
    Secp521r1 = MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1 as u16,
    BrainpoolP256r1 = MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1 as u16,
    BrainpoolP384r1 = MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1 as u16,
    BrainpoolP512r1 = MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1 as u16,
    X25519 = MBEDTLS_SSL_IANA_TLS_GROUP_X25519 as u16,
    X448 = MBEDTLS_SSL_IANA_TLS_GROUP_X448 as u16,
    Ffdhe2048 = MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048 as u16,
    Ffdhe3072 = MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072 as u16,
    Ffdhe4096 = MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096 as u16,
    Ffdhe6144 = MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144 as u16,
    Ffdhe8192 = MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192 as u16,
}

impl TlsGroup {
    const fn mbedtls_id(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerSessionConfig<'a> {
    /// Trusted CA (Certificate Authority) chain to be used for certificate
    /// verification during the SSL/TLS handshake.
    ///
    /// The CA chain should contain the trusted CA certificates
    /// that will be used to verify the client's certificate by the server during the handshake.
    pub ca_chain: Option<Certificate<'a>>,
    /// How the server proves to the client who it is.
    pub authentication: Authentication<'a>,
    /// Client certificate verification mode. Can be overriden.
    /// By default, [AuthMode::None] will be used
    pub auth_mode: AuthMode,
    /// The minimum TLS version that will be supported by a particular `Session` instance
    pub min_version: TlsVersion,
    /// ALPN protocols
    pub alpn_protocols: Option<&'a [&'a CStr]>,
    /// Raw verification callback for the client's certificate chain in
    /// mutual TLS — the server-side counterpart of
    /// [`ClientSessionConfig::verify_callback`], see [VerifyCallback].
    ///
    /// A server configured with a callback and without `ca_chain` sends an
    /// empty acceptable-CA list in its CertificateRequest (the same
    /// trade-off Mbed TLS documents for its own CA-callback API).
    pub verify_callback: Option<VerifyCallback>,
}

impl<'a> ServerSessionConfig<'a> {
    pub const fn new(authentication: Authentication<'a>) -> Self {
        Self {
            ca_chain: None,
            authentication,
            auth_mode: AuthMode::None,
            min_version: TlsVersion::Tls1_2,
            alpn_protocols: None,
            verify_callback: None,
        }
    }
}

/// Configuration for a TLS session
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionConfig<'a> {
    Client(ClientSessionConfig<'a>),
    Server(ServerSessionConfig<'a>),
}

impl<'a> SessionConfig<'a> {
    fn ca_chain(&self) -> Option<&Certificate<'a>> {
        match self {
            SessionConfig::Client(ClientSessionConfig { ca_chain, .. }) => ca_chain.as_ref(),
            SessionConfig::Server(ServerSessionConfig { ca_chain, .. }) => ca_chain.as_ref(),
        }
    }

    fn authentication(&self) -> Option<&Authentication<'a>> {
        match self {
            SessionConfig::Client(ClientSessionConfig { authentication, .. }) => {
                authentication.as_ref()
            }
            SessionConfig::Server(ServerSessionConfig { authentication, .. }) => {
                Some(authentication)
            }
        }
    }

    fn creds(&self) -> Option<&Credentials<'a>> {
        match self.authentication() {
            Some(Authentication::Certificate(creds)) => Some(creds),
            _ => None,
        }
    }

    fn auth_mode(&self) -> AuthMode {
        match self {
            SessionConfig::Client(ClientSessionConfig { auth_mode, .. }) => *auth_mode,
            SessionConfig::Server(ServerSessionConfig { auth_mode, .. }) => *auth_mode,
        }
    }

    fn min_version(&self) -> TlsVersion {
        match self {
            SessionConfig::Client(ClientSessionConfig { min_version, .. }) => *min_version,
            SessionConfig::Server(ServerSessionConfig { min_version, .. }) => *min_version,
        }
    }

    fn max_version(&self) -> Option<TlsVersion> {
        match self {
            SessionConfig::Client(ClientSessionConfig { max_version, .. }) => *max_version,
            SessionConfig::Server { .. } => None,
        }
    }

    fn alpn_protocols(&self) -> Option<&'a [&'a CStr]> {
        match self {
            SessionConfig::Client(ClientSessionConfig { alpn_protocols, .. }) => *alpn_protocols,
            SessionConfig::Server(ServerSessionConfig { alpn_protocols, .. }) => *alpn_protocols,
        }
    }

    fn key_exchange_groups(&self) -> Option<&'a [TlsGroup]> {
        match self {
            SessionConfig::Client(ClientSessionConfig {
                key_exchange_groups,
                ..
            }) => *key_exchange_groups,
            SessionConfig::Server { .. } => None,
        }
    }

    fn verify_callback(&self) -> Option<VerifyCallback> {
        match self {
            SessionConfig::Client(ClientSessionConfig {
                verify_callback, ..
            })
            | SessionConfig::Server(ServerSessionConfig {
                verify_callback, ..
            }) => *verify_callback,
        }
    }

    #[cfg(any(
        all(not(target_os = "espidf"), feature = "kex-ecjpake"),
        esp_idf_mbedtls_key_exchange_ecjpake
    ))]
    fn ecjpake_password(&self) -> Option<&'a [u8]> {
        match self.authentication() {
            Some(Authentication::EcJpake(password)) => Some(*password),
            _ => None,
        }
    }

    fn skip_hostname_verification(&self) -> bool {
        match self {
            SessionConfig::Client(ClientSessionConfig {
                skip_hostname_verification,
                ..
            }) => *skip_hostname_verification,
            SessionConfig::Server { .. } => false,
        }
    }

    fn raw_mode(&self) -> c_int {
        match self {
            Self::Client { .. } => MBEDTLS_SSL_IS_CLIENT as c_int,
            Self::Server { .. } => MBEDTLS_SSL_IS_SERVER as c_int,
        }
    }
}

/// RAII storage for an array of ALPN protocol names. Per mbedtls requirements,
/// the array is always terminated with a NULL pointer. The array is allocated
/// via mbedtls_calloc, but the pointers stored in the array refer to memory
/// owned by the original CStr, hence the lifetime bound.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ALPNArray<'a>(NonNull<*const c_char>, PhantomData<&'a CStr>);

impl<'a> ALPNArray<'a> {
    pub fn from_slice(slice: &'a [&'a CStr]) -> Option<Self> {
        NonNull::new(
            unsafe { mbedtls_calloc(slice.len() + 1, size_of::<*const c_char>()) }
                .cast::<*const c_char>(),
        )
        .map(|ptr| {
            // we allocate the memory via calloc, so it is zero-filled
            // we fill all the entries excluding the null terminator
            let output = unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), slice.len()) };
            for (index, element) in slice.iter().enumerate() {
                output[index] = element.as_ptr()
            }
            Self(ptr, PhantomData)
        })
    }

    pub fn as_ptr(&self) -> *mut *const c_char {
        self.0.as_ptr()
    }
}

impl<'a> Drop for ALPNArray<'a> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_free(self.0.as_ptr() as *mut c_void);
        }
    }
}

/// Owned, zero-terminated group-ID array allocated through Mbed TLS.
struct GroupArray(NonNull<u16>);

impl GroupArray {
    fn from_slice(groups: &[TlsGroup]) -> Option<Self> {
        let count = groups.len().checked_add(1)?;
        let ptr = NonNull::new(unsafe { mbedtls_calloc(count, size_of::<u16>()) }.cast::<u16>())?;
        let output = unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), groups.len()) };
        for (output, group) in output.iter_mut().zip(groups) {
            *output = group.mbedtls_id();
        }
        Some(Self(ptr))
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

impl Drop for GroupArray {
    fn drop(&mut self) {
        unsafe { mbedtls_free(self.0.as_ptr().cast::<c_void>()) }
    }
}

/// Owned, zero-terminated cipher suite list allocated through Mbed TLS.
#[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
struct CiphersuiteArray(NonNull<c_int>);

#[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
impl CiphersuiteArray {
    /// The cipher suites of pre-shared keys, from those of the build: TLS
    /// 1.3's (which negotiates its key exchange apart), then ECDHE-PSK, then
    /// DHE-PSK, then plain PSK, each in Mbed TLS's order of preference.
    /// RSA-PSK is left out: it needs a server certificate.
    fn psk() -> Option<Self> {
        let all = unsafe { mbedtls_ssl_list_ciphersuites() };
        let mut len = 0;
        while unsafe { *all.add(len) } != 0 {
            len += 1;
        }
        let all = unsafe { core::slice::from_raw_parts(all, len) };

        let count = len.checked_add(1)?;
        let ptr =
            NonNull::new(unsafe { mbedtls_calloc(count, size_of::<c_int>()) }.cast::<c_int>())?;
        let output = unsafe { core::slice::from_raw_parts_mut(ptr.as_ptr(), len) };

        let tls13 = mbedtls_ssl_protocol_version_MBEDTLS_SSL_VERSION_TLS1_3;
        let groups: [&dyn Fn(&mbedtls_ssl_ciphersuite_t) -> bool; 4] = [
            &|suite| suite.private_min_tls_version as mbedtls_ssl_protocol_version == tls13,
            &|suite| {
                suite.private_key_exchange as mbedtls_key_exchange_type_t
                    == mbedtls_key_exchange_type_t_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK
            },
            &|suite| {
                suite.private_key_exchange as mbedtls_key_exchange_type_t
                    == mbedtls_key_exchange_type_t_MBEDTLS_KEY_EXCHANGE_DHE_PSK
            },
            &|suite| {
                suite.private_key_exchange as mbedtls_key_exchange_type_t
                    == mbedtls_key_exchange_type_t_MBEDTLS_KEY_EXCHANGE_PSK
            },
        ];

        let mut taken = 0;
        for group in groups {
            for &id in all {
                let suite = unsafe { mbedtls_ssl_ciphersuite_from_id(id).as_ref() };
                if suite.is_some_and(group) {
                    output[taken] = id;
                    taken += 1;
                }
            }
        }

        Some(Self(ptr))
    }

    fn as_ptr(&self) -> *const c_int {
        self.0.as_ptr()
    }
}

#[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
impl Drop for CiphersuiteArray {
    fn drop(&mut self) {
        unsafe { mbedtls_free(self.0.as_ptr().cast::<c_void>()) }
    }
}

/// Session state
struct SessionState<'a> {
    /// The SSL context
    ssl_context: MBox<mbedtls_ssl_context>,
    /// The DRBG context
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _drbg: MBox<mbedtls_ctr_drbg_context>,
    /// The SSL configuration
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _ssl_config: MBox<mbedtls_ssl_config>,
    /// The CA chain
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _ca_chain: Option<Certificate<'a>>,
    /// The credentials
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _creds: Option<Credentials<'a>>,
    /// ALPN protocol array
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _alpn_ptrs: Option<ALPNArray<'a>>,
    /// Key-exchange group IDs referenced by the SSL configuration.
    ///
    /// This must remain after `ssl_context` and `_ssl_config` so Rust drops those fields first.
    _group_ids: Option<GroupArray>,
    /// The cipher suites of a PSK session, referenced by the SSL configuration.
    ///
    /// This must remain after `ssl_context` and `_ssl_config` so Rust drops those fields first.
    #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
    _ciphersuites: Option<CiphersuiteArray>,
    /// Set again after each reset of the SSL context, see [`SessionState::reset`].
    #[cfg(any(
        all(not(target_os = "espidf"), feature = "kex-ecjpake"),
        esp_idf_mbedtls_key_exchange_ecjpake
    ))]
    ecjpake_password: Option<&'a [u8]>,
}

/// Placeholder CA chain for [`VerifyCallback`] sessions without `ca_chain`:
/// zero-initialized, it only satisfies the client handshake's non-NULL
/// CA-chain check and never matches a peer chain (all names and keys are
/// empty). Mirrors esp-idf `esp_crt_bundle`'s dummy certificate.
struct DummyCrt(mbedtls_x509_crt);
// Only ever read through MbedTLS's chain walk.
unsafe impl Sync for DummyCrt {}

static DUMMY_CRT: DummyCrt = DummyCrt(unsafe { core::mem::zeroed() });

/// The ciphersuites of an EC J-PAKE session, zero-terminated.
#[cfg(any(
    all(not(target_os = "espidf"), feature = "kex-ecjpake"),
    esp_idf_mbedtls_key_exchange_ecjpake
))]
static ECJPAKE_CIPHERSUITES: [c_int; 2] = [MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8 as c_int, 0];

impl<'a> SessionState<'a> {
    /// Initialize the Session state using the given configuration
    fn new(conf: &SessionConfig<'a>) -> Result<Self, MbedtlsError> {
        Self::with_transport(conf, MBEDTLS_SSL_TRANSPORT_STREAM, |_| ())
    }

    /// Initialize the Session state for `transport` (`MBEDTLS_SSL_TRANSPORT_*`).
    /// `configure` completes the SSL configuration before the SSL context is set up.
    fn with_transport(
        conf: &SessionConfig<'a>,
        transport: u32,
        configure: impl FnOnce(&mut mbedtls_ssl_config),
    ) -> Result<Self, MbedtlsError> {
        merr!(unsafe { psa_crypto_init() })?;

        let mut ssl_config = MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        merr!(unsafe {
            mbedtls_ssl_config_defaults(
                &mut *ssl_config,
                conf.raw_mode(),
                transport as i32,
                MBEDTLS_SSL_PRESET_DEFAULT as i32,
            )
        })?;

        // Set the minimum TLS version
        // Use a direct field modified for compatibility with the `esp-idf-svc` mbedtls
        ssl_config.private_min_tls_version = conf.min_version().mbed_tls_version();

        if let Some(max_version) = conf.max_version() {
            ssl_config.private_max_tls_version = max_version.mbed_tls_version();
        }

        #[cfg(any(
            all(not(target_os = "espidf"), feature = "kex-ecjpake"),
            esp_idf_mbedtls_key_exchange_ecjpake
        ))]
        if conf.ecjpake_password().is_some() {
            // EC J-PAKE is a TLS 1.2 key exchange.
            ssl_config.private_max_tls_version = TlsVersion::Tls1_2.mbed_tls_version();

            unsafe {
                mbedtls_ssl_conf_ciphersuites(&mut *ssl_config, ECJPAKE_CIPHERSUITES.as_ptr());
            }
        }

        #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
        let ciphersuites = match conf.authentication() {
            Some(Authentication::Psk { identity, key }) => {
                // Copied by Mbed TLS.
                merr!(unsafe {
                    mbedtls_ssl_conf_psk(
                        &mut *ssl_config,
                        key.as_ptr(),
                        key.len(),
                        identity.as_ptr(),
                        identity.len(),
                    )
                })?;

                Some(Self::conf_psk_only(&mut ssl_config)?)
            }
            Some(Authentication::PskLookup(callback)) => {
                if !matches!(conf, SessionConfig::Server(_)) {
                    return Err(MbedtlsError::new(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
                }

                unsafe {
                    mbedtls_ssl_conf_psk_cb(&mut *ssl_config, Some(callback.f), callback.p_ctx);
                }

                Some(Self::conf_psk_only(&mut ssl_config)?)
            }
            _ => None,
        };

        Tls::hook_debug_logs(&mut ssl_config);

        unsafe {
            mbedtls_ssl_conf_authmode(&mut *ssl_config, conf.auth_mode().mbedtls_authmode());
        }

        if let Some(creds) = conf.creds() {
            merr!(unsafe {
                mbedtls_ssl_conf_own_cert(
                    &mut *ssl_config,
                    &*creds.certificate.crt as *const _ as *mut _,
                    &*creds.private_key.0 as *const _ as *mut _,
                )
            })?;
        }

        let verify_callback = conf.verify_callback();
        if verify_callback.is_some() && conf.skip_hostname_verification() {
            // Both feed the same `mbedtls_ssl_conf_verify` slot; combining
            // them would silently drop one of the callbacks.
            return Err(MbedtlsError::new(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
        }
        if let Some(ca_chain) = conf.ca_chain() {
            unsafe {
                mbedtls_ssl_conf_ca_chain(
                    &mut *ssl_config,
                    &*ca_chain.crt as *const _ as *mut _,
                    core::ptr::null_mut(),
                );
            }
        } else if verify_callback.is_some() {
            unsafe {
                // A placeholder CA chain is still required: the handshake's
                // "no CA chain" check counts the CA chain, not the verify
                // callback, so without one a session with
                // `AuthMode::Required` aborts before certificate
                // verification runs. The zero-initialized certificate never
                // matches a peer chain; trust is decided exclusively by the
                // callback. (Same trick as esp-idf `esp_crt_bundle`'s dummy
                // certificate.)
                mbedtls_ssl_conf_ca_chain(
                    &mut *ssl_config,
                    &DUMMY_CRT.0 as *const _ as *mut _,
                    core::ptr::null_mut(),
                );
            }
        }
        if let Some(callback) = verify_callback {
            unsafe {
                mbedtls_ssl_conf_verify(&mut *ssl_config, Some(callback.f), callback.p_ctx);
            }
        }

        let alpn = if let Some(alpn_protocols) = conf.alpn_protocols() {
            let alpn = ALPNArray::from_slice(alpn_protocols)
                .ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;
            merr!(unsafe { mbedtls_ssl_conf_alpn_protocols(&mut *ssl_config, alpn.as_ptr()) })?;
            Some(alpn)
        } else {
            None
        };

        let group_ids = if let Some(groups) = conf.key_exchange_groups() {
            if groups.is_empty() {
                return Err(MbedtlsError::new(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
            }
            let group_ids = GroupArray::from_slice(groups)
                .ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;
            unsafe { mbedtls_ssl_conf_groups(&mut *ssl_config, group_ids.as_ptr()) };
            Some(group_ids)
        } else {
            None
        };

        let mut drbg_context =
            MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        // Init RNG
        unsafe {
            mbedtls_ssl_conf_rng(
                &mut *ssl_config,
                Some(mbedtls_rng),
                &mut *drbg_context as *mut _ as *mut c_void,
            );
        }

        configure(&mut ssl_config);

        let mut ssl_context = MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        merr!(unsafe { mbedtls_ssl_setup(&mut *ssl_context, &*ssl_config) })?;

        if let SessionConfig::Client(conf) = conf {
            if let Some(name) = conf.server_name {
                merr!(unsafe { mbedtls_ssl_set_hostname(&mut *ssl_context, name.as_ptr()) })?;
            }
            // SNI is still sent (`set_hostname` above), but the verify callback
            // clears the leaf certificate's CN/SAN mismatch flag. The rest of the
            // chain verification is not affected.
            if conf.skip_hostname_verification {
                unsafe {
                    mbedtls_ssl_conf_verify(
                        &mut *ssl_config,
                        Some(verify_skip_hostname_mismatch),
                        core::ptr::null_mut(),
                    );
                }
            }
        }

        Ok(Self {
            ssl_context,
            _drbg: drbg_context,
            _ssl_config: ssl_config,
            _ca_chain: conf.ca_chain().cloned(),
            _creds: conf.creds().cloned(),
            _alpn_ptrs: alpn,
            _group_ids: group_ids,
            #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
            _ciphersuites: ciphersuites,
            #[cfg(any(
                all(not(target_os = "espidf"), feature = "kex-ecjpake"),
                esp_idf_mbedtls_key_exchange_ecjpake
            ))]
            ecjpake_password: conf.ecjpake_password(),
        })
    }

    /// Have `ssl_config` offer only the cipher suites and the TLS 1.3 modes
    /// of pre-shared keys. The configuration references the returned list.
    #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_psk_modes))]
    fn conf_psk_only(
        ssl_config: &mut mbedtls_ssl_config,
    ) -> Result<CiphersuiteArray, MbedtlsError> {
        let ciphersuites =
            CiphersuiteArray::psk().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        unsafe {
            mbedtls_ssl_conf_ciphersuites(ssl_config, ciphersuites.as_ptr());
        }

        #[cfg(any(not(target_os = "espidf"), esp_idf_mbedtls_ssl_proto_tls1_3))]
        unsafe {
            mbedtls_ssl_conf_tls13_key_exchange_modes(
                ssl_config,
                MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL as c_int,
            );
        }

        Ok(ciphersuites)
    }

    /// Reset the SSL context for a new handshake.
    fn reset(&mut self) -> Result<(), MbedtlsError> {
        merr!(unsafe { mbedtls_ssl_session_reset(self.ssl_context.as_mut_ptr()) })?;

        // The password goes with the handshake state, which the reset renews.
        #[cfg(any(
            all(not(target_os = "espidf"), feature = "kex-ecjpake"),
            esp_idf_mbedtls_key_exchange_ecjpake
        ))]
        if let Some(password) = self.ecjpake_password {
            merr!(unsafe {
                mbedtls_ssl_set_hs_ecjpake_password(
                    self.ssl_context.as_mut_ptr(),
                    password.as_ptr(),
                    password.len(),
                )
            })?;
        }

        Ok(())
    }
}

/// Clears the hostname mismatch flag of the leaf certificate (depth 0). All
/// other verification flags are left untouched and are still evaluated by
/// MbedTLS according to the configured [AuthMode].
unsafe extern "C" fn verify_skip_hostname_mismatch(
    _ctx: *mut c_void,
    _crt: *mut mbedtls_x509_crt,
    depth: c_int,
    flags: *mut u32,
) -> c_int {
    if depth == 0 && !flags.is_null() {
        unsafe { *flags &= !MBEDTLS_X509_BADCERT_CN_MISMATCH };
    }
    0
}

/// Error type for session operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// MBedTLS error
    MbedTls(MbedtlsError),
    /// IO error
    Io(ErrorKind),
}

impl SessionError {
    /// Create a SessionError from an embedded-io Error
    pub fn from_io<E: Error>(err: E) -> Self {
        Self::Io(err.kind())
    }
}

impl From<MbedtlsError> for SessionError {
    fn from(e: MbedtlsError) -> Self {
        Self::MbedTls(e)
    }
}

impl From<ErrorKind> for SessionError {
    fn from(e: ErrorKind) -> Self {
        Self::Io(e)
    }
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MbedTls(e) => write!(f, "{}", e),
            Self::Io(e) => write!(f, "IO({:?})", e),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SessionError {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::MbedTls(e) => defmt::write!(f, "{}", e),
            Self::Io(e) => defmt::write!(f, "IO({:?})", debug2format!(e)),
        }
    }
}

impl core::error::Error for SessionError {}

impl embedded_io::Error for SessionError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(e) => *e,
            _ => embedded_io::ErrorKind::Other,
        }
    }
}
