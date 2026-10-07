use core::ffi::CStr;
use core::marker::PhantomData;

use super::sys::*;
use super::{MRc, SessionError, TlsReference};

/// Holds a reference to a PEM or DER-encoded X509 certificate or private key.
///
/// # Examples
/// Initialize with a PEM certificate
/// (`ignore`d: the examples include user-provided certificate files)
/// ```ignore
/// let x509 = X509::PEM(CStr::from_bytes_with_nul(concat!(include_str!("cert.pem"), "\0").as_bytes()).unwrap());
/// ```
///
/// Initialize with a DER certificate
/// ```ignore
/// let x509 = X509::DER(include_bytes!("cert.der"));
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum X509<'a> {
    PEM(&'a CStr),
    DER(&'a [u8]),
}

/// A parsed X509 certificate or certificate chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Certificate<'d> {
    pub(crate) crt: MRc<mbedtls_x509_crt>,
    _t: PhantomData<&'d ()>,
}

impl Certificate<'static> {
    /// Parse an X509 certificate into RAM by making a copy
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in PEM or DER format
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// certificate in a PEM format, and vice-versa.
    pub fn new(x509: X509<'_>) -> Result<Self, MbedtlsError> {
        let mut crt: MRc<mbedtls_x509_crt> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_X509_ALLOC_FAILED))?;

        match x509 {
            X509::PEM(str) => merr!(unsafe {
                mbedtls_x509_crt_parse(
                    crt.as_mut_ptr(),
                    str.as_ptr() as *const _,
                    str.count_bytes() + 1,
                )
            }),
            X509::DER(bytes) => merr!(unsafe {
                mbedtls_x509_crt_parse_der(crt.as_mut_ptr(), bytes.as_ptr(), bytes.len())
            }),
        }?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

impl<'d> Certificate<'d> {
    /// Parse an X509 certificate without making a copy in RAM. This requires that the underlying data
    /// lives for the lifetime of the certificate.
    /// Note: This is currently only supported for DER encoded certificates
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in DER format only
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing.
    /// [TlsError::InvalidFormat] will be returned if a PEM encoded certificate is passed.
    pub fn new_no_copy(x509_der: &'d [u8]) -> Result<Self, SessionError> {
        let mut crt: MRc<mbedtls_x509_crt> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_X509_ALLOC_FAILED))?;

        merr!(unsafe {
            mbedtls_x509_crt_parse_der_nocopy(crt.as_mut_ptr(), x509_der.as_ptr(), x509_der.len())
        })?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

/// A parsed private key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrivateKey(pub(crate) MRc<mbedtls_pk_context>);

impl PrivateKey {
    /// Perform one private-key operation and discard the result.
    ///
    /// MbedTLS sets up RSA blinding on the first private operation of a freshly parsed key,
    /// using a constant-time modular inverse that can take over a second on a small MCU.
    /// Later operations on the same key only update the blinding values. Calling this ahead
    /// of the first handshake moves that setup out of the handshake, for instance to a moment
    /// the application spends waiting for the network anyway.
    ///
    /// The signature is written to `signature` and otherwise ignored, so the call is safe to
    /// repeat. The buffer must hold a signature for this key: the key's size in bytes for RSA
    /// (512 for a 4096-bit key), or a DER-encoded ECDSA signature for EC keys (at most 141
    /// bytes, for P-521). A buffer that is too small returns an error.
    ///
    /// Call this before the key is cloned or given to a session: the operation updates the
    /// key's blinding values in place.
    ///
    /// The [`TlsReference`] proves that the RNG the operation draws on has been registered.
    pub fn warm(
        &mut self,
        signature: &mut [u8],
        _tls: TlsReference<'_>,
    ) -> Result<(), MbedtlsError> {
        let digest = [0x5a_u8; 32];
        let mut written = 0_usize;

        // SAFETY: the context was parsed by `new`; MbedTLS only updates its blinding values here,
        // and `&mut self` plus the documented call order keep clones from reading it meanwhile.
        // Both buffers outlive the call. `mbedtls_rng` ignores its context pointer and draws on
        // the RNG `Tls::new` registered, which `_tls` proves exists.
        merr!(unsafe {
            mbedtls_pk_sign(
                self.0.as_mut_ptr(),
                mbedtls_md_type_t_MBEDTLS_MD_SHA256,
                digest.as_ptr(),
                digest.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut written,
                Some(crate::mbedtls_rng),
                core::ptr::null_mut(),
            )
        })?;

        Ok(())
    }

    /// Parse an X509 private key into RAM and returns a wrapped pointer if successful.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The X509 private key in DER or PEM format
    /// * `password` - The optional password if the private key is password protected
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// private key in a PEM format, and vice-versa.
    pub fn new(x509: X509<'_>, password: Option<&str>) -> Result<Self, SessionError> {
        let mut pk: MRc<mbedtls_pk_context> =
            MRc::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_PK_ALLOC_FAILED))?;

        #[allow(clippy::unnecessary_cast)]
        let (ptr, len) = match x509 {
            X509::PEM(str) => (str.as_ptr() as *const u8, str.count_bytes() + 1),
            X509::DER(bytes) => (bytes.as_ptr(), bytes.len()),
        };

        let (password_ptr, password_len) = if let Some(password) = password {
            (password.as_ptr(), password.len())
        } else {
            (core::ptr::null(), 0)
        };

        merr!(unsafe {
            mbedtls_pk_parse_key(
                pk.as_mut_ptr(),
                ptr as _,
                len,
                password_ptr,
                password_len,
                None,
                core::ptr::null_mut(),
            )
        })?;

        Ok(Self(pk))
    }
}
