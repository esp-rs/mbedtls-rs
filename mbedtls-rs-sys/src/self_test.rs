//! MbedTLS self-test wrappers.
//!
//! Each `mbedtls_<alg>_self_test` symbol only exists when the corresponding
//! algorithm is compiled in (see the `alg-*` cargo features / `gen/features.rs`),
//! so every variant here is gated behind its feature. `Mpi` is always available
//! (bignum is part of the always-on core).

#[cfg(feature = "alg-aes")]
use crate::mbedtls_aes_self_test;
#[cfg(feature = "alg-md5")]
use crate::mbedtls_md5_self_test;
#[cfg(feature = "alg-rsa")]
use crate::mbedtls_rsa_self_test;
#[cfg(feature = "alg-sha1")]
use crate::mbedtls_sha1_self_test;
#[cfg(feature = "alg-sha256")]
use crate::{mbedtls_sha224_self_test, mbedtls_sha256_self_test};
#[cfg(feature = "alg-sha512")]
use crate::{mbedtls_sha384_self_test, mbedtls_sha512_self_test};

use crate::mbedtls_mpi_self_test;

/// An MbedTLS self-test type.
///
/// Variants are only present when the underlying algorithm is enabled.
#[derive(enumset::EnumSetType, Debug)]
pub enum MbedtlsSelfTest {
    Mpi = 0,
    #[cfg(feature = "alg-rsa")]
    Rsa = 1,
    #[cfg(feature = "alg-sha1")]
    Sha1 = 2,
    #[cfg(feature = "alg-sha256")]
    Sha224 = 3,
    #[cfg(feature = "alg-sha256")]
    Sha256 = 4,
    #[cfg(feature = "alg-sha512")]
    Sha384 = 5,
    #[cfg(feature = "alg-sha512")]
    Sha512 = 6,
    #[cfg(feature = "alg-aes")]
    Aes = 7,
    #[cfg(feature = "alg-md5")]
    Md5 = 8,
}

impl MbedtlsSelfTest {
    /// Run a self-test on the MbedTLS library
    ///
    /// # Arguments
    ///
    /// * `test` - The test to run
    /// * `verbose` - Whether to run the test in verbose mode
    pub fn run(&mut self, verbose: bool) -> bool {
        let verbose = verbose as _;

        let result = unsafe {
            match self {
                Self::Mpi => mbedtls_mpi_self_test(verbose),
                #[cfg(feature = "alg-rsa")]
                Self::Rsa => mbedtls_rsa_self_test(verbose),
                #[cfg(feature = "alg-sha1")]
                Self::Sha1 => mbedtls_sha1_self_test(verbose),
                #[cfg(feature = "alg-sha256")]
                Self::Sha224 => mbedtls_sha224_self_test(verbose),
                #[cfg(feature = "alg-sha256")]
                Self::Sha256 => mbedtls_sha256_self_test(verbose),
                #[cfg(feature = "alg-sha512")]
                Self::Sha384 => mbedtls_sha384_self_test(verbose),
                #[cfg(feature = "alg-sha512")]
                Self::Sha512 => mbedtls_sha512_self_test(verbose),
                #[cfg(feature = "alg-aes")]
                Self::Aes => mbedtls_aes_self_test(verbose),
                #[cfg(feature = "alg-md5")]
                Self::Md5 => mbedtls_md5_self_test(verbose),
            }
        };

        result == 0
    }
}

impl core::fmt::Display for MbedtlsSelfTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MbedtlsSelfTest::Mpi => write!(f, "MPI"),
            #[cfg(feature = "alg-rsa")]
            MbedtlsSelfTest::Rsa => write!(f, "RSA"),
            #[cfg(feature = "alg-sha1")]
            MbedtlsSelfTest::Sha1 => write!(f, "SHA1"),
            #[cfg(feature = "alg-sha256")]
            MbedtlsSelfTest::Sha224 => write!(f, "SHA224"),
            #[cfg(feature = "alg-sha256")]
            MbedtlsSelfTest::Sha256 => write!(f, "SHA256"),
            #[cfg(feature = "alg-sha512")]
            MbedtlsSelfTest::Sha384 => write!(f, "SHA384"),
            #[cfg(feature = "alg-sha512")]
            MbedtlsSelfTest::Sha512 => write!(f, "SHA512"),
            #[cfg(feature = "alg-aes")]
            MbedtlsSelfTest::Aes => write!(f, "AES"),
            #[cfg(feature = "alg-md5")]
            MbedtlsSelfTest::Md5 => write!(f, "MD5"),
        }
    }
}
