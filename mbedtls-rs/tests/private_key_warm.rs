//! `PrivateKey::warm` against a real key.

use core::convert::Infallible;
use std::sync::Mutex;

use mbedtls_rs::{PrivateKey, Tls, X509};
use rand::{Rng, TryCryptoRng, TryRng};

const EC_KEY: &[u8] = include_bytes!("fixtures/key.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/rsa_key.der");

// A PKCS#1 v1.5 signature is exactly as long as the RSA modulus.
const RSA_KEY_BYTES: usize = 2048 / 8;

// Tls owns a process-global RNG callback, so tests must not overlap Tls lifetimes.
static SERIAL: Mutex<()> = Mutex::new(());

struct StdRng;

impl TryRng for StdRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::rng().next_u64())
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        rand::rng().fill_bytes(destination);
        Ok(())
    }
}

impl TryCryptoRng for StdRng {}

#[test]
fn warm_succeeds_on_a_freshly_parsed_ec_key() {
    // Given
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, which is dropped before it.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let mut key = PrivateKey::new(X509::DER(EC_KEY), None).unwrap();
    let mut signature = [0_u8; 128];

    // When
    let result = key.warm(&mut signature, tls.reference());

    // Then
    result.unwrap();
}

#[test]
fn warm_can_be_repeated() {
    // Given
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, which is dropped before it.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let mut key = PrivateKey::new(X509::DER(EC_KEY), None).unwrap();
    let mut signature = [0_u8; 128];
    key.warm(&mut signature, tls.reference()).unwrap();

    // When
    let result = key.warm(&mut signature, tls.reference());

    // Then
    result.unwrap();
}

#[test]
fn warm_fails_when_the_signature_buffer_is_too_small() {
    // Given
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, which is dropped before it.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let mut key = PrivateKey::new(X509::DER(EC_KEY), None).unwrap();
    let mut signature = [0_u8; 8];

    // When
    let result = key.warm(&mut signature, tls.reference());

    // Then
    assert!(result.is_err());
}

#[test]
fn warm_succeeds_on_a_freshly_parsed_rsa_key_with_a_key_sized_buffer() {
    // Given
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, which is dropped before it.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let mut key = PrivateKey::new(X509::DER(RSA_KEY), None).unwrap();
    let mut signature = [0_u8; RSA_KEY_BYTES];

    // When
    let result = key.warm(&mut signature, tls.reference());

    // Then
    result.unwrap();
}

#[test]
fn warm_fails_on_an_rsa_key_when_the_buffer_is_one_byte_short() {
    // Given
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, which is dropped before it.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let mut key = PrivateKey::new(X509::DER(RSA_KEY), None).unwrap();
    let mut signature = [0_u8; RSA_KEY_BYTES - 1];

    // When
    let result = key.warm(&mut signature, tls.reference());

    // Then
    assert!(result.is_err());
}
