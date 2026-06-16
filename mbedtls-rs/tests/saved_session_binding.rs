//! Behavioral lock for the saved-session peer-binding check (F-34).
//!
//! `check_saved_session_server_name` is `pub(crate)` and the comparison runs
//! inside `connect_internal` behind a TLS handshake (needs the MbedTLS C library
//! plus a live peer), so (like `rng_ffi.rs` / `blocking_eof.rs`) this test
//! re-creates the exact decision logic the fix relies on rather than calling the
//! real function. It does NOT exercise the real shim, so it cannot catch
//! production drift on its own; it pins the intended contract so a change is a
//! visible, reviewed edit to BOTH this file and `session.rs`.
//!
//! Contract: a saved session may only be resumed against the same configured
//! server name. A mismatch (including `None` vs `Some`) is rejected with
//! `MBEDTLS_ERR_SSL_BAD_INPUT_DATA`, reusing the existing error path rather than
//! a new `SessionError` variant.

// Mirrors the real MbedTLS constant the fix returns on mismatch.
const MBEDTLS_ERR_SSL_BAD_INPUT_DATA: i32 = -0x7100;

/// Re-creation of `check_saved_session_server_name`: `Ok(())` if the saved and
/// current server names are equal, otherwise the `BAD_INPUT_DATA` error code.
fn check(saved: &Option<Vec<u8>>, current: &Option<Vec<u8>>) -> Result<(), i32> {
    if saved == current {
        Ok(())
    } else {
        Err(MBEDTLS_ERR_SSL_BAD_INPUT_DATA)
    }
}

#[test]
fn different_server_names_are_rejected() {
    let saved = Some(b"a.example\0".to_vec());
    let current = Some(b"b.example\0".to_vec());
    assert_eq!(check(&saved, &current), Err(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
}

#[test]
fn matching_server_names_are_accepted() {
    let saved = Some(b"a.example\0".to_vec());
    let current = Some(b"a.example\0".to_vec());
    assert_eq!(check(&saved, &current), Ok(()));
}

#[test]
fn nameless_saved_into_named_is_rejected() {
    // A session saved with no server name carries no peer binding and must not
    // silently resume into a named session.
    let saved = None;
    let current = Some(b"a.example\0".to_vec());
    assert_eq!(check(&saved, &current), Err(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
}

#[test]
fn named_saved_into_nameless_is_rejected() {
    let saved = Some(b"a.example\0".to_vec());
    let current = None;
    assert_eq!(check(&saved, &current), Err(MBEDTLS_ERR_SSL_BAD_INPUT_DATA));
}

#[test]
fn both_nameless_is_accepted() {
    // Equally-nameless is the only case where a no-binding session may resume.
    let saved: Option<Vec<u8>> = None;
    let current: Option<Vec<u8>> = None;
    assert_eq!(check(&saved, &current), Ok(()));
}
