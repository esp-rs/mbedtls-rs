//! Behavioral lock for the blocking BIO EOF / error mapping (F-11 + F-10).
//!
//! The real `bio_receive` / `bio_send` / `last_io_err` plumbing on
//! `session::blocking::Session` is private, and driving the public
//! `Session::read` needs the MbedTLS C library plus a live handshake, so this
//! test re-creates the exact decision logic the fix relies on over a mock
//! `embedded-io` stream (mirroring how `async_split_aliasing.rs` re-creates the
//! provenance pattern). It locks two properties:
//!
//! - F-11: a stream `Ok(0)` (EOF for a non-empty buffer per the `embedded-io`
//!   contract) maps to `MBEDTLS_ERR_SSL_CONN_EOF`, NOT `WANT_READ` (which made
//!   the blocking read loop spin forever against a closed peer).
//! - F-10: a stream `Err` is recorded as its real `ErrorKind` and surfaced,
//!   instead of being swallowed as a clean `0` (= EOF to MbedTLS).
//!
//! It also models the `read`-loop arm: drain the captured kind first, then map
//! the `0` that MbedTLS returns on a BIO `CONN_EOF` to `ConnectionReset`.

use embedded_io::{Error, ErrorKind, ErrorType, Read, Write};

// These mirror the real MbedTLS constants used by the fix; hard-coding them
// keeps the test free of the sys crate while asserting the exact values the
// production code returns.
const MBEDTLS_ERR_SSL_CONN_EOF: i32 = -29312;
const MBEDTLS_ERR_SSL_WANT_READ: i32 = -26880;

/// A mock stream whose `read`/`write` outcome is scripted per call.
struct MockStream {
    read_result: Result<usize, ErrorKind>,
    write_result: Result<usize, ErrorKind>,
}

impl ErrorType for MockStream {
    type Error = ErrorKind;
}

impl Read for MockStream {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, ErrorKind> {
        self.read_result
    }
}

impl Write for MockStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorKind> {
        self.write_result.map(|n| n.min(buf.len()))
    }

    fn flush(&mut self) -> Result<(), ErrorKind> {
        Ok(())
    }
}

/// Re-creation of `Session::bio_receive`'s decision logic.
fn bio_receive(stream: &mut MockStream, last_io_err: &mut Option<ErrorKind>) -> i32 {
    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        Ok(0) => MBEDTLS_ERR_SSL_CONN_EOF,
        Ok(len) => len as i32,
        Err(e) => {
            *last_io_err = Some(e.kind());
            MBEDTLS_ERR_SSL_CONN_EOF
        }
    }
}

/// Re-creation of `Session::bio_send`'s decision logic.
fn bio_send(stream: &mut MockStream, last_io_err: &mut Option<ErrorKind>) -> i32 {
    match stream.write(b"payload") {
        Ok(0) => {
            *last_io_err = Some(ErrorKind::WriteZero);
            MBEDTLS_ERR_SSL_CONN_EOF
        }
        Ok(written) => written as i32,
        Err(e) => {
            *last_io_err = Some(e.kind());
            MBEDTLS_ERR_SSL_CONN_EOF
        }
    }
}

/// Re-creation of the blocking `read` loop's terminal-arm mapping, given the
/// value MbedTLS returns (0 on a BIO `CONN_EOF`) and any captured kind.
fn map_read_result(
    mbedtls_ret: i32,
    last_io_err: &mut Option<ErrorKind>,
) -> Result<usize, ErrorKind> {
    if let Some(kind) = last_io_err.take() {
        return Err(kind);
    }
    if mbedtls_ret == 0 {
        return Err(ErrorKind::ConnectionReset);
    }
    Ok(mbedtls_ret as usize)
}

#[test]
fn eof_maps_to_conn_eof_not_want_read() {
    let mut stream = MockStream {
        read_result: Ok(0),
        write_result: Ok(7),
    };
    let mut last_io_err = None;

    let ret = bio_receive(&mut stream, &mut last_io_err);

    assert_eq!(ret, MBEDTLS_ERR_SSL_CONN_EOF);
    assert_ne!(ret, MBEDTLS_ERR_SSL_WANT_READ); // the old spin-causing value
    assert_eq!(last_io_err, None); // EOF is not a stream error
}

#[test]
fn read_error_is_captured_and_surfaced() {
    let mut stream = MockStream {
        read_result: Err(ErrorKind::ConnectionReset),
        write_result: Ok(7),
    };
    let mut last_io_err = None;

    let ret = bio_receive(&mut stream, &mut last_io_err);

    assert_eq!(ret, MBEDTLS_ERR_SSL_CONN_EOF);
    assert_eq!(last_io_err, Some(ErrorKind::ConnectionReset));
}

#[test]
fn read_loop_surfaces_captured_error_before_eof() {
    // A captured stream error wins over the bare `0` from MbedTLS.
    let mut last_io_err = Some(ErrorKind::ConnectionReset);
    assert_eq!(
        map_read_result(0, &mut last_io_err),
        Err(ErrorKind::ConnectionReset)
    );
    assert_eq!(last_io_err, None); // drained
}

#[test]
fn read_loop_maps_bare_zero_to_connection_reset() {
    // Abrupt half-close with no captured error: MbedTLS returns 0 -> ConnectionReset.
    let mut last_io_err = None;
    assert_eq!(
        map_read_result(0, &mut last_io_err),
        Err(ErrorKind::ConnectionReset)
    );
}

#[test]
fn read_loop_passes_through_positive_length() {
    let mut last_io_err = None;
    assert_eq!(map_read_result(5, &mut last_io_err), Ok(5));
}

#[test]
fn write_zero_is_captured_as_write_zero() {
    let mut stream = MockStream {
        read_result: Ok(0),
        write_result: Ok(0),
    };
    let mut last_io_err = None;

    let ret = bio_send(&mut stream, &mut last_io_err);

    assert_eq!(ret, MBEDTLS_ERR_SSL_CONN_EOF);
    assert_eq!(last_io_err, Some(ErrorKind::WriteZero));
}

#[test]
fn write_error_is_captured_and_surfaced() {
    let mut stream = MockStream {
        read_result: Ok(0),
        write_result: Err(ErrorKind::BrokenPipe),
    };
    let mut last_io_err = None;

    let ret = bio_send(&mut stream, &mut last_io_err);

    assert_eq!(ret, MBEDTLS_ERR_SSL_CONN_EOF);
    assert_eq!(last_io_err, Some(ErrorKind::BrokenPipe));
}

/// Re-creation of `Session::read`'s entry guards that short-circuit before the
/// MbedTLS read loop (the `eof` flag and the empty-buffer case).
fn read_entry(eof: bool, buf_is_empty: bool) -> Option<Result<usize, ErrorKind>> {
    if eof {
        return Some(Ok(0));
    }
    if buf_is_empty {
        return Some(Ok(0));
    }
    None
}

#[test]
fn empty_buffer_short_circuits_to_ok_zero() {
    // A zero-length read returns Ok(0) without entering the loop, so it can
    // never be misreported as ConnectionReset by the `other == 0` arm.
    assert_eq!(read_entry(false, true), Some(Ok(0)));
}

#[test]
fn non_empty_buffer_enters_loop() {
    assert_eq!(read_entry(false, false), None);
}

#[test]
fn eof_flag_short_circuits_to_ok_zero() {
    assert_eq!(read_entry(true, false), Some(Ok(0)));
}

/// Re-creation of `Session::close`'s terminal mapping: a captured I/O kind wins
/// over the raw MbedTLS close-notify return code.
fn map_close_result(
    mbedtls_ret: i32,
    last_io_err: &mut Option<ErrorKind>,
) -> Result<(), ErrorKind> {
    if let Some(kind) = last_io_err.take() {
        return Err(kind);
    }
    // `merr!` turns a negative code into an error; 0 is success.
    if mbedtls_ret < 0 {
        return Err(ErrorKind::Other);
    }
    Ok(())
}

#[test]
fn close_surfaces_captured_io_error() {
    // A transport failure while sending close-notify surfaces as the real kind,
    // not the opaque MbedTLS code.
    let mut last_io_err = Some(ErrorKind::BrokenPipe);
    assert_eq!(
        map_close_result(MBEDTLS_ERR_SSL_CONN_EOF, &mut last_io_err),
        Err(ErrorKind::BrokenPipe)
    );
    assert_eq!(last_io_err, None); // drained
}

#[test]
fn close_without_io_error_is_ok() {
    let mut last_io_err = None;
    assert_eq!(map_close_result(0, &mut last_io_err), Ok(()));
}
