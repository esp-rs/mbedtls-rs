//! Behavioral lock for the async write-accounting drain (F-13 / PR #152).
//!
//! The real `MBio::write` / `drain_pending` / `wait_writable` plumbing on
//! `session::asynch` is private, and driving the public `Session::write` needs
//! the MbedTLS C library plus a live handshake and a partially-writable
//! transport to force `WANT_WRITE`, so (like `blocking_eof.rs` and
//! `cert_key_ctor_aliasing.rs`) this test re-creates the exact decision logic
//! the fix relies on. It does NOT call the real shims, so it cannot catch
//! production drift on its own; it pins the intended contract so a change to it
//! is a visible, reviewed edit to BOTH this file and `session/asynch.rs`.
//!
//! Properties locked:
//!
//! - `write_in_flight` is set when `mbedtls_ssl_write` returns `WANT_WRITE` and
//!   cleared only when a public SSL write returns `>= 0` (the real write or the
//!   zero-length drain). A dropped future leaves it set.
//! - `drain_pending` is a no-op when the flag is clear, so an idle `write` /
//!   `flush` / `close` never issues the zero-length `mbedtls_ssl_write` that
//!   would emit a spurious empty TLS record.
//! - After a cancelled write (flag left set), the next `write(B)` drains the old
//!   record first (returning nothing for it) and then reports only `B`'s own
//!   byte count - it never attributes the old record's bytes to `B`.

// Mirrors the real MbedTLS constants the fix matches on; hard-coding them keeps
// the test free of the sys crate while asserting the exact branch outcomes.
const MBEDTLS_ERR_SSL_WANT_WRITE: i32 = -0x6880;

/// Models MbedTLS's `out_left` (pending outgoing record) plus the wrapper's
/// `write_in_flight` guard, and how a sequence of `mbedtls_ssl_write` returns
/// drives them. `pending` stands in for `out_left != 0` inside MbedTLS.
struct WriteModel {
    /// Stand-in for MbedTLS `out_left != 0` (a record is buffered, not yet sent).
    pending: bool,
    /// The wrapper's `write_in_flight` guard.
    write_in_flight: bool,
}

impl WriteModel {
    fn new() -> Self {
        Self {
            pending: false,
            write_in_flight: false,
        }
    }

    /// Re-creation of one `mbedtls_ssl_write(buf, len)` call outcome.
    ///
    /// - `transport_ready`: whether the underlying transport can take the record
    ///   this call (if not, MbedTLS buffers it and returns `WANT_WRITE`).
    /// - Returns the value the wrapper observes: `WANT_WRITE` or `len`.
    ///
    /// When a record is already `pending`, MbedTLS flushes it and IGNORES the
    /// new buffer, returning `len` (clamped) - this is the misaccounting source
    /// the drain guards against.
    fn ssl_write(&mut self, len: usize, transport_ready: bool) -> i32 {
        if self.pending {
            // out_left != 0: flush the OLD record, ignore the new buffer.
            if transport_ready {
                self.pending = false;
                len as i32
            } else {
                MBEDTLS_ERR_SSL_WANT_WRITE
            }
        } else if len == 0 {
            // Idle zero-length write would emit an empty record; the wrapper must
            // never reach here unguarded (see `drain` below).
            0
        } else if transport_ready {
            len as i32
        } else {
            self.pending = true;
            MBEDTLS_ERR_SSL_WANT_WRITE
        }
    }

    /// Re-creation of `MBio::write`: drain first, then write `data`, maintaining
    /// the guard. `transport_ready` scripts the single retry outcome.
    fn write(&mut self, data_len: usize, transport_ready: bool) -> Result<usize, ()> {
        self.drain(transport_ready)?;

        loop {
            match self.ssl_write(data_len, transport_ready) {
                MBEDTLS_ERR_SSL_WANT_WRITE => {
                    self.write_in_flight = true;
                    // wait_writable would push the staged byte; the next retry is
                    // scripted by `transport_ready`. If it never becomes ready the
                    // real loop awaits; here one pass with a ready transport drains.
                    if !transport_ready {
                        return Err(());
                    }
                }
                other => {
                    // merr! would turn a negative into an error; >= 0 is a count.
                    let len = other as usize;
                    self.write_in_flight = false;
                    return Ok(len);
                }
            }
        }
    }

    /// Re-creation of `MBio::drain_pending`: only runs when the guard is set.
    fn drain(&mut self, transport_ready: bool) -> Result<(), ()> {
        if !self.write_in_flight {
            return Ok(());
        }

        loop {
            match self.ssl_write(0, transport_ready) {
                MBEDTLS_ERR_SSL_WANT_WRITE => {
                    if !transport_ready {
                        return Err(());
                    }
                }
                _other => {
                    // Any non-negative return means the pending record drained.
                    self.write_in_flight = false;
                    return Ok(());
                }
            }
        }
    }
}

#[test]
fn idle_drain_is_a_noop_and_emits_no_record() {
    let mut m = WriteModel::new();
    // No write in flight -> drain must not issue any zero-length write.
    assert!(m.drain(true).is_ok());
    assert!(!m.write_in_flight);
    assert!(!m.pending);
}

#[test]
fn want_write_sets_flag_then_completion_clears_it() {
    let mut m = WriteModel::new();

    // First attempt: transport not ready -> WANT_WRITE, flag set, record pending.
    assert_eq!(m.ssl_write(10, false), MBEDTLS_ERR_SSL_WANT_WRITE);
    m.write_in_flight = true;
    assert!(m.pending);

    // Resume with a ready transport: the pending record flushes, returns len.
    assert_eq!(m.ssl_write(10, true), 10);
    m.write_in_flight = false;
    assert!(!m.pending);
}

#[test]
fn cancelled_write_then_different_buffer_reports_only_new_bytes() {
    let mut m = WriteModel::new();

    // write(A) with A.len()=10 hits WANT_WRITE and is then "dropped":
    assert_eq!(m.ssl_write(10, false), MBEDTLS_ERR_SSL_WANT_WRITE);
    m.write_in_flight = true; // survives the dropped future
    assert!(m.pending); // A's record still inside MbedTLS

    // Next call is write(B) with B.len()=3 and a now-ready transport.
    let reported = m.write(3, true).expect("write succeeds");

    // The old record (A) was flushed by the drain, NOT attributed to B; the
    // call reports exactly B's own length.
    assert_eq!(reported, 3);
    assert!(!m.write_in_flight);
    assert!(!m.pending);
}

#[test]
fn straight_through_write_needs_no_drain_and_reports_its_length() {
    let mut m = WriteModel::new();
    // No prior in-flight write, transport ready: returns the buffer's length.
    assert_eq!(m.write(7, true).expect("write succeeds"), 7);
    assert!(!m.write_in_flight);
    assert!(!m.pending);
}
