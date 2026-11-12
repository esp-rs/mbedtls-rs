// Regenerate the fixtures with:
// openssl ecparam -name prime256v1 -genkey -noout -out key.pem
// openssl req -x509 -key key.pem -out cert.pem -sha256 -days 36500 -subj "/CN=mbedtls-rs.local" -addext "subjectAltName=DNS:mbedtls-rs.local"
// openssl x509 -in cert.pem -outform der -out cert.der
// openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out key.der

use core::cell::RefCell;
use core::convert::Infallible;
use core::ffi::{c_int, c_void, CStr};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::sync::{Mutex, MutexGuard, PoisonError};

use mbedtls_rs::blocking::io::{ErrorKind, ErrorType, Read, Write};
use mbedtls_rs::blocking::Session;
use mbedtls_rs::sys::{
    mbedtls_x509_crt, MbedtlsError, MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
    MBEDTLS_ERR_X509_CERT_VERIFY_FAILED, MBEDTLS_ERR_X509_FATAL_ERROR,
    MBEDTLS_X509_BADCERT_CN_MISMATCH, MBEDTLS_X509_BADCERT_NOT_TRUSTED,
};
use mbedtls_rs::{
    Certificate, ClientSessionConfig, Credentials, PrivateKey, ServerSessionConfig, SessionConfig,
    SessionError, Tls, VerifyCallback, X509,
};
use rand::{Rng, TryCryptoRng, TryRng};

const CERTIFICATE: &[u8] = include_bytes!("fixtures/cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/key.der");
const PAYLOAD: &[u8] = b"real mbedtls-rs verify callback";

// Tls owns a process-global RNG callback, so tests must not overlap Tls lifetimes.
static SERIAL: Mutex<()> = Mutex::new(());

fn serialize_tls_lifetimes() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

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

/// A stream that never carries any bytes, for the session-creation-only tests.
struct IdleStream;

impl ErrorType for IdleStream {
    type Error = Infallible;
}

impl Read for IdleStream {
    fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

impl Write for IdleStream {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// `embedded-io` adapter over a `std` TCP stream, with the `ErrorKind` mapped
/// by hand (the `embedded-io` `std` feature is not enabled for this crate).
struct TcpEndpoint(TcpStream);

fn io_error_kind(error: std::io::Error) -> ErrorKind {
    match error.kind() {
        std::io::ErrorKind::BrokenPipe => ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionAborted => ErrorKind::ConnectionAborted,
        std::io::ErrorKind::ConnectionReset => ErrorKind::ConnectionReset,
        std::io::ErrorKind::Interrupted => ErrorKind::Interrupted,
        std::io::ErrorKind::NotConnected => ErrorKind::NotConnected,
        std::io::ErrorKind::TimedOut => ErrorKind::TimedOut,
        _ => ErrorKind::Other,
    }
}

impl ErrorType for TcpEndpoint {
    type Error = ErrorKind;
}

impl Read for TcpEndpoint {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        std::io::Read::read(&mut self.0, buffer).map_err(io_error_kind)
    }
}

impl Write for TcpEndpoint {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        std::io::Write::write(&mut self.0, buffer).map_err(io_error_kind)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        std::io::Write::flush(&mut self.0).map_err(io_error_kind)
    }
}

/// What the callback does with the flags it gets, and what it saw.
struct Observer {
    /// The flags that the callback clears at depth 0.
    clear: u32,
    /// `(depth, flags as received)` for every call.
    seen: RefCell<Vec<(c_int, u32)>>,
}

impl Observer {
    fn new(clear: u32) -> Self {
        Self {
            clear,
            seen: RefCell::new(Vec::new()),
        }
    }

    fn callback(&self) -> VerifyCallback {
        VerifyCallback {
            f: observe,
            p_ctx: self as *const Self as *mut c_void,
        }
    }
}

unsafe extern "C" fn observe(
    p_ctx: *mut c_void,
    _crt: *mut mbedtls_x509_crt,
    depth: c_int,
    flags: *mut u32,
) -> c_int {
    let observer = unsafe { &*(p_ctx as *const Observer) };
    // No panic path: a panic cannot unwind out of an `extern "C"` function.
    let Ok(mut seen) = observer.seen.try_borrow_mut() else {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    };
    seen.push((depth, unsafe { *flags }));
    if depth == 0 {
        unsafe { *flags &= !observer.clear };
    }
    0
}

fn server_config() -> SessionConfig<'static> {
    SessionConfig::Server(ServerSessionConfig::new(Credentials {
        certificate: Certificate::new_no_copy(CERTIFICATE).unwrap(),
        private_key: PrivateKey::new(X509::DER(PRIVATE_KEY), None).unwrap(),
    }))
}

fn idle_session(config: &SessionConfig<'_>) -> Result<(), SessionError> {
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and the session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    Session::new(tls.reference(), IdleStream, config).map(drop)
}

/// Runs a real handshake against the fixture server and echoes a payload. The
/// client has a verify callback that clears `clear` at depth 0 and, if
/// `ca_chain` is true, trusts the fixture certificate through `ca_chain`.
/// Returns the client's handshake result and what the callback saw.
fn handshake(
    ca_chain: bool,
    server_name: &'static CStr,
    clear: u32,
) -> (Result<(), SessionError>, Vec<(c_int, u32)>) {
    let _serial = serialize_tls_lifetimes();
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let tls_reference = tls.reference();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    // The client signals completion by dropping its sender, so the server keeps
    // its TCP stream open until the client has sent its own close notify.
    let (client_done_sender, client_done_receiver) = channel::<()>();

    std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, _peer) = listener.accept().unwrap();
            let mut session =
                Session::new(tls_reference, TcpEndpoint(stream), &server_config()).unwrap();
            // The server fails too when the client rejects its certificate.
            if session.connect().is_ok() {
                let mut received = [0; PAYLOAD.len()];
                session.read_exact(&mut received).unwrap();
                session.write_all(&received).unwrap();
                session.close().unwrap();
            }
            let _ = client_done_receiver.recv();
        });
        let client = scope.spawn(move || {
            let observer = Observer::new(clear);
            let config = SessionConfig::Client(ClientSessionConfig {
                ca_chain: ca_chain.then(|| Certificate::new_no_copy(CERTIFICATE).unwrap()),
                server_name: Some(server_name),
                verify_callback: Some(observer.callback()),
                ..ClientSessionConfig::new()
            });
            let stream = TcpStream::connect(address).unwrap();
            let mut session = Session::new(tls_reference, TcpEndpoint(stream), &config).unwrap();
            let result = session.connect();
            if result.is_ok() {
                session.write_all(PAYLOAD).unwrap();
                let mut echoed = [0; PAYLOAD.len()];
                session.read_exact(&mut echoed).unwrap();
                assert_eq!(echoed, PAYLOAD);
                session.close().unwrap();
            }
            drop(session);
            drop(client_done_sender);
            (result, observer.seen.take())
        });

        server.join().unwrap();
        client.join().unwrap()
    })
}

#[test]
fn client_verify_callback_with_ca_chain_is_accepted() {
    let _serial = serialize_tls_lifetimes();
    let observer = Observer::new(0);
    let config = SessionConfig::Client(ClientSessionConfig {
        ca_chain: Some(Certificate::new_no_copy(CERTIFICATE).unwrap()),
        verify_callback: Some(observer.callback()),
        ..ClientSessionConfig::new()
    });

    let created = idle_session(&config);

    assert!(created.is_ok(), "session creation failed: {created:?}");
}

#[test]
fn server_verify_callback_with_ca_chain_is_accepted() {
    let _serial = serialize_tls_lifetimes();
    let observer = Observer::new(0);
    let SessionConfig::Server(mut server) = server_config() else {
        unreachable!()
    };
    server.ca_chain = Some(Certificate::new_no_copy(CERTIFICATE).unwrap());
    server.verify_callback = Some(observer.callback());

    let created = idle_session(&SessionConfig::Server(server));

    assert!(created.is_ok(), "session creation failed: {created:?}");
}

#[test]
fn verify_callback_with_skip_hostname_verification_is_rejected() {
    let _serial = serialize_tls_lifetimes();
    let observer = Observer::new(0);
    let config = SessionConfig::Client(ClientSessionConfig {
        skip_hostname_verification: true,
        verify_callback: Some(observer.callback()),
        ..ClientSessionConfig::new()
    });

    let error = idle_session(&config).unwrap_err();

    assert_eq!(
        error,
        SessionError::MbedTls(MbedtlsError::new(MBEDTLS_ERR_SSL_BAD_INPUT_DATA))
    );
}

/// The callback gets the verdict of the verification against `ca_chain`: no
/// flags for a certificate that `ca_chain` trusts. Without `ca_chain`, the
/// same certificate gets `MBEDTLS_X509_BADCERT_NOT_TRUSTED`, see
/// `callback_alone_gets_not_trusted_from_the_placeholder_ca_chain`.
#[test]
fn callback_gets_the_ca_chain_verdict() {
    let (result, seen) = handshake(true, c"mbedtls-rs.local", 0);

    assert_eq!(result, Ok(()));
    assert_eq!(seen, [(0, 0)]);
}

/// A callback that returns `0` and leaves the flags keeps the verdict of the
/// verification against `ca_chain`.
#[test]
fn ca_chain_verdict_stands_when_the_callback_keeps_the_flags() {
    let (result, seen) = handshake(true, c"other.local", 0);

    assert_eq!(
        result,
        Err(SessionError::MbedTls(MbedtlsError::new(
            MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
        )))
    );
    assert_eq!(seen, [(0, MBEDTLS_X509_BADCERT_CN_MISMATCH)]);
}

/// A callback can change the verdict, for example to skip the hostname check
/// (in place of `skip_hostname_verification`).
#[test]
fn callback_can_clear_a_flag_of_the_ca_chain_verdict() {
    let (result, seen) = handshake(true, c"other.local", MBEDTLS_X509_BADCERT_CN_MISMATCH);

    assert_eq!(result, Ok(()));
    assert_eq!(seen, [(0, MBEDTLS_X509_BADCERT_CN_MISMATCH)]);
}

/// Without `ca_chain`, the callback gets the verdict against the placeholder
/// CA chain: the fixture certificate is not trusted, and the handshake fails
/// if the callback keeps the flag. This is the behavior of #187.
#[test]
fn callback_alone_gets_not_trusted_from_the_placeholder_ca_chain() {
    let (result, seen) = handshake(false, c"mbedtls-rs.local", 0);

    assert_eq!(
        result,
        Err(SessionError::MbedTls(MbedtlsError::new(
            MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
        )))
    );
    assert_eq!(seen, [(0, MBEDTLS_X509_BADCERT_NOT_TRUSTED)]);
}

/// Without `ca_chain`, the callback is the only source of trust: when it
/// clears `MBEDTLS_X509_BADCERT_NOT_TRUSTED`, the handshake completes.
#[test]
fn callback_alone_can_accept_the_certificate() {
    let (result, seen) = handshake(false, c"mbedtls-rs.local", MBEDTLS_X509_BADCERT_NOT_TRUSTED);

    assert_eq!(result, Ok(()));
    assert_eq!(seen, [(0, MBEDTLS_X509_BADCERT_NOT_TRUSTED)]);
}
