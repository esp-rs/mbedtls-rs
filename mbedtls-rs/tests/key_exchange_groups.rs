// Regenerate the fixtures with:
// openssl ecparam -name prime256v1 -genkey -noout -out key.pem
// openssl req -x509 -key key.pem -out cert.pem -sha256 -days 36500 -subj "/CN=mbedtls-rs.local" -addext "subjectAltName=DNS:mbedtls-rs.local"
// openssl x509 -in cert.pem -outform der -out cert.der
// openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out key.der

use core::convert::Infallible;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::sync::{Mutex, MutexGuard, PoisonError};

use mbedtls_rs::blocking::io::{ErrorKind, ErrorType, Read, Write};
use mbedtls_rs::blocking::Session;
use mbedtls_rs::sys::MbedtlsError;
use mbedtls_rs::{
    Certificate, ClientSessionConfig, Credentials, PrivateKey, ServerSessionConfig, SessionConfig,
    SessionError, Tls, TlsGroup, TlsReference, X509,
};
use rand::{Rng, TryCryptoRng, TryRng};

const CERTIFICATE: &[u8] = include_bytes!("fixtures/cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/key.der");
const PAYLOAD: &[u8] = b"real mbedtls-rs key exchange groups";
const MBEDTLS_ERR_SSL_BAD_INPUT_DATA: i32 = -0x7100;

static GROUPS: [TlsGroup; 1] = [TlsGroup::Secp256r1];

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

/// `embedded-io` adapter over a `std` TCP stream. Both `embedded_io::Error for
/// std::io::Error` and the `std::io::ErrorKind` conversion live behind the
/// `embedded-io` crate's `std` feature, which this crate does not enable, so the
/// stream reports an `ErrorKind` mapped by hand.
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

fn write_all<T: Read + Write>(session: &mut Session<'_, T>, mut buffer: &[u8]) {
    while !buffer.is_empty() {
        let written = session.write(buffer).unwrap();
        assert!(written > 0, "TLS stream accepted no bytes");
        buffer = &buffer[written..];
    }
}

fn read_exact<T: Read + Write>(session: &mut Session<'_, T>, mut buffer: &mut [u8]) {
    while !buffer.is_empty() {
        let read = session.read(buffer).unwrap();
        assert!(read > 0, "TLS stream reached EOF before the echo completed");
        buffer = &mut buffer[read..];
    }
}

fn server_config() -> SessionConfig<'static> {
    SessionConfig::Server(ServerSessionConfig::new(
        Credentials {
            certificate: Certificate::new_no_copy(CERTIFICATE).unwrap(),
            private_key: PrivateKey::new(X509::DER(PRIVATE_KEY), None).unwrap(),
        }
        .into(),
    ))
}

fn client_config() -> SessionConfig<'static> {
    SessionConfig::Client(ClientSessionConfig {
        ca_chain: Some(Certificate::new_no_copy(CERTIFICATE).unwrap()),
        server_name: Some(c"mbedtls-rs.local"),
        key_exchange_groups: Some(&GROUPS),
        ..ClientSessionConfig::new()
    })
}

fn idle_session_is_created(
    tls_reference: TlsReference<'_>,
    key_exchange_groups: Option<&[TlsGroup]>,
) -> Result<(), SessionError> {
    let config = SessionConfig::Client(ClientSessionConfig {
        key_exchange_groups,
        ..ClientSessionConfig::new()
    });

    Session::new(tls_reference, IdleStream, &config).map(drop)
}

#[test]
fn tls_groups_use_the_mbed_tls_iana_ids() {
    let groups = [
        (TlsGroup::Secp192k1, 18),
        (TlsGroup::Secp192r1, 19),
        (TlsGroup::Secp224k1, 20),
        (TlsGroup::Secp224r1, 21),
        (TlsGroup::Secp256k1, 22),
        (TlsGroup::Secp256r1, 23),
        (TlsGroup::Secp384r1, 24),
        (TlsGroup::Secp521r1, 25),
        (TlsGroup::BrainpoolP256r1, 26),
        (TlsGroup::BrainpoolP384r1, 27),
        (TlsGroup::BrainpoolP512r1, 28),
        (TlsGroup::X25519, 29),
        (TlsGroup::X448, 30),
        (TlsGroup::Ffdhe2048, 256),
        (TlsGroup::Ffdhe3072, 257),
        (TlsGroup::Ffdhe4096, 258),
        (TlsGroup::Ffdhe6144, 259),
        (TlsGroup::Ffdhe8192, 260),
    ];

    for (group, expected) in groups {
        assert_eq!(group as u16, expected);
    }
}

#[test]
fn client_defaults_leave_key_exchange_groups_unset() {
    assert_eq!(ClientSessionConfig::new().key_exchange_groups, None);
}

#[test]
fn empty_group_allowlist_is_rejected_at_session_creation() {
    let _serial = serialize_tls_lifetimes();
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    let error = idle_session_is_created(tls.reference(), Some(&[])).unwrap_err();

    assert_eq!(
        error,
        SessionError::MbedTls(MbedtlsError::new(MBEDTLS_ERR_SSL_BAD_INPUT_DATA))
    );
}

#[test]
fn session_with_a_group_allowlist_is_created_and_dropped() {
    let _serial = serialize_tls_lifetimes();
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    static ALLOWLIST: [TlsGroup; 2] = [TlsGroup::Secp256r1, TlsGroup::Secp384r1];
    let created = idle_session_is_created(tls.reference(), Some(&ALLOWLIST));

    assert!(created.is_ok(), "session creation failed: {created:?}");
}

#[test]
fn handshake_completes_with_a_group_allowlist() {
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
            session.connect().unwrap();
            let mut received = [0; PAYLOAD.len()];
            read_exact(&mut session, &mut received);
            assert_eq!(received, PAYLOAD);
            write_all(&mut session, &received);
            session.close().unwrap();
            let _ = client_done_receiver.recv();
        });
        let client = scope.spawn(move || {
            let stream = TcpStream::connect(address).unwrap();
            let mut session =
                Session::new(tls_reference, TcpEndpoint(stream), &client_config()).unwrap();
            session.connect().unwrap();
            write_all(&mut session, PAYLOAD);
            let mut echoed = [0; PAYLOAD.len()];
            read_exact(&mut session, &mut echoed);
            assert_eq!(echoed, PAYLOAD);
            session.close().unwrap();
            drop(client_done_sender);
        });

        server.join().unwrap();
        client.join().unwrap();
    });
}
