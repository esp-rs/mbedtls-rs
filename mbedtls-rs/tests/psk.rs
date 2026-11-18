//! TLS sessions that authenticate with pre-shared keys, over localhost TCP.

use core::convert::Infallible;
use core::ffi::{c_int, c_uchar, c_void};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use mbedtls_rs::blocking::io::{ErrorKind, ErrorType, Read, Write};
use mbedtls_rs::blocking::Session;
use mbedtls_rs::sys::{
    mbedtls_ssl_context, mbedtls_ssl_set_hs_psk, MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
};
use mbedtls_rs::{
    Authentication, ClientSessionConfig, PskCallback, ServerSessionConfig, SessionConfig,
    SessionError, Tls, TlsVersion,
};
use rand::{Rng, TryCryptoRng, TryRng};

const PAYLOAD: &[u8] = b"real mbedtls-rs pre-shared key";

/// The keys of the server's clients.
const KEYS: &[(&[u8], &[u8])] = &[(b"device-1", &[0x11; 16]), (b"device-2", &[0x22; 32])];

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

struct TcpEndpoint(TcpStream);

impl ErrorType for TcpEndpoint {
    type Error = ErrorKind;
}

impl Read for TcpEndpoint {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        std::io::Read::read(&mut self.0, buffer).map_err(|_| ErrorKind::Other)
    }
}

impl Write for TcpEndpoint {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        std::io::Write::write(&mut self.0, buffer).map_err(|_| ErrorKind::Other)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        std::io::Write::flush(&mut self.0).map_err(|_| ErrorKind::Other)
    }
}

/// How the server knows its client's key.
#[derive(Clone, Copy)]
enum Server {
    /// One identity and its key.
    Key(&'static [u8], &'static [u8]),
    /// [`KEYS`], through [`lookup`].
    Lookup,
}

/// The `PskCallback` of [`Server::Lookup`].
unsafe extern "C" fn lookup(
    _ctx: *mut c_void,
    ssl: *mut mbedtls_ssl_context,
    identity: *const c_uchar,
    identity_len: usize,
) -> c_int {
    let identity = unsafe { core::slice::from_raw_parts(identity, identity_len) };

    match KEYS.iter().find(|(name, _)| *name == identity) {
        Some((_, key)) => unsafe { mbedtls_ssl_set_hs_psk(ssl, key.as_ptr(), key.len()) },
        None => -1,
    }
}

/// Hand-shake with `identity` and `key`, then echo [`PAYLOAD`].
///
/// # Returns
/// - The client's handshake result, and the version it negotiated.
fn handshake(
    identity: &'static [u8],
    key: &'static [u8],
    server: Server,
    max_version: Option<TlsVersion>,
) -> Result<Option<TlsVersion>, SessionError> {
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
        scope.spawn(move || {
            let authentication = match server {
                Server::Key(identity, key) => Authentication::Psk { identity, key },
                Server::Lookup => Authentication::PskLookup(PskCallback {
                    f: lookup,
                    p_ctx: core::ptr::null_mut(),
                }),
            };
            let config = SessionConfig::Server(ServerSessionConfig::new(authentication));

            let (stream, _peer) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut session = Session::new(tls_reference, TcpEndpoint(stream), &config).unwrap();

            if session.connect().is_ok() {
                let mut received = [0; PAYLOAD.len()];
                session.read_exact(&mut received).unwrap();
                session.write_all(&received).unwrap();
                session.close().unwrap();
                let _ = client_done_receiver.recv();
            }
        });

        let client = scope.spawn(move || {
            let config = SessionConfig::Client(ClientSessionConfig {
                authentication: Some(Authentication::Psk { identity, key }),
                max_version,
                ..ClientSessionConfig::new()
            });

            let stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut session = Session::new(tls_reference, TcpEndpoint(stream), &config).unwrap();

            let result = session.connect();
            let version = session.tls_version();
            if result.is_ok() {
                session.write_all(PAYLOAD).unwrap();
                let mut echoed = [0; PAYLOAD.len()];
                session.read_exact(&mut echoed).unwrap();
                assert_eq!(echoed, PAYLOAD);
                session.close().unwrap();
            }

            drop(session);
            drop(client_done_sender);
            result.map(|()| version)
        });

        client.join().unwrap()
    })
}

#[test]
fn tls12_with_a_key() {
    let (identity, key) = KEYS[0];

    assert_eq!(
        handshake(
            identity,
            key,
            Server::Key(identity, key),
            Some(TlsVersion::Tls1_2)
        ),
        Ok(Some(TlsVersion::Tls1_2))
    );
}

#[test]
fn tls13_with_a_key() {
    let (identity, key) = KEYS[0];

    assert_eq!(
        handshake(identity, key, Server::Key(identity, key), None),
        Ok(Some(TlsVersion::Tls1_3))
    );
}

#[test]
fn server_looks_the_key_up() {
    let (identity, key) = KEYS[1];

    for max_version in [Some(TlsVersion::Tls1_2), None] {
        assert!(handshake(identity, key, Server::Lookup, max_version).is_ok());
    }
}

#[test]
fn fails_with_another_key() {
    let (identity, key) = KEYS[0];

    for max_version in [Some(TlsVersion::Tls1_2), None] {
        assert!(handshake(identity, KEYS[1].1, Server::Key(identity, key), max_version).is_err());
        assert!(handshake(identity, KEYS[1].1, Server::Lookup, max_version).is_err());
    }
}

#[test]
fn fails_with_an_unknown_identity() {
    let (identity, key) = KEYS[0];

    for max_version in [Some(TlsVersion::Tls1_2), None] {
        assert!(handshake(b"device-9", key, Server::Key(identity, key), max_version).is_err());
        assert!(handshake(b"device-9", key, Server::Lookup, max_version).is_err());
    }
}

#[test]
fn a_client_cannot_look_keys_up() {
    let _serial = serialize_tls_lifetimes();
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();

    let config = SessionConfig::Client(ClientSessionConfig {
        authentication: Some(Authentication::PskLookup(PskCallback {
            f: lookup,
            p_ctx: core::ptr::null_mut(),
        })),
        ..ClientSessionConfig::new()
    });

    assert!(matches!(
        Session::new(tls.reference(), TcpEndpoint(stream), &config),
        Err(SessionError::MbedTls(e)) if e.code() == MBEDTLS_ERR_SSL_BAD_INPUT_DATA
    ));
}
