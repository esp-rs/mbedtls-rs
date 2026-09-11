// Regenerate the fixtures with:
// openssl ecparam -name prime256v1 -genkey -noout -out key.pem
// openssl req -x509 -key key.pem -out cert.pem -sha256 -days 36500 -subj "/CN=mbedtls-rs.local" -addext "subjectAltName=DNS:mbedtls-rs.local"
// openssl x509 -in cert.pem -outform der -out cert.der
// openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out key.der

use core::convert::Infallible;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::Wake;

use mbedtls_rs::blocking::io::{
    ErrorType as BlockingErrorType, Read as BlockingRead, Write as BlockingWrite,
};
use mbedtls_rs::blocking::Session as BlockingSession;
use mbedtls_rs::io::{ErrorType as AsyncErrorType, Read as AsyncRead, Write as AsyncWrite};
use mbedtls_rs::{
    Certificate, ClientSessionConfig, Credentials, PrivateKey, ServerSessionConfig,
    Session as AsyncSession, SessionConfig, Tls, TlsReference, TlsVersion, X509,
};
use rand::{Rng, TryCryptoRng, TryRng};

const CERTIFICATE: &[u8] = include_bytes!("fixtures/cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/key.der");
const PAYLOAD: &[u8] = b"real mbedtls-rs loopback";
const DRIVER_ITERATION_LIMIT: usize = 1_000_000;

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

fn client_session_config(maximum_version: Option<TlsVersion>) -> ClientSessionConfig<'static> {
    ClientSessionConfig {
        ca_chain: Some(Certificate::new_no_copy(CERTIFICATE).unwrap()),
        server_name: Some(c"mbedtls-rs.local"),
        max_version: maximum_version,
        ..ClientSessionConfig::new()
    }
}

fn client_config(maximum_version: Option<TlsVersion>) -> SessionConfig<'static> {
    SessionConfig::Client(client_session_config(maximum_version))
}

fn server_config() -> SessionConfig<'static> {
    let certificate = Certificate::new_no_copy(CERTIFICATE).unwrap();
    SessionConfig::Server(ServerSessionConfig::new(Credentials {
        certificate,
        private_key: PrivateKey::new(X509::DER(PRIVATE_KEY), None).unwrap(),
    }))
}

/// A completed handshake must report a version, and a client cap must be exactly
/// what gets negotiated - the loopback server offers every version the client can
/// ask for. Called on each end, so both peers are held to the same expectation.
fn assert_negotiated_version(version: Option<TlsVersion>, maximum_version: Option<TlsVersion>) {
    assert!(
        version.is_some(),
        "no version reported after a successful handshake"
    );
    if maximum_version.is_some() {
        assert_eq!(
            version, maximum_version,
            "the negotiated version does not match the client's cap"
        );
    }
}

#[derive(Debug, Default)]
struct AsyncDirection {
    bytes: RefCell<VecDeque<u8>>,
    closed: Cell<bool>,
}

#[derive(Debug)]
struct AsyncEndpoint {
    incoming: Rc<AsyncDirection>,
    outgoing: Rc<AsyncDirection>,
}

fn async_pipe() -> (AsyncEndpoint, AsyncEndpoint) {
    let client_to_server = Rc::new(AsyncDirection::default());
    let server_to_client = Rc::new(AsyncDirection::default());

    (
        AsyncEndpoint {
            incoming: server_to_client.clone(),
            outgoing: client_to_server.clone(),
        },
        AsyncEndpoint {
            incoming: client_to_server,
            outgoing: server_to_client,
        },
    )
}

impl AsyncErrorType for AsyncEndpoint {
    type Error = Infallible;
}

impl AsyncRead for AsyncEndpoint {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        // The round-robin driver polls both peers, so deliberately omitting wake
        // registration keeps its wake counter specific to TLS cooperation.
        poll_fn(|_| {
            let mut bytes = self.incoming.bytes.borrow_mut();
            if bytes.is_empty() && !self.incoming.closed.get() && !buffer.is_empty() {
                return Poll::Pending;
            }

            let length = buffer.len().min(bytes.len());
            for (destination, byte) in buffer.iter_mut().zip(bytes.drain(..length)) {
                *destination = byte;
            }
            Poll::Ready(Ok(length))
        })
        .await
    }
}

impl AsyncWrite for AsyncEndpoint {
    async fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        self.outgoing.bytes.borrow_mut().extend(buffer);
        Ok(buffer.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Drop for AsyncEndpoint {
    fn drop(&mut self) {
        self.outgoing.closed.set(true);
    }
}

struct CountingWake(AtomicUsize);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn drive_pair<ClientFuture, ServerFuture>(
    client_future: ClientFuture,
    server_future: ServerFuture,
    client_wake: Arc<CountingWake>,
) -> (ClientFuture::Output, ServerFuture::Output)
where
    ClientFuture: Future,
    ServerFuture: Future,
{
    let mut client_future = pin!(client_future);
    let mut server_future = pin!(server_future);
    let client_waker = Waker::from(client_wake);
    let mut client_context = Context::from_waker(&client_waker);
    let mut server_context = Context::from_waker(Waker::noop());
    let mut client_output = None;
    let mut server_output = None;

    for _ in 0..DRIVER_ITERATION_LIMIT {
        if client_output.is_none() {
            if let Poll::Ready(output) = client_future.as_mut().poll(&mut client_context) {
                client_output = Some(output);
            }
        }
        if server_output.is_none() {
            if let Poll::Ready(output) = server_future.as_mut().poll(&mut server_context) {
                server_output = Some(output);
            }
        }
        match (client_output.take(), server_output.take()) {
            (Some(client_output), Some(server_output)) => {
                return (client_output, server_output);
            }
            (client, server) => {
                client_output = client;
                server_output = server;
            }
        }
    }

    panic!("loopback futures did not complete within {DRIVER_ITERATION_LIMIT} polls");
}

async fn async_write_all<T>(session: &mut AsyncSession<'_, T>, mut data: &[u8])
where
    T: AsyncRead + AsyncWrite,
{
    while !data.is_empty() {
        let written = session.write(data).await.unwrap();
        assert!(written > 0, "TLS write made no progress");
        data = &data[written..];
    }
}

async fn async_read_exact<T>(session: &mut AsyncSession<'_, T>, mut buffer: &mut [u8])
where
    T: AsyncRead + AsyncWrite,
{
    while !buffer.is_empty() {
        let read = session.read(buffer).await.unwrap();
        assert!(read > 0, "TLS stream reached EOF before the echo completed");
        buffer = &mut buffer[read..];
    }
}

fn run_async_loopback(
    tls_reference: TlsReference<'_>,
    maximum_version: Option<TlsVersion>,
) -> usize {
    let (client_stream, server_stream) = async_pipe();
    let mut client = AsyncSession::new(
        tls_reference,
        client_stream,
        &client_config(maximum_version),
    )
    .unwrap();
    let mut server = AsyncSession::new(tls_reference, server_stream, &server_config()).unwrap();

    assert_eq!(
        client.tls_version(),
        None,
        "a version was reported before the handshake"
    );

    let handshake_wake = Arc::new(CountingWake(AtomicUsize::new(0)));
    let (client_result, server_result) =
        drive_pair(client.connect(), server.connect(), handshake_wake.clone());
    client_result.unwrap();
    server_result.unwrap();

    assert_eq!(
        client.tls_version(),
        server.tls_version(),
        "peers disagree on the negotiated version"
    );
    assert_negotiated_version(client.tls_version(), maximum_version);

    let echo_wake = Arc::new(CountingWake(AtomicUsize::new(0)));
    let client_echo = async {
        async_write_all(&mut client, PAYLOAD).await;
        let mut echoed = [0; PAYLOAD.len()];
        async_read_exact(&mut client, &mut echoed).await;
        assert_eq!(echoed, PAYLOAD);
    };
    let server_echo = async {
        let mut received = [0; PAYLOAD.len()];
        async_read_exact(&mut server, &mut received).await;
        assert_eq!(received, PAYLOAD);
        async_write_all(&mut server, &received).await;
    };
    drive_pair(client_echo, server_echo, echo_wake);

    let close_wake = Arc::new(CountingWake(AtomicUsize::new(0)));
    let (client_result, server_result) = drive_pair(client.close(), server.close(), close_wake);
    client_result.unwrap();
    server_result.unwrap();

    handshake_wake.0.load(Ordering::Relaxed)
}

#[derive(Debug, Default)]
struct BlockingState {
    bytes: VecDeque<u8>,
    closed: bool,
}

type BlockingDirection = Arc<(Mutex<BlockingState>, Condvar)>;

#[derive(Debug)]
struct BlockingEndpoint {
    incoming: BlockingDirection,
    outgoing: BlockingDirection,
}

fn blocking_pipe() -> (BlockingEndpoint, BlockingEndpoint) {
    let client_to_server = Arc::new((Mutex::new(BlockingState::default()), Condvar::new()));
    let server_to_client = Arc::new((Mutex::new(BlockingState::default()), Condvar::new()));

    (
        BlockingEndpoint {
            incoming: server_to_client.clone(),
            outgoing: client_to_server.clone(),
        },
        BlockingEndpoint {
            incoming: client_to_server,
            outgoing: server_to_client,
        },
    )
}

impl BlockingErrorType for BlockingEndpoint {
    type Error = Infallible;
}

impl BlockingRead for BlockingEndpoint {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        let (state, ready) = &*self.incoming;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        while state.bytes.is_empty() && !state.closed && !buffer.is_empty() {
            state = ready.wait(state).unwrap_or_else(|error| error.into_inner());
        }

        let length = buffer.len().min(state.bytes.len());
        for (destination, byte) in buffer.iter_mut().zip(state.bytes.drain(..length)) {
            *destination = byte;
        }
        Ok(length)
    }
}

impl BlockingWrite for BlockingEndpoint {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, Self::Error> {
        let (state, ready) = &*self.outgoing;
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .bytes
            .extend(buffer);
        ready.notify_one();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Drop for BlockingEndpoint {
    fn drop(&mut self) {
        let (state, ready) = &*self.outgoing;
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed = true;
        ready.notify_all();
    }
}

fn blocking_write_all<T>(session: &mut BlockingSession<'_, T>, mut data: &[u8])
where
    T: BlockingRead + BlockingWrite,
{
    while !data.is_empty() {
        let written = session.write(data).unwrap();
        assert!(written > 0, "TLS write made no progress");
        data = &data[written..];
    }
}

fn blocking_read_exact<T>(session: &mut BlockingSession<'_, T>, mut buffer: &mut [u8])
where
    T: BlockingRead + BlockingWrite,
{
    while !buffer.is_empty() {
        let read = session.read(buffer).unwrap();
        assert!(read > 0, "TLS stream reached EOF before the echo completed");
        buffer = &mut buffer[read..];
    }
}

fn run_blocking_loopback(
    tls_reference: TlsReference<'_>,
    maximum_version: Option<TlsVersion>,
    client_yield_fn: Option<fn()>,
) {
    let (client_stream, server_stream) = blocking_pipe();

    std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            let mut session =
                BlockingSession::new(tls_reference, server_stream, &server_config()).unwrap();
            session.connect().unwrap();
            // The discriminating end: the server is never capped, so its seeded
            // version is the MbedTLS default maximum. Reporting the client's lower
            // cap here means a genuinely negotiated version is being read.
            assert_negotiated_version(session.tls_version(), maximum_version);
            let mut received = [0; PAYLOAD.len()];
            blocking_read_exact(&mut session, &mut received);
            assert_eq!(received, PAYLOAD);
            blocking_write_all(&mut session, &received);
            session.close().unwrap();
        });
        let client = scope.spawn(move || {
            let config = client_config(maximum_version);
            let mut session = match client_yield_fn {
                Some(yield_fn) => {
                    BlockingSession::new_with_yield(tls_reference, client_stream, &config, yield_fn)
                }
                None => BlockingSession::new(tls_reference, client_stream, &config),
            }
            .unwrap();
            assert_eq!(
                session.tls_version(),
                None,
                "a version was reported before the handshake"
            );
            session.connect().unwrap();
            assert_negotiated_version(session.tls_version(), maximum_version);
            blocking_write_all(&mut session, PAYLOAD);
            let mut echoed = [0; PAYLOAD.len()];
            blocking_read_exact(&mut session, &mut echoed);
            assert_eq!(echoed, PAYLOAD);
            session.close().unwrap();
        });

        server.join().unwrap();
        client.join().unwrap();
    });
}

#[cfg(feature = "ecp-restartable")]
struct RestartableGuard;

#[cfg(feature = "ecp-restartable")]
impl RestartableGuard {
    fn with_max_ops(maximum_operations: u32) -> Self {
        mbedtls_rs::ecp::set_restartable_max_ops(maximum_operations);
        Self
    }
}

#[cfg(feature = "ecp-restartable")]
impl Drop for RestartableGuard {
    fn drop(&mut self) {
        mbedtls_rs::ecp::set_restartable_max_ops(0);
    }
}

#[test]
fn async_loopback_handshake_and_echo() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    run_async_loopback(tls.reference(), None);
}

#[test]
fn async_construction_failure_leaves_borrowed_stream_usable() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    let (mut client_stream, server_stream) = async_pipe();

    // A caller that wants the stream back after a failed creation passes it by
    // `&mut`: the borrow ends with the returned error. An over-long server name
    // is the easiest deterministic constructor failure.
    let over_long_name = std::ffi::CString::new(vec![b'a'; 256]).unwrap();
    let failing_config = SessionConfig::Client(ClientSessionConfig {
        server_name: Some(&over_long_name),
        ..client_session_config(None)
    });
    let failed = AsyncSession::new(tls.reference(), &mut client_stream, &failing_config);
    assert!(
        failed.is_err(),
        "over-long server name should be rejected at session creation"
    );
    drop(failed);

    // The same stream, still owned by the caller, then carries a working
    // session through a full handshake.
    let mut client =
        AsyncSession::new(tls.reference(), &mut client_stream, &client_config(None)).unwrap();
    let mut server = AsyncSession::new(tls.reference(), server_stream, &server_config()).unwrap();

    let handshake_wake = Arc::new(CountingWake(AtomicUsize::new(0)));
    let (client_result, server_result) =
        drive_pair(client.connect(), server.connect(), handshake_wake);
    client_result.unwrap();
    server_result.unwrap();
}

/// The cap paths of the runners above otherwise only run under `ecp-restartable`,
/// so pin the cap-to-negotiated-version mapping unconditionally on both flavours.
#[test]
fn loopback_negotiated_version_honours_the_client_cap() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    // `run_*_loopback` asserts the negotiated version against the cap it is given.
    run_async_loopback(tls.reference(), Some(TlsVersion::Tls1_2));
    run_async_loopback(tls.reference(), Some(TlsVersion::Tls1_3));
    run_blocking_loopback(tls.reference(), Some(TlsVersion::Tls1_2), None);
    run_blocking_loopback(tls.reference(), Some(TlsVersion::Tls1_3), None);
}

#[test]
fn blocking_loopback_handshake_and_echo() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    run_blocking_loopback(tls.reference(), None, None);
}

#[cfg(feature = "ecp-restartable")]
#[test]
fn async_restartable_handshake_yields() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    // Declared before Tls so unwinding drops Tls before resetting the global budget.
    let _restartable = RestartableGuard::with_max_ops(1);
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    // Mbed TLS 3.6's TLS 1.3 handshake crypto is not restartable, so the client
    // caps at TLS 1.2; there the ECDSA signature and certificate verification are
    // restartable whichever group the key exchange lands on.
    let wake_count = run_async_loopback(tls.reference(), Some(TlsVersion::Tls1_2));
    assert!(wake_count > 0, "restartable handshake never yielded");
}

#[cfg(feature = "ecp-restartable")]
#[test]
fn blocking_restartable_handshake_completes() {
    static YIELD_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn count_yield() {
        YIELD_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    // Declared before Tls so unwinding drops Tls before resetting the global budget.
    let _restartable = RestartableGuard::with_max_ops(1);
    let mut rng = StdRng;
    // SAFETY: `rng` is declared before `tls`, and every session and `tls` are
    // dropped in this scope before the borrowed RNG can go out of scope.
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    YIELD_CALLS.store(0, Ordering::Relaxed);
    run_blocking_loopback(tls.reference(), Some(TlsVersion::Tls1_2), Some(count_yield));
    assert!(
        YIELD_CALLS.load(Ordering::Relaxed) > 0,
        "yield hook never invoked during a restartable handshake"
    );
}
