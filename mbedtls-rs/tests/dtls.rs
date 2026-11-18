//! DTLS sessions over an in-memory datagram link.
//!
//! The futures run on a waker that unparks the test thread, and the clock
//! wakes it from a timer thread, so a lost wake-up stalls a test, which then
//! fails.

#![cfg(feature = "tls-proto-dtls")]

use core::convert::Infallible;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Wake;
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use mbedtls_rs::dtls::{Clock, CookieCheck, Cookies, Datagram, DtlsConfig, Session};
use mbedtls_rs::io::ErrorType;
use mbedtls_rs::sys::{MBEDTLS_ERR_SSL_BAD_INPUT_DATA, MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE};
use mbedtls_rs::{
    Authentication, Certificate, ClientSessionConfig, Credentials, PrivateKey, ServerSessionConfig,
    SessionConfig, SessionError, Tls, TlsVersion, X509,
};
use rand::{Rng, TryCryptoRng, TryRng};

const CERTIFICATE: &[u8] = include_bytes!("fixtures/cert.der");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/key.der");

/// The handshake message types of `HelloVerifyRequest` and `ServerHello`.
const HELLO_VERIFY_REQUEST: u8 = 3;
const SERVER_HELLO: u8 = 2;

/// The offset of the handshake message type in a datagram, after the
/// record's header.
const MESSAGE_TYPE: usize = 13;

/// How long a test may wait without a wake-up.
const STALL: Duration = Duration::from_secs(10);

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

/// The datagrams going one way, and the waker of their receiver.
#[derive(Default)]
struct Direction {
    datagrams: VecDeque<Vec<u8>>,
    /// Kept by `readable` only: as with async-io, a dropped `recv` future
    /// keeps no waker.
    waker: Option<Waker>,
    /// The last datagram sent, and how many times it was sent twice in a row.
    /// A retransmitted flight is not the same datagram: its records have new
    /// sequence numbers.
    last: Option<Vec<u8>>,
    duplicates: usize,
    /// The handshake message type of the first datagram sent.
    first: Option<u8>,
}

/// What goes wrong on the way out of an endpoint.
#[derive(Default, Clone, Copy)]
struct Faults {
    /// How many of the first datagrams to lose.
    lose: usize,
    /// How many sends return `Pending` once, before they can send.
    stall: usize,
}

/// One end of an in-memory datagram link.
struct Endpoint {
    incoming: Rc<RefCell<Direction>>,
    outgoing: Rc<RefCell<Direction>>,
    faults: Faults,
}

impl ErrorType for Endpoint {
    type Error = Infallible;
}

impl Datagram for Endpoint {
    async fn readable(&mut self) -> Result<(), Self::Error> {
        poll_fn(|cx| {
            let mut incoming = self.incoming.borrow_mut();

            if incoming.datagrams.is_empty() {
                incoming.waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        })
        .await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        poll_fn(|_| match self.incoming.borrow_mut().datagrams.pop_front() {
            Some(datagram) => {
                let len = datagram.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram[..len]);
                Poll::Ready(Ok(len))
            }
            None => Poll::Pending,
        })
        .await
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if self.faults.stall > 0 {
            self.faults.stall -= 1;

            // Writable again at once.
            let mut stalled = false;
            poll_fn(|cx| {
                if stalled {
                    Poll::Ready(())
                } else {
                    stalled = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }

        if self.faults.lose > 0 {
            self.faults.lose -= 1;
            return Ok(());
        }

        let mut outgoing = self.outgoing.borrow_mut();

        if outgoing.first.is_none() {
            outgoing.first = data.get(MESSAGE_TYPE).copied();
        }

        if outgoing.last.as_deref() == Some(data) {
            outgoing.duplicates += 1;
        }
        outgoing.last = Some(data.to_vec());

        outgoing.datagrams.push_back(data.to_vec());
        if let Some(waker) = outgoing.waker.take() {
            waker.wake();
        }

        Ok(())
    }
}

fn link(client_faults: Faults) -> (Endpoint, Endpoint) {
    let to_server = Rc::new(RefCell::new(Direction::default()));
    let to_client = Rc::new(RefCell::new(Direction::default()));

    (
        Endpoint {
            incoming: to_client.clone(),
            outgoing: to_server.clone(),
            faults: client_faults,
        },
        Endpoint {
            incoming: to_server,
            outgoing: to_client,
            faults: Faults::default(),
        },
    )
}

/// A clock on `Instant`, which wakes the waiting task from a timer thread.
struct StdClock(Instant);

impl Clock for StdClock {
    fn now(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }

    fn wait_until(&mut self, at: u64) -> impl Future<Output = ()> {
        let mut armed = false;

        poll_fn(move |cx| {
            let now = self.now();
            if now >= at {
                return Poll::Ready(());
            }

            if !armed {
                armed = true;
                let waker = cx.waker().clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(at - now));
                    waker.wake();
                });
            }

            Poll::Pending
        })
    }
}

/// Wakes the test thread.
struct Unpark {
    thread: Thread,
    woken: AtomicBool,
}

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
        self.thread.unpark();
    }
}

/// Run `fut` on this thread; panic if nothing wakes it for [`STALL`].
fn block_on<F: Future>(fut: F) -> F::Output {
    let unpark = Arc::new(Unpark {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(unpark.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);

    loop {
        if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
            return output;
        }

        let since = Instant::now();
        while !unpark.woken.swap(false, Ordering::SeqCst) {
            assert!(since.elapsed() < STALL, "no wake-up for {STALL:?}");
            thread::park_timeout(STALL);
        }
    }
}

/// Run `a` and `b` together.
async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (pin!(a), pin!(b));
    let (mut a_output, mut b_output) = (None, None);

    poll_fn(|cx| {
        if a_output.is_none() {
            if let Poll::Ready(output) = a.as_mut().poll(cx) {
                a_output = Some(output);
            }
        }
        if b_output.is_none() {
            if let Poll::Ready(output) = b.as_mut().poll(cx) {
                b_output = Some(output);
            }
        }

        if a_output.is_some() && b_output.is_some() {
            Poll::Ready((a_output.take().unwrap(), b_output.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

fn dtls_config() -> DtlsConfig<'static> {
    DtlsConfig {
        handshake_timeout_min: 100,
        handshake_timeout_max: 400,
        mtu: Some(1232),
        ..DtlsConfig::new()
    }
}

fn certificate_configs() -> (SessionConfig<'static>, SessionConfig<'static>) {
    let client = SessionConfig::Client(ClientSessionConfig {
        ca_chain: Some(Certificate::new_no_copy(CERTIFICATE).unwrap()),
        server_name: Some(c"mbedtls-rs.local"),
        ..ClientSessionConfig::new()
    });

    let server = SessionConfig::Server(ServerSessionConfig::new(
        Credentials {
            certificate: Certificate::new_no_copy(CERTIFICATE).unwrap(),
            private_key: PrivateKey::new(X509::DER(PRIVATE_KEY), None).unwrap(),
        }
        .into(),
    ));

    (client, server)
}

/// Hand-shake; then the client sends `ping`, the server answers `pong`, and
/// the client closes the session.
fn ping_pong(
    client_config: &SessionConfig<'_>,
    server_config: &SessionConfig<'_>,
    client_faults: Faults,
) -> Result<Vec<u8>, SessionError> {
    ping_pong_with(client_config, server_config, client_faults, true)
}

/// [`ping_pong`], with the server checking the client's address with a
/// cookie, or not.
fn ping_pong_with(
    client_config: &SessionConfig<'_>,
    server_config: &SessionConfig<'_>,
    client_faults: Faults,
    cookies: bool,
) -> Result<Vec<u8>, SessionError> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = StdRng;
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    let secret = Cookies::new(tls.reference()).unwrap();
    let server_dtls = DtlsConfig {
        cookie_check: Some(if cookies {
            CookieCheck::Verify {
                cookies: &secret,
                client: b"client",
            }
        } else {
            CookieCheck::Off
        }),
        ..dtls_config()
    };

    let (client_io, server_io) = link(client_faults);
    let start = Instant::now();

    let mut client = Session::new(
        tls.reference(),
        client_io,
        StdClock(start),
        client_config,
        &dtls_config(),
    )?;
    let mut server = Session::new(
        tls.reference(),
        server_io,
        StdClock(start),
        server_config,
        &server_dtls,
    )?;

    let client_side = async {
        client.connect().await?;
        client.write(b"ping").await?;
        let mut buf = [0; 64];
        let len = client.read(&mut buf).await?;
        client.close().await?;
        Ok::<_, SessionError>(buf[..len].to_vec())
    };

    let server_side = async {
        server.connect().await?;
        let mut buf = [0; 64];
        let len = server.read(&mut buf).await?;
        assert_eq!(&buf[..len], b"ping");
        server.write(b"pong").await?;
        // The close notify
        let len = server.read(&mut buf).await?;
        assert_eq!(len, 0);
        Ok::<_, SessionError>(())
    };

    let (answer, served) = block_on(join(client_side, server_side));

    for end in [client.io(), server.io()] {
        assert_eq!(end.outgoing.borrow().duplicates, 0, "a datagram sent twice");
    }

    if answer.is_ok() {
        let first = if cookies {
            HELLO_VERIFY_REQUEST
        } else {
            SERVER_HELLO
        };
        assert_eq!(server.io().outgoing.borrow().first, Some(first));
    }

    served?;
    answer
}

#[test]
fn certificate_handshake() {
    let (client, server) = certificate_configs();

    assert_eq!(
        ping_pong(&client, &server, Faults::default()).unwrap(),
        b"pong"
    );
}

#[test]
fn waits_for_the_transport_to_send() {
    let (client, server) = certificate_configs();
    let faults = Faults {
        stall: 3,
        ..Faults::default()
    };

    assert_eq!(ping_pong(&client, &server, faults).unwrap(), b"pong");
}

#[test]
fn without_cookies() {
    let (client, server) = certificate_configs();

    assert_eq!(
        ping_pong_with(&client, &server, Faults::default(), false).unwrap(),
        b"pong"
    );
}

#[test]
fn a_server_needs_a_cookie_check() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = StdRng;
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let (_, server_io) = link(Faults::default());
    let (_, server) = certificate_configs();

    let session = Session::new(
        tls.reference(),
        server_io,
        StdClock(Instant::now()),
        &server,
        &dtls_config(),
    );

    assert!(matches!(
        session,
        Err(SessionError::MbedTls(e)) if e.code() == MBEDTLS_ERR_SSL_BAD_INPUT_DATA
    ));
}

#[test]
fn refuses_tls_1_3() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = StdRng;
    let tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();
    let (client_io, _) = link(Faults::default());

    let config = SessionConfig::Client(ClientSessionConfig {
        max_version: Some(TlsVersion::Tls1_3),
        ..ClientSessionConfig::new()
    });
    let session = Session::new(
        tls.reference(),
        client_io,
        StdClock(Instant::now()),
        &config,
        &dtls_config(),
    );

    assert!(matches!(
        session,
        Err(SessionError::MbedTls(e)) if e.code() == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE
    ));
}

#[test]
fn retransmits_a_lost_flight() {
    let (client, server) = certificate_configs();

    let faults = Faults {
        lose: 1,
        ..Faults::default()
    };

    assert_eq!(ping_pong(&client, &server, faults).unwrap(), b"pong");
}

#[test]
fn psk_handshake() {
    let identity = b"device-1";
    let key = &[0x11; 16];

    let client = SessionConfig::Client(ClientSessionConfig {
        authentication: Some(Authentication::Psk { identity, key }),
        ..ClientSessionConfig::new()
    });
    let server = SessionConfig::Server(ServerSessionConfig::new(Authentication::Psk {
        identity,
        key,
    }));

    assert_eq!(
        ping_pong(&client, &server, Faults::default()).unwrap(),
        b"pong"
    );

    let other = SessionConfig::Client(ClientSessionConfig {
        authentication: Some(Authentication::Psk {
            identity,
            key: &[0x22; 16],
        }),
        ..ClientSessionConfig::new()
    });

    assert!(ping_pong(&other, &server, Faults::default()).is_err());
}

#[cfg(feature = "kex-ecjpake")]
mod ecjpake {
    use super::*;

    fn configs<'a>(
        client_password: &'a [u8],
        server_password: &'a [u8],
    ) -> (SessionConfig<'a>, SessionConfig<'a>) {
        let client = SessionConfig::Client(ClientSessionConfig {
            authentication: Some(Authentication::EcJpake(client_password)),
            ..ClientSessionConfig::new()
        });

        let server = SessionConfig::Server(ServerSessionConfig::new(Authentication::EcJpake(
            server_password,
        )));

        (client, server)
    }

    #[test]
    fn handshake() {
        let (client, server) = configs(b"123456789", b"123456789");

        assert_eq!(
            ping_pong(&client, &server, Faults::default()).unwrap(),
            b"pong"
        );
    }

    #[test]
    fn retransmits_a_lost_flight() {
        let (client, server) = configs(b"123456789", b"123456789");

        assert_eq!(
            ping_pong(
                &client,
                &server,
                Faults {
                    lose: 1,
                    ..Faults::default()
                }
            )
            .unwrap(),
            b"pong"
        );
    }

    #[test]
    fn fails_with_another_password() {
        let (client, server) = configs(b"987654321", b"123456789");

        assert!(ping_pong(&client, &server, Faults::default()).is_err());
    }
}
