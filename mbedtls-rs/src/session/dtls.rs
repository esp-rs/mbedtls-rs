//! DTLS: TLS 1.2 over datagrams.
//!
//! A DTLS [`Session`] runs over a datagram transport connected to the peer
//! ([`Datagram`]), and times the retransmissions of its handshake with a
//! [`Clock`]. It takes the same [`SessionConfig`] as a TLS session, plus a
//! [`DtlsConfig`].
//!
//! On ESP-IDF, the module needs `CONFIG_MBEDTLS_SSL_PROTO_DTLS`.
//!
//! MbedTLS has no DTLS 1.3: [`Session::new`] fails with
//! `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE` if the [`SessionConfig`] allows
//! TLS 1.3 (`min_version` or `max_version`).
//!
//! A server session does not use the cookie exchange of DTLS
//! (`HelloVerifyRequest`): it answers the first `ClientHello` that its
//! transport receives.

use core::ffi::{c_int, c_uchar, c_void};
use core::future::{pending, poll_fn, Future};
use core::pin::pin;
use core::ptr::{null, null_mut};
use core::task::{Context, Poll};

use embedded_io::{Error, ErrorKind, ErrorType};

use crate::sys::*;
use crate::{MBox, MInit, SessionError, TlsReference};

use super::{SessionConfig, SessionState};

/// A datagram transport connected to the peer: each datagram it receives
/// comes from the peer, and each one it sends goes to the peer.
///
/// MbedTLS reads and writes from callbacks that cannot wait. There, the
/// session polls `recv` and `send` once, into and out of MbedTLS's own
/// buffers, and drops them if they are not ready. Then it waits with
/// `readable`, or by sending the datagram itself. Thus:
/// - `recv` takes a datagram only when it returns it, and returns it on its
///   first poll once `readable` has said that one has arrived;
/// - `send` sends nothing unless it returns, and sends on its first poll when
///   the transport can.
pub trait Datagram: ErrorType {
    /// Wait until a datagram has arrived, without taking it.
    fn readable(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Receive one datagram into `buf`, and return its length.
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>>;

    /// Send `data` as one datagram.
    fn send(&mut self, data: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<T> Datagram for &mut T
where
    T: Datagram + ?Sized,
{
    fn readable(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        T::readable(self)
    }

    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>> {
        T::recv(self, buf)
    }

    fn send(&mut self, data: &[u8]) -> impl Future<Output = Result<(), Self::Error>> {
        T::send(self, data)
    }
}

/// The clock of a DTLS session, which times the retransmissions of the
/// handshake.
pub trait Clock {
    /// The time in milliseconds since some point in the past. It never
    /// decreases.
    fn now(&self) -> u64;

    /// Wait until [`Clock::now`] has reached `at`.
    fn wait_until(&mut self, at: u64) -> impl Future<Output = ()>;
}

impl<T> Clock for &mut T
where
    T: Clock + ?Sized,
{
    fn now(&self) -> u64 {
        T::now(self)
    }

    fn wait_until(&mut self, at: u64) -> impl Future<Output = ()> {
        T::wait_until(self, at)
    }
}

/// A [`Clock`] on `embassy-time`.
#[cfg(feature = "embassy-time")]
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EmbassyClock;

#[cfg(feature = "embassy-time")]
impl Clock for EmbassyClock {
    fn now(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }

    fn wait_until(&mut self, at: u64) -> impl Future<Output = ()> {
        embassy_time::Timer::at(embassy_time::Instant::from_millis(at))
    }
}

/// The settings of a DTLS session, besides its [`SessionConfig`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DtlsConfig {
    /// How long the handshake waits for the answer to a flight before it
    /// sends the flight again, in milliseconds. The wait doubles with each
    /// retransmission.
    pub handshake_timeout_min: u32,
    /// The longest wait of the handshake, in milliseconds. The handshake fails
    /// when a wait this long has passed without an answer.
    pub handshake_timeout_max: u32,
    /// The size of the largest datagram to send. `None`: as large as the
    /// records.
    pub mtu: Option<u16>,
}

impl DtlsConfig {
    /// MbedTLS's defaults: from 1 to 60 seconds, no MTU.
    pub const fn new() -> Self {
        Self {
            handshake_timeout_min: MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN,
            handshake_timeout_max: MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX,
            mtu: None,
        }
    }
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A DTLS session over a datagram transport.
pub struct Session<'a, T, C>
where
    T: Datagram,
    C: Clock,
{
    /// The transport
    io: T,
    /// The clock of the retransmissions
    clock: C,
    /// The session state. Before `timer`: the SSL context points to it.
    state: SessionState<'a>,
    /// MbedTLS's retransmission timer
    timer: MBox<Timer>,
    /// The datagram that the session sent while MbedTLS waited, see
    /// [`Wait::Send`]
    sent: Option<(*const u8, usize)>,
    /// Whether the handshake is done
    connected: bool,
    /// Reference to the active Tls instance
    _token: TlsReference<'a>,
}

impl<'a, T, C> Session<'a, T, C>
where
    T: Datagram,
    C: Clock,
{
    /// Create a session over `io`, not connected yet.
    ///
    /// # Arguments
    /// - `tls` - A reference to the active `Tls` instance.
    /// - `io` - The transport, connected to the peer.
    /// - `clock` - The clock of the retransmissions.
    /// - `config` - The session configuration.
    /// - `dtls` - The DTLS settings.
    pub fn new(
        tls: TlsReference<'a>,
        io: T,
        clock: C,
        config: &SessionConfig<'a>,
        dtls: &DtlsConfig,
    ) -> Result<Self, SessionError> {
        let server = matches!(config, SessionConfig::Server(_));

        let mut state =
            SessionState::with_transport(config, MBEDTLS_SSL_TRANSPORT_DATAGRAM, |ssl_config| {
                unsafe {
                    mbedtls_ssl_conf_handshake_timeout(
                        ssl_config,
                        dtls.handshake_timeout_min,
                        dtls.handshake_timeout_max,
                    );
                }

                if server {
                    // No cookie exchange, see the module documentation.
                    unsafe {
                        mbedtls_ssl_conf_dtls_cookies(ssl_config, None, None, null_mut());
                    }
                }
            })?;

        let mut timer = MBox::<Timer>::new().ok_or(SessionError::MbedTls(MbedtlsError::new(
            MBEDTLS_ERR_SSL_ALLOC_FAILED,
        )))?;

        let ssl_context = state.ssl_context.as_mut_ptr();

        // Once for the session's life: setting the callbacks also stops the timer.
        unsafe {
            mbedtls_ssl_set_timer_cb(
                ssl_context,
                timer.as_mut_ptr() as *mut c_void,
                Some(timer_set),
                Some(timer_get),
            );
        }

        if let Some(mtu) = dtls.mtu {
            unsafe {
                mbedtls_ssl_set_mtu(ssl_context, mtu);
            }
        }

        Ok(Self {
            io,
            clock,
            state,
            timer,
            sent: None,
            connected: false,
            _token: tls,
        })
    }

    /// Get the transport.
    pub fn io(&mut self) -> &mut T {
        &mut self.io
    }

    /// Do the handshake, unless it is done.
    ///
    /// Calling it is not mandatory: the first read or write does the
    /// handshake too.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe. The handshake resets the SSL context before it runs
    /// across several `.await` points. If this future is dropped in the middle
    /// of the handshake, a retry starts a new one, which the peer might not
    /// expect.
    // NOT cancel-safe: see `# Cancel safety`.
    pub async fn connect(&mut self) -> Result<(), SessionError> {
        if self.connected {
            return Ok(());
        }

        self.state.reset()?;

        merr!(
            self.drive(|ssl| unsafe { mbedtls_ssl_handshake(ssl) })
                .await?
        )?;

        self.connected = true;

        Ok(())
    }

    /// Read the data of one record into `buf`.
    ///
    /// # Returns
    /// - The number of bytes read, 0 when the peer has closed the session.
    ///   Data that does not fit in `buf` is left for the next read.
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe once connected: a record is taken only when the read
    /// returns.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        self.connect().await?;

        match self
            .drive(|ssl| unsafe { mbedtls_ssl_read(ssl, buf.as_mut_ptr(), buf.len()) })
            .await?
        {
            MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => Ok(0),
            ret => Ok(merr!(ret)? as usize),
        }
    }

    /// Write `data` as one record.
    ///
    /// The data and the record's overhead must fit in the MTU, if there is
    /// one.
    ///
    /// # Returns
    /// - The number of bytes written.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe. If this future is dropped while the record waits for
    /// the transport, MbedTLS keeps the record, and expects the same data
    /// with the next write.
    // NOT cancel-safe: see `# Cancel safety`.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, SessionError> {
        self.connect().await?;

        let len = merr!(
            self.drive(|ssl| unsafe { mbedtls_ssl_write(ssl, data.as_ptr(), data.len()) })
                .await?
        )?;

        Ok(len as usize)
    }

    /// Tell the peer that the session is over ("close notify").
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe, as [`Session::write`].
    // NOT cancel-safe: see `# Cancel safety`.
    pub async fn close(&mut self) -> Result<(), SessionError> {
        merr!(
            self.drive(|ssl| unsafe { mbedtls_ssl_close_notify(ssl) })
                .await?
        )?;

        Ok(())
    }

    /// Call `op` until it is done with the transport, waiting for the
    /// transport and for the retransmission timer in between.
    ///
    /// # Returns
    /// - What `op` returned last, or the transport's error.
    async fn drive<F>(&mut self, mut op: F) -> Result<c_int, SessionError>
    where
        F: FnMut(*mut mbedtls_ssl_context) -> c_int,
    {
        loop {
            let (ret, wait) = self.call(&mut op).await?;

            if ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE {
                break Ok(ret);
            }

            match wait {
                Wait::Readable => self.wait_readable().await?,
                Wait::Send(data, len) => {
                    // MbedTLS does not touch the datagram until it is called
                    // again, which sends it once more: see `bio_send`.
                    let datagram = unsafe { core::slice::from_raw_parts(data, len) };

                    self.io
                        .send(datagram)
                        .await
                        .map_err(SessionError::from_io)?;

                    self.sent = Some((data, len));
                }
                // MbedTLS sent a flight again, and returned without reading:
                // call it again, so that it reads.
                Wait::None => (),
            }
        }
    }

    /// Call `op` once, with the transport and the clock at MbedTLS's hand.
    ///
    /// # Returns
    /// - What `op` returned, and what to wait for before the next call, or
    ///   the transport's error.
    async fn call<F>(&mut self, op: &mut F) -> Result<(c_int, Wait), SessionError>
    where
        F: FnMut(*mut mbedtls_ssl_context) -> c_int,
    {
        poll_fn(|cx| {
            let ssl_context = self.state.ssl_context.as_mut_ptr();

            self.timer.clock = &self.clock as *const C as *const c_void;
            self.timer.now = Some(clock_now::<C>);

            let mut call = Call {
                io: &mut self.io,
                cx,
                sent: &mut self.sent,
                wait: Wait::None,
                error: None,
            };

            unsafe {
                mbedtls_ssl_set_bio(
                    ssl_context,
                    &mut call as *mut Call<'_, '_, T> as *mut c_void,
                    Some(bio_send::<T>),
                    Some(bio_recv::<T>),
                    None,
                );
            }

            let ret = op(ssl_context);

            // Unhook, so that MbedTLS cannot reach `call` and the clock once
            // they are gone.
            unsafe {
                mbedtls_ssl_set_bio(ssl_context, null_mut(), None, None, None);
            }

            self.timer.clock = null();
            self.timer.now = None;

            // Used or not, it is not for later calls.
            *call.sent = None;

            if let Some(kind) = call.error {
                return Poll::Ready(Err(SessionError::Io(kind)));
            }

            if ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS {
                call.cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            Poll::Ready(Ok((ret, call.wait)))
        })
        .await
    }

    /// Wait until a datagram has arrived, or until the retransmission timer
    /// expires.
    async fn wait_readable(&mut self) -> Result<(), SessionError> {
        let fin = self.timer.fin;
        let clock = &mut self.clock;

        let mut readable = pin!(self.io.readable());
        let mut expired = pin!(async move {
            match fin {
                0 => pending().await,
                fin => clock.wait_until(fin).await,
            }
        });

        poll_fn(|cx| {
            if let Poll::Ready(result) = readable.as_mut().poll(cx) {
                return Poll::Ready(result.map_err(SessionError::from_io));
            }

            expired.as_mut().poll(cx).map(Ok)
        })
        .await
    }
}

/// What the BIO callbacks reach during a [`Session::call`].
struct Call<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
    /// See [`Session::sent`].
    sent: &'a mut Option<(*const u8, usize)>,
    /// What to wait for before the next call.
    wait: Wait,
    /// The transport failed.
    error: Option<ErrorKind>,
}

/// What to wait for before MbedTLS is called again, after it returned
/// `WANT_READ` or `WANT_WRITE`.
enum Wait {
    /// Nothing: MbedTLS did not try the transport.
    None,
    /// A datagram to arrive.
    Readable,
    /// The transport to send the datagram that MbedTLS handed over. It stays
    /// in MbedTLS's buffer, and MbedTLS hands it over again on the next call.
    Send(*const u8, usize),
}

/// MbedTLS's retransmission timer, in [`Clock::now`] milliseconds.
///
/// All zeros is a stopped timer, without a clock.
struct Timer {
    /// The clock of the call in progress, a `*const C`.
    clock: *const c_void,
    /// Reads the time from `clock`.
    now: Option<unsafe fn(*const c_void) -> u64>,
    /// When the intermediate delay ends.
    int: u64,
    /// When the final delay ends. 0: stopped.
    fin: u64,
}

impl Timer {
    fn now(&self) -> Option<u64> {
        self.now.map(|now| unsafe { now(self.clock) })
    }
}

impl MInit for Timer {}

/// The [`Timer::now`] of a `C`.
unsafe fn clock_now<C: Clock>(clock: *const c_void) -> u64 {
    unsafe { (*(clock as *const C)).now() }
}

/// The MbedTLS BIO send callback
unsafe extern "C" fn bio_send<T: Datagram>(
    ctx: *mut c_void,
    buf: *const c_uchar,
    len: usize,
) -> c_int {
    let call = unsafe { &mut *(ctx as *mut Call<'_, '_, T>) };

    // The session sent it while MbedTLS waited.
    if call.sent.take() == Some((buf, len)) {
        return len as c_int;
    }

    let data = unsafe { core::slice::from_raw_parts(buf, len) };
    let mut send = pin!(call.io.send(data));

    match send.as_mut().poll(call.cx) {
        Poll::Ready(Ok(())) => len as c_int,
        Poll::Ready(Err(e)) => {
            call.error = Some(e.kind());
            // The session reports `call.error` instead.
            MBEDTLS_ERR_SSL_INTERNAL_ERROR
        }
        Poll::Pending => {
            call.wait = Wait::Send(buf, len);
            MBEDTLS_ERR_SSL_WANT_WRITE
        }
    }
}

/// The MbedTLS BIO receive callback
unsafe extern "C" fn bio_recv<T: Datagram>(
    ctx: *mut c_void,
    buf: *mut c_uchar,
    len: usize,
) -> c_int {
    let call = unsafe { &mut *(ctx as *mut Call<'_, '_, T>) };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut recv = pin!(call.io.recv(buf));

    match recv.as_mut().poll(call.cx) {
        Poll::Ready(Ok(len)) => len as c_int,
        Poll::Ready(Err(e)) => {
            call.error = Some(e.kind());
            // The session reports `call.error` instead.
            MBEDTLS_ERR_SSL_INTERNAL_ERROR
        }
        Poll::Pending => {
            call.wait = Wait::Readable;
            MBEDTLS_ERR_SSL_WANT_READ
        }
    }
}

/// The MbedTLS timer callback that starts (`fin_ms` > 0) or stops the timer
unsafe extern "C" fn timer_set(ctx: *mut c_void, int_ms: u32, fin_ms: u32) {
    let timer = unsafe { &mut *(ctx as *mut Timer) };

    match timer.now() {
        Some(now) if fin_ms > 0 => {
            timer.int = now + int_ms as u64;
            timer.fin = now + fin_ms as u64;
        }
        _ => {
            timer.int = 0;
            timer.fin = 0;
        }
    }
}

/// The MbedTLS timer callback: -1 stopped, 0 running, 1 past the intermediate
/// delay, 2 expired
unsafe extern "C" fn timer_get(ctx: *mut c_void) -> c_int {
    let timer = unsafe { &*(ctx as *const Timer) };

    if timer.fin == 0 {
        return -1;
    }

    let Some(now) = timer.now() else {
        return 0;
    };

    if now >= timer.fin {
        2
    } else if now >= timer.int {
        1
    } else {
        0
    }
}
