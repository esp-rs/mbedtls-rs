use core::ffi::{c_int, c_uchar, c_void, CStr};
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Context, Poll};

use embedded_io::ErrorKind;

use io::{ErrorType, Read, Write};

use crate::sys::*;
use crate::{SessionError, TlsReference};

use super::{SavedSession, SessionConfig, SessionState};

/// Re-export of the `embedded-io-async` crate so that users don't have to explicitly depend on it
/// to use e.g. `write_all` or `read_exact`.
pub mod io {
    pub use embedded_io_async::*;
}

/// Re-export of the `edge-nal` crate so that users don't have to explicitly depend on it
/// to use e.g. `TlsAccept` and `TlsConnect` methods.
#[cfg(feature = "edge-nal")]
pub mod nal {
    pub use edge_nal::*;
}

/// An async TLS session over a stream represented by `embedded-io-async`'s `Read` and `Write` traits.
pub struct Session<'a, T>
where
    T: Read + Write,
{
    /// The underlying stream
    stream: T,
    /// The session state
    state: SessionState<'a>,
    /// Whether the session is connected
    connected: bool,
    /// Whether we received a close notify from the peer
    eof: bool,
    /// A state necessary so as to implement `MBio::readable`
    read_byte: Option<u8>,
    /// A state necessary so as to implement `MBio::writable`
    write_byte: Option<u8>,
    /// Reference to the active Tls instance
    _token: TlsReference<'a>,
}

impl<'a, T> Session<'a, T>
where
    T: Read + Write,
{
    /// Create a session for a TLS stream.
    ///
    /// # Arguments
    /// - `tls` - A reference to the active `Tls` instance.
    /// - `stream` - The stream for the connection, implementing `Read` and `Write`.
    /// - `config`` - The session configuration
    ///
    /// # Returns
    /// - A `Session` instance or a `TlsError` on failure.
    pub fn new(
        tls: TlsReference<'a>,
        stream: T,
        config: &SessionConfig<'a>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            stream,
            state: SessionState::new(config)?,
            connected: false,
            eof: false,
            read_byte: None,
            write_byte: None,
            _token: tls,
        })
    }

    /// Get the TLS verification details
    ///
    /// The details are a bitmask of various flags indicating the result of the certificate verification.
    ///
    /// # Returns
    /// - 0 if verification succeeded
    /// - A bitmask of verification failure flags otherwise
    ///
    /// NOTE: This function should be called only after a `connect()` call.
    pub fn tls_verification_details(&self) -> u32 {
        unsafe { mbedtls_ssl_get_verify_result(&*self.state.ssl_context) }
    }

    /// Get the negotiated ALPN protocol, if any.
    ///
    /// NOTE: This function should be called only after a `connect()` call.
    pub fn tls_alpn(&self) -> Option<&CStr> {
        unsafe {
            let ptr = mbedtls_ssl_get_alpn_protocol(&*self.state.ssl_context);
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr))
            }
        }
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream(&mut self) -> &mut T {
        &mut self.stream
    }

    /// Set the server name for the TLS connection
    ///
    /// # Arguments
    /// - `server_name`: The server name as a C string
    pub fn set_server_name(&mut self, server_name: &CStr) -> Result<(), SessionError> {
        merr!(unsafe {
            mbedtls_ssl_set_hostname(&mut *self.state.ssl_context, server_name.as_ptr())
        })?;

        Ok(())
    }

    async fn connect_internal(
        &mut self,
        saved_session: Option<&SavedSession>,
    ) -> Result<(), SessionError> {
        if self.connected {
            return Ok(());
        }

        MBio::from_session(self).connect(saved_session).await?;

        self.connected = true;
        self.eof = false;

        Ok(())
    }

    /// Negotiate the TLS connection
    ///
    /// This function will perform the TLS handshake with the server.
    ///
    /// Note that calling it is not mandatory, because the TLS session is anyway
    /// negotiated during the first read or write operation, or when splitting the session.
    pub async fn connect(&mut self) -> Result<(), SessionError> {
        self.connect_internal(None).await
    }

    /// Negotiate the TLS connection attempting to reuse a previously captured session.
    ///
    /// Use [`Session::save`] to get a copy of the session to use here  
    pub async fn connect_with_session(
        &mut self,
        saved_session: &SavedSession,
    ) -> Result<(), SessionError> {
        self.connect_internal(Some(saved_session)).await
    }

    /// Split the TLS session into read and write halves
    ///
    /// # Returns
    /// - A tuple containing the read and write halves of the session
    pub async fn split(
        &mut self,
    ) -> Result<
        (
            SessionRead<'_, impl Read + '_>,
            SessionWrite<'_, impl Write + '_>,
        ),
        SessionError,
    >
    where
        T: Split,
    {
        self.connect().await?;

        let (read, write) = self.stream.split();

        Ok((
            SessionRead {
                stream: NoWrite(read),
                ssl_context: &self.state.ssl_context,
                eof: &mut self.eof,
                read_byte: &mut self.read_byte,
                write_byte: None,
            },
            SessionWrite {
                stream: NoRead(write),
                ssl_context: &self.state.ssl_context,
                eof: false,
                read_byte: None,
                write_byte: &mut self.write_byte,
            },
        ))
    }

    /// Read unencrypted data from the TLS connection
    ///
    /// # Arguments
    /// - `buf` - The buffer to read the data into
    ///
    /// # Returns
    /// - The number of bytes read or an error
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        self.connect().await?;

        if self.eof || buf.is_empty() {
            return Ok(0);
        }

        MBio::from_session(self).read(buf).await
    }

    /// Write unencrypted data to the TLS connection
    ///
    /// # Arguments:
    /// - `data` - The data to write
    ///
    /// # Returns:
    /// - The number of bytes written or an error
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, SessionError> {
        self.connect().await?;

        if data.is_empty() {
            return Ok(0);
        }

        MBio::from_session(self).write(data).await
    }

    /// Flush the TLS connection
    ///
    /// This function will flush the TLS connection, ensuring that all data is sent.
    ///
    /// # Returns:
    /// - An error if the flush failed
    pub async fn flush(&mut self) -> Result<(), SessionError> {
        self.connect().await?;

        MBio::from_session(self).flush().await
    }

    /// Close the TLS connection
    ///
    /// This function will close the TLS connection, sending the TLS "close notify" info to the peer.
    ///
    /// # Returns:
    /// - An error if the close failed
    pub async fn close(&mut self) -> Result<(), SessionError> {
        if !self.connected {
            return Ok(());
        }

        MBio::from_session(self).close().await?;

        self.connected = false;

        Ok(())
    }

    /// Capture the negotiated MbedTLS session for possible reuse.
    pub fn save(&self) -> Result<SavedSession, SessionError> {
        let mut mbedtls_session: super::super::MBox<mbedtls_ssl_session> =
            super::super::MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        merr!(unsafe { mbedtls_ssl_get_session(&*self.state.ssl_context, &mut *mbedtls_session) })?;

        Ok(SavedSession { mbedtls_session })
    }
}

impl<T> Drop for Session<'_, T>
where
    T: Read + Write,
{
    fn drop(&mut self) {
        if self.connected {
            warn!("Session dropped without being closed properly");
        }

        debug!("Session dropped - freeing memory");
    }
}

impl<T> ErrorType for Session<'_, T>
where
    T: Read + Write,
{
    type Error = SessionError;
}

impl<T> Read for Session<'_, T>
where
    T: Read + Write,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Self::read(self, buf).await
    }
}

impl<T> Write for Session<'_, T>
where
    T: Read + Write,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Self::write(self, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Self::flush(self).await
    }
}

/// A trait for splitting a stream into read and write halves.
///
/// This is used by the `Session::split` method to split the underlying stream and the stream MUST implement
/// this trait for the `split` method to be available.
///
/// NOTE: While the `edge-nal` crate does have its own `Split` trait, we provide our own trait
/// so as to keep the core of this library independent of `edge-nal`.
pub trait Split: ErrorType {
    /// The read half of the stream.
    type Read<'a>: Read<Error = Self::Error>
    where
        Self: 'a;
    /// The write half of the stream.
    type Write<'a>: Write<Error = Self::Error>
    where
        Self: 'a;

    /// Split the stream into read and write halves.
    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>);
}

impl<T> Split for &mut T
where
    T: Split,
{
    type Read<'a>
        = T::Read<'a>
    where
        Self: 'a;
    type Write<'a>
        = T::Write<'a>
    where
        Self: 'a;

    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
        T::split(self)
    }
}

/// A type representing the read half of a TLS session
/// when the session has been split into read and write halves.
pub struct SessionRead<'a, T>
where
    T: Read,
{
    /// The underlying stream
    stream: NoWrite<T>,
    /// The MbedTLS SSL context
    ssl_context: &'a mbedtls_ssl_context,
    /// Whether we had received a close notify from the peer
    eof: &'a mut bool,
    /// A state necessary so as to implement `MBio::wait_readable`
    read_byte: &'a mut Option<u8>,
    /// A state necessary so as to implement `MBio::wait_writable`
    write_byte: Option<u8>,
}

impl<T> SessionRead<'_, T>
where
    T: Read,
{
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        if *self.eof || buf.is_empty() {
            return Ok(0);
        }

        MBio::from_read(self).read(buf).await
    }
}

impl<T> ErrorType for SessionRead<'_, T>
where
    T: Read,
{
    type Error = SessionError;
}

impl<T> Read for SessionRead<'_, T>
where
    T: Read,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Self::read(self, buf).await
    }
}

/// A type representing the write half of a TLS session
/// when the session has been split into read and write halves.
pub struct SessionWrite<'a, T>
where
    T: Write,
{
    /// The underlying stream
    stream: NoRead<T>,
    /// The MbedTLS SSL context
    ssl_context: &'a mbedtls_ssl_context,
    /// A dummy value, as we don't need to track EOF in the write half
    eof: bool,
    /// A state necessary so as to implement `MBio::wait_readable`
    read_byte: Option<u8>,
    /// A state necessary so as to implement `MBio::wait_writable`
    write_byte: &'a mut Option<u8>,
}

impl<T> SessionWrite<'_, T>
where
    T: Write,
{
    /// Write unencrypted data to the TLS connection
    ///
    /// # Arguments
    /// - `data` - The data to write
    ///
    /// # Returns
    /// - The number of bytes written or an error
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, SessionError> {
        if data.is_empty() {
            return Ok(0);
        }

        MBio::from_write(self).write(data).await
    }

    /// Flush the TLS connection
    pub async fn flush(&mut self) -> Result<(), SessionError> {
        MBio::from_write(self).flush().await
    }
}

impl<T> ErrorType for SessionWrite<'_, T>
where
    T: Write,
{
    type Error = SessionError;
}

impl<T> Write for SessionWrite<'_, T>
where
    T: Write,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Self::write(self, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Self::flush(self).await
    }
}

/// A type for using the async `Read` and `Write` traits from within the synchronous MbedTLS "mbio" callbacks
/// **without any additional buffers** / memory.
///
/// Using the MbedTLS callback-based IO metaphor is a bit of a challenge with the async `Read` and `Write` traits,
/// in that these cannot be `await`-ed from within the MbedTLS mbio callbacks, as the latter are synchronous callback
/// functions.
///
/// What this type implements therefore is the following trick:
/// - While we cannot `await` on the `Read` and `Write` traits directly from within the "mbio" callbacks, we can still
///   poll them (with `Future::poll`). This is because the `poll` method is synchronous in that it either resolves the
///   future immediately (`Poll::Ready`), or returns `Poll::Pending` if the future needs to be polled again.
/// - Because of the `Read` and `Write` traits' semantics, polling them MUST return immediately, if there is even one
///   byte available for reading from the networking stack buffers (or - correspondingly - if there is space to write
///   even one byte in the networking stack buffers).
/// - Since the network stack usually does not operate byte-by-byte, what this means is that by just calling `Future::poll`
///   on the `Read` / `Write` trait, we can efficiently transfer the incoming/outgoing data from/to the network stack, without
///   any additional network buffers.
/// - Of course, if the network read buffers are empty (or write buffers are full), we still need to `await` outside the
///   MbedTLS callbacks, in the `Session::read` / `Session::write` / `Session::connect` methods.
///
/// Note also, that the implementation is a tad more complex, because it is implemented purely in terms of the
/// `Read` and `Write` traits, rather than `edge-nal`'s `Readable` and (future) `Writable`, so we need to shuffle single bytes
/// between the "mbio" callbacks and the `Session` asunc context to make it work.
///
/// On the other hand, this enables `Session` to be used over any streaming transport that implements the `Read` and `Write` traits
/// (i.e. UART and others).
struct MBio<'a, T> {
    /// The underlying stream
    stream: T,
    /// The MbedTLS SSL context
    ssl_context: &'a mbedtls_ssl_context,
    /// `true` if we had received a close notify from the peer
    eof: &'a mut bool,
    /// A state necessary so as to implement `MBio::wait_readable`
    read_byte: &'a mut Option<u8>,
    /// A state necessary so as to implement `MBio::wait_writable`
    write_byte: &'a mut Option<u8>,
}

impl<'a, T> MBio<'a, &'a mut T>
where
    T: Read + Write,
{
    fn from_session(session: &'a mut Session<'_, T>) -> Self {
        Self::new(
            &mut session.stream,
            &session.state.ssl_context,
            &mut session.eof,
            &mut session.read_byte,
            &mut session.write_byte,
        )
    }
}

impl<'a, T> MBio<'a, &'a mut NoWrite<T>>
where
    T: Read,
{
    fn from_read(session: &'a mut SessionRead<'_, T>) -> Self {
        Self::new(
            &mut session.stream,
            session.ssl_context,
            session.eof,
            session.read_byte,
            &mut session.write_byte,
        )
    }
}

impl<'a, T> MBio<'a, &'a mut NoRead<T>>
where
    T: Write,
{
    fn from_write(session: &'a mut SessionWrite<'_, T>) -> Self {
        Self::new(
            &mut session.stream,
            session.ssl_context,
            &mut session.eof,
            &mut session.read_byte,
            session.write_byte,
        )
    }
}

impl<'a, T> MBio<'a, T>
where
    T: Read + Write,
{
    const fn new(
        stream: T,
        ssl_context: &'a mbedtls_ssl_context,
        eof: &'a mut bool,
        read_byte: &'a mut Option<u8>,
        write_byte: &'a mut Option<u8>,
    ) -> Self {
        Self {
            stream,
            ssl_context,
            eof,
            read_byte,
            write_byte,
        }
    }

    /// Establish the SSL connection
    async fn connect(&mut self, saved_session: Option<&SavedSession>) -> Result<(), SessionError> {
        debug!("Establishing SSL connection");

        merr!(unsafe { mbedtls_ssl_session_reset(self.ssl_context as *const _ as *mut _) })?;

        if let Some(saved_session) = saved_session {
            merr!(unsafe {
                mbedtls_ssl_set_session(
                    self.ssl_context as *const _ as *mut _,
                    &*saved_session.mbedtls_session,
                )
            })?;
        }

        loop {
            match self
                .call_mbedtls(|ssl_ctx| unsafe {
                    mbedtls_ssl_handshake(ssl_ctx as *const _ as *mut _)
                })
                .await
            {
                MBEDTLS_ERR_SSL_WANT_READ => {
                    if !self.wait_readable().await.map_err(SessionError::from_io)? {
                        return Err(SessionError::Io(ErrorKind::BrokenPipe));
                    }
                }
                MBEDTLS_ERR_SSL_WANT_WRITE => {
                    if !self.wait_writable().await.map_err(SessionError::from_io)? {
                        return Err(SessionError::Io(ErrorKind::BrokenPipe));
                    }
                }
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                other => {
                    merr!(other)?;
                    break Ok(());
                }
            }
        }
    }

    /// Read unencrypted data from the TLS connection
    ///
    /// # Arguments
    /// - `buf` - The buffer to read the data into
    ///
    /// # Returns
    /// - The number of bytes read or an error
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        loop {
            match self
                .call_mbedtls(|ssl_ctx| unsafe {
                    mbedtls_ssl_read(
                        ssl_ctx as *const _ as *mut _,
                        buf.as_mut_ptr() as *mut _,
                        buf.len() as _,
                    )
                })
                .await
            {
                MBEDTLS_ERR_SSL_WANT_READ => {
                    if !self.wait_readable().await.map_err(SessionError::from_io)? {
                        return Err(SessionError::Io(ErrorKind::BrokenPipe));
                    }
                }
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => {
                    *self.eof = true;
                    break Ok(0);
                }
                other => {
                    let len = merr!(other)?;
                    break Ok(len as usize);
                }
            }
        }
    }

    /// Write unencrypted data to the TLS connection
    ///
    /// Arguments:
    /// - `data` - The data to write
    ///
    /// Returns:
    /// - The number of bytes written or an error
    async fn write(&mut self, data: &[u8]) -> Result<usize, SessionError> {
        loop {
            match self
                .call_mbedtls(|ssl_ctx| unsafe {
                    mbedtls_ssl_write(
                        ssl_ctx as *const _ as *mut _,
                        data.as_ptr() as *const _,
                        data.len() as _,
                    )
                })
                .await
            {
                MBEDTLS_ERR_SSL_WANT_WRITE => {
                    if !self.wait_writable().await.map_err(SessionError::from_io)? {
                        return Err(SessionError::Io(ErrorKind::BrokenPipe));
                    }
                }
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                other => {
                    let len = merr!(other)?;
                    break Ok(len as usize);
                }
            }
        }
    }

    /// Flush the TLS connection by writing any outstanding data to the underlying stream
    /// and then flushing the stream
    async fn flush(&mut self) -> Result<(), SessionError> {
        if !self.wait_writable().await.map_err(SessionError::from_io)? {
            return Err(SessionError::Io(ErrorKind::BrokenPipe));
        }

        self.stream.flush().await.map_err(SessionError::from_io)
    }

    /// Close the TLS connection by sending the "close notify" alert to the peer and flushing the stream
    pub async fn close(&mut self) -> Result<(), SessionError> {
        merr!(
            self.call_mbedtls(|ssl| unsafe { mbedtls_ssl_close_notify(ssl as *const _ as *mut _) })
                .await
        )?;

        self.flush().await?;

        Ok(())
    }

    /// Wait until the underlying stream is readable
    ///
    /// A side effect of this function is that it reads one byte from the stream
    /// and stores it for later consumption by the `bio_receive` method.
    ///
    /// Return `Ok(true)` if the stream is readable, `Ok(false)` if EOF is reached,
    /// or an error otherwise.
    async fn wait_readable(&mut self) -> Result<bool, T::Error> {
        if self.read_byte.is_none() {
            let mut buf = [0u8; 1];
            let len = self.stream.read(&mut buf).await?;
            if len == 0 {
                return Ok(false);
            }

            *self.read_byte = Some(buf[0]);
        }

        Ok(true)
    }

    /// Wait until the underlying stream is writable
    ///
    /// A side effect of this function is that it writes one byte to the stream
    /// where that byte had been provided by the `bio_send` method.
    ///
    /// Return `Ok(true)` if the stream is writable (or there is no byte to write), `Ok(false)` if EOF is reached,
    /// or an error otherwise.
    async fn wait_writable(&mut self) -> Result<bool, T::Error> {
        if let Some(byte) = self.write_byte.as_ref() {
            let len = self.stream.write(&[*byte]).await?;
            if len == 0 {
                return Ok(false);
            }

            self.write_byte.take();
        }

        Ok(true)
    }

    /// Call an MbedTLS function with the proper BIO callbacks set
    /// and with a proper context for the async operations on the underlying stream
    async fn call_mbedtls<F>(&mut self, mut f: F) -> i32
    where
        F: FnMut(&mbedtls_ssl_context) -> i32,
    {
        poll_fn(|ctx| {
            let mut io_ctx = MBioCallCtx { io: self, ctx };

            unsafe {
                mbedtls_ssl_set_bio(
                    io_ctx.io.ssl_context as *const _ as *mut _,
                    &mut io_ctx as *const _ as *mut MBioCallCtx<'_, '_, '_, T> as *mut c_void,
                    Some(Self::raw_send),
                    Some(Self::raw_receive),
                    None,
                );
            }

            let result = f(io_ctx.io.ssl_context);

            // Remove the callbacks so that we get a warning from MbedTLS in case
            // it needs to invoke them when we don't anticipate so (for bugs detection)
            unsafe {
                mbedtls_ssl_set_bio(
                    io_ctx.io.ssl_context as *const _ as *mut _,
                    core::ptr::null_mut(),
                    None,
                    None,
                    None,
                );
            }

            Poll::Ready(result)
        })
        .await
    }

    /// The MbedTLS BIO receive callback
    fn bio_receive(&mut self, buf: &mut [u8], ctx: &mut Context<'_>) -> i32 {
        trace!("Receive {}B", buf.len());

        match self.poll_read(ctx, buf) {
            Poll::Ready(len) => len as _,
            Poll::Pending => MBEDTLS_ERR_SSL_WANT_READ,
        }
    }

    /// The MbedTLS BIO send callback
    fn bio_send(&mut self, buf: &[u8], ctx: &mut Context<'_>) -> i32 {
        trace!("Send {}B", buf.len());

        match self.poll_write(ctx, buf) {
            Poll::Ready(len) => len as _,
            Poll::Pending => MBEDTLS_ERR_SSL_WANT_WRITE,
        }
    }

    /// Read data from the underlying stream without blocking
    fn poll_read(&mut self, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<usize> {
        if buf.is_empty() {
            // Buffer is empty, nothing to read
            return Poll::Ready(0);
        }

        let mut len = 0;

        if let Some(byte) = self.read_byte.take() {
            // We have one byte ready via `wait_readable`
            // Push it to the buffer

            buf[0] = byte;
            len += 1;
        }

        if buf.len() > len {
            // Buffer has extra space, try to read more, if data is available

            let mut fut = pin!(self.stream.read(&mut buf[len..]));

            if let Poll::Ready(Ok(poll_len)) = fut.as_mut().poll(ctx) {
                len += poll_len;
            }
        }

        if len > 0 {
            Poll::Ready(len)
        } else {
            Poll::Pending
        }
    }

    /// Write data to the underlying stream without blocking
    fn poll_write(&mut self, ctx: &mut Context<'_>, data: &[u8]) -> Poll<usize> {
        if self.write_byte.is_some() {
            // First, try to send the pending byte from `wait_writable`

            let data = [self.write_byte.unwrap()];
            let mut fut = pin!(self.stream.write(&data));

            if let Poll::Ready(Ok(1)) = fut.as_mut().poll(ctx) {
                *self.write_byte = None;
            }
        }

        if data.is_empty() {
            // Data is empty, nothing to write
            return Poll::Ready(0);
        }

        let mut len = 0;

        if self.write_byte.is_none() {
            // Since there is no outstanding byte to write, try to write the data

            // First, try to write directly to the stream as much as possible without blocking

            let mut fut = pin!(self.stream.write(data));

            if let Poll::Ready(Ok(poll_len)) = fut.as_mut().poll(ctx) {
                len += poll_len;
            }

            if data.len() > len {
                // Next, store the next byte to be written later via `wait_writable`

                *self.write_byte = Some(data[len]);
                len += 1;
            }
        }

        if len > 0 {
            Poll::Ready(len)
        } else {
            Poll::Pending
        }
    }

    /// The raw MbedTLS BIO receive callback
    unsafe extern "C" fn raw_receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
        let ctx = (ctx as *mut MBioCallCtx<'_, '_, '_, T>).as_mut().unwrap();

        ctx.io
            .bio_receive(core::slice::from_raw_parts_mut(buf as *mut _, len), ctx.ctx)
    }

    /// The raw MbedTLS BIO send callback
    unsafe extern "C" fn raw_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
        let ctx = (ctx as *mut MBioCallCtx<'_, '_, '_, T>).as_mut().unwrap();

        ctx.io
            .bio_send(core::slice::from_raw_parts(buf as *const _, len), ctx.ctx)
    }
}

/// The context passed to the MbedTLS BIO callbacks.
///
/// Basically, a pair of a mutable reference to the `MBio` instance
/// and a mutable reference to the async `Context` where the latter is necessary
/// so that we can poll the stream from within the BIO callbacks.
struct MBioCallCtx<'a, 'b, 'c, T> {
    io: &'a mut MBio<'b, T>,
    ctx: &'a mut Context<'c>,
}

/// A wrapper around a type implementing `Write` which turns it into
/// a type implementing both `Read` and `Write`, but where the `Read` implementation
/// is unreachable.
///
/// Used when splitting a `Session` into a read-only and write-only halves, for the
/// "write" half.
///
/// This type is necessary because the `MBio` struct requires both `Read` and `Write`
/// traits to be implemented on the stream.
struct NoRead<T>(T);

impl<T> ErrorType for NoRead<T>
where
    T: ErrorType,
{
    type Error = T::Error;
}

impl<T> Read for NoRead<T>
where
    T: ErrorType,
{
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        unreachable!()
    }
}

impl<T> Write for NoRead<T>
where
    T: Write,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush().await
    }
}

/// A wrapper around a type implementing `Read` which turns it into
/// a type implementing both `Read` and `Write`, but where the `Write` implementation
/// is unreachable.
///
/// Used when splitting a `Session` into a read-only and write-only halves, for the
/// "read" half.
///
/// This type is necessary because the `MBio` struct requires both `Read` and `Write`
/// traits to be implemented on the stream.
struct NoWrite<T>(T);

impl<T> ErrorType for NoWrite<T>
where
    T: ErrorType,
{
    type Error = T::Error;
}

impl<T> Read for NoWrite<T>
where
    T: Read,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).await
    }
}

impl<T> Write for NoWrite<T>
where
    T: ErrorType,
{
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        unreachable!()
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        unreachable!()
    }
}
