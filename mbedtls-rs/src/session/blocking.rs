use core::ffi::{c_int, c_uchar, c_void, CStr};

use io::{ErrorType, Read, Write};

use crate::sys::*;

use super::{SavedSession, SessionConfig, SessionError, SessionState, TlsReference};

/// Re-export of the `embedded-io` crate so that users don't have to explicitly depend on it
/// to use e.g. `write_all` or `read_exact`.
pub mod io {
    pub use embedded_io::*;
}

/// A blocking TLS session over a stream represented by `embedded-io`'s `Read` and `Write` traits.
pub struct Session<'a, T>
where
    T: Read + Write,
{
    /// The underlying stream implementing `Read` and `Write`
    stream: T,
    /// The session state
    state: SessionState<'a>,
    /// Whether the session is connected
    connected: bool,
    /// Whether we received a close notify from the peer
    eof: bool,
    /// Reference to the active Tls instance
    _tls_ref: TlsReference<'a>,
}

impl<'a, T> Session<'a, T>
where
    T: Read + Write,
{
    /// Create a session for a TLS stream.
    ///
    /// # Arguments
    /// - `tls_ref` - A reference to the active `Tls` instance.
    /// - `stream` - The stream for the connection.
    /// - `config` - The session configuration.
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
            _tls_ref: tls,
        })
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

    fn connect_internal(
        &mut self,
        saved_session: Option<&SavedSession>,
    ) -> Result<(), SessionError> {
        if self.connected {
            return Ok(());
        }

        merr!(unsafe { mbedtls_ssl_session_reset(&mut *self.state.ssl_context) })?;

        if let Some(saved_session) = saved_session {
            merr!(unsafe {
                mbedtls_ssl_set_session(
                    &*self.state.ssl_context as *const _ as *mut _,
                    &*saved_session.mbedtls_session,
                )
            })?;
        }

        loop {
            match self.call_mbedtls(|ssl_ctx| unsafe { mbedtls_ssl_handshake(ssl_ctx) }) {
                MBEDTLS_ERR_SSL_WANT_READ => continue,
                MBEDTLS_ERR_SSL_WANT_WRITE => continue,
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                other => {
                    merr!(other)?;

                    self.connected = true;
                    self.eof = false;

                    break Ok(());
                }
            }
        }
    }

    /// Negotiate the TLS connection
    ///
    /// This function will perform the TLS handshake with the server.
    ///
    /// Note that calling it is not mandatory, because the TLS session is anyway
    /// negotiated during the first read or write operation.
    pub fn connect(&mut self) -> Result<(), SessionError> {
        self.connect_internal(None)
    }

    /// Negotiate the TLS connection attempting to reuse a previously captured session.
    ///
    /// Use [`Session::save`] to get a copy of the session to use here  
    pub fn connect_with_session(
        &mut self,
        saved_session: &SavedSession,
    ) -> Result<(), SessionError> {
        self.connect_internal(Some(saved_session))
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

    /// Read unencrypted data from the TLS connection
    ///
    /// # Arguments
    /// - `buf` - The buffer to read the data into
    ///
    /// # Returns
    /// The number of bytes read or an error
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
        self.connect()?;

        if self.eof {
            return Ok(0);
        }

        loop {
            match self.call_mbedtls(|ssl_ctx| unsafe {
                mbedtls_ssl_read(ssl_ctx as *const _ as *mut _, buf.as_mut_ptr(), buf.len())
            }) {
                MBEDTLS_ERR_SSL_WANT_READ => continue,
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => {
                    self.eof = true;
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
    /// # Arguments:
    /// - `data` - The data to write
    ///
    /// # Returns:
    /// - The number of bytes written or an error
    pub fn write(&mut self, data: &[u8]) -> Result<usize, SessionError> {
        self.connect()?;

        loop {
            match self.call_mbedtls(|ssl_ctx| unsafe {
                mbedtls_ssl_write(ssl_ctx as *const _ as *mut _, data.as_ptr(), data.len())
            }) {
                MBEDTLS_ERR_SSL_WANT_WRITE => continue,
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                other => {
                    let len = merr!(other)?;
                    break Ok(len as usize);
                }
            }
        }
    }

    /// Flush the TLS connection
    ///
    /// This function will flush the TLS connection, ensuring that all data is sent.
    ///
    /// # Returns:
    /// - An error if the flush failed
    pub fn flush(&mut self) -> Result<(), SessionError> {
        self.connect()?;

        self.stream.flush().map_err(SessionError::from_io)
    }

    /// Close the TLS connection
    ///
    /// This function will close the TLS connection, sending the TLS "close notify" info to the peer.
    ///
    /// # Returns:
    /// - An error if the close failed
    pub fn close(&mut self) -> Result<(), SessionError> {
        if !self.connected {
            return Ok(());
        }

        merr!(
            self.call_mbedtls(|ssl| unsafe { mbedtls_ssl_close_notify(ssl as *const _ as *mut _) })
        )?;

        self.flush()?;

        self.connected = false;

        Ok(())
    }

    /// Helper function to call MbedTLS functions with BIO callbacks set
    fn call_mbedtls<F>(&mut self, mut f: F) -> c_int
    where
        F: FnMut(&mut mbedtls_ssl_context) -> c_int,
    {
        unsafe {
            mbedtls_ssl_set_bio(
                &mut *self.state.ssl_context as *mut _,
                self as *const _ as *mut Self as *mut c_void,
                Some(Self::raw_send),
                Some(Self::raw_receive),
                None,
            );
        }

        let result = f(&mut self.state.ssl_context);

        // Remove the callbacks so that we get a warning from MbedTLS in case
        // it needs to invoke them when we don't anticipate so (for bugs detection)
        unsafe {
            mbedtls_ssl_set_bio(
                &*self.state.ssl_context as *const _ as *mut _,
                core::ptr::null_mut(),
                None,
                None,
                None,
            );
        }

        result
    }

    /// The MbedTLS BIO receive callback
    fn bio_receive(&mut self, buf: &mut [u8]) -> c_int {
        let res = self.stream.read(buf);

        match res {
            Ok(len) => {
                if len == 0 {
                    MBEDTLS_ERR_SSL_WANT_READ
                } else {
                    len as c_int
                }
            }
            Err(_) => 0,
        }
    }

    /// The MbedTLS BIO send callback
    fn bio_send(&mut self, data: &[u8]) -> c_int {
        let res = self.stream.write(data);

        match res {
            Ok(written) => {
                if written > 0 {
                    written as i32
                } else {
                    MBEDTLS_ERR_SSL_WANT_WRITE
                }
            }
            Err(_) => 0,
        }
    }

    /// The raw MbedTLS BIO receive callback
    unsafe extern "C" fn raw_receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
        let session = (ctx as *mut Self).as_mut().unwrap();

        session.bio_receive(core::slice::from_raw_parts_mut(buf as *mut _, len))
    }

    /// The raw MbedTLS BIO send callback
    unsafe extern "C" fn raw_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
        let session = (ctx as *mut Self).as_mut().unwrap();

        session.bio_send(core::slice::from_raw_parts(buf as *const _, len))
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
        if let Err(e) = self.close() {
            error!("Error during TLS session close: {:?}", e);
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
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Self::read(self, buf)
    }
}

impl<T> Write for Session<'_, T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Self::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Self::flush(self)
    }
}
