# mbedtls-rs

Rust library implementing transparent TLS encryption/decryption for IO streams.
`no_std` compatible (but needs `alloc`!) and thus suitable for use on baremetal MCUs.

Uses MbedTLS 3.X under the hood, via `mbedtls-rs-sys`.

## Authentication

A session proves to its peer who it is with an `Authentication`: a certificate and its private key, a pre-shared key (`Authentication::Psk`, or `Authentication::PskLookup` for a server with a key for each client) or, with the `kex-ecjpake` feature, an EC J-PAKE password. On ESP-IDF, MbedTLS is ESP-IDF's, and pre-shared keys and EC J-PAKE follow its configuration.

## DTLS

The `dtls` module has DTLS 1.2 sessions over datagram transports. A session times the retransmissions of its handshake with a `dtls::Clock`; `dtls::EmbassyClock` is one, with the `embassy-time` feature. A server session first checks, with a cookie, that its client receives at the address it sends from (`dtls::CookieCheck`), so that a forged address does not get the server's flights. With the `kex-ecjpake` feature, a session can use an EC J-PAKE handshake instead of certificates (`Authentication::EcJpake`), as Thread commissioning does.

## Certificate validity dates

By default the `notBefore` / `notAfter` window of a peer certificate is **not** checked, so an expired or not-yet-valid certificate is accepted even under `AuthMode::Required`. Chain, signature and hostname verification are unaffected.

This is because `MBEDTLS_HAVE_TIME_DATE` is off unless the `hook-wall-clock` feature is enabled: a `no_std` target has no wall clock unless the consumer supplies one. To enable the date checks, turn on `hook-wall-clock` and install an `MbedtlsWallClock` implementation (plus an `MbedtlsTimer`, which `hook-wall-clock` enables) before any X.509 use. With the feature enabled and no clock installed, validation fails closed.

Example (see all in the `examples` folder):
```rust
//! A platform-agnostic HTTPS 1.0 request-response client using the async API.

use core::ffi::CStr;

use mbedtls_rs::io::{Read, Write};
use mbedtls_rs::{Session, SessionConfig, SessionError, TlsReference};

use log::info;

#[path = "certs.rs"]
mod certs;

/// Perform a simple HTTPS 1.0 GET request and print the response to the log.
///
/// # Arguments:
/// - `tls`: A reference to the TLS context.
/// - `socket`: The underlying socket implementing `Read` and `Write`.
/// - `server_name_cstr`: The server name as a C string.
/// - `server_path`: The path to request from the server.
/// - `mtls`: Whether to use mutual TLS authentication.
/// - `buf`: A buffer to read the response into.
pub async fn request<T>(
    tls: TlsReference<'_>,
    socket: T,
    server_name_cstr: &CStr,
    server_path: &str,
    mtls: bool,
    buf: &mut [u8],
) -> Result<(), SessionError>
where
    T: Read + Write,
{
    let server_name = server_name_cstr.to_str().unwrap();

    info!("Creating TLS session");

    let mut session = Session::new(
        tls,
        socket,
        &SessionConfig::Client(certs::client_conf(mtls, Some(server_name_cstr))),
    )?;

    info!("Requesting GET {} from server", server_path);

    session.write_all(b"GET ").await?;
    session.write_all(server_path.as_bytes()).await?;
    session.write_all(b" HTTP/1.0\r\nHost: ").await?;
    session.write_all(server_name.as_bytes()).await?;
    session.write_all(b"\r\n\r\n").await?;

    info!("Reading response\n=============================");

    loop {
        let len = session.read(buf).await?;
        if len == 0 {
            break;
        }

        info!("{}", core::str::from_utf8(&buf[..len]).unwrap_or("???"));
    }

    info!("\n=============================");

    session.close().await?;

    info!("Done");

    Ok(())
}
```
