# mbedtls-rs

Rust library implementing transparent TLS encryption/decryption for IO streams.
`no_std` compatible (but needs `alloc`!) and thus suitable for use on baremetal MCUs.

Uses MbedTLS 3.X under the hood, via `mbedtls-rs-sys`.

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
