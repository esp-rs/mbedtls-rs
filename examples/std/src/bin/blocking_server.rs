//! Example of an HTTPS server, using the blocking API.
//!
//! This example runs a simple HTTPS server that answers with a fixed text message to all HTTP GET requests.
//!
//! Since the server certificates are self-signed, the easiest way to test is with:
//! ```sh
//! curl -k https://localhost:8443/
//! ```
//!
//! Alternatively, accept the self-signed certificate warning in the browser.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use std::net::TcpListener;

use embedded_io_adapters::std::FromStd;

use mbedtls_rs::Tls;

use log::{info, warn};

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/std_rng.rs"]
mod rng;
#[path = "../../../common/blocking_server.rs"]
mod server;

fn main() {
    bootstrap::bootstrap();

    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    // SAFETY: `rng` is declared before `tls` and outlives it; `tls` is dropped
    // at the end of this scope and never leaked, so the borrow stays valid for
    // the whole lifetime of the global RNG slot.
    let mut tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    tls.set_debug(1);

    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        8443,
    )))
    .unwrap();

    info!("Listening on port 8443");

    loop {
        let (socket, addr) = listener.accept().unwrap();

        info!("Accepted connection from {}", addr);

        std::thread::scope(|s| {
            let tls = tls.reference();

            s.spawn(move || {
                let mut buf = [0u8; 4096];

                if let Err(e) = server::reply(tls, FromStd::new(socket), false, &mut buf) {
                    warn!("Error handling connection from {}: {:?}", addr, e);
                }
            });
        });
    }
}
