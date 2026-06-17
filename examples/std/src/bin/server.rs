//! Example of an HTTPS server.
//! Demonstrates the usage of the async API of mbedtls-rs.
//!
//! Since the server certificates are self-signed, the easiest way to test is with:
//! ```sh
//! curl -k https://localhost:8443/
//! ```
//!
//! Alternatively, accept the self-signed certificate warning in the browser.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use std::net::TcpListener;

use async_executor::LocalExecutor;

use async_io_mini::Async;

use embedded_io_adapters::futures_03::FromFutures;

use mbedtls_rs::Tls;

use log::{info, warn};

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/std_rng.rs"]
mod rng;
#[path = "../../../common/server.rs"]
mod server;

fn main() {
    bootstrap::bootstrap();

    bootstrap::block_on(run());
}

async fn run() {
    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    // SAFETY: `rng` is declared before `tls` and outlives it; `tls` is dropped
    // at the end of this scope and never leaked, so the borrow stays valid for
    // the whole lifetime of the global RNG slot.
    let mut tls = unsafe { Tls::new_local_borrows(&mut rng) }.unwrap();

    tls.set_debug(0);

    let executor = LocalExecutor::new();

    executor.run(accept(&executor, &tls)).await;
}

async fn accept<'a>(executor: &LocalExecutor<'a>, tls: &'a Tls<'_>) {
    let listener = Async::<TcpListener>::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        8443,
    )))
    .unwrap();

    info!("Listening on port 8443");

    loop {
        let (socket, addr) = listener.accept().await.unwrap();

        info!("Accepted connection from {}", addr);

        let tls = tls.reference();

        executor
            .spawn(async move {
                let mut buf = vec![0; 4096];

                if let Err(e) = server::reply(tls, FromFutures::new(socket), false, &mut buf).await
                {
                    warn!("Error handling connection from {}: {:?}", addr, e);
                }
            })
            .detach();
    }
}
