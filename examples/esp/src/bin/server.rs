//! Example of an HTTPS server.
//! Demonstrates the usage of the async API of mbedtls-rs.
//!
//! Since the server certificates are self-signed, the easiest way to test is with:
//! ```sh
//! curl -k https://<ip-printed-by-this-example>/
//! ```
//!
//! Alternatively, accept the self-signed certificate warning in the browser.

#![no_std]
#![no_main]
#![recursion_limit = "256"]

use embassy_executor::Spawner;

use embassy_net::{tcp::TcpSocket, IpListenEndpoint, StackResources};

use esp_alloc::heap_allocator;
use esp_backtrace as _;

use mbedtls_rs::Tls;

use log::{info, warn};

use tinyrlibc as _;

use crate::bootstrap::RECLAIMED_RAM;

extern crate alloc;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/server.rs"]
mod server;

const HEAP_SIZE: usize = 160 * 1024;

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);

    let stack_resources = mk_static!(StackResources<4>, StackResources::new());

    let (mut tls, stack, mut accel, ..) =
        bootstrap::bootstrap_stack(spawner, stack_resources).await;

    tls.set_debug(1);

    let _accel_queue = accel.start();

    let tls = mk_static!(Tls, tls);

    spawner.spawn(http_task("Task 1", tls, stack)).ok();
    spawner.spawn(http_task("Task 2", tls, stack)).ok();

    // Don't exit so that the acceleration routines can stay registered
    core::future::pending::<()>().await
}

#[embassy_executor::task(pool_size = 2)]
async fn http_task(
    task_id: &'static str,
    tls: &'static Tls<'static>,
    stack: embassy_net::Stack<'static>,
) {
    loop {
        let mut rx_buf = [0; 1024];
        let mut tx_buf = [0; 1024];

        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);

        info!("[{}] Listening on port 443", task_id);

        socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 443,
            })
            .await
            .unwrap();

        info!(
            "[{}] Accepted connection from: {:?}",
            task_id,
            socket.remote_endpoint()
        );

        let mut buf = [0u8; 4096];

        if let Err(e) = server::reply(tls.reference(), &mut socket, false, &mut buf).await {
            warn!(
                "[{}] Error handling connection from {:?}: {:?}",
                task_id,
                socket.remote_endpoint(),
                e
            );
        } else {
            info!(
                "[{}] Connection from {:?} handled successfully",
                task_id,
                socket.remote_endpoint()
            );
        }

        socket.close();
    }
}
