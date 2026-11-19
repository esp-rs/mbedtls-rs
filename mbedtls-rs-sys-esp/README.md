# mbedtls-rs-sys-esp

Hardware acceleration of MbedTLS for the ESP32 chips, for baremetal firmware based on `esp-hal`.

The crate implements the hooks of [`mbedtls-rs-sys`](../mbedtls-rs-sys) (see "Hooking" in its README) with the crypto accelerators of the chip:

| Chip     | SHA | RSA (modular exponentiation) | AES | ECC (P-192, P-256) |
|----------|-----|------------------------------|-----|--------------------|
| esp32    |  -  |  x                           |  x  |  -                 |
| esp32s2  |  x  |  x                           |  x  |  -                 |
| esp32s3  |  x  |  x                           |  x  |  -                 |
| esp32c2  |  x  |  -                           |  -  |  x                 |
| esp32c3  |  x  |  x                           |  x  |  -                 |
| esp32c5  |  x  |  x                           |  x  |  x                 |
| esp32c6  |  x  |  x                           |  x  |  x                 |
| esp32h2  |  x  |  x                           |  x  |  x                 |

SHA-1 and SHA-224/256 are accelerated on all chips with SHA, and SHA-384/512 on the esp32s2 and esp32s3 only. The SHA peripheral of the esp32 is not supported by `esp-hal`.

It also has a wall clock based on the RTC (`EspRtcWallClock`), for the X.509 date checks.

## Usage

Select the chip with one of the `esp32`, `esp32c2`, `esp32c3`, `esp32c5`, `esp32c6`, `esp32h2`, `esp32s2` or `esp32s3` features:

```toml
mbedtls-rs-sys-esp = { version = "0.1", features = ["esp32c6"] }
```

The chip feature enables the `mbedtls-rs-sys` hooks of the accelerators that the chip has. A hook is only installed if its algorithm is compiled into MbedTLS as well, so this crate does not change the selection of algorithms. The prebuilt MbedTLS libraries are built with all the algorithm hooks, so with the default `tls` profile they are used as they are. Other profiles, and the wall clock, need MbedTLS to be compiled on the fly.

The wall clock is only available if the `hook-wall-clock` feature of `mbedtls-rs-sys` (or of `mbedtls-rs`) is enabled. It is not enabled by this crate, because it turns on the X.509 date checks, which need a correct time.

Then, early in the firmware, start the `esp-hal` crypto backends and register the hooks:

```rust,ignore
use mbedtls_rs_sys_esp::EspAccel;

let mut accel = EspAccel::new()
    .with_sha(peripherals.SHA)
    .with_rsa(peripherals.RSA)
    .with_aes(peripherals.AES)
    .with_ecc(peripherals.ECC);

let queue = accel.start();
let _hooks = unsafe { queue.hook() };

// Use MbedTLS while `queue` and `_hooks` are alive
```

`EspAccel` is optional. If other parts of the firmware use the `esp-hal` crypto backends too, start them yourself and register the hooks with `EspHooks`. Note that an algorithm whose hook is registered, but whose `esp-hal` work queue is not serviced, blocks forever.
