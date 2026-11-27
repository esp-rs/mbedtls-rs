# mbedtls-rs-sys-embassy

Implementations of the [`mbedtls-rs-sys`](../mbedtls-rs-sys) hooks for the Embassy ecosystem:
- Acceleration with the [`embassy-crypto`](https://github.com/embassy-rs/embassy/tree/main/embassy-crypto) drivers
- A monotonic timer over `embassy-time` (`timer::EmbassyTimer`), for the DTLS retransmission timeouts (`hook_timer`)

## `embassy-crypto`

The crate implements the hooks of [`mbedtls-rs-sys`](../mbedtls-rs-sys) (see "Hooking" in its README) over the `embassy-crypto` operations. `embassy-crypto` defines one link-time pluggable driver per operation, and the firmware registers the drivers it has: hardware drivers (e.g. those of `embassy-nrf`), or software ones like those of `embassy-crypto-rustcrypto`.

| Hook           | Implementation               | `embassy-crypto` drivers                                                   |
|----------------|------------------------------|----------------------------------------------------------------------------|
| `hook_sha1`    | `SHA1`                       | `Sha1`                                                                     |
| `hook_sha224`  | `SHA224`                     | `Sha224`                                                                   |
| `hook_sha256`  | `SHA256`                     | `Sha256`                                                                   |
| `hook_sha384`  | `SHA384`                     | `Sha384`                                                                   |
| `hook_sha512`  | `SHA512`                     | `Sha512`                                                                   |
| `hook_aes`     | `AES`, `aes::EmbassyAes`     | `Aes128Ecb`, `Aes256Ecb`                                                   |
| `hook_ecp_mul` | `ECP`, `ecp::EmbassyEcp`     | `P256Arith`, optionally `P384Arith`                                        |
| `hook_ecdsa`   | `ECDSA`, `ecp::EmbassyEcdsa` | `P256Ecdsa`, optionally `P384Ecdsa` (both drawing their nonces from `Rng`) |
| `hook_ecdh`    | `ECDH`, `ecp::EmbassyEcdh`   | `P256Ecdh`, optionally `P384Ecdh`                                          |

- Hook: the `mbedtls-rs-sys` function that registers the implementation
- Implementation: the ready-made static of this crate, and the generic type behind it (for other sets of key sizes or curves)
- `embassy-crypto` drivers: the drivers the firmware must register for the implementation

Only the drivers behind the registered hooks are needed. The AES and elliptic-curve implementations are generic over the set of drivers they use (e.g. `EmbassyAes<embassy_crypto::Aes128>` needs the AES-128 driver only); what is outside the set is left to the MbedTLS software implementation.

### Usage

```toml
mbedtls-rs-sys-embassy = "0.1"
```

The crate has no features. An implementation is only available if its hook is installed in MbedTLS. The prebuilt MbedTLS libraries have all the hooks, so with the default `tls` profile nothing else is needed. With other profiles, MbedTLS is compiled on the fly, and the hooks to install are selected with the `hook-*` features of `mbedtls-rs-sys` (or of `mbedtls-rs`) - e.g. `hook-sha256`, `hook-aes` and `hook-ecdsa` for the example below. This crate cannot enable them itself, as it does not know which drivers the firmware registers.

Then, early in the firmware, before MbedTLS is used:

```rust,ignore
use mbedtls_rs_sys::hook::aes::hook_aes;
use mbedtls_rs_sys::hook::digest::hook_sha256;
use mbedtls_rs_sys::hook::ecdsa::hook_ecdsa;
use mbedtls_rs_sys_embassy::{AES, ECDSA, SHA256};

// Requires the `Sha256`, `Aes128Ecb`, `Aes256Ecb`, `P256Ecdsa` and `Rng` drivers
unsafe {
    hook_sha256(Some(&SHA256));
    hook_aes(Some(&AES));
    hook_ecdsa(Some(&ECDSA));
}
```

The ECDSA drivers draw their nonces from the `embassy-crypto` `Rng` driver, so their signatures are randomized, also where MbedTLS would make deterministic (RFC 6979) ones.

## `embassy-time`

The timer needs the `hook-timer` feature of `mbedtls-rs-sys` (or of `mbedtls-rs`); the prebuilt MbedTLS libraries do not have it. Register it with `hook_timer`:

```rust,ignore
use mbedtls_rs_sys::hook::timer::hook_timer;
use mbedtls_rs_sys_embassy::timer::EmbassyTimer;

static TIMER: EmbassyTimer = EmbassyTimer;

unsafe {
    hook_timer(Some(&TIMER));
}
```

## Testing

The host tests use the software drivers of `embassy-crypto-rustcrypto`. The tests of a hook only run if the hook is installed:

```sh
cargo test -p mbedtls-rs-sys-embassy --features mbedtls-rs-sys/hook-sha1,mbedtls-rs-sys/hook-sha256,mbedtls-rs-sys/hook-sha512,mbedtls-rs-sys/hook-aes,mbedtls-rs-sys/hook-ecp-mul,mbedtls-rs-sys/hook-ecdsa,mbedtls-rs-sys/hook-ecdh
```
