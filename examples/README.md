# `mbedtls-rs` Examples

The examples currently run on the following platforms:

## STD (and ESP-IDF)

Check folder [std](std).

Build:
```sh
cd examples/std
cargo build
```

Build for ESP-IDF*:
```sh
export WIFI_SSID="your-wifi-ssid"
export WIFI_PASS="your-wifi-password"
export MCU="<your-mcu>"
cd examples/std
cargo build --target <esp-idf-target> --Zbuild-std=std,panic_abort
```

...where:
- `<your-mcu>` - the ESP32 MCU you would like to build for
- `<esp-idf-target>` - the ESP-IDF target corresponding to the ESP32 MCU

Supported `esp32xx` MCUs (relevant HW acceleration is automatically enabled by ESP-IDF itself):
| MCU          | Target                       |
| ------------ | ---------------------------- |
| esp32        | xtensa-esp32-espidf          |
| esp32c2      | riscv32imac-esp-espidf       |
| esp32c3      | riscv32imc-esp-iespidf       |
| esp32c6      | riscv32imac-esp-espidf       |
| esp32h2      | riscv32imac-esp-espidf       |
| esp32s2      | xtensa-esp32s2-espidf        |
| esp32s3      | xtensa-esp32s3-espidf        |

(*) **NOTE: Building for xtensa targets requires the usage of the `esp` Rust toolchain, by instaling `espup`, i.e.:**
```sh
cargo install espup
espup install
rusup default esp
```

## Baremetal ESP32-XX with `esp-hal` and `embassy-net`

Check folder [esp](esp).

Build*:
```sh
export WIFI_SSID="your-wifi-ssid"
export WIFI_PASS="your-wifi-password"
cd examples/esp
cargo build --no-default-features --features <esp32XX> --target <esp32XX-target>
```

To build and run one example, i.e. `client`*:
```sh
export WIFI_SSID="your-wifi-ssid"
export WIFI_PASS="your-wifi-password"
cd examples/esp
cargo run --bin client --no-default-features --features <esp32XX> --target <esp32XX-target>
```

...where:
- `<esp32XX>` - the ESP32 MCU you would like to build for
- `<esp32XX-target>` - the target corresponding to the ESP32 MCU

Supported `esp32xx` MCUs and their corresponding `<esp32XX-target>` targets:
| MCU          | Target                       | Hardware Acceleration                            |
| ------------ | ---------------------------- | ------------------------------------------------ |
| esp32        | xtensa-esp32-none-elf        | RSA-ExpMod                                       |
| esp32c2      | riscv32imac-unknown-none-elf | SHA1, SHA224, SHA256                             |
| esp32c3      | riscv32imc-unknown-none-elf  | RSA-ExpMod, SHA1, SHA224, SHA256                 |
| esp32c6      | riscv32imac-unknown-none-elf | RSA-ExpMod, SHA1, SHA224, SHA256                 |
| esp32h2      | riscv32imac-unknown-none-elf | RSA-ExpMod, SHA1, SHA224, SHA256                 |
| esp32s2      | xtensa-esp32s2-none-elf      | RSA-ExpMod, SHA1, SHA224, SHA256, SHA384, SHA512 |
| esp32s3      | xtensa-esp32s3-none-elf      | RSA-ExpMod, SHA1, SHA224, SHA256, SHA384, SHA512 |

(*) **NOTE: Building for xtensa targets requires the usage of the `esp` Rust toolchain, by instaling `espup`, i.e.:**
```sh
cargo install espup
espup install
rusup default esp
. ~/export_esp.sh
```

## Upcoming soon

- Baremetal Raspberry Pi Pico
- Baremetal NRF52
  
## Available example binaries

### client

A basic TLS (HTTPS) client demonstrating a TLS and an mTLS client

### verify_callback

A TLS (HTTPS) client whose trust store is plugged in through `ClientSessionConfig::verify_callback` instead of a parsed `ca_chain`: a sample verification callback (esp-idf `esp_crt_bundle` style) turns a root found in the store into trust

### server

A basic TLS (HTTPS) server with a self-signed certificate

### edge_client

Similar to `client` but utilizing the true HTTP client from `edge-http`

### edge_server

Similar to `server` but utilizing the true HTTP server from `edge-http`

### crypto_self_tests

Runs the MbedTLS crypto self tests for all hookable MbedTLS algorithms in `mbedtls-rs-sys`
