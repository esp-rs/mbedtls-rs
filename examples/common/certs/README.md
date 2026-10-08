# Certificates for the `mbedtls-rs` Examples

This folder contains certificates used by the examples:
- `ca-bundle.pem`
  - This is a certificate bundle (a sequence of PEM certificates) containing all ROOT CAs of the Mozilla browser
  - The bundle was obtained by running cURL's [`mk-ca-bundle.pl` Perls script](https://curl.se/docs/mk-ca-bundle.html) as follows:
    ```sh
    mk-ca-bundle.pl ca-bundle.pem
    ```
- `ca-bundle-small.pem`
  - A manual extraction of just two root CAs from `ca-bundle.pem` which are known to be used by the websites used in the client examples (`httpbin.org` and `client.badssl.com`)
  - Done for reducing memory and flash size when using `mbedtls-rs`
- `ca-bundle.bin`
  - All root CAs of `ca-bundle.pem` packed into esp-idf's `x509_crt_bundle` binary format: each root contributes only its subject Name and SubjectPublicKeyInfo, so the whole Mozilla trust store fits in roughly 65 KB of flash (no RAM), and the `verify_callback` example binary-searches roots directly in flash and parses only the one key a peer chain needs
  - Generated with esp-idf's `gen_crt_bundle.py` (the script needs the `esp-pylib`, `rich-click` and `cryptography` Python packages):
    ```sh
    curl -fsSL -o gen_crt_bundle.py https://raw.githubusercontent.com/espressif/esp-idf/v5.5/components/mbedtls/esp_crt_bundle/gen_crt_bundle.py
    python gen_crt_bundle.py -i ca-bundle.pem
    mv x509_crt_bundle ca-bundle.bin
    ```
  - Regenerate it in the same commit as any change to `ca-bundle.pem`
- `badssl-client-cert.der` / `badssl-client-key.der`
  - The client certificate (and its key, decrypted) that `https://client.badssl.com/` requires for its mutual-TLS test endpoint, used by the client examples. It is published by badssl.com and rotated every couple of years; refresh it with:
    ```sh
    curl -O https://badssl.com/certs/badssl.com-client.pem
    openssl x509 -in badssl.com-client.pem -outform DER -out badssl-client-cert.der
    openssl pkey -in badssl.com-client.pem -passin pass:badssl.com -outform DER -out badssl-client-key.der
    ```
- `cert.der` / `cert.pem` + `key.der` / `key.pem`
  - Self-signed certificate used by the server examples and its corresponding key
  - Can be re-generated with:
    ```sh
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=mbedtls-rs.local"
    openssl x509 -in cert.pem -out cert.der -outform DER
    openssl rsa -in key.pem -out key.der -outform DER
    ```
