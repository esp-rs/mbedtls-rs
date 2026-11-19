//! On ESP-IDF, MbedTLS is ESP-IDF's, with the options of ESP-IDF's
//! configuration. `mbedtls-rs-sys` passes that configuration on; the options
//! this crate looks at become `esp_idf_*` cfgs, as `embuild` names them.

use std::env;

/// The ESP-IDF options this crate looks at.
const ESP_IDF_CFGS: &[&str] = &[
    "esp_idf_mbedtls_ssl_proto_dtls",
    "esp_idf_mbedtls_ssl_proto_tls1_3",
    "esp_idf_mbedtls_key_exchange_ecjpake",
    "esp_idf_mbedtls_psk_modes",
];

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_MBEDTLS_EMBUILD_CFG_ARGS");

    // `:`-separated, as `embuild::build::CfgArgs::propagate` writes it
    let esp_idf = env::var("DEP_MBEDTLS_EMBUILD_CFG_ARGS").unwrap_or_default();
    let esp_idf = esp_idf.split(':').collect::<Vec<_>>();

    for cfg in ESP_IDF_CFGS {
        println!("cargo::rustc-check-cfg=cfg({cfg})");

        if esp_idf.contains(cfg) {
            println!("cargo::rustc-cfg={cfg}");
        }
    }
}
