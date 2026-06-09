//! Feature-driven MbedTLS algorithm/module selection.
//!
//! MbedTLS's footprint is dominated by *runtime, table-driven* dispatch:
//! `mbedtls_cipher_definitions` (in `cipher_wrap.c`) and the message-digest
//! table (in `md.c`) are single `.rodata` objects that hold function pointers
//! to *every* enabled cipher / hash. The cipher- and digest-info lookups
//! (`mbedtls_cipher_info_from_type`, `mbedtls_md_info_from_type`) scan those
//! tables by enum value, so the linker cannot prove which entries are unused —
//! `--gc-sections` keeps the whole table and everything it points at. The only
//! way to drop an unused algorithm is therefore to never compile it in.
//!
//! This module models that selection as **additive cargo features**, mirroring
//! MbedTLS's own additive `#define MBEDTLS_*` options:
//!
//! - The generated user config first `#undef`s the entire *optional* universe
//!   ([`OPTIONAL_UNIVERSE`]), so "feature off" genuinely means "define absent",
//!   regardless of what the upstream `mbedtls_config.h` turns on by default.
//! - Each enabled cargo feature then re-`#define`s exactly the options it needs
//!   ([`FEATURE_DEFINES`]). Granularity is "one feature per independently
//!   linkable unit of code": each `*_C` module (its own `.c`), each ECP curve
//!   (its own comb table), each cipher mode and key exchange. Sub-options that
//!   share object code (e.g. `SHA224_C` rides with `SHA256_C`) or that MbedTLS's
//!   `check_config.h` refuses to split are folded into the owning feature.
//!
//! The `tls` bundle re-enables the full set, so `default = ["tls"]` reproduces
//! the historical (full) config byte-for-byte.

use super::config::MbedtlsUserConfig;

/// Options that are always defined, regardless of selected features.
///
/// These are the non-negotiable core that every consumer needs (platform glue,
/// the generic MD/cipher front-ends, ASN.1/OID, bignum, the PSA core), plus the
/// platform tweaks this crate always applies. They are *not* part of the
/// `#undef` universe below.
pub const ALWAYS_ON: &[&str] = &[
    // Core building blocks
    "BIGNUM_C",
    "MD_C",
    "OID_C",
    "ASN1_PARSE_C",
    "ASN1_WRITE_C",
    "CIPHER_C",
    "ERROR_C",
    "VERSION_C",
    "VERSION_FEATURES",
    "PSA_CRYPTO_C",
    // Platform glue this crate always wants
    "PLATFORM_C",
    // The crate's `self_test` module re-exports `mbedtls_*_self_test`, so the
    // self-test code must always be compiled in.
    "SELF_TEST",
];

/// Options that are always *disabled*, regardless of selected features.
///
/// These are environment / IO / HW-accel facilities this crate never wants
/// (we provide our own RNG/zeroize, never touch the filesystem or sockets, and
/// build portable C without CPU-specific accel). They are emitted as `false`
/// (i.e. only `#undef`).
pub const ALWAYS_OFF: &[&str] = &[
    "HAVE_TIME",
    "HAVE_TIME_DATE",
    "FS_IO",
    "NET_C",
    "TIMING_C",
    "GENPRIME",
    "AESNI_C",
    "AESCE_C",
    "PADLOCK_C",
    "HAVE_ASM",
    "SHA3_C",
    "LMS_C",
    "PSA_CRYPTO_STORAGE_C",
    "PSA_ITS_FILE_C",
    "PSA_KEY_STORE_DYNAMIC",
    "PK_PARSE_EC_COMPRESSED",
    "SSL_KEYING_MATERIAL_EXPORT",
];

/// Platform tweaks always applied as `#define ... <value>` (or boolean `true`).
///
/// Kept separate from [`ALWAYS_ON`] because some carry a literal value or model
/// an alternative implementation hook.
pub const ALWAYS_ON_TWEAKS: &[(&str, bool)] = &[
    ("DEPRECATED_REMOVED", true),
    ("PLATFORM_MEMORY", true),
    ("AES_ROM_TABLES", true),
    ("NO_PLATFORM_ENTROPY", true),
    ("PSA_CRYPTO_EXTERNAL_RNG", true),
];

/// The complete set of *optional* MbedTLS options this crate knows how to
/// select. Every one of these is `#undef`'d at the top of the generated user
/// config; enabled features re-`#define` the ones they need.
///
/// This is the master "reset" list. New optional upstream modules stay off
/// until added here — the safe direction for a size-minimizing crate.
pub const OPTIONAL_UNIVERSE: &[&str] = &[
    // Hashes
    "SHA1_C",
    "SHA224_C",
    "SHA256_C",
    "SHA384_C",
    "SHA512_C",
    "MD5_C",
    "RIPEMD160_C",
    // Block ciphers + modes + padding
    "AES_C",
    "DES_C",
    "ARIA_C",
    "CAMELLIA_C",
    "CHACHA20_C",
    "CIPHER_MODE_CBC",
    "CIPHER_MODE_CFB",
    "CIPHER_MODE_OFB",
    "CIPHER_MODE_CTR",
    "CIPHER_MODE_XTS",
    "CIPHER_PADDING_PKCS7",
    "CIPHER_PADDING_ONE_AND_ZEROS",
    "CIPHER_PADDING_ZEROS",
    "CIPHER_PADDING_ZEROS_AND_LEN",
    // AEAD / MAC
    "GCM_C",
    "CCM_C",
    "CMAC_C",
    "CHACHAPOLY_C",
    "POLY1305_C",
    "NIST_KW_C",
    // Public-key / EC
    "RSA_C",
    "PKCS1_V15",
    "PKCS1_V21",
    "X509_RSASSA_PSS_SUPPORT",
    "PK_RSA_ALT_SUPPORT",
    "DHM_C",
    "ECP_C",
    "ECP_NIST_OPTIM",
    "ECDH_C",
    "ECDSA_C",
    "ECDSA_DETERMINISTIC",
    "ECJPAKE_C",
    "PK_C",
    "PK_PARSE_C",
    "PK_WRITE_C",
    "PK_PARSE_EC_EXTENDED",
    // Curves
    "ECP_DP_SECP192R1_ENABLED",
    "ECP_DP_SECP224R1_ENABLED",
    "ECP_DP_SECP256R1_ENABLED",
    "ECP_DP_SECP384R1_ENABLED",
    "ECP_DP_SECP521R1_ENABLED",
    "ECP_DP_SECP192K1_ENABLED",
    "ECP_DP_SECP224K1_ENABLED",
    "ECP_DP_SECP256K1_ENABLED",
    "ECP_DP_BP256R1_ENABLED",
    "ECP_DP_BP384R1_ENABLED",
    "ECP_DP_BP512R1_ENABLED",
    "ECP_DP_CURVE25519_ENABLED",
    "ECP_DP_CURVE448_ENABLED",
    // KDF / DRBG / entropy
    "HKDF_C",
    "PKCS5_C",
    "PKCS12_C",
    "CTR_DRBG_C",
    "HMAC_DRBG_C",
    "ENTROPY_C",
    // Encoding / X.509
    "BASE64_C",
    "PEM_PARSE_C",
    "PEM_WRITE_C",
    "PKCS7_C",
    "X509_USE_C",
    "X509_CRT_PARSE_C",
    "X509_CRL_PARSE_C",
    "X509_CSR_PARSE_C",
    "X509_CREATE_C",
    "X509_CRT_WRITE_C",
    "X509_CSR_WRITE_C",
    // TLS core + sub-flags
    "SSL_TLS_C",
    "SSL_CLI_C",
    "SSL_SRV_C",
    "SSL_CACHE_C",
    "SSL_TICKET_C",
    "SSL_COOKIE_C",
    "DEBUG_C",
    "SSL_ALL_ALERT_MESSAGES",
    "SSL_ALPN",
    "SSL_ENCRYPT_THEN_MAC",
    "SSL_EXTENDED_MASTER_SECRET",
    "SSL_KEEP_PEER_CERTIFICATE",
    "SSL_MAX_FRAGMENT_LENGTH",
    "SSL_RENEGOTIATION",
    "SSL_SERVER_NAME_INDICATION",
    "SSL_SESSION_TICKETS",
    "SSL_CONTEXT_SERIALIZATION",
    // TLS protocol versions
    "SSL_PROTO_TLS1_2",
    "SSL_PROTO_TLS1_3",
    "SSL_PROTO_DTLS",
    "SSL_DTLS_ANTI_REPLAY",
    "SSL_DTLS_HELLO_VERIFY",
    "SSL_DTLS_CLIENT_PORT_REUSE",
    "SSL_DTLS_CONNECTION_ID",
    // NOTE: SSL_DTLS_CONNECTION_ID_COMPAT is a *valued* (`#define ... 0`),
    // deprecated compat shim — intentionally not modeled here. We leave the
    // upstream `#define ... 0` untouched (defined-as-off); turning it into a
    // bare presence define breaks the `... != 0` checks in check_config.h.
    "SSL_TLS1_3_COMPATIBILITY_MODE",
    "SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED",
    "SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED",
    "SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED",
    // Key exchanges
    "KEY_EXCHANGE_PSK_ENABLED",
    "KEY_EXCHANGE_ECDHE_ECDSA_ENABLED",
    "KEY_EXCHANGE_ECDHE_RSA_ENABLED",
    "KEY_EXCHANGE_ECDH_ECDSA_ENABLED",
    "KEY_EXCHANGE_ECDH_RSA_ENABLED",
    "KEY_EXCHANGE_RSA_ENABLED",
    "KEY_EXCHANGE_RSA_PSK_ENABLED",
    "KEY_EXCHANGE_DHE_RSA_ENABLED",
    "KEY_EXCHANGE_DHE_PSK_ENABLED",
    "KEY_EXCHANGE_ECDHE_PSK_ENABLED",
    "KEY_EXCHANGE_ECJPAKE_ENABLED",
    // Platform alternatives
    "PLATFORM_ZEROIZE_ALT",
];

/// Maps each public cargo feature (by its `CARGO_FEATURE_*` env-var suffix) to
/// the MbedTLS options it enables. Folded sub-options (e.g. `SHA224_C` with
/// `SHA256_C`, `PKCS1_V15` with `RSA_C`) live with the feature whose code they
/// belong to, so a single feature is always a self-consistent unit that passes
/// `check_config.h`.
///
/// The first tuple element is the *uppercased, underscored* feature name as
/// Cargo exposes it in `CARGO_FEATURE_<NAME>` (so `alg-sha256` -> `ALG_SHA256`).
pub const FEATURE_DEFINES: &[(&str, &[&str])] = &[
    // ---- Hashes ----
    ("ALG_SHA256", &["SHA256_C", "SHA224_C"]),
    ("ALG_SHA512", &["SHA512_C", "SHA384_C"]),
    ("ALG_SHA1", &["SHA1_C"]),
    ("ALG_MD5", &["MD5_C"]),
    ("ALG_RIPEMD160", &["RIPEMD160_C"]),
    // ---- Block ciphers + modes ----
    ("ALG_AES", &["AES_C"]),
    ("ALG_DES", &["DES_C"]),
    ("ALG_ARIA", &["ARIA_C"]),
    ("ALG_CAMELLIA", &["CAMELLIA_C"]),
    ("ALG_CHACHA20", &["CHACHA20_C"]),
    (
        "CIPHER_MODE_CBC",
        &[
            "CIPHER_MODE_CBC",
            "CIPHER_PADDING_PKCS7",
            "CIPHER_PADDING_ONE_AND_ZEROS",
            "CIPHER_PADDING_ZEROS",
            "CIPHER_PADDING_ZEROS_AND_LEN",
        ],
    ),
    ("CIPHER_MODE_CFB", &["CIPHER_MODE_CFB"]),
    ("CIPHER_MODE_OFB", &["CIPHER_MODE_OFB"]),
    ("CIPHER_MODE_CTR", &["CIPHER_MODE_CTR"]),
    ("CIPHER_MODE_XTS", &["CIPHER_MODE_XTS"]),
    // ---- AEAD / MAC ----
    ("ALG_GCM", &["GCM_C"]),
    ("ALG_CCM", &["CCM_C"]),
    ("ALG_CMAC", &["CMAC_C"]),
    ("ALG_CHACHAPOLY", &["CHACHAPOLY_C", "POLY1305_C"]),
    ("ALG_NIST_KW", &["NIST_KW_C"]),
    // ---- Public-key / EC ----
    ("ALG_RSA", &["RSA_C", "PKCS1_V15", "PK_RSA_ALT_SUPPORT"]),
    ("ALG_RSA_PSS", &["PKCS1_V21", "X509_RSASSA_PSS_SUPPORT"]),
    ("ALG_DHM", &["DHM_C"]),
    ("ALG_ECP", &["ECP_C", "ECP_NIST_OPTIM"]),
    ("ALG_ECDH", &["ECDH_C"]),
    // Deterministic ECDSA (RFC 6979) requires HMAC-DRBG (check_config.h), so
    // it is folded in here.
    (
        "ALG_ECDSA",
        &["ECDSA_C", "ECDSA_DETERMINISTIC", "HMAC_DRBG_C"],
    ),
    ("ALG_ECJPAKE", &["ECJPAKE_C"]),
    (
        "PK",
        &["PK_C", "PK_PARSE_C", "PK_WRITE_C", "PK_PARSE_EC_EXTENDED"],
    ),
    // ---- Curves ----
    ("CURVE_SECP192R1", &["ECP_DP_SECP192R1_ENABLED"]),
    ("CURVE_SECP224R1", &["ECP_DP_SECP224R1_ENABLED"]),
    ("CURVE_SECP256R1", &["ECP_DP_SECP256R1_ENABLED"]),
    ("CURVE_SECP384R1", &["ECP_DP_SECP384R1_ENABLED"]),
    ("CURVE_SECP521R1", &["ECP_DP_SECP521R1_ENABLED"]),
    ("CURVE_SECP192K1", &["ECP_DP_SECP192K1_ENABLED"]),
    ("CURVE_SECP224K1", &["ECP_DP_SECP224K1_ENABLED"]),
    ("CURVE_SECP256K1", &["ECP_DP_SECP256K1_ENABLED"]),
    ("CURVE_BP256R1", &["ECP_DP_BP256R1_ENABLED"]),
    ("CURVE_BP384R1", &["ECP_DP_BP384R1_ENABLED"]),
    ("CURVE_BP512R1", &["ECP_DP_BP512R1_ENABLED"]),
    ("CURVE_CURVE25519", &["ECP_DP_CURVE25519_ENABLED"]),
    ("CURVE_CURVE448", &["ECP_DP_CURVE448_ENABLED"]),
    // ---- KDF / DRBG / entropy ----
    ("ALG_HKDF", &["HKDF_C"]),
    ("ALG_PKCS5", &["PKCS5_C"]),
    ("ALG_PKCS12", &["PKCS12_C"]),
    ("DRBG_CTR", &["CTR_DRBG_C"]),
    ("DRBG_HMAC", &["HMAC_DRBG_C"]),
    ("ENTROPY", &["ENTROPY_C"]),
    // ---- Encoding / X.509 ----
    ("BASE64", &["BASE64_C"]),
    ("PEM_PARSE", &["PEM_PARSE_C"]),
    ("PEM_WRITE", &["PEM_WRITE_C"]),
    ("PKCS7", &["PKCS7_C"]),
    (
        "X509_PARSE",
        &[
            "X509_USE_C",
            "X509_CRT_PARSE_C",
            "X509_CRL_PARSE_C",
            "X509_CSR_PARSE_C",
        ],
    ),
    (
        "X509_WRITE",
        &["X509_CREATE_C", "X509_CRT_WRITE_C", "X509_CSR_WRITE_C"],
    ),
    // ---- TLS ----
    // The bare SSL/TLS+DTLS engine, free of X.509-coupled extensions, so it can
    // be used for cert-less DTLS (e.g. OpenThread's J-PAKE / PSK MeshCoP). These
    // are the X.509-independent SSL options (cf. mbedtls's own
    // `configs/config-ccm-psk-dtls1_2.h`).
    (
        "TLS_ENGINE",
        &[
            "SSL_TLS_C",
            "SSL_ALL_ALERT_MESSAGES",
            "SSL_ALPN",
            "SSL_MAX_FRAGMENT_LENGTH",
        ],
    ),
    // Full TLS feature set: the engine plus extensions that require X.509
    // certificate handling (SNI, renegotiation, session tickets, etc.). The
    // `tls-core` cargo feature pulls `tls-engine`, so its defines union in.
    (
        "TLS_CORE",
        &[
            "SSL_ENCRYPT_THEN_MAC",
            "SSL_EXTENDED_MASTER_SECRET",
            "SSL_KEEP_PEER_CERTIFICATE",
            "SSL_RENEGOTIATION",
            "SSL_SERVER_NAME_INDICATION",
            "SSL_SESSION_TICKETS",
            "SSL_CONTEXT_SERIALIZATION",
        ],
    ),
    ("TLS_CLIENT", &["SSL_CLI_C"]),
    ("TLS_SERVER", &["SSL_SRV_C"]),
    ("TLS_CACHE", &["SSL_CACHE_C"]),
    ("TLS_TICKET", &["SSL_TICKET_C"]),
    ("TLS_DEBUG", &["DEBUG_C"]),
    ("TLS_PROTO_TLS12", &["SSL_PROTO_TLS1_2"]),
    (
        "TLS_PROTO_TLS13",
        &[
            "SSL_PROTO_TLS1_3",
            "SSL_TLS1_3_COMPATIBILITY_MODE",
            "SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED",
            "SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED",
            "SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED",
        ],
    ),
    (
        "TLS_PROTO_DTLS",
        &[
            "SSL_PROTO_DTLS",
            "SSL_COOKIE_C",
            "SSL_DTLS_ANTI_REPLAY",
            "SSL_DTLS_HELLO_VERIFY",
            "SSL_DTLS_CLIENT_PORT_REUSE",
            "SSL_DTLS_CONNECTION_ID",
        ],
    ),
    // ---- Key exchanges ----
    ("KEX_PSK", &["KEY_EXCHANGE_PSK_ENABLED"]),
    ("KEX_ECDHE_ECDSA", &["KEY_EXCHANGE_ECDHE_ECDSA_ENABLED"]),
    ("KEX_ECDHE_RSA", &["KEY_EXCHANGE_ECDHE_RSA_ENABLED"]),
    ("KEX_ECDH_ECDSA", &["KEY_EXCHANGE_ECDH_ECDSA_ENABLED"]),
    ("KEX_ECDH_RSA", &["KEY_EXCHANGE_ECDH_RSA_ENABLED"]),
    ("KEX_RSA", &["KEY_EXCHANGE_RSA_ENABLED"]),
    ("KEX_RSA_PSK", &["KEY_EXCHANGE_RSA_PSK_ENABLED"]),
    ("KEX_DHE_RSA", &["KEY_EXCHANGE_DHE_RSA_ENABLED"]),
    ("KEX_DHE_PSK", &["KEY_EXCHANGE_DHE_PSK_ENABLED"]),
    ("KEX_ECDHE_PSK", &["KEY_EXCHANGE_ECDHE_PSK_ENABLED"]),
    ("KEX_ECJPAKE", &["KEY_EXCHANGE_ECJPAKE_ENABLED"]),
    // ---- Platform alternatives ----
    // Opt-in: replace MbedTLS's own `mbedtls_platform_zeroize` with a
    // user-supplied one.
    // Off by default — MbedTLS ships a portable, compiler-barrier-protected
    // zeroize that already resists dead-store elimination, so most users want
    // the default. Enable this only to provide a custom implementation.
    ("PLATFORM_ZEROIZE_ALT", &["PLATFORM_ZEROIZE_ALT"]),
];

/// The `FEATURE_DEFINES` keys that the `prebuilt` profile enables — i.e. the
/// exact algorithm set the committed per-target `.a` libraries and bindings are
/// built with (see `xtask`, which builds them with `--features prebuilt`).
///
/// `prebuilt = ["tls"]` in `Cargo.toml`, so this is precisely the leaves the
/// `tls` bundle pulls in. It is the single source of truth the prebuilt-vs-
/// on-the-fly decision compares against; keep it in sync with the `tls` bundle.
pub const PREBUILT_FEATURES: &[&str] = &[
    // hashes
    "ALG_SHA256",
    "ALG_SHA512",
    "ALG_SHA1",
    "ALG_MD5",
    "ALG_RIPEMD160",
    // ciphers + modes
    "ALG_AES",
    "ALG_DES",
    "ALG_ARIA",
    "ALG_CAMELLIA",
    "ALG_CHACHA20",
    "CIPHER_MODE_CBC",
    "CIPHER_MODE_CFB",
    "CIPHER_MODE_OFB",
    "CIPHER_MODE_CTR",
    "CIPHER_MODE_XTS",
    // aead / mac
    "ALG_GCM",
    "ALG_CCM",
    "ALG_CMAC",
    "ALG_CHACHAPOLY",
    "ALG_NIST_KW",
    // public-key / ec
    "ALG_RSA",
    "ALG_RSA_PSS",
    "ALG_DHM",
    "ALG_ECP",
    "ALG_ECDH",
    "ALG_ECDSA",
    "ALG_ECJPAKE",
    "PK",
    // curves
    "CURVE_SECP192R1",
    "CURVE_SECP224R1",
    "CURVE_SECP256R1",
    "CURVE_SECP384R1",
    "CURVE_SECP521R1",
    "CURVE_SECP192K1",
    "CURVE_SECP224K1",
    "CURVE_SECP256K1",
    "CURVE_BP256R1",
    "CURVE_BP384R1",
    "CURVE_BP512R1",
    "CURVE_CURVE25519",
    "CURVE_CURVE448",
    // kdf / drbg / entropy
    "ALG_HKDF",
    "ALG_PKCS5",
    "ALG_PKCS12",
    "DRBG_CTR",
    "DRBG_HMAC",
    "ENTROPY",
    // encoding / x509
    "BASE64",
    "PEM_PARSE",
    "PEM_WRITE",
    "PKCS7",
    "X509_PARSE",
    "X509_WRITE",
    // tls
    "TLS_ENGINE",
    "TLS_CORE",
    "TLS_CLIENT",
    "TLS_SERVER",
    "TLS_CACHE",
    "TLS_TICKET",
    "TLS_DEBUG",
    "TLS_PROTO_TLS12",
    "TLS_PROTO_TLS13",
    "TLS_PROTO_DTLS",
    // key exchanges (NOTE: KEX_ECJPAKE intentionally excluded — see `tls` bundle)
    "KEX_PSK",
    "KEX_ECDHE_ECDSA",
    "KEX_ECDHE_RSA",
    "KEX_ECDH_ECDSA",
    "KEX_ECDH_RSA",
    "KEX_RSA",
    "KEX_RSA_PSK",
    "KEX_DHE_RSA",
    "KEX_DHE_PSK",
    "KEX_ECDHE_PSK",
];

/// Apply the additive, feature-driven algorithm selection to `config`, using
/// `is_active` to decide whether each `FEATURE_DEFINES` entry is enabled.
///
/// 1. `#undef` the entire optional universe (so absent features = absent
///    defines, regardless of upstream defaults).
/// 2. Apply the always-off and always-on core + tweaks.
/// 3. For every *active* feature, `#define` its options.
fn build_config(config: &mut MbedtlsUserConfig, is_active: impl Fn(&str) -> bool) {
    // 1. Reset: undef every optional option.
    for opt in OPTIONAL_UNIVERSE {
        config.set(opt, false);
    }

    // 2a. Things we never want (explicit undef; harmless if already undef'd).
    for opt in ALWAYS_OFF {
        config.set(opt, false);
    }

    // 2b. Mandatory core.
    for opt in ALWAYS_ON {
        config.set(opt, true);
    }

    // 2c. Platform tweaks.
    for (opt, on) in ALWAYS_ON_TWEAKS {
        config.set(opt, *on);
    }

    // 3. Re-enable per active feature.
    for (feature, defines) in FEATURE_DEFINES {
        if is_active(feature) {
            for define in *defines {
                config.set(define, true);
            }
        }
    }
}

/// Apply the additive, feature-driven algorithm selection to `config` based on
/// the currently enabled `CARGO_FEATURE_*` environment variables.
///
/// Reads the environment Cargo sets for the build script, so this must only be
/// called from within the build script.
pub fn apply_features(config: &mut MbedtlsUserConfig) {
    build_config(config, |feature| {
        std::env::var_os(format!("CARGO_FEATURE_{feature}")).is_some()
    });
}

/// Build the algorithm-selection config the *prebuilt* artifacts correspond to
/// (the [`PREBUILT_FEATURES`] set). Used only to validate the prebuilt libs.
///
/// Hooks are intentionally *not* applied here: the committed prebuilt libraries
/// are built with [`crate::DEFAULT_HOOKS`] only, so a build that toggles hooks
/// must already fall back to on-the-fly compilation (handled by the caller).
pub fn prebuilt_features_config() -> MbedtlsUserConfig {
    let mut config = MbedtlsUserConfig::new();
    build_config(&mut config, |feature| PREBUILT_FEATURES.contains(&feature));
    config
}
