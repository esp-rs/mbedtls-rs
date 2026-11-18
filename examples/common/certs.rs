#![allow(unused)]

use core::ffi::CStr;

use mbedtls_rs::{Certificate, ClientSessionConfig, Credentials, ServerSessionConfig, X509};

const CA_BUNDLE: &CStr = match CStr::from_bytes_with_nul(
    concat!(include_str!("certs/ca-bundle-small.pem"), "\0").as_bytes(),
) {
    Ok(bundle) => bundle,
    _ => panic!("CA bundle is not a valid text file"),
};

const CERT: &[u8] = include_bytes!("certs/cert.der");
const KEY: &[u8] = include_bytes!("certs/key.der");

// The client certificate `client.badssl.com` requires (see `certs/README.md`)
const CLIENT_CERT: &[u8] = include_bytes!("certs/badssl-client-cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("certs/badssl-client-key.der");

pub fn client_conf<'a>(mtls: bool, server_name: Option<&'a CStr>) -> ClientSessionConfig<'a> {
    let mut conf = ClientSessionConfig {
        ca_chain: Some(Certificate::new(X509::PEM(CA_BUNDLE)).unwrap()),
        server_name,
        ..ClientSessionConfig::new()
    };

    if mtls {
        conf.authentication = Some(
            Credentials {
                certificate: Certificate::new_no_copy(CLIENT_CERT).unwrap(),
                private_key: mbedtls_rs::PrivateKey::new(X509::DER(CLIENT_KEY), None).unwrap(),
            }
            .into(),
        );
    }

    conf
}

pub fn server_conf(mtls: bool) -> ServerSessionConfig<'static> {
    let cert = Certificate::new_no_copy(CERT).unwrap();

    let mut conf = ServerSessionConfig {
        ca_chain: Some(cert.clone()),
        ..ServerSessionConfig::new(
            Credentials {
                certificate: cert.clone(),
                private_key: mbedtls_rs::PrivateKey::new(X509::DER(KEY), None).unwrap(),
            }
            .into(),
        )
    };

    if mtls {
        // The assumption is that the client would use the same CERT/KEY pair that the server itself uses
        conf.ca_chain = Some(Certificate::new_no_copy(CERT).unwrap());
    }

    conf
}
