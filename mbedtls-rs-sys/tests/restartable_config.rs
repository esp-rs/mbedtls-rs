//! Configuration checks for the restartable-ECP feature mapping.

#[allow(dead_code)]
#[path = "../gen/config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../gen/features.rs"]
mod features;

#[test]
fn restartable_ecp_has_a_feature_mapping() {
    assert!(features::OPTIONAL_UNIVERSE.contains(&"ECP_RESTARTABLE"));
    assert!(features::FEATURE_DEFINES.contains(&("ECP_RESTARTABLE", &["ECP_RESTARTABLE"])));
}

#[test]
fn generic_prebuilt_does_not_enable_restartable_ecp() {
    assert!(!features::PREBUILT_FEATURES.contains(&"ECP_RESTARTABLE"));
    let prebuilt = features::prebuilt_features_config();
    let mut restartable = features::prebuilt_features_config();
    restartable.set("ECP_RESTARTABLE", true);
    assert_eq!(
        restartable.effective_delta(&prebuilt),
        "+MBEDTLS_ECP_RESTARTABLE"
    );
}

#[test]
fn default_prebuilt_configuration_is_unchanged() {
    let config = features::prebuilt_features_config();
    assert!(!config.effective_defines().contains_key("ECP_RESTARTABLE"));
}
