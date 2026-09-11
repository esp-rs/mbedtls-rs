#[cfg(any(feature = "embassy-time", feature = "embassy-crypto"))]
pub mod embassy;
// Mounted without `esp-hal` too (under the internal `_route-test` feature) so
// the pure-logic `esp::exp_mod_route` submodule can be unit tested on the
// host; every `esp-hal`-dependent item inside is gated on the `esp-hal`
// feature.
#[cfg(any(feature = "esp-hal", feature = "_route-test"))]
pub mod esp;
#[cfg(feature = "std")]
pub mod std;
