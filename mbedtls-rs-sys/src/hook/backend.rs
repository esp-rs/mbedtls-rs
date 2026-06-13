#[cfg(feature = "embassy-time")]
pub mod embassy;
#[cfg(feature = "esp-hal")]
pub mod esp;
#[cfg(all(not(feature = "esp-hal"), feature = "_route-test"))]
pub mod esp_exp_mod_route;
#[cfg(all(
    feature = "esp-hal",
    not(any(feature = "esp32c2", feature = "nohook-exp-mod"))
))]
pub(crate) mod esp_exp_mod_route;
#[cfg(feature = "std")]
pub mod std;
