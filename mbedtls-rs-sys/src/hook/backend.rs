#[cfg(feature = "embassy-time")]
pub mod embassy;
#[cfg(feature = "esp-hal")]
pub mod esp;
#[cfg(feature = "std")]
pub mod std;
