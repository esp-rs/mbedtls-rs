#[cfg(feature = "timer-embassy")]
pub mod embassy;

#[cfg(feature = "timer-std")]
pub mod std;
