//! keysweep: find and lock down AI tool API keys on your laptop.
//!
//! Secrets are held in [`secret::Secret`], which cannot be printed or
//! serialized; every report shows fingerprints only.

pub mod detect;
pub mod fix;
pub mod registry;
pub mod report;
pub mod risk;
pub mod scan;
pub mod secret;
