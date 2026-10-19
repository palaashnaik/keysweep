//! A wrapper that keeps secret material out of logs, debug output and serialization.

use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Raw credential value. It deliberately implements neither `Display` nor
/// `Serialize`, its `Debug` is redacted, and the buffer is zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(Zeroizing::new(value.into()))
    }

    /// Access the raw value. Only fix actions (keychain writes, file rewrites)
    /// and in-process comparisons should ever call this.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// First 8 hex chars of the SHA-256 of the value.
    pub fn short_hash(&self) -> String {
        let digest = Sha256::digest(self.0.as_bytes());
        digest.iter().take(4).map(|b| format!("{b:02x}")).collect()
    }

    /// Display-safe identifier: the provider's public prefix (never any of the
    /// random part) followed by a short hash.
    pub fn fingerprint(&self, public_prefix: &str) -> String {
        format!("{public_prefix}…{}", self.short_hash())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("super-secret-value-123");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn fingerprint_has_no_secret_material() {
        let raw = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let s = Secret::new(raw);
        let fp = s.fingerprint("sk-ant-api03-");
        assert!(fp.starts_with("sk-ant-api03-…"));
        assert!(!fp.contains("ABCDEF"));
        assert_eq!(fp.chars().count(), "sk-ant-api03-".len() + 1 + 8);
    }

    #[test]
    fn hash_is_stable() {
        assert_eq!(Secret::new("x").short_hash(), Secret::new("x").short_hash());
        assert_ne!(Secret::new("x").short_hash(), Secret::new("y").short_hash());
    }
}
