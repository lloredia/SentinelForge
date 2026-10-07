//! API-key authentication.
//!
//! Keys are loaded from configuration, stored only as SHA-256 digests, and
//! compared in constant time.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MIN_KEY_LEN: usize = 16;
const MAX_KEY_LEN: usize = 256;

/// SHA-256 digests of configured API keys.
#[derive(Clone, Debug)]
pub struct ApiKeyStore {
    hashes: Vec<[u8; 32]>,
}

impl ApiKeyStore {
    /// Parse a comma-separated list of API keys.
    ///
    /// Empty entries and keys outside the accepted length are ignored.
    pub fn from_csv(raw: &str) -> Self {
        let hashes = raw
            .split(',')
            .map(str::trim)
            .filter(|key| (MIN_KEY_LEN..=MAX_KEY_LEN).contains(&key.len()))
            .map(hash_key)
            .collect();
        Self { hashes }
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Return whether `presented` matches any configured key.
    ///
    /// Every configured digest is compared, and a digest is still computed
    /// when the header is missing, so the check does not bail out early.
    pub fn verify(&self, presented: Option<&str>) -> bool {
        let material = presented.unwrap_or("");
        if material.len() > MAX_KEY_LEN {
            let _ = hash_key("too-long").ct_eq(&[0u8; 32]);
            return false;
        }

        let digest = hash_key(material);
        if self.hashes.is_empty() {
            let _ = digest.ct_eq(&[0u8; 32]);
            return false;
        }

        let mut ok = subtle::Choice::from(0u8);
        for hash in &self.hashes {
            ok |= digest.ct_eq(hash);
        }
        bool::from(ok) && !material.is_empty()
    }
}

/// Authentication policy shared by the API middleware.
#[derive(Clone, Debug)]
pub struct AuthState {
    keys: ApiKeyStore,
    pub require_read_auth: bool,
}

impl AuthState {
    pub fn new(keys_csv: &str, require_read_auth: bool) -> Self {
        Self {
            keys: ApiKeyStore::from_csv(keys_csv),
            require_read_auth,
        }
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn authorize(&self, presented: Option<&str>) -> bool {
        self.keys.verify(presented)
    }
}

fn hash_key(key: &str) -> [u8; 32] {
    let digest = Sha256::digest(key.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_configured_keys_only() {
        let store = ApiKeyStore::from_csv("correct-horse-battery,second-valid-key!");
        assert!(store.verify(Some("correct-horse-battery")));
        assert!(store.verify(Some("second-valid-key!")));
        assert!(!store.verify(Some("correct-horse-batter")));
        assert!(!store.verify(Some("correct-horse-battery-nope")));
        assert!(!store.verify(Some("")));
        assert!(!store.verify(None));
    }

    #[test]
    fn empty_or_short_keys_are_not_loaded() {
        let store = ApiKeyStore::from_csv("short, ,also-too-short");
        assert!(store.is_empty());
        assert!(!store.verify(Some("short")));
        assert!(!store.verify(Some("also-too-short")));
    }

    #[test]
    fn rejects_overlong_presented_key() {
        let store = ApiKeyStore::from_csv("correct-horse-battery");
        let huge = "a".repeat(MAX_KEY_LEN + 1);
        assert!(!store.verify(Some(&huge)));
    }
}
