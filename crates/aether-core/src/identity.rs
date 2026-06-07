//! Cryptographic agent identity.
//!
//! Every agent in AetherOS is a first-class, accountable principal with a unique
//! cryptographic identity. An [`AgentIdentity`] binds a stable `agent_id` (UUIDv4)
//! to an Ed25519 keypair. The private signing key is held by the identity and used
//! to issue and sign capability leases; the public verifying key is what relying
//! parties use to check signatures and is summarized by a short `fingerprint`.
//!
//! Design (atom of thoughts):
//!   AgentIdentity = agent_id + display_name + Ed25519 signing key + created_at
//!   public view   = agent_id + display_name + public_key (hex) + fingerprint
//!
//! The signing key never appears in the public/serializable view; identities are
//! exported as either a *public descriptor* (safe to share) or a *secret bundle*
//! (PKCS#8, to be stored in a secret manager).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::canonical::sha256_hex;
use crate::error::{CoreError, Result};

/// Length of the public-key fingerprint in hex characters (first 16 bytes of SHA-256).
const FINGERPRINT_HEX_LEN: usize = 32;

/// A cryptographic identity for an AetherOS agent.
///
/// Holds the secret signing key in memory. Use [`AgentIdentity::descriptor`] to get
/// a shareable public view, and [`AgentIdentity::sign`] to sign canonical bytes.
#[derive(Clone)]
pub struct AgentIdentity {
    agent_id: String,
    display_name: String,
    created_at: String,
    signing_key: SigningKey,
}

/// Public, serializable view of an [`AgentIdentity`]. Safe to share and persist.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDescriptor {
    /// Stable agent identifier (UUIDv4).
    pub agent_id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// RFC3339 creation timestamp.
    pub created_at: String,
    /// Ed25519 public key, lowercase hex (32 bytes => 64 hex chars).
    pub public_key: String,
    /// Short fingerprint: first 16 bytes of SHA-256(public_key_bytes), hex.
    pub fingerprint: String,
}

impl AgentIdentity {
    /// Generate a brand-new identity with a fresh Ed25519 keypair.
    pub fn generate(display_name: impl Into<String>, created_at: impl Into<String>) -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let agent_id = uuid::Uuid::new_v4().to_string();
        Self {
            agent_id,
            display_name: display_name.into(),
            created_at: created_at.into(),
            signing_key,
        }
    }

    /// Reconstruct an identity from a known agent_id and a 32-byte Ed25519 seed (hex).
    ///
    /// Used by the bindings to restore an identity whose secret seed was persisted in
    /// a secret manager.
    pub fn from_seed_hex(
        agent_id: impl Into<String>,
        display_name: impl Into<String>,
        created_at: impl Into<String>,
        seed_hex: &str,
    ) -> Result<Self> {
        let seed =
            hex::decode(seed_hex).map_err(|e| CoreError::InvalidInput(format!("seed hex: {e}")))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| CoreError::InvalidInput("seed must be 32 bytes".into()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self {
            agent_id: agent_id.into(),
            display_name: display_name.into(),
            created_at: created_at.into(),
            signing_key,
        })
    }

    /// The stable agent identifier.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// The display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Creation timestamp (RFC3339).
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Public key as lowercase hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }

    /// Export the 32-byte secret seed as hex. Handle as a secret.
    pub fn secret_seed_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Compute the public-key fingerprint (first 16 bytes of SHA-256 of pubkey bytes).
    pub fn fingerprint(&self) -> String {
        public_key_fingerprint(&self.verifying_key().to_bytes())
    }

    /// Produce a shareable public descriptor.
    pub fn descriptor(&self) -> AgentDescriptor {
        AgentDescriptor {
            agent_id: self.agent_id.clone(),
            display_name: self.display_name.clone(),
            created_at: self.created_at.clone(),
            public_key: self.public_key_hex(),
            fingerprint: self.fingerprint(),
        }
    }

    /// Sign canonical message bytes, returning the Ed25519 signature as lowercase hex.
    pub fn sign(&self, message: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(message);
        hex::encode(sig.to_bytes())
    }
}

/// Compute a public-key fingerprint: first 16 bytes of SHA-256(public_key_bytes), hex.
pub fn public_key_fingerprint(public_key_bytes: &[u8]) -> String {
    let full = sha256_hex(public_key_bytes);
    full[..FINGERPRINT_HEX_LEN].to_string()
}

/// Verify an Ed25519 signature (hex) over `message` against a public key (hex).
pub fn verify_signature(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| CoreError::InvalidInput(format!("public key hex: {e}")))?;
    let pk_bytes: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| CoreError::InvalidInput("public key must be 32 bytes".into()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| CoreError::Crypto(e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| CoreError::InvalidInput(format!("signature hex: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CoreError::InvalidInput("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| CoreError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> String {
        "2026-06-07T00:00:00Z".to_string()
    }

    #[test]
    fn generate_produces_unique_ids() {
        let a = AgentIdentity::generate("agent-a", ts());
        let b = AgentIdentity::generate("agent-b", ts());
        assert_ne!(a.agent_id(), b.agent_id());
        assert_eq!(a.public_key_hex().len(), 64);
        assert_eq!(a.fingerprint().len(), FINGERPRINT_HEX_LEN);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = AgentIdentity::generate("signer", ts());
        let msg = b"governed action: read s3 bucket";
        let sig = id.sign(msg);
        assert!(verify_signature(&id.public_key_hex(), msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let id = AgentIdentity::generate("signer", ts());
        let sig = id.sign(b"original");
        assert!(verify_signature(&id.public_key_hex(), b"tampered", &sig).is_err());
    }

    #[test]
    fn seed_roundtrip_preserves_key() {
        let id = AgentIdentity::generate("seedy", ts());
        let seed = id.secret_seed_hex();
        let restored =
            AgentIdentity::from_seed_hex(id.agent_id(), id.display_name(), id.created_at(), &seed)
                .unwrap();
        assert_eq!(id.public_key_hex(), restored.public_key_hex());
        // A signature from the restored key verifies under the original pubkey.
        let sig = restored.sign(b"msg");
        assert!(verify_signature(&id.public_key_hex(), b"msg", &sig).is_ok());
    }
}
