use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single attribute's ZK credential data.
/// All field elements are serialised as decimal strings so that
/// they can be fed directly into snarkjs / circom as JSON inputs.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttributeData {
    /// Share 1  (Fr decimal string)
    pub x1: String,
    /// Share 2  (Fr decimal string) — private, x = x1 + x2 in Fr
    pub x2: String,
    /// Blinding randomness r  (Fr decimal string) — private
    pub r: String,
    /// Base commitment  C = Poseidon(x, r)  (Fr decimal string) — public
    #[serde(rename = "C")]
    pub c: String,
}

/// Full long-lived credential emitted by `issuer issue`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    /// UUIDv4 for this credential
    pub credential_id: String,
    /// Hex-encoded Ed25519 public key of the issuer
    pub issuer_pk: String,
    /// Hex-encoded Ed25519 signature over the credential message
    pub sig: String,
    /// Per-attribute ZK data
    pub attributes: HashMap<String, AttributeData>,
}

/// Per-verifier, per-session unlinkability binding.
/// Emitted by `issuer session`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionPublic {
    /// Session commitment SC = Poseidon(C, nonce, verifier_domain)  (Fr decimal)
    #[serde(rename = "SC")]
    pub sc: String,
}

/// Full session file emitted by `issuer session`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    pub verifier_id: String,
    /// Fresh nonce (Fr decimal string) — unique per session
    pub nonce: String,
    /// Min thresholds the holder wants to prove
    pub thresholds: HashMap<String, u64>,
    /// Public values forwarded to the verifier / circuit
    pub public: HashMap<String, SessionPublic>,
}
