//! PyO3 bindings exposing AetherOS core primitives to Python.
//!
//! This module is a thin, well-typed bridge. It does no policy or business logic of
//! its own — it wraps [`aether_core`] types, converts errors into Python exceptions,
//! and marshals JSON payloads across the boundary. The reproducible canonical
//! serialization in the core guarantees that anything signed or hashed here is
//! byte-identical to what pure-Rust callers would produce.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyType;

use aether_core::autonomy::AutonomyRecord as CoreAutonomy;
use aether_core::constitution::{ActionContext as CoreAction, Constitution as CoreConstitution};
use aether_core::error::CoreError;
use aether_core::evidence::EvidenceLedger as CoreLedger;
use aether_core::identity::{verify_signature as core_verify, AgentIdentity as CoreIdentity};
use aether_core::lease::{Budget as CoreBudget, CapabilityLease as CoreLease};
use aether_core::policy::{PolicyRequest as CoreReq, PolicySet as CorePolicySet};
use aether_core::transparency::{
    verify_consistency as core_verify_consistency, verify_inclusion as core_verify_inclusion,
    ConsistencyProof as CoreConsistencyProof, InclusionProof as CoreInclusionProof,
    TransparencyLog as CoreTransparencyLog,
};

/// Map a core error into an appropriate Python exception.
fn map_err(e: CoreError) -> PyErr {
    match e {
        CoreError::InvalidInput(_) | CoreError::Serialization(_) => {
            PyValueError::new_err(e.to_string())
        }
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

/// A cryptographic agent identity (Ed25519).
#[pyclass(name = "AgentIdentity")]
struct PyAgentIdentity {
    inner: CoreIdentity,
}

#[pymethods]
impl PyAgentIdentity {
    /// Generate a fresh identity with a new keypair.
    #[staticmethod]
    fn generate(display_name: String, created_at: String) -> Self {
        PyAgentIdentity {
            inner: CoreIdentity::generate(display_name, created_at),
        }
    }

    /// Restore an identity from a persisted 32-byte secret seed (hex).
    #[staticmethod]
    fn from_seed_hex(
        agent_id: String,
        display_name: String,
        created_at: String,
        seed_hex: String,
    ) -> PyResult<Self> {
        let inner = CoreIdentity::from_seed_hex(agent_id, display_name, created_at, &seed_hex)
            .map_err(map_err)?;
        Ok(PyAgentIdentity { inner })
    }

    #[getter]
    fn agent_id(&self) -> String {
        self.inner.agent_id().to_string()
    }

    #[getter]
    fn display_name(&self) -> String {
        self.inner.display_name().to_string()
    }

    #[getter]
    fn created_at(&self) -> String {
        self.inner.created_at().to_string()
    }

    #[getter]
    fn public_key(&self) -> String {
        self.inner.public_key_hex()
    }

    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// Export the secret seed (hex). Treat as a secret.
    fn secret_seed_hex(&self) -> String {
        self.inner.secret_seed_hex()
    }

    /// Sign UTF-8 message bytes, returning the signature as hex.
    fn sign(&self, message: &[u8]) -> String {
        self.inner.sign(message)
    }

    /// Return the public descriptor as a JSON string.
    fn descriptor_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.descriptor())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// Verify an Ed25519 signature (hex) over message bytes against a public key (hex).
#[pyfunction]
fn verify_signature(public_key_hex: String, message: &[u8], signature_hex: String) -> bool {
    core_verify(&public_key_hex, message, &signature_hex).is_ok()
}

/// A signed, scoped, time-bounded capability lease.
#[pyclass(name = "CapabilityLease")]
struct PyCapabilityLease {
    inner: CoreLease,
}

#[pymethods]
impl PyCapabilityLease {
    /// Issue and sign a new lease.
    #[staticmethod]
    fn issue(
        issuer: &PyAgentIdentity,
        subject_agent_id: String,
        scopes: Vec<String>,
        currency: String,
        limit_minor: u64,
        issued_at: String,
        expires_at: String,
    ) -> PyResult<Self> {
        let budget = CoreBudget::new(currency, limit_minor);
        let inner = CoreLease::issue(
            &issuer.inner,
            subject_agent_id,
            scopes,
            budget,
            issued_at,
            expires_at,
        )
        .map_err(map_err)?;
        Ok(PyCapabilityLease { inner })
    }

    /// Rehydrate a lease from its JSON representation.
    #[classmethod]
    fn from_json(_cls: &Bound<'_, PyType>, json: String) -> PyResult<Self> {
        let inner: CoreLease =
            serde_json::from_str(&json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyCapabilityLease { inner })
    }

    #[getter]
    fn lease_id(&self) -> String {
        self.inner.body.lease_id.clone()
    }

    #[getter]
    fn subject_agent_id(&self) -> String {
        self.inner.body.subject_agent_id.clone()
    }

    #[getter]
    fn scopes(&self) -> Vec<String> {
        self.inner.body.scopes.clone()
    }

    #[getter]
    fn remaining_minor(&self) -> u64 {
        self.inner.remaining_minor()
    }

    #[getter]
    fn spent_minor(&self) -> u64 {
        self.inner.spent_minor
    }

    #[getter]
    fn revoked(&self) -> bool {
        self.inner.revoked
    }

    /// Verify the issuer signature over the lease body.
    fn verify(&self) -> bool {
        self.inner.verify_signature().is_ok()
    }

    /// Mark the lease as revoked.
    fn revoke(&mut self) {
        self.inner.revoke();
    }

    /// Whether `scope` is granted.
    fn grants_scope(&self, scope: String) -> bool {
        self.inner.grants_scope(&scope)
    }

    /// Full authorization check. Raises on denial with an explanatory message.
    fn authorize(&self, scope: String, cost_minor: u64, now_rfc3339: String) -> PyResult<()> {
        self.inner
            .authorize(&scope, cost_minor, &now_rfc3339)
            .map_err(map_err)
    }

    /// Record a successful spend against the budget.
    fn record_spend(&mut self, amount_minor: u64) -> PyResult<()> {
        self.inner.record_spend(amount_minor).map_err(map_err)
    }

    /// Serialize the lease to JSON.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// An append-only, hash-chained evidence ledger.
#[pyclass(name = "EvidenceLedger")]
struct PyEvidenceLedger {
    inner: CoreLedger,
}

#[pymethods]
impl PyEvidenceLedger {
    #[new]
    fn new() -> Self {
        PyEvidenceLedger {
            inner: CoreLedger::new(),
        }
    }

    /// Load a ledger from JSON, verifying integrity.
    #[classmethod]
    fn from_json(_cls: &Bound<'_, PyType>, json: String) -> PyResult<Self> {
        let inner = CoreLedger::from_json(&json).map_err(map_err)?;
        Ok(PyEvidenceLedger { inner })
    }

    #[getter]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[getter]
    fn head_hash(&self) -> String {
        self.inner.head_hash()
    }

    /// Append an event. `payload_json` must be a JSON object/value string.
    /// Returns (seq, entry_hash).
    fn append(
        &mut self,
        timestamp: String,
        actor: String,
        event_type: String,
        payload_json: String,
    ) -> PyResult<(u64, String)> {
        let payload: serde_json::Value = serde_json::from_str(&payload_json)
            .map_err(|e| PyValueError::new_err(format!("payload_json: {e}")))?;
        self.inner
            .append(timestamp, actor, event_type, payload)
            .map_err(map_err)
    }

    /// Verify the full hash chain. Returns True if intact.
    fn verify(&self) -> bool {
        self.inner.verify().is_ok()
    }

    /// Replay summary as a list of (seq, event_type, actor).
    fn replay_summary(&self) -> PyResult<Vec<(u64, String, String)>> {
        self.inner.replay_summary().map_err(map_err)
    }

    /// Serialize the ledger to JSON.
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(map_err)
    }
}

/// A policy engine wrapping the integrity-critical Rust evaluation core.
///
/// Constructed from a JSON policy set; evaluates JSON requests and returns JSON
/// decisions. Rule authoring/loading lives in Python; the allow/deny computation
/// (deny-overrides, default-deny) lives in Rust where it cannot be bypassed.
#[pyclass(name = "PolicyEngine")]
struct PyPolicyEngine {
    inner: CorePolicySet,
}

#[pymethods]
impl PyPolicyEngine {
    /// Build a policy engine from a JSON policy-set document.
    #[staticmethod]
    fn from_json(json: String) -> PyResult<Self> {
        let inner: CorePolicySet =
            serde_json::from_str(&json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyPolicyEngine { inner })
    }

    /// Number of rules in the set.
    #[getter]
    fn rule_count(&self) -> usize {
        self.inner.rules.len()
    }

    /// Evaluate a JSON request and return the decision as a JSON string.
    fn evaluate(&self, request_json: String) -> PyResult<String> {
        let req: CoreReq = serde_json::from_str(&request_json)
            .map_err(|e| PyValueError::new_err(format!("request_json: {e}")))?;
        let decision = self.inner.evaluate(&req);
        serde_json::to_string(&decision).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// A constitution engine wrapping the supreme Rust governance core.
///
/// Constructed from a JSON constitution document; judges JSON actions and returns JSON
/// judgments. Article *authoring* lives in Python; the supremacy semantics (forbid is
/// absolute, evaluated above policy, no tier exemption) live in Rust where they cannot
/// be bypassed.
#[pyclass(name = "ConstitutionEngine")]
struct PyConstitutionEngine {
    inner: CoreConstitution,
}

#[pymethods]
impl PyConstitutionEngine {
    /// Build a constitution engine from a JSON constitution document.
    #[staticmethod]
    fn from_json(json: String) -> PyResult<Self> {
        let inner: CoreConstitution =
            serde_json::from_str(&json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyConstitutionEngine { inner })
    }

    /// The constitution's version label.
    #[getter]
    fn version(&self) -> String {
        self.inner.version.clone()
    }

    /// Number of articles in the constitution.
    #[getter]
    fn article_count(&self) -> usize {
        self.inner.len()
    }

    /// Judge a JSON action and return the judgment as a JSON string.
    fn judge(&self, action_json: String) -> PyResult<String> {
        let action: CoreAction = serde_json::from_str(&action_json)
            .map_err(|e| PyValueError::new_err(format!("action_json: {e}")))?;
        let judgment = self.inner.judge(&action);
        serde_json::to_string(&judgment).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// An agent's earned-autonomy record (governance state owned by the Rust core).
#[pyclass(name = "AutonomyRecord")]
struct PyAutonomyRecord {
    inner: CoreAutonomy,
}

#[pymethods]
impl PyAutonomyRecord {
    /// Create a record for an agent with explicit promotion threshold and max tier.
    #[new]
    fn new(agent_id: String, promotion_threshold: u32, max_tier: u8) -> Self {
        PyAutonomyRecord {
            inner: CoreAutonomy::with_policy(agent_id, promotion_threshold, max_tier),
        }
    }

    /// Rehydrate from JSON.
    #[classmethod]
    fn from_json(_cls: &Bound<'_, PyType>, json: String) -> PyResult<Self> {
        let inner: CoreAutonomy =
            serde_json::from_str(&json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyAutonomyRecord { inner })
    }

    #[getter]
    fn agent_id(&self) -> String {
        self.inner.agent_id.clone()
    }

    #[getter]
    fn tier(&self) -> u8 {
        self.inner.tier
    }

    #[getter]
    fn success_streak(&self) -> u32 {
        self.inner.success_streak
    }

    #[getter]
    fn total_successes(&self) -> u64 {
        self.inner.total_successes
    }

    #[getter]
    fn total_violations(&self) -> u64 {
        self.inner.total_violations
    }

    /// Record a successful governed run. Returns True if promoted.
    fn record_success(&mut self) -> bool {
        self.inner.record_success()
    }

    /// Record a violation. Returns True if demoted.
    fn record_violation(&mut self) -> bool {
        self.inner.record_violation()
    }

    /// Serialize to JSON.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// A Merkle transparency log (RFC 6962) over evidence entry hashes.
///
/// Built from the ordered `entry_hash` values of an evidence ledger. It commits to those
/// hashes with a single Merkle root, signs that root into a Signed Tree Head with an
/// `AgentIdentity`, and emits inclusion and consistency proofs. Tree construction and
/// proof generation live in Rust where the RFC 6962 hashing is fixed and auditable.
#[pyclass(name = "TransparencyLog")]
struct PyTransparencyLog {
    inner: CoreTransparencyLog,
}

#[pymethods]
impl PyTransparencyLog {
    #[new]
    fn new() -> Self {
        PyTransparencyLog {
            inner: CoreTransparencyLog::new(),
        }
    }

    /// Build a log from a JSON array of evidence entry hashes (hex strings), in order.
    #[staticmethod]
    fn from_entry_hashes(entry_hashes_json: String) -> PyResult<Self> {
        let hashes: Vec<String> = serde_json::from_str(&entry_hashes_json)
            .map_err(|e| PyValueError::new_err(format!("entry_hashes_json: {e}")))?;
        let inner = CoreTransparencyLog::from_entry_hashes(&hashes).map_err(map_err)?;
        Ok(PyTransparencyLog { inner })
    }

    /// Append one evidence entry hash (hex) as a new leaf.
    fn append_entry_hash(&mut self, entry_hash_hex: String) -> PyResult<()> {
        self.inner
            .append_entry_hash(&entry_hash_hex)
            .map_err(map_err)
    }

    #[getter]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[getter]
    fn root_hash(&self) -> String {
        self.inner.root_hash()
    }

    /// Produce a Signed Tree Head over the current root, returned as a JSON string.
    fn signed_tree_head(&self, signer: &PyAgentIdentity, timestamp: String) -> PyResult<String> {
        let sth = self
            .inner
            .signed_tree_head(&signer.inner, timestamp)
            .map_err(map_err)?;
        serde_json::to_string(&sth).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Build an inclusion proof for the leaf at `index`, returned as a JSON string.
    fn inclusion_proof(&self, index: usize) -> PyResult<String> {
        let proof = self.inner.inclusion_proof(index).map_err(map_err)?;
        serde_json::to_string(&proof).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Build a consistency proof from tree size `first` to the current size, as JSON.
    fn consistency_proof(&self, first: usize) -> PyResult<String> {
        let proof = self.inner.consistency_proof(first).map_err(map_err)?;
        serde_json::to_string(&proof).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

/// Verify an inclusion proof (JSON) that `entry_hash` sits under `root_hash`.
#[pyfunction]
fn verify_inclusion(proof_json: String, entry_hash_hex: String, root_hash_hex: String) -> bool {
    let proof: CoreInclusionProof = match serde_json::from_str(&proof_json) {
        Ok(p) => p,
        Err(_) => return false,
    };
    core_verify_inclusion(&proof, &entry_hash_hex, &root_hash_hex).is_ok()
}

/// Verify a consistency proof (JSON) connecting `first_root` to `second_root`.
#[pyfunction]
fn verify_consistency(proof_json: String, first_root_hex: String, second_root_hex: String) -> bool {
    let proof: CoreConsistencyProof = match serde_json::from_str(&proof_json) {
        Ok(p) => p,
        Err(_) => return false,
    };
    core_verify_consistency(&proof, &first_root_hex, &second_root_hex).is_ok()
}

/// The native AetherOS extension module.
#[pymodule]
fn _aether_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__core_version__", aether_core::VERSION)?;
    m.add_class::<PyAgentIdentity>()?;
    m.add_class::<PyCapabilityLease>()?;
    m.add_class::<PyEvidenceLedger>()?;
    m.add_class::<PyPolicyEngine>()?;
    m.add_class::<PyConstitutionEngine>()?;
    m.add_class::<PyAutonomyRecord>()?;
    m.add_class::<PyTransparencyLog>()?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(verify_inclusion, m)?)?;
    m.add_function(wrap_pyfunction!(verify_consistency, m)?)?;
    Ok(())
}
