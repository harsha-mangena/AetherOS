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
use aether_core::error::CoreError;
use aether_core::evidence::EvidenceLedger as CoreLedger;
use aether_core::identity::{verify_signature as core_verify, AgentIdentity as CoreIdentity};
use aether_core::lease::{Budget as CoreBudget, CapabilityLease as CoreLease};
use aether_core::policy::{PolicyRequest as CoreReq, PolicySet as CorePolicySet};

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

/// The native AetherOS extension module.
#[pymodule]
fn _aether_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__core_version__", aether_core::VERSION)?;
    m.add_class::<PyAgentIdentity>()?;
    m.add_class::<PyCapabilityLease>()?;
    m.add_class::<PyEvidenceLedger>()?;
    m.add_class::<PyPolicyEngine>()?;
    m.add_class::<PyAutonomyRecord>()?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    Ok(())
}
