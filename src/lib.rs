//! AgentGate Core -- high-performance Rust engine for the AgentGate AI agent
//! security framework.
//!
//! This crate exposes three primary capabilities via PyO3:
//!
//! 1. **PolicyMatcher** -- compile and evaluate deny-first tool-call policies.
//! 2. **AuditWriter**  -- batched, non-blocking audit event writing to SQLite.
//! 3. **AuditSigner**  -- Ed25519 signing and verification of audit records.

// PyO3's map_err conversions from String -> PyErr are flagged by clippy as
// "useless" because PyO3 implements From<String> for PyErr. However, the
// explicit map_err is needed to select the correct exception type
// (PyValueError vs PyRuntimeError). Suppress globally for this module.
#![allow(clippy::useless_conversion)]

pub mod audit;
pub mod policy;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Arc;

// ===========================================================================
// Python wrapper: PolicyMatcher
// ===========================================================================

/// Python-visible policy matcher.
///
/// Usage from Python:
/// ```python
/// from agentgate._core import PolicyMatcher
///
/// pm = PolicyMatcher()
/// pm.compile_policy("agent-1", deny_rules_json, allow_rules_json)
/// result = pm.check_tool_call("agent-1", "file_read", '{"path": "/tmp/x"}')
/// # result == {"decision": "allowed", "reason": None}
/// ```
#[pyclass(name = "PolicyMatcher")]
struct PyPolicyMatcher {
    inner: Arc<policy::PolicyMatcher>,
}

#[pymethods]
impl PyPolicyMatcher {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(policy::PolicyMatcher::new()),
        }
    }

    /// Compile a policy for the given agent.
    ///
    /// Both `deny_rules_json` and `allow_rules_json` must be JSON arrays of
    /// rule objects.
    fn compile_policy(
        &self,
        agent_id: &str,
        deny_rules_json: &str,
        allow_rules_json: &str,
    ) -> PyResult<()> {
        self.inner
            .compile_policy(agent_id, deny_rules_json, allow_rules_json)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// Check whether a tool call is permitted.
    ///
    /// Returns a dict with keys `"decision"` and `"reason"`.
    fn check_tool_call<'py>(
        &self,
        py: Python<'py>,
        agent_id: &str,
        tool_name: &str,
        args_json: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let decision = self.inner.check_tool_call(agent_id, tool_name, args_json);

        let dict = PyDict::new_bound(py);
        dict.set_item("decision", decision.label())?;
        match decision.reason() {
            Some(r) => dict.set_item("reason", r)?,
            None => dict.set_item("reason", py.None())?,
        }
        Ok(dict.unbind().into_bound(py))
    }

    /// Remove the compiled policy for an agent.
    fn remove_policy(&self, agent_id: &str) -> bool {
        self.inner.remove_policy(agent_id)
    }

    /// Return the number of agents with compiled policies.
    fn policy_count(&self) -> usize {
        self.inner.policy_count()
    }

    /// Check whether a policy exists for the given agent.
    fn has_policy(&self, agent_id: &str) -> bool {
        self.inner.has_policy(agent_id)
    }
}

// ===========================================================================
// Python wrapper: AuditWriter
// ===========================================================================

/// Python-visible audit writer.
///
/// Usage from Python:
/// ```python
/// from agentgate._core import AuditWriter
///
/// writer = AuditWriter("/tmp/audit.db", batch_size=100, flush_interval_ms=1000)
/// writer.write_event('{"event_id": "...", ...}')
/// writer.flush()
/// writer.close()
/// ```
#[pyclass(name = "AuditWriter")]
struct PyAuditWriter {
    inner: Option<audit::AuditWriter>,
}

#[pymethods]
impl PyAuditWriter {
    /// Create a new AuditWriter.
    ///
    /// - `db_path`           -- path to the SQLite database file.
    /// - `batch_size`        -- max events per batch (default 100).
    /// - `flush_interval_ms` -- max ms between flushes (default 1000).
    #[new]
    #[pyo3(signature = (db_path, batch_size=100, flush_interval_ms=1000))]
    fn new(db_path: &str, batch_size: usize, flush_interval_ms: u64) -> PyResult<Self> {
        let writer = audit::AuditWriter::new(db_path, batch_size, flush_interval_ms)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Self {
            inner: Some(writer),
        })
    }

    /// Enqueue an audit event (non-blocking).
    fn write_event(&self, event_json: &str) -> PyResult<()> {
        match &self.inner {
            Some(w) => w
                .write_event(event_json)
                .map_err(pyo3::exceptions::PyRuntimeError::new_err),
            None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                "AuditWriter is closed",
            )),
        }
    }

    /// Force-flush pending events to SQLite.
    fn flush(&self) -> PyResult<()> {
        match &self.inner {
            Some(w) => w.flush().map_err(pyo3::exceptions::PyRuntimeError::new_err),
            None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                "AuditWriter is closed",
            )),
        }
    }

    /// Flush and shut down the background writer thread.
    fn close(&mut self) -> PyResult<()> {
        match &mut self.inner {
            Some(w) => {
                w.close()
                    .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
                self.inner = None;
                Ok(())
            }
            None => Ok(()), // already closed, idempotent
        }
    }
}

// ===========================================================================
// Python wrapper: AuditSigner
// ===========================================================================

/// Python-visible Ed25519 audit signer.
///
/// Usage from Python:
/// ```python
/// from agentgate._core import AuditSigner
///
/// signer = AuditSigner()
/// sig = signer.sign("some data")
/// assert signer.verify("some data", sig)
/// pk = signer.public_key_hex()
/// ```
#[pyclass(name = "AuditSigner")]
struct PyAuditSigner {
    inner: audit::AuditSigner,
}

#[pymethods]
impl PyAuditSigner {
    /// Generate a new random Ed25519 keypair.
    #[new]
    fn new() -> Self {
        Self {
            inner: audit::AuditSigner::new(),
        }
    }

    /// Reconstruct a signer from existing secret key bytes.
    ///
    /// `secret_bytes` must be exactly 32 bytes.
    #[staticmethod]
    fn from_bytes(secret_bytes: &[u8]) -> PyResult<Self> {
        let signer = audit::AuditSigner::from_bytes(secret_bytes)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(Self { inner: signer })
    }

    /// Sign data and return the hex-encoded Ed25519 signature.
    fn sign(&self, data: &str) -> String {
        self.inner.sign(data)
    }

    /// Verify a hex-encoded signature against the given data.
    fn verify(&self, data: &str, signature: &str) -> bool {
        self.inner.verify(data, signature)
    }

    /// Return the public key as a hex string (64 hex chars / 32 bytes).
    fn public_key_hex(&self) -> String {
        self.inner.public_key_hex()
    }
}

// ===========================================================================
// PyO3 module registration
// ===========================================================================

/// The native extension module exposed to Python as `agentgate._core`.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPolicyMatcher>()?;
    m.add_class::<PyAuditWriter>()?;
    m.add_class::<PyAuditSigner>()?;
    Ok(())
}
