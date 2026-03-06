"""YAML policy loading and validation for AgentGate.

This module provides functions to load, parse, validate, and merge
AgentGate policy files.  Policies are expressed in YAML and validated
against the Pydantic v2 models defined in :mod:`agentgate.policy.schema`.

Typical usage::

    from agentgate.policy.loader import load_policy

    policy = load_policy("policy.yaml")
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Union

import yaml
from pydantic import ValidationError

from agentgate.policy.schema import AgentGatePolicy, AgentPolicy

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_policy(path: Union[str, Path]) -> AgentGatePolicy:
    """Load and validate an AgentGate policy from a YAML file.

    Parameters
    ----------
    path:
        Path to the YAML policy file.

    Returns
    -------
    AgentGatePolicy
        A fully validated policy object.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    yaml.YAMLError
        If the file contains invalid YAML.
    ValueError
        If the parsed data fails Pydantic schema validation.
    """
    filepath = Path(path)

    if not filepath.exists():
        raise FileNotFoundError(f"Policy file not found: {filepath}")

    if not filepath.is_file():
        raise ValueError(f"Policy path is not a regular file: {filepath}")

    raw_text = filepath.read_text(encoding="utf-8")

    if not raw_text.strip():
        raise ValueError(f"Policy file is empty: {filepath}")

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise yaml.YAMLError(
            f"Failed to parse YAML from {filepath}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Policy file must contain a YAML mapping at the top level, "
            f"got {type(data).__name__}"
        )

    return _validate_dict(data, source=str(filepath))


def load_policy_from_string(yaml_string: str) -> AgentGatePolicy:
    """Parse and validate an AgentGate policy from a YAML string.

    Parameters
    ----------
    yaml_string:
        Raw YAML content.

    Returns
    -------
    AgentGatePolicy
        A fully validated policy object.

    Raises
    ------
    yaml.YAMLError
        If the string contains invalid YAML.
    ValueError
        If the parsed data fails Pydantic schema validation.
    """
    if not yaml_string or not yaml_string.strip():
        raise ValueError("YAML string is empty")

    try:
        data = yaml.safe_load(yaml_string)
    except yaml.YAMLError as exc:
        raise yaml.YAMLError(f"Failed to parse YAML string: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"YAML string must contain a mapping at the top level, "
            f"got {type(data).__name__}"
        )

    return _validate_dict(data, source="<string>")


def load_policy_from_dict(data: dict) -> AgentGatePolicy:
    """Validate a plain dictionary as an AgentGate policy.

    This is useful when the policy data has already been deserialised
    (e.g. from a JSON API response or an in-memory configuration).

    Parameters
    ----------
    data:
        Dictionary conforming to the AgentGatePolicy schema.

    Returns
    -------
    AgentGatePolicy
        A fully validated policy object.

    Raises
    ------
    TypeError
        If *data* is not a ``dict``.
    ValueError
        If *data* fails Pydantic schema validation.
    """
    if not isinstance(data, dict):
        raise TypeError(
            f"Expected a dict, got {type(data).__name__}"
        )

    return _validate_dict(data, source="<dict>")


def merge_policies(*policies: AgentGatePolicy) -> AgentGatePolicy:
    """Merge multiple policies into a single policy.

    Later policies override earlier ones on a per-agent basis.  Top-level
    scalar fields (``version``, ``description``) are taken from the *last*
    policy that defines them.  The ``audit`` and ``anomaly`` sections are
    replaced wholesale by later policies (no deep-merge).

    Parameters
    ----------
    policies:
        Two or more :class:`AgentGatePolicy` instances to merge.

    Returns
    -------
    AgentGatePolicy
        A new policy that is the merged result.

    Raises
    ------
    ValueError
        If fewer than one policy is provided.
    """
    if not policies:
        raise ValueError("merge_policies() requires at least one policy")

    if len(policies) == 1:
        return policies[0].model_copy(deep=True)

    # Start from the first policy and layer subsequent ones on top.
    merged_agents: dict[str, AgentPolicy] = {}
    merged_version: str = policies[0].version
    merged_description: str | None = policies[0].description
    merged_audit = policies[0].audit
    merged_anomaly = policies[0].anomaly

    for policy in policies:
        # Per-agent: later definitions replace earlier ones entirely.
        for agent_id, agent_policy in policy.agents.items():
            merged_agents[agent_id] = agent_policy.model_copy(deep=True)

        # Top-level scalars: last writer wins.
        merged_version = policy.version
        if policy.description is not None:
            merged_description = policy.description
        merged_audit = policy.audit.model_copy(deep=True)
        merged_anomaly = policy.anomaly.model_copy(deep=True)

    return AgentGatePolicy(
        version=merged_version,
        description=merged_description,
        agents=merged_agents,
        audit=merged_audit,
        anomaly=merged_anomaly,
    )


def validate_policy_file(path: Union[str, Path]) -> list[str]:
    """Validate a YAML policy file and return any warnings or errors.

    Unlike :func:`load_policy`, this function never raises -- all problems
    are returned as human-readable strings.  An empty list means the file
    is valid.

    Parameters
    ----------
    path:
        Path to the YAML policy file.

    Returns
    -------
    list[str]
        A list of warning/error messages.  Empty if the file is valid.
    """
    issues: list[str] = []
    filepath = Path(path)

    # --- File-level checks ---------------------------------------------------

    if not filepath.exists():
        issues.append(f"error: Policy file not found: {filepath}")
        return issues

    if not filepath.is_file():
        issues.append(f"error: Path is not a regular file: {filepath}")
        return issues

    try:
        raw_text = filepath.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(f"error: Unable to read file: {exc}")
        return issues

    if not raw_text.strip():
        issues.append("error: Policy file is empty")
        return issues

    # --- YAML parsing --------------------------------------------------------

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        issues.append(f"error: Invalid YAML: {exc}")
        return issues

    if not isinstance(data, dict):
        issues.append(
            f"error: Top-level value must be a YAML mapping, "
            f"got {type(data).__name__}"
        )
        return issues

    # --- Schema validation ---------------------------------------------------

    try:
        policy = AgentGatePolicy.model_validate(data)
    except ValidationError as exc:
        for error in exc.errors():
            loc = " -> ".join(str(part) for part in error["loc"])
            issues.append(f"error: {loc}: {error['msg']}")
        return issues

    # --- Semantic warnings (non-fatal) ----------------------------------------

    issues.extend(_semantic_warnings(policy))

    return issues


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_dict(data: dict[str, Any], *, source: str) -> AgentGatePolicy:
    """Validate a dictionary against the AgentGatePolicy schema.

    Wraps Pydantic ``ValidationError`` in a friendlier ``ValueError``
    that includes the source context.
    """
    try:
        return AgentGatePolicy.model_validate(data)
    except ValidationError as exc:
        error_lines = []
        for error in exc.errors():
            loc = " -> ".join(str(part) for part in error["loc"])
            error_lines.append(f"  {loc}: {error['msg']}")
        detail = "\n".join(error_lines)
        raise ValueError(
            f"Policy validation failed ({source}):\n{detail}"
        ) from exc


def _semantic_warnings(policy: AgentGatePolicy) -> list[str]:
    """Generate non-fatal semantic warnings for a validated policy."""
    warnings: list[str] = []

    if not policy.agents:
        warnings.append(
            "warning: No agents defined in policy; all requests will use "
            "implicit defaults"
        )

    # Check for agents with no tool rules at all.
    for agent_id, agent_policy in policy.agents.items():
        if agent_policy.tools is None:
            warnings.append(
                f"warning: Agent '{agent_id}' has no tool rules defined; "
                f"all tool calls will be implicitly denied"
            )
        elif not agent_policy.tools.allowed and not agent_policy.tools.denied:
            warnings.append(
                f"warning: Agent '{agent_id}' has empty allowed and denied "
                f"tool lists; all tool calls will be implicitly denied"
            )

    # Check for common fallback agent names.
    _FALLBACK_NAMES = {"default", "__default__"}
    has_fallback = any(name in policy.agents for name in _FALLBACK_NAMES)
    if not has_fallback and policy.agents:
        warnings.append(
            "warning: No 'default' or '__default__' agent defined; "
            "unrecognised agents will have no policy"
        )

    # Audit disabled is unusual -- warn.
    if not policy.audit.enabled:
        warnings.append("warning: Audit logging is disabled")

    return warnings
