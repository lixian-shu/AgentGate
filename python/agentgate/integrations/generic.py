"""Framework-agnostic ``@protect()`` decorator for AgentGate.

Wrap any function -- sync or async -- with AgentGate policy enforcement,
audit logging, and anomaly detection.

Usage::

    from agentgate.integrations.generic import protect

    @protect(policy="policy.yaml", agent_id="my-agent")
    def read_file(path: str) -> str:
        return open(path).read()

    # This call will be checked against the policy before executing.
    content = read_file(path="/tmp/data.txt")

A shared :class:`~agentgate.core.AgentGate` instance is cached per
policy configuration so that wrapping multiple functions does not create
redundant engines.
"""

from __future__ import annotations

import asyncio
import functools
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, TypeVar, overload

from agentgate.core import AgentGate
from agentgate.policy.schema import AgentGatePolicy

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Global gate cache (keyed by policy identity)
# ---------------------------------------------------------------------------

_gate_cache: dict[str, AgentGate] = {}
_gate_lock = threading.Lock()


def _get_or_create_gate(
    policy: str | Path | AgentGatePolicy | None,
) -> AgentGate:
    """Return a cached :class:`AgentGate` instance for the given policy.

    When *policy* is a file path the cache key is the resolved absolute
    path; when it is an ``AgentGatePolicy`` the key is the object's id;
    when ``None`` the literal string ``"__default__"`` is used.
    """
    if policy is None:
        cache_key = "__default__"
    elif isinstance(policy, AgentGatePolicy):
        cache_key = f"obj:{id(policy)}"
    elif isinstance(policy, dict):
        # Dicts are converted to AgentGatePolicy on each gate creation;
        # use a stable hash of the sorted repr as cache key.
        cache_key = f"dict:{hash(repr(sorted(policy.items())))}"
    else:
        cache_key = f"path:{Path(policy).resolve()}"

    with _gate_lock:
        if cache_key not in _gate_cache:
            _gate_cache[cache_key] = AgentGate(policy=policy)
        return _gate_cache[cache_key]


def clear_gate_cache() -> None:
    """Close and remove all cached :class:`AgentGate` instances.

    Primarily useful in tests to ensure clean state between runs.
    """
    with _gate_lock:
        for gate in _gate_cache.values():
            try:
                gate.close()
            except Exception:
                pass
        _gate_cache.clear()


# ---------------------------------------------------------------------------
# The @protect() decorator
# ---------------------------------------------------------------------------


def protect(
    policy: str | Path | AgentGatePolicy | None = None,
    agent_id: str = "default",
    session_id: str | None = None,
    gate: AgentGate | None = None,
) -> Callable[[F], F]:
    """Decorator to protect any function with AgentGate security.

    Parameters
    ----------
    policy : str | Path | AgentGatePolicy | None
        Policy file path, a pre-built policy object, or ``None`` to use
        the built-in default.  Ignored when *gate* is provided.
    agent_id : str
        Agent identifier used for policy look-ups and audit records.
    session_id : str | None
        Session identifier.  A new UUID-4 is generated per decorated
        function if not supplied.
    gate : AgentGate | None
        An existing :class:`AgentGate` instance to reuse.  When provided,
        *policy* is ignored and no global caching is performed.

    Returns
    -------
    Callable
        A decorator that wraps the target function.

    Examples
    --------
    Protect a synchronous function::

        @protect(policy="policy.yaml")
        def delete_file(path: str) -> None:
            os.remove(path)

    Protect an async function::

        @protect(agent_id="data-pipeline")
        async def fetch_url(url: str) -> str:
            async with aiohttp.ClientSession() as s:
                resp = await s.get(url)
                return await resp.text()
    """

    def decorator(fn: F) -> F:
        resolved_gate = gate if gate is not None else _get_or_create_gate(policy)
        # Each decorated function gets its own session if none was supplied.
        resolved_session_id = session_id or str(uuid.uuid4())
        tool_name = fn.__qualname__ or fn.__name__

        if asyncio.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Build tool_args from kwargs (positional args are not
                # introspected to keep the decorator lightweight).
                tool_args = dict(kwargs)
                return await resolved_gate.intercept_tool_call(
                    agent_id=agent_id,
                    session_id=resolved_session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    execute_fn=lambda **_kw: fn(*args, **kwargs),
                )

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                tool_args = dict(kwargs)
                return resolved_gate.intercept_tool_call_sync(
                    agent_id=agent_id,
                    session_id=resolved_session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    execute_fn=lambda **_kw: fn(*args, **kwargs),
                )

            return sync_wrapper  # type: ignore[return-value]

    return decorator  # type: ignore[return-value]
