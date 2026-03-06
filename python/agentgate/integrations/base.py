"""Abstract base class for AgentGate framework integrations.

Every framework-specific adapter (LangChain, CrewAI, AutoGen, etc.)
subclasses :class:`BaseInterceptor` so that the install/uninstall
lifecycle is uniform and testable.

Usage for implementers::

    class MyFrameworkInterceptor(BaseInterceptor):
        def install(self, agent_or_framework):
            # Hook into the framework's tool-call pathway.
            ...

        def uninstall(self):
            # Remove hooks.
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentgate.core import AgentGate


class BaseInterceptor(ABC):
    """Abstract base for framework integrations.

    Parameters
    ----------
    gate : AgentGate
        The :class:`~agentgate.core.AgentGate` instance that performs
        the actual policy evaluation, audit, and anomaly detection.
    """

    def __init__(self, gate: "AgentGate") -> None:
        self.gate = gate

    @abstractmethod
    def install(self, agent_or_framework: Any) -> None:
        """Install this interceptor into the target framework.

        The exact type of *agent_or_framework* depends on the specific
        integration (e.g. a LangChain ``AgentExecutor``, a CrewAI
        ``Crew`` instance, an AutoGen ``GroupChat``).
        """

    @abstractmethod
    def uninstall(self) -> None:
        """Remove this interceptor from the target framework.

        After calling this, tool calls should bypass AgentGate and
        execute directly as they would without the integration.
        """
