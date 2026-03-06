"""Framework integrations for AgentGate.

Submodules
----------
base
    Abstract :class:`BaseInterceptor` base class.
generic
    Framework-agnostic ``@protect()`` decorator.
langchain
    LangChain callback handler (:class:`AgentGateMiddleware`).
crewai
    CrewAI step callback (:class:`AgentGateCrewCallback`).
autogen
    AutoGen event adapter (:class:`AgentGateAutoGenAdapter`).
"""
