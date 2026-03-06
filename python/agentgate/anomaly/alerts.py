"""Alert dispatch system for the anomaly detection subsystem.

When the :class:`~agentgate.anomaly.detector.AnomalyDetector` scores an
event above the configured sensitivity threshold, the
:class:`AlertDispatcher` fans the alert out to every registered
:class:`AlertHandler`.

Two concrete handlers are provided out of the box:

* :class:`LogAlertHandler` -- writes to the Python ``logging`` system.
* :class:`WebhookAlertHandler` -- POSTs a JSON payload to a URL
  (non-blocking via a background thread).
"""

from __future__ import annotations

import json
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from agentgate.audit.models import AuditEvent
from agentgate.policy.schema import AnomalyConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitivity threshold mapping (mirrors detector.py)
# ---------------------------------------------------------------------------

_SENSITIVITY_THRESHOLDS: dict[str, float] = {
    "low": 0.8,
    "medium": 0.6,
    "high": 0.4,
}

# ---------------------------------------------------------------------------
# Alert payload
# ---------------------------------------------------------------------------


@dataclass
class AlertPayload:
    """Immutable data packet delivered to alert handlers.

    Attributes
    ----------
    event:
        The original audit event that triggered the alert.
    anomaly_score:
        The computed anomaly score for the event (0.0 -- 1.0).
    anomaly_flags:
        Human-readable flags describing detected anomalies.
    timestamp:
        The time at which the alert was generated.
    message:
        A pre-formatted human-readable summary of the anomaly.
    """

    event: AuditEvent
    anomaly_score: float
    anomaly_flags: list[str]
    timestamp: datetime
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise the payload to a JSON-compatible dict."""
        return {
            "event_id": self.event.event_id,
            "agent_id": self.event.agent_id,
            "session_id": self.event.session_id,
            "action_type": self.event.action_type,
            "tool_name": self.event.tool_name,
            "decision": self.event.decision,
            "anomaly_score": self.anomaly_score,
            "anomaly_flags": list(self.anomaly_flags),
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# Abstract handler
# ---------------------------------------------------------------------------


class AlertHandler(ABC):
    """Base class for alert delivery channels."""

    @abstractmethod
    def send(self, alert: AlertPayload) -> None:
        """Deliver *alert* to this channel.

        Implementations **must not** raise exceptions -- delivery failures
        should be logged and silently swallowed so that one broken handler
        does not prevent other handlers from running.
        """


# ---------------------------------------------------------------------------
# Concrete handlers
# ---------------------------------------------------------------------------


class LogAlertHandler(AlertHandler):
    """Writes alerts to the Python logging subsystem at WARNING level."""

    def __init__(self, logger_name: str = "agentgate.anomaly.alerts") -> None:
        self._logger = logging.getLogger(logger_name)

    def send(self, alert: AlertPayload) -> None:
        try:
            self._logger.warning(
                "Anomaly alert | agent=%s score=%.2f flags=%s | %s",
                alert.event.agent_id,
                alert.anomaly_score,
                alert.anomaly_flags,
                alert.message,
            )
        except Exception:
            # Logging should never crash the pipeline.
            pass


class WebhookAlertHandler(AlertHandler):
    """POSTs a JSON payload to a webhook URL.

    The HTTP request is executed in a daemon thread so that the calling
    code is never blocked by network latency.  Delivery failures are
    logged at ERROR level but never propagated.

    Parameters
    ----------
    url:
        The destination URL to POST alerts to.
    timeout_seconds:
        Maximum number of seconds to wait for the HTTP response.
    """

    def __init__(self, url: str, timeout_seconds: float = 10.0) -> None:
        self._url = url
        self._timeout = timeout_seconds

    def send(self, alert: AlertPayload) -> None:
        """Fire-and-forget HTTP POST in a background thread."""
        thread = threading.Thread(
            target=self._deliver,
            args=(alert,),
            daemon=True,
            name=f"webhook-alert-{alert.event.event_id[:8]}",
        )
        thread.start()

    def _deliver(self, alert: AlertPayload) -> None:
        """Execute the actual HTTP POST (runs in background thread)."""
        try:
            payload_bytes = json.dumps(alert.to_dict()).encode("utf-8")
            request = Request(
                self._url,
                data=payload_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=self._timeout) as response:
                status = response.status
                if status >= 400:
                    logger.error(
                        "Webhook alert delivery failed: status=%d url=%s",
                        status,
                        self._url,
                    )
        except URLError as exc:
            logger.error(
                "Webhook alert delivery error: %s url=%s", exc, self._url
            )
        except Exception as exc:
            logger.error(
                "Unexpected error delivering webhook alert: %s url=%s",
                exc,
                self._url,
            )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _build_alert_message(
    event: AuditEvent, anomaly_score: float, anomaly_flags: list[str]
) -> str:
    """Build a human-readable alert message."""
    flag_str = ", ".join(anomaly_flags) if anomaly_flags else "none"
    return (
        f"Agent '{event.agent_id}' triggered anomaly detection "
        f"(score={anomaly_score:.2f}) during {event.action_type}"
        f"{' on ' + event.tool_name if event.tool_name else ''} "
        f"in session '{event.session_id}'. Flags: [{flag_str}]"
    )


class AlertDispatcher:
    """Fans anomaly alerts out to all registered handlers.

    On construction the dispatcher reads the ``alerts`` list from the
    supplied :class:`~agentgate.policy.schema.AnomalyConfig` and
    automatically instantiates the corresponding built-in handlers.
    Additional handlers can be added at runtime via :meth:`add_handler`.

    Parameters
    ----------
    config:
        Optional anomaly configuration.  When ``None`` a default config
        is used (no alert channels configured, sensitivity ``"medium"``).
    """

    def __init__(self, config: AnomalyConfig | None = None) -> None:
        self._config: AnomalyConfig = config or AnomalyConfig()
        self._threshold: float = _SENSITIVITY_THRESHOLDS.get(
            self._config.sensitivity, _SENSITIVITY_THRESHOLDS["medium"]
        )
        self._handlers: list[AlertHandler] = []

        # Instantiate handlers from config.
        for alert_cfg in self._config.alerts:
            handler = self._handler_from_config(alert_cfg)
            if handler is not None:
                self._handlers.append(handler)

    # -- public API ---------------------------------------------------------

    def dispatch(
        self,
        event: AuditEvent,
        anomaly_score: float,
        anomaly_flags: list[str],
    ) -> None:
        """Send an alert to all handlers if *anomaly_score* exceeds the threshold.

        The sensitivity threshold determines the minimum score required to
        trigger an alert:

        * ``low``    -- score must exceed **0.8**
        * ``medium`` -- score must exceed **0.6**
        * ``high``   -- score must exceed **0.4**

        If *anomaly_score* is below the threshold the call is a no-op.
        """
        if anomaly_score < self._threshold:
            return

        if not self._handlers:
            logger.debug(
                "Anomaly score %.2f exceeds threshold %.2f but no handlers "
                "are configured; alert suppressed.",
                anomaly_score,
                self._threshold,
            )
            return

        payload = AlertPayload(
            event=event,
            anomaly_score=anomaly_score,
            anomaly_flags=list(anomaly_flags),
            timestamp=datetime.now(timezone.utc),
            message=_build_alert_message(event, anomaly_score, anomaly_flags),
        )

        for handler in self._handlers:
            try:
                handler.send(payload)
            except Exception as exc:
                # Guard against handlers that violate the no-raise contract.
                logger.error(
                    "Alert handler %s raised an unexpected exception: %s",
                    type(handler).__name__,
                    exc,
                )

    def add_handler(self, handler: AlertHandler) -> None:
        """Register an additional alert handler at runtime."""
        if not isinstance(handler, AlertHandler):
            raise TypeError(
                f"Expected an AlertHandler instance, got {type(handler).__name__}"
            )
        self._handlers.append(handler)

    @property
    def handlers(self) -> list[AlertHandler]:
        """Return a snapshot of the currently registered handlers."""
        return list(self._handlers)

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _handler_from_config(alert_cfg: Any) -> AlertHandler | None:
        """Instantiate a built-in handler from an ``AlertConfig`` entry.

        Returns ``None`` (with a warning) for unrecognised channel types
        so that the rest of the system is not affected by a misconfigured
        alert channel.
        """
        channel_type = alert_cfg.type

        if channel_type == "log":
            return LogAlertHandler()

        if channel_type == "webhook":
            url = alert_cfg.url
            if not url:
                logger.warning(
                    "Webhook alert channel configured without a 'url'; skipping."
                )
                return None
            return WebhookAlertHandler(url=url)

        # 'email' and other future types are not yet implemented.
        logger.warning(
            "Alert channel type '%s' is not yet implemented; skipping.",
            channel_type,
        )
        return None
