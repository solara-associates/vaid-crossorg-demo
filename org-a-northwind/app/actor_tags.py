"""Entry-point classification markers (Architectural Rules A7.actor).

Every route in main.py is deliberately @public: this demo has no operator
authentication in front of mint/delegate/revoke, so the browser page can call
them directly and the crossing view can show real network traffic. In a real
deployment these would be @privileged behind Org A's own operator auth —
noted as a limitation in README.md, not hidden by leaving the entry points
unclassified.
"""

from __future__ import annotations

from typing import Callable, TypeVar

F = TypeVar("F", bound=Callable)


def public(func: F) -> F:
    return func
