"""Org B's RevocationCheck transport.

VAID's RevocationCheck (vaid_mint.revocation) is a local, in-process seam: it
answers about a lineage it is handed, from a store it already holds. It does
not define how a verifier with no shared infrastructure learns an issuer's
revocation state in the first place — that is deliberately out of scope of
the VAID wire format (see docs/spec/revocation.md R.4).

This module is the integration choice that fills that gap for this demo: Org
A exposes a revocation status endpoint; Org B polls it, caches the answer for
CACHE_WINDOW_SECONDS, and maps the response onto VAID's own three-state
RevocationStatus (clean / revoked / indeterminate) so the fail-closed
semantics are preserved end to end. A network failure or a non-2xx response is
"indeterminate", never silently "clean".
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

_CACHE: dict[str, dict] = {}


def check(trust_domain: str, lineage_ids: list[str], cache_window_seconds: int) -> tuple[str, bool]:
    now = time.time()
    cached = _CACHE.get(trust_domain)
    if cached and (now - cached["fetched_at"]) < cache_window_seconds:
        revoked_set = cached["revoked"]
        cache_hit = True
    else:
        try:
            url = f"https://{trust_domain}/vaid-revocations/status"
            with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
                doc = json.loads(resp.read())
            revoked_set = set(doc["revoked_vaid_ids"])
            _CACHE[trust_domain] = {"revoked": revoked_set, "fetched_at": now}
            cache_hit = False
        except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError):
            return "indeterminate", False

    status = "revoked" if any(v in revoked_set for v in lineage_ids) else "clean"
    return status, cache_hit
