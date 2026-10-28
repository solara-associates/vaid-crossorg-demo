"""Harbor Ops' own policy. Deny by default.

Nothing here is part of VAID. VAID tells Org B who signed a credential, what it
is attenuated to, and whether it is revoked. What Org B is willing to let that
identity *do* is Org B's own decision, held entirely on Org B's side.
"""

from __future__ import annotations

import os

# Trust-domain allowlist: which issuers Org B is willing to even look up a key
# for. Everything else is refused before any crypto runs. Set at deploy time
# via the TRUST_DOMAIN_ALLOWLIST env var (comma-separated); there is no
# hardcoded default because there is no legitimate trust domain to default to.
ALLOWED_TRUST_DOMAINS = {
    d.strip() for d in os.environ.get("TRUST_DOMAIN_ALLOWLIST", "").split(",") if d.strip()
}

# Org B's own maximum delegation depth. VAID's chain verification has no
# opinion on how deep delegation may go; this is Org B refusing past depth 1
# regardless of what a longer, authentic chain would attenuate correctly to.
MAX_DELEGATION_DEPTH = int(os.environ.get("MAX_DELEGATION_DEPTH", "1"))

# Resource scope Org B grants per trust domain, for this demo's one partner.
# A request for anything not listed as a prefix match here is refused with
# reason "outside_scope" even if the presented credential's own scope
# boundary would cover it — this is Org B's policy, checked in addition to
# (not instead of) the credential's own attenuation chain.
#
# Keyed by trust domain only, not agent_class: a sub-agent Northwind delegates
# to (scenario 3) legitimately carries a different agent_class than its
# root, and the delegation chain itself — verified separately, in full — is
# what vouches for that sub-agent, not a string match on its class name.
_GRANTED_TRUST_DOMAIN = os.environ.get("GRANTED_TRUST_DOMAIN", "")
_GRANTED_PREFIXES = [p.strip() for p in os.environ.get("GRANTED_RESOURCE_PREFIXES", "").split(",") if p.strip()]

GRANTED_RESOURCE_PREFIXES: dict[str, list[str]] = {
    _GRANTED_TRUST_DOMAIN: _GRANTED_PREFIXES
} if _GRANTED_TRUST_DOMAIN else {}


def is_trust_domain_allowed(trust_domain: str) -> bool:
    return trust_domain in ALLOWED_TRUST_DOMAINS


def granted_prefixes(trust_domain: str) -> list[str]:
    return GRANTED_RESOURCE_PREFIXES.get(trust_domain, [])


def resource_in_scope(trust_domain: str, agent_class: str, resource: str) -> bool:
    return any(resource.startswith(p) for p in granted_prefixes(trust_domain))
