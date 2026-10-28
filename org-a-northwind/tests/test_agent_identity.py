"""agent_id vs vaid_id (s361 fix 1).

Proves, without any real GCP dependency, the two claims the demo page makes:
the stable agent identity does not change across re-mints, and the per-mint
credential id does; and that revoking one credential for an agent leaves a
newly issued credential for that same agent accepted.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from agent_registry import FirestoreAgentRegistry  # noqa: E402
from vaid_mint.issuer import ReferenceIssuer  # noqa: E402
from vaid_mint.revocation import (  # noqa: E402
    InMemoryLineageStore,
    InMemoryRevocationList,
    RevocationBackend,
)


def _issuer_with_backend() -> tuple[ReferenceIssuer, InMemoryRevocationList]:
    # vaid-mint >=0.9.0 defaults revocation to fail-closed (UNAVAILABLE) until a
    # backend is installed (R.4.5) — the same requirement Org A's main.py meets
    # with Firestore-backed stores. These tests mirror that wiring with
    # in-memory stores so they need no GCP dependency. Once a backend is
    # installed, ReferenceIssuer.revoke() no longer does anything (it only
    # mutates the built-in store, which is no longer consulted) — revoking
    # means going through this returned check object instead.
    check = InMemoryRevocationList.assume_nothing_revoked()
    issuer = ReferenceIssuer.ephemeral(1, "northwind.example").with_revocation_backend(
        RevocationBackend(check=check, lineage=InMemoryLineageStore())
    )
    return issuer, check


class _FakeSnapshot:
    def __init__(self, data):
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return self._data


class _FakeDocRef:
    def __init__(self, store, key):
        self._store = store
        self._key = key

    def get(self):
        return _FakeSnapshot(self._store.get(self._key))

    def set(self, data):
        self._store[self._key] = data


class _FakeCollection:
    def __init__(self):
        self._docs = {}

    def document(self, key):
        return _FakeDocRef(self._docs, key)


class _FakeFirestoreClient:
    def __init__(self):
        self._collections = {}

    def collection(self, name):
        return self._collections.setdefault(name, _FakeCollection())


def _scope(prefix="harbor-ops/deploy/"):
    return [{"kind": "prefix", "value": prefix}]


def test_stable_agent_id_persists_across_repeated_lookups():
    registry = FirestoreAgentRegistry(_FakeFirestoreClient())
    first = registry.get_or_create("infra-agent")
    second = registry.get_or_create("infra-agent")
    assert first == second


def test_stable_agent_id_differs_between_named_agents():
    registry = FirestoreAgentRegistry(_FakeFirestoreClient())
    root_id = registry.get_or_create("infra-agent")
    helper_id = registry.get_or_create("infra-agent-sub")
    assert root_id != helper_id


def test_remint_keeps_agent_id_but_issues_a_fresh_vaid_id():
    issuer, _ = _issuer_with_backend()
    registry = FirestoreAgentRegistry(_FakeFirestoreClient())

    stable_agent_id = registry.get_or_create("infra-agent")
    first = issuer.issue_vaid_with_lineage(
        agent_class="infra-agent", version="1", tenant_id="t1",
        parent_vaid=None, scope_boundary=_scope(), capability_set=["deploy"],
    )
    assert registry.get_or_create("infra-agent") == stable_agent_id

    second = issuer.issue_vaid_with_lineage(
        agent_class="infra-agent", version="1", tenant_id="t1",
        parent_vaid=None, scope_boundary=_scope(), capability_set=["deploy"],
    )
    assert registry.get_or_create("infra-agent") == stable_agent_id

    # The two credentials are for the same stable agent, but are not the same
    # credential: this is the agent_id vs vaid_id distinction the demo page
    # must show, not the VAID spec's per-document agent_id/vaid_id equality.
    assert first["vaid_id"] != second["vaid_id"]
    assert first["agent_id"] == first["vaid_id"]  # VAID's own spec invariant, untouched
    assert second["agent_id"] == second["vaid_id"]


def test_revoking_one_credential_leaves_a_freshly_issued_one_for_the_same_agent_accepted():
    issuer, revocation_check = _issuer_with_backend()

    old = issuer.issue_vaid_with_lineage(
        agent_class="infra-agent", version="1", tenant_id="t1",
        parent_vaid=None, scope_boundary=_scope(), capability_set=["deploy"],
    )
    new = issuer.issue_vaid_with_lineage(
        agent_class="infra-agent", version="1", tenant_id="t1",
        parent_vaid=None, scope_boundary=_scope(), capability_set=["deploy"],
    )

    assert issuer.verify_vaid(old) is True
    assert issuer.verify_vaid(new) is True

    revocation_check.revoke(old["vaid_id"])

    assert issuer.verify_vaid(old) is False
    assert issuer.verify_vaid(new) is True


def test_delegated_helper_has_its_own_agent_id_and_vaid_id_with_parent_vaid_set():
    issuer, _ = _issuer_with_backend()
    registry = FirestoreAgentRegistry(_FakeFirestoreClient())

    root_agent_id = registry.get_or_create("infra-agent")
    root = issuer.issue_vaid_with_lineage(
        agent_class="infra-agent", version="1", tenant_id="t1",
        parent_vaid=None, scope_boundary=_scope(), capability_set=["deploy"],
    )

    helper_agent_id = registry.get_or_create("infra-agent-sub")
    helper = issuer.issue_vaid_with_lineage(
        agent_class="infra-agent-sub", version="1", tenant_id="t1",
        parent_vaid=root["vaid_id"], scope_boundary=_scope(), capability_set=["deploy"],
    )

    assert helper_agent_id != root_agent_id
    assert helper["vaid_id"] != root["vaid_id"]
    assert helper["parent_vaid"] == root["vaid_id"]
