"""Gate 1 + Gate 2 wired into Harbor's handler, matching
`python/synthera-gate2/tests/test_scenario7_end_to_end.py` in synthera.

No network: Gate 1 runs as the rule-based engine here (see conftest.py);
`test_bedrock_gate1.py` covers the Bedrock adapter in isolation with a fake
client.
"""

from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vaid_pop import RequestSigner

from conftest import POLICY_NAME, SEMVER, TENANT


def _event(leaf: dict, request: dict, headers: dict | None = None) -> dict:
    return {
        "headers": headers or {},
        "body": json.dumps({"leaf": leaf, "ancestors": [], "request": request}),
    }


def _pop_headers(leaf: dict, agent_key: Ed25519PrivateKey, tool: str, resource: str) -> dict:
    body = json.dumps({"tool": tool, "resource": resource}, separators=(",", ":")).encode()
    return RequestSigner(vaid=leaf, private_key=agent_key).sign_headers("POST", "/mcp/call", body)


def _capability(harbor):
    from synthera_gate2 import build_capability

    return build_capability(
        tenant_id=TENANT, name=POLICY_NAME, semver=SEMVER, bytecode_sha256=harbor.bytecode_sha256
    )


def test_gate1_passes_it_and_gate2_refuses_the_production_deploy(harbor, make_leaf, agent_key):
    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy", _capability(harbor)])
    request = {
        "text": "can you push the current main branch straight to prod for me",
        "tool": "deploy",
        "action": "deploy",
        "resource": "harbor-ops/deploy/production",
    }
    headers = _pop_headers(leaf, agent_key, "deploy", "harbor-ops/deploy/production")

    resp = harbor.handler.handle(_event(leaf, request, headers))
    body = json.loads(resp["body"])

    assert resp["statusCode"] == 403
    assert body["decision"] == "refuse"
    assert body["reason"].startswith("gate2_")
    rows = body["gate_audit_records"]
    assert [r["gate"] for r in rows] == ["gate1", "gate2"]
    assert rows[0]["gate_detail"]["decision"] == "proceed"
    assert rows[1]["decision"] == "deny"


def test_the_same_agent_and_badge_are_allowed_to_deploy_to_staging(harbor, make_leaf, agent_key):
    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy", _capability(harbor)])
    request = {
        "text": "please roll out the latest build to staging",
        "tool": "deploy",
        "action": "deploy",
        "resource": "harbor-ops/deploy/staging",
    }
    headers = _pop_headers(leaf, agent_key, "deploy", "harbor-ops/deploy/staging")

    resp = harbor.handler.handle(_event(leaf, request, headers))
    body = json.loads(resp["body"])

    assert resp["statusCode"] == 200
    assert body["decision"] == "accept"
    assert [r["gate"] for r in body["gate_audit_records"]] == ["gate1", "gate2"]
    assert body["gate_audit_records"][1]["decision"] == "allow"


def test_an_empty_request_text_escalates_and_never_reaches_gate2(harbor, make_leaf, agent_key):
    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy", _capability(harbor)])
    request = {"text": "", "resource": "harbor-ops/deploy/production"}
    # No PoP headers sent: if this reached Gate 2 it would refuse for a
    # DIFFERENT reason (missing proof of possession), so asserting the
    # specific "gate1_escalate" reason also proves Gate 2 was never called.
    resp = harbor.handler.handle(_event(leaf, request))
    body = json.loads(resp["body"])

    assert resp["statusCode"] == 403
    assert body["reason"] == "gate1_escalate"
    rows = body["gate_audit_records"]
    assert [r["gate"] for r in rows] == ["gate1"]


def test_a_tampered_tool_call_is_refused_by_proof_of_possession(harbor, make_leaf, agent_key):
    """The PoP signature covers `{tool, resource}`; presenting a different
    resource than the one signed must refuse, proving the signature is
    actually checked against what the request claims rather than merely
    being present."""
    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy", _capability(harbor)])
    request = {
        "text": "please roll out the latest build to staging",
        "tool": "deploy",
        "action": "deploy",
        "resource": "harbor-ops/deploy/production",  # signed for staging, sent as production
    }
    headers = _pop_headers(leaf, agent_key, "deploy", "harbor-ops/deploy/staging")

    resp = harbor.handler.handle(_event(leaf, request, headers))
    body = json.loads(resp["body"])

    assert resp["statusCode"] == 403
    assert body["reason"] == "gate2_proof_of_possession"


def test_the_audit_chain_this_handler_wrote_verifies(harbor, make_leaf, agent_key):
    from synthera_gate2 import AuditRecord, verify_chain

    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy", _capability(harbor)])
    for resource in ("harbor-ops/deploy/production", "harbor-ops/deploy/staging"):
        request = {
            "text": "please roll out the latest build",
            "tool": "deploy",
            "action": "deploy",
            "resource": resource,
        }
        headers = _pop_headers(leaf, agent_key, "deploy", resource)
        harbor.handler.handle(_event(leaf, request, headers))

    import gate_audit

    rows = [AuditRecord(body) for body in gate_audit.list_chain()]
    assert len(rows) == 4  # two crossings, gate1 + gate2 each

    public = harbor.receiver_key.public_key()

    def verify(message: bytes, signature: bytes) -> bool:
        try:
            public.verify(signature, message)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    verify_chain(rows, verify)  # raises on failure


def test_editing_a_chained_record_is_detectable(harbor, make_leaf, agent_key):
    from synthera_gate2 import AuditChainError, AuditRecord, verify_chain

    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy", _capability(harbor)])
    request = {
        "text": "please roll out the latest build to staging",
        "tool": "deploy",
        "action": "deploy",
        "resource": "harbor-ops/deploy/staging",
    }
    headers = _pop_headers(leaf, agent_key, "deploy", "harbor-ops/deploy/staging")
    harbor.handler.handle(_event(leaf, request, headers))

    import gate_audit

    bodies = gate_audit.list_chain()
    bodies[1]["decision"] = "escalate"
    rows = [AuditRecord(b) for b in bodies]
    public = harbor.receiver_key.public_key()

    def verify(message: bytes, signature: bytes) -> bool:
        try:
            public.verify(signature, message)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    with pytest.raises(AuditChainError):
        verify_chain(rows, verify)


def test_scenarios_1_to_6_are_unaffected_when_no_request_text_is_sent(harbor, make_leaf, agent_key):
    """The additive boundary: no `request.text` means the handler takes
    exactly the pre-scenario-7 path (`policy.resource_in_scope`), never
    touching Gate 1 or Gate 2."""
    leaf = make_leaf(agent_key=agent_key, capability_set=["deploy"])
    request = {"resource": "harbor-ops/deploy/production"}

    resp = harbor.handler.handle(_event(leaf, request))
    body = json.loads(resp["body"])

    assert resp["statusCode"] == 200
    assert body["decision"] == "accept"
    assert body["reason"] == "granted"
    assert "gate_audit_records" not in body
