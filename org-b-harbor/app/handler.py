"""Harbor Ops (Org B) — AWS Lambda behind a Function URL, eu-west-2 only.

Receives a VAID credential bundle and a change request over plain HTTPS from a
browser running Org A's demo page. Holds no Org A secret, no shared IAM, no
federation with Org A. Everything it knows about Org A it learned by fetching
a public document over HTTPS from a domain on its own allowlist.

Runs every check in the order the demo's crossing view shows it, and returns
the full step-by-step trace alongside the decision so the UI does not have to
re-derive what happened.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
import hashlib
import base64

import boto3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import vaid_mint
from vaid_mint.chain import PresentedBundle, verify_chain, ChainVerification
from vaid_mint.verify import verify_vaid_authenticity, parse_vaid_document
from vaid_mint.document import is_expired

from synthera_gate2 import BadgeVerification, ToolCall, decide

import policy
import audit
import gate_audit
import gates
import keystore
import revocation_client

CACHE_WINDOW_SECONDS = int(os.environ.get("CACHE_WINDOW_SECONDS", "60"))


def _step(trace: list, name: str, ok: bool, detail: dict) -> None:
    trace.append({"step": name, "ok": ok, "detail": detail, "t_ms": int(time.time() * 1000)})


def handle(event: dict) -> dict:
    t0 = time.time()
    trace: list[dict] = []
    headers = {str(k): v for k, v in (event.get("headers") or {}).items()}
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"decision": "refuse", "reason": "bad_request", "trace": trace})

    leaf = body.get("leaf")
    ancestors = body.get("ancestors", [])
    request = body.get("request", {})
    resource = request.get("resource", "")
    request_text = request.get("text", "")
    tool_call = ToolCall(
        tool=request.get("tool", "deploy"),
        action=request.get("action", "deploy"),
        resource=resource,
    )
    # Demo-only knob: the crossing view lets a viewer set the cache window
    # visibly, including shorter than the deployed default, so the revocation
    # scenario is demonstrable without a multi-minute wait. Bounded so the
    # demo page cannot push it below 1s or above the deployed default.
    cache_window = CACHE_WINDOW_SECONDS
    if "cache_window_seconds" in request:
        try:
            cache_window = max(1, min(int(request["cache_window_seconds"]), CACHE_WINDOW_SECONDS))
        except (TypeError, ValueError):
            pass

    if not isinstance(leaf, dict) or "vaid_id" not in leaf:
        return _response(400, {"decision": "refuse", "reason": "bad_request", "trace": trace})

    bundle_hash = hashlib.sha256(
        json.dumps({"leaf": leaf, "ancestors": ancestors}, sort_keys=True).encode()
    ).hexdigest()

    trust_domain = leaf.get("trust_domain", "")

    # 1. trust-domain allowlist
    allowed = policy.is_trust_domain_allowed(trust_domain)
    _step(trace, "trust_domain_allowlist", allowed, {"trust_domain": trust_domain})
    if not allowed:
        return _finish(trace, bundle_hash, leaf, "refuse", "untrusted_domain", t0)

    # 2. public-key fetch (cache hit/miss, key id)
    try:
        pubkey_der, key_id, cache_hit = keystore.get_org_a_public_key(trust_domain, cache_window)
    except Exception as exc:  # noqa: BLE001 - surfaced to caller as a decision, not a 500
        _step(trace, "public_key_fetch", False, {"error": str(exc)})
        return _finish(trace, bundle_hash, leaf, "refuse", "key_fetch_failed", t0)
    _step(trace, "public_key_fetch", True, {"key_id": key_id, "cache_hit": cache_hit})

    pubkey = Ed25519PublicKey.from_public_bytes(pubkey_der)

    # 3. signature
    sig_ok = verify_vaid_authenticity(pubkey_der, leaf)
    _step(trace, "signature", sig_ok, {"vaid_id": leaf.get("vaid_id")})
    if not sig_ok:
        return _finish(trace, bundle_hash, leaf, "refuse", "signature_invalid", t0)

    # 4. expiry
    expired = is_expired(leaf)
    _step(trace, "expiry", not expired, {"expires_at": leaf.get("expires_at")})
    if expired:
        return _finish(trace, bundle_hash, leaf, "refuse", "credential_expired", t0)

    # 5. revocation — queried from Org A's revocation status endpoint, cached
    #    for CACHE_WINDOW_SECONDS. This is Org B's RevocationCheck
    #    implementation; VAID defines the three-state seam, not the transport.
    lineage_ids = [a.get("vaid_id") for a in ancestors] + [leaf["vaid_id"]]
    try:
        status, cache_hit_rev = revocation_client.check(trust_domain, lineage_ids, cache_window)
    except Exception as exc:  # noqa: BLE001
        _step(trace, "revocation", False, {"error": str(exc)})
        return _finish(trace, bundle_hash, leaf, "refuse", "revocation_unavailable", t0)
    rev_ok = status == "clean"
    _step(trace, "revocation", rev_ok, {"status": status, "cache_hit": cache_hit_rev, "window_s": cache_window})
    if status == "indeterminate":
        return _finish(trace, bundle_hash, leaf, "refuse", "revocation_unavailable", t0)
    if status == "revoked":
        return _finish(trace, bundle_hash, leaf, "refuse", "revoked", t0)

    # 6. delegation depth and attenuation
    depth = len(ancestors)
    depth_ok = depth <= policy.MAX_DELEGATION_DEPTH
    chain_result = verify_chain(pubkey_der, leaf, PresentedBundle(ancestors))
    attenuated = chain_result is ChainVerification.ATTENUATED
    _step(
        trace,
        "delegation_depth_and_attenuation",
        depth_ok and attenuated,
        {"depth": depth, "max_depth": policy.MAX_DELEGATION_DEPTH, "chain_result": chain_result.value},
    )
    if not attenuated:
        return _finish(trace, bundle_hash, leaf, "refuse", "chain_" + chain_result.value, t0)
    if not depth_ok:
        return _finish(trace, bundle_hash, leaf, "refuse", "delegation_depth_exceeded", t0)

    # 7/8. Gate 1 + Gate 2, for scenario 7 ONLY — triggered by `request.text`,
    # a field scenarios 1-6 never send. Absent `text`, behaviour is byte-for-
    # byte what it was before this change (the `else` branch below): this is
    # a deliberate, additive boundary, not an oversight. Gate 2 checks a
    # signed policy against a presented capability reference the scenario
    # 1-6 badges do not carry, so making this unconditional would turn every
    # existing scenario's "accept" into "no policy reference" on reaching
    # this code path — a regression with no test in this repo to catch it.
    agent_class = leaf.get("agent_class", "")
    if "text" not in request:
        # Keyed on PRESENCE of the field, not its truthiness: a caller that
        # explicitly sends an empty `text` is asking for a classification and
        # must get Gate 1's own fail-closed "escalate" on empty input, not a
        # silent fall-through to the legacy scope check below.
        in_scope = policy.resource_in_scope(trust_domain, agent_class, resource)
        _step(trace, "scope_policy", in_scope, {"resource": resource, "agent_class": agent_class})
        if not in_scope:
            return _finish(trace, bundle_hash, leaf, "refuse", "outside_scope", t0)
        return _finish(trace, bundle_hash, leaf, "accept", "granted", t0)

    g1 = gates.GATE1.classify(request_text)
    _step(
        trace,
        "gate1_classification",
        g1.may_proceed,
        {"action": g1.action, "confidence": g1.confidence, "engine_id": g1.engine_id},
    )
    if not g1.may_proceed:
        # Matches the design contract exactly (see
        # test_an_unavailable_classifier_stops_the_request_without_reaching_gate_2):
        # an escalation is a block pending a human, and Gate 2 is never
        # called. Still audited, alone: a decision that stopped the request
        # is a decision, and the chain should say so.
        rows = gate_audit.append([
            gate_audit.PendingRecord(
                org="harbor-ops",
                agent_vaid_id=leaf.get("vaid_id"),
                verified_agent_class=agent_class,
                tool=tool_call.tool,
                action=tool_call.action,
                resource=tool_call.resource,
                decision=g1.outcome,
                reason=g1.reason,
                policy=None,
                gate="gate1",
                credential_hash=bundle_hash,
                extra=g1.audit_fields(),
            )
        ])
        return _finish(
            trace, bundle_hash, leaf, "refuse", "gate1_" + g1.outcome, t0, gate_rows=rows
        )

    # 8. Gate 2 — does the signed policy this badge names permit this tool call?
    pop_body = json.dumps(
        {"tool": tool_call.tool, "resource": tool_call.resource}, separators=(",", ":")
    ).encode()
    g2 = decide(
        tool_call=tool_call,
        leaf=leaf,
        badge=BadgeVerification(verified=True),
        headers=headers,
        method=gates.POP_METHOD,
        path=gates.POP_PATH,
        body=pop_body,
        mirror=gates.MIRROR,
        policy_keys=gates.POLICY_KEYS,
        nonce_store=gates.NONCE_STORE,
    )
    _step(
        trace,
        "gate2_policy_decision",
        g2.tool_may_run,
        {"outcome": g2.outcome, "refused_at": g2.refused_at, "policy": g2.policy},
    )

    rows = gate_audit.append([
        gate_audit.PendingRecord(
            org="harbor-ops",
            agent_vaid_id=leaf.get("vaid_id"),
            verified_agent_class=agent_class,
            tool=tool_call.tool,
            action=tool_call.action,
            resource=tool_call.resource,
            decision=g1.outcome,
            reason=g1.reason,
            policy=None,
            gate="gate1",
            credential_hash=bundle_hash,
            extra=g1.audit_fields(),
        ),
        gate_audit.PendingRecord(
            org="harbor-ops",
            agent_vaid_id=leaf.get("vaid_id"),
            verified_agent_class=agent_class,
            tool=tool_call.tool,
            action=tool_call.action,
            resource=tool_call.resource,
            decision=g2.outcome,
            reason=g2.reason,
            policy=g2.policy,
            gate="gate2",
            credential_hash=bundle_hash,
        ),
    ])

    if not g2.tool_may_run:
        return _finish(
            trace, bundle_hash, leaf, "refuse", "gate2_" + (g2.refused_at or g2.outcome), t0,
            gate_rows=rows,
        )

    return _finish(trace, bundle_hash, leaf, "accept", "granted", t0, gate_rows=rows)


def _finish(trace, bundle_hash, leaf, decision, reason, t0, *, gate_rows=None) -> dict:
    record = audit.write_record(
        bundle_hash=bundle_hash,
        agent_vaid_id=leaf.get("vaid_id"),
        agent_class=leaf.get("agent_class"),
        decision=decision,
        reason=reason,
        trace=trace,
    )
    body = {
        "decision": decision,
        "reason": reason,
        "agent_vaid_id": leaf.get("vaid_id"),
        "agent_class": leaf.get("agent_class"),
        "trace": trace,
        "latency_ms": int((time.time() - t0) * 1000),
        "audit_record": record,
    }
    if gate_rows:
        # The Gate 1 + Gate 2 chained, signed rows this decision produced —
        # distinct from `audit_record` above, which is Harbor's own
        # unchained record for scenarios 1-6. See gate_audit.py.
        body["gate_audit_records"] = [r.body for r in gate_rows]
    status = 200 if decision == "accept" else 403
    return _response(status, body)


def _response(status: int, body: dict) -> dict:
    # CORS headers are NOT set here. The Function URL's own CORS config
    # (set at deploy time via `create-function-url-config --cors`) already
    # injects them, and AWS evaluates that before this code ever runs — a
    # second, duplicate Access-Control-Allow-Origin from here causes browsers
    # to reject the response outright, even when both values are identical.
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def lambda_handler(event, context):  # noqa: ANN001 - AWS Lambda entrypoint signature
    method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
    path = event.get("rawPath", "/")
    # OPTIONS preflight is handled entirely by the Function URL's own CORS
    # config before invocation reaches here in normal operation; this branch
    # is a harmless fallback, not the active path.
    if method == "OPTIONS":
        return _response(204, {})
    if path.endswith("/pubkey") and method == "GET":
        return _response(200, keystore.org_b_public_key_document())
    if path.endswith("/audit") and method == "GET":
        return _response(200, {"records": audit.list_records()})
    if path.endswith("/gate-audit") and method == "GET":
        # The Gate 1 + Gate 2 chained, signed records (scenario 7), separate
        # from /audit above. A caller (the smoke test, the verify page)
        # reconstructs `AuditRecord(body)` per record and calls
        # `synthera_gate2.verify_chain` against Org B's own published key.
        return _response(200, {"records": gate_audit.list_chain()})
    return handle(event)
