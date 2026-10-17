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

import policy
import audit
import keystore
import revocation_client

CACHE_WINDOW_SECONDS = int(os.environ.get("CACHE_WINDOW_SECONDS", "60"))


def _step(trace: list, name: str, ok: bool, detail: dict) -> None:
    trace.append({"step": name, "ok": ok, "detail": detail, "t_ms": int(time.time() * 1000)})


def handle(event: dict) -> dict:
    t0 = time.time()
    trace: list[dict] = []
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"decision": "refuse", "reason": "bad_request", "trace": trace})

    leaf = body.get("leaf")
    ancestors = body.get("ancestors", [])
    request = body.get("request", {})
    resource = request.get("resource", "")

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
        pubkey_der, key_id, cache_hit = keystore.get_org_a_public_key(trust_domain, CACHE_WINDOW_SECONDS)
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
        status, cache_hit_rev = revocation_client.check(trust_domain, lineage_ids, CACHE_WINDOW_SECONDS)
    except Exception as exc:  # noqa: BLE001
        _step(trace, "revocation", False, {"error": str(exc)})
        return _finish(trace, bundle_hash, leaf, "refuse", "revocation_unavailable", t0)
    rev_ok = status == "clean"
    _step(trace, "revocation", rev_ok, {"status": status, "cache_hit": cache_hit_rev, "window_s": CACHE_WINDOW_SECONDS})
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

    # 7. scope against Org B's own policy
    agent_class = leaf.get("agent_class", "")
    in_scope = policy.resource_in_scope(trust_domain, agent_class, resource)
    _step(trace, "scope_policy", in_scope, {"resource": resource, "agent_class": agent_class})
    if not in_scope:
        return _finish(trace, bundle_hash, leaf, "refuse", "outside_scope", t0)

    return _finish(trace, bundle_hash, leaf, "accept", "granted", t0)


def _finish(trace, bundle_hash, leaf, decision, reason, t0) -> dict:
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
    status = 200 if decision == "accept" else 403
    return _response(status, body)


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": os.environ.get("CORS_ORIGIN", "*"),
            "Access-Control-Allow-Headers": "content-type",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        },
        "body": json.dumps(body),
    }


def lambda_handler(event, context):  # noqa: ANN001 - AWS Lambda entrypoint signature
    method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
    path = event.get("rawPath", "/")
    if method == "OPTIONS":
        return _response(204, {})
    if path.endswith("/pubkey") and method == "GET":
        return _response(200, keystore.org_b_public_key_document())
    if path.endswith("/audit") and method == "GET":
        return _response(200, {"records": audit.list_records()})
    return handle(event)
