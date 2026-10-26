"""Northwind Platform (Org A) — Cloud Run, min-instances=0 (region is in
regions.yaml, not here).

Mints VAID credentials for its own agents with vaid-mint 0.11 (Python),
publishes its public key for anyone to fetch over HTTPS, and exposes a
revocation status feed Org B polls and caches. Holds the only copy of its
signing private key, in Secret Manager; nothing here ever returns it.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from google.cloud import firestore
from pydantic import BaseModel

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vaid_mint.issuer import ReferenceIssuer, RevocationBackend
from vaid_pop import RequestSigner
from synthera_gate2 import build_capability

import keyring_gcp
from actor_tags import public
from agent_registry import FirestoreAgentRegistry
from durable_store import FirestoreLineageStore, FirestoreRevocationCheck

TRUST_DOMAIN = os.environ["TRUST_DOMAIN"]  # the service's own Cloud Run hostname
TENANT_ID = os.environ.get("TENANT_ID", "northwind-platform")
VAID_TTL_HOURS = int(os.environ.get("VAID_TTL_HOURS", "1"))

# Firestore's (default) database is per PROJECT, not per deployment. A staging
# copy of this service in the same project as live would otherwise read and
# write the SAME lineage and revocation collections as live — see
# s396-deploy-scenario7-staging.sh for the incident that motivates this.
# Defaulted to the names this service has always used, so a deployment that
# does not set these (including the live one, today) is unchanged.
VAID_LINEAGE_COLLECTION = os.environ.get("VAID_LINEAGE_COLLECTION", "vaid_lineage")
VAID_REVOKED_COLLECTION = os.environ.get("VAID_REVOKED_COLLECTION", "vaid_revoked")

# Scenario 7's caller-held badge key (`/mint`'s `agent_public_key_b64`), off
# unless a deployment opts in. A caller-held key is strictly MORE capability
# than the default path gives out: the default `issue_vaid_with_lineage`
# generates the keypair here and destroys the private half, so no badge it
# issues can ever be used to prove possession. Accepting a caller's public key
# hands back a badge whose private half a third party holds and keeps.
#
# That is exactly what Gate 2's proof-of-possession check needs, and exactly
# what the live demo must not offer: live mints badges for a browser page with
# no operator authentication in front of it (see actor_tags.py), so an opt-in
# flag, default off, is the difference between "a staging service that can run
# scenario 7" and "a public endpoint that mints usable held credentials to
# anyone". The staging deploy script sets it; no live deploy does.
ALLOW_CALLER_HELD_KEY = os.environ.get("ALLOW_CALLER_HELD_KEY", "").strip().lower() in {
    "1", "true", "yes", "on",
}

# Scenario 7 only. The capability reference embedded in a scenario-7 badge
# names the exact signed policy bundle Harbor's Gate 2 will check it against
# (tenant, policy name, semver, and the compiled bytecode's own digest) — it
# is not a secret, the deploy script prints it and bakes the same four values
# into Harbor. Unset on every deployment that does not run scenario 7
# (including live), so /scenario7/run refuses rather than minting a
# capability reference that names a policy Harbor was never given.
GATE2_POLICY_TENANT_ID = os.environ.get("GATE2_POLICY_TENANT_ID", "")
GATE2_POLICY_NAME = os.environ.get("GATE2_POLICY_NAME", "")
GATE2_POLICY_SEMVER = os.environ.get("GATE2_POLICY_SEMVER", "")
GATE2_POLICY_BYTECODE_SHA256 = os.environ.get("GATE2_POLICY_BYTECODE_SHA256", "")
ORG_B_URL = os.environ.get("ORG_B_URL", "")

app = FastAPI(title="Northwind Platform — VAID issuer")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_fs_client = firestore.Client()
_lineage = FirestoreLineageStore(_fs_client, collection=VAID_LINEAGE_COLLECTION)
_revocation = FirestoreRevocationCheck(_fs_client, collection=VAID_REVOKED_COLLECTION)
_agents = FirestoreAgentRegistry(_fs_client)
_audit_col = _fs_client.collection("vaid_audit")

_kernel_key = keyring_gcp.load_kernel_key()
_issuer = ReferenceIssuer(_kernel_key, VAID_TTL_HOURS, TRUST_DOMAIN).with_revocation_backend(
    RevocationBackend(check=_revocation, lineage=_lineage)
)


def _sign_audit(record: dict) -> dict:
    payload = json.dumps(record, sort_keys=True).encode()
    signature = _kernel_key.sign(payload)
    record = dict(record)
    record["signature_b64"] = base64.b64encode(signature).decode()
    record["key_id"] = keyring_gcp.key_id()
    _audit_col.document(record["record_id"]).set(record)
    return record


class MintRequest(BaseModel):
    agent_class: str = "infra-agent"
    scope_prefix: str = "harbor-ops/deploy/"
    capability_set: list[str] = ["deploy"]
    # Scenario 7 only. `issue_vaid_with_lineage` (the default path below)
    # generates its own keypair and DISCARDS the private half — by design,
    # for a demo where nothing afterwards ever proves possession. Proof of
    # possession (scenario 7's Gate 2 PoP check) needs the presenter to hold
    # the badge's private key, so the presenter must generate the keypair
    # itself and hand this service only the public half. Omitted, behaviour
    # is identical to before this field existed. Sending it at all is refused
    # unless the deployment sets ALLOW_CALLER_HELD_KEY — see that constant.
    agent_public_key_b64: str | None = None


class DelegateRequest(BaseModel):
    parent_vaid: str
    agent_class: str = "infra-agent-sub"
    scope_prefix: str
    capability_set: list[str] = ["deploy"]


class RevokeRequest(BaseModel):
    vaid_id: str


@app.get("/.well-known/vaid-keys.json")
@public
def well_known_keys():
    pub = _kernel_key.public_key().public_bytes_raw()
    return {
        "org": "northwind-platform",
        "trust_domain": TRUST_DOMAIN,
        "keys": [
            {
                "key_id": keyring_gcp.key_id(),
                "algorithm": "Ed25519",
                "public_key_b64": base64.b64encode(pub).decode(),
            }
        ],
    }


@app.get("/vaid-revocations/status")
@public
def revocation_status():
    return {"revoked_vaid_ids": _revocation.all_revoked_ids()}


@app.post("/mint")
@public
def mint(req: MintRequest):
    # Keyed on PRESENCE, not truthiness: a caller that sends
    # `"agent_public_key_b64": ""` against a deployment with the flag off is
    # asking for the caller-held-key path and must be told it is disabled,
    # not silently given a badge whose private half this service destroyed.
    if req.agent_public_key_b64 is not None:
        if not ALLOW_CALLER_HELD_KEY:
            raise HTTPException(
                400,
                "agent_public_key_b64 is not accepted by this deployment. "
                "Caller-held badge keys are disabled (ALLOW_CALLER_HELD_KEY is "
                "not set). Re-send the request without that field to get a "
                "badge whose private key this service generates and discards.",
            )
        if not req.agent_public_key_b64.strip():
            raise HTTPException(400, "agent_public_key_b64 was sent but is empty")
        try:
            public_key_der = base64.b64decode(req.agent_public_key_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HTTPException(400, "agent_public_key_b64 is not valid base64") from exc
        doc = _issuer.issue_vaid_with_key(
            agent_class=req.agent_class,
            version="1",
            tenant_id=TENANT_ID,
            parent_vaid=None,
            scope_boundary=[{"kind": "prefix", "value": req.scope_prefix}],
            capability_set=req.capability_set,
            public_key_der=public_key_der,
        )
    else:
        doc = _issuer.issue_vaid_with_lineage(
            agent_class=req.agent_class,
            version="1",
            tenant_id=TENANT_ID,
            parent_vaid=None,
            scope_boundary=[{"kind": "prefix", "value": req.scope_prefix}],
            capability_set=req.capability_set,
        )
    _sign_audit({
        "record_id": str(uuid.uuid4()),
        "ts": int(time.time() * 1000),
        "org": "northwind-platform",
        "action": "mint",
        "vaid_id": doc["vaid_id"],
        "parent_vaid": None,
    })
    agent_id = _agents.get_or_create(req.agent_class)
    bundle = {"leaf": doc, "ancestors": [], "agent": {"agent_class": req.agent_class, "agent_id": agent_id}}
    _fs_client.collection("vaid_documents").document(doc["vaid_id"]).set(bundle)
    return bundle


@app.post("/delegate")
@public
def delegate(req: DelegateRequest):
    parent_doc = _fs_client.collection("vaid_documents").document(req.parent_vaid).get()
    if not parent_doc.exists:
        raise HTTPException(404, "unknown parent_vaid. mint it on this service first")
    parent = parent_doc.to_dict()

    child = _issuer.issue_vaid_with_lineage(
        agent_class=req.agent_class,
        version="1",
        tenant_id=TENANT_ID,
        parent_vaid=req.parent_vaid,
        scope_boundary=[{"kind": "prefix", "value": req.scope_prefix}],
        capability_set=req.capability_set,
        not_after=parent["leaf"]["expires_at"],
    )
    _sign_audit({
        "record_id": str(uuid.uuid4()),
        "ts": int(time.time() * 1000),
        "org": "northwind-platform",
        "action": "delegate",
        "vaid_id": child["vaid_id"],
        "parent_vaid": req.parent_vaid,
    })
    ancestors = parent["ancestors"] + [parent["leaf"]]
    agent_id = _agents.get_or_create(req.agent_class)
    bundle = {"leaf": child, "ancestors": ancestors, "agent": {"agent_class": req.agent_class, "agent_id": agent_id}}
    _fs_client.collection("vaid_documents").document(child["vaid_id"]).set(bundle)
    return bundle


@app.post("/revoke")
@public
def revoke(req: RevokeRequest):
    _revocation.revoke(req.vaid_id)
    _sign_audit({
        "record_id": str(uuid.uuid4()),
        "ts": int(time.time() * 1000),
        "org": "northwind-platform",
        "action": "revoke",
        "vaid_id": req.vaid_id,
        "parent_vaid": None,
    })
    return {"ok": True, "revoked_vaid_id": req.vaid_id}


@app.get("/audit")
@public
def audit(limit: int = 50):
    docs = _audit_col.order_by("ts").limit(limit).stream()
    return {"records": [d.to_dict() for d in docs]}


class Scenario7Crossing(BaseModel):
    text: str
    resource: str
    tool: str = "deploy"
    action: str = "deploy"


class Scenario7Request(BaseModel):
    crossings: list[Scenario7Crossing]


def _scenario7_configured() -> bool:
    return bool(
        ALLOW_CALLER_HELD_KEY
        and GATE2_POLICY_TENANT_ID
        and GATE2_POLICY_NAME
        and GATE2_POLICY_SEMVER
        and GATE2_POLICY_BYTECODE_SHA256
        and ORG_B_URL
    )


def _cross_to_harbor(leaf: dict, ancestors: list, request: dict, pop_headers: dict) -> dict:
    """POST one crossing to Harbor, over plain HTTPS, the same way the
    browser does for scenarios 1-6 — the only difference here is who holds
    the pen: this process generated the keypair and signs with it below,
    rather than the browser, because the proof-of-possession signer
    (`vaid_pop.RequestSigner`) is a byte-identity-locked package already
    conformance-tested against Rust; re-deriving its RFC 8785 canonicalisation
    independently in JavaScript for one demo screen is exactly the kind of
    second definition that package's own docstring warns drifts from the
    first. The agent's private key lives only in this request's memory and is
    discarded when it returns — never written to Firestore, a log, or sent
    back to the browser."""
    payload = json.dumps({"leaf": leaf, "ancestors": ancestors, "request": request}).encode()
    req = urllib.request.Request(
        ORG_B_URL,
        data=payload,
        headers={"Content-Type": "application/json", **pop_headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())
    except (urllib.error.URLError, TimeoutError) as exc:
        # Harbor itself (the Lambda, or the network to it) did not answer —
        # distinct from "gate1_escalate", which is Gate 1's OWN decision
        # server not answering INSIDE a Harbor that did respond. Both are
        # fail-closed from this agent's point of view: neither produces a
        # tool call.
        return {
            "decision": "refuse",
            "reason": "harbor_unreachable",
            "trace": [],
            "latency_ms": None,
            "error": str(exc),
        }


@app.post("/scenario7/run")
@public
def scenario7_run(req: Scenario7Request):
    """Mint one caller-held badge and run one or more crossings against it,
    each through Gate 1 (classification, grants nothing) and Gate 2 (the
    signed-policy decision) at Harbor. One endpoint, not the usual
    mint-then-cross pair, because the private key proving possession of the
    badge must never leave this process — see `_cross_to_harbor`."""
    if not _scenario7_configured():
        raise HTTPException(
            400,
            "scenario 7 is not configured on this deployment (needs "
            "ALLOW_CALLER_HELD_KEY, GATE2_POLICY_TENANT_ID/NAME/SEMVER/"
            "BYTECODE_SHA256, and ORG_B_URL). Live deploys do not set these.",
        )
    if not req.crossings:
        raise HTTPException(400, "crossings must be a non-empty list")

    agent_key = Ed25519PrivateKey.generate()
    agent_pub_der = agent_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    capability = build_capability(
        tenant_id=GATE2_POLICY_TENANT_ID,
        name=GATE2_POLICY_NAME,
        semver=GATE2_POLICY_SEMVER,
        bytecode_sha256=GATE2_POLICY_BYTECODE_SHA256,
    )
    doc = _issuer.issue_vaid_with_key(
        agent_class="infra-deployer",
        version="1",
        tenant_id=TENANT_ID,
        parent_vaid=None,
        scope_boundary=[{"kind": "prefix", "value": "harbor-ops/deploy/"}],
        capability_set=["deploy", capability],
        public_key_der=agent_pub_der,
    )
    _sign_audit({
        "record_id": str(uuid.uuid4()),
        "ts": int(time.time() * 1000),
        "org": "northwind-platform",
        "action": "mint",
        "vaid_id": doc["vaid_id"],
        "parent_vaid": None,
    })
    agent_id = _agents.get_or_create("infra-deployer")
    bundle = {"leaf": doc, "ancestors": [], "agent": {"agent_class": "infra-deployer", "agent_id": agent_id}}
    _fs_client.collection("vaid_documents").document(doc["vaid_id"]).set(bundle)

    results = []
    for crossing in req.crossings:
        pop_body = json.dumps(
            {"tool": crossing.tool, "resource": crossing.resource}, separators=(",", ":")
        ).encode()
        pop_headers = RequestSigner(vaid=doc, private_key=agent_key).sign_headers(
            "POST", "/mcp/call", pop_body
        )
        decision = _cross_to_harbor(
            doc,
            [],
            {
                "text": crossing.text,
                "tool": crossing.tool,
                "action": crossing.action,
                "resource": crossing.resource,
            },
            pop_headers,
        )
        results.append({"request": crossing.model_dump(), "decision": decision})

    return {"bundle": bundle, "crossings": results}


@app.get("/health")
@public
def health():
    # Not "/healthz": *.run.app intercepts that exact literal path before it
    # reaches the container (verified empirically — every other path,
    # including "/health" and "/healthcheck", reaches FastAPI normally).
    return {"ok": True}


@app.get("/config.json")
@public
def config():
    """Non-secret runtime config the demo page needs: where Org B lives.
    Nothing here is sensitive — it is the same information a public DNS
    lookup would give a stranger."""
    return {"org_b_url": os.environ.get("ORG_B_URL", ""), "scenario7_enabled": _scenario7_configured()}


class VerifyBundleRequest(BaseModel):
    org_a_pubkey_b64: str
    org_b_pubkey_b64: str
    org_a_records: list[dict]
    org_b_records: list[dict]


@app.post("/verify-bundle")
@public
def verify_bundle(req: VerifyBundleRequest):
    """Checks a tamper-and-verify evidence bundle using only the two public
    keys the caller supplies (normally fetched fresh from each org's own
    published endpoint). No private key is read or needed here."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    def check(records: list[dict], pubkey_b64: str) -> list[dict]:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
        results = []
        for record in records:
            sig_b64 = record.get("signature_b64")
            body = {k: v for k, v in record.items() if k not in ("signature_b64", "key_id")}
            payload = json.dumps(body, sort_keys=True).encode()
            ok = False
            if sig_b64:
                try:
                    pub.verify(base64.b64decode(sig_b64), payload)
                    ok = True
                except (InvalidSignature, ValueError):
                    ok = False
            results.append({"record_id": record.get("record_id"), "signature_valid": ok})
        return results

    return {
        "org_a": check(req.org_a_records, req.org_a_pubkey_b64),
        "org_b": check(req.org_b_records, req.org_b_pubkey_b64),
    }


# Build marker so a presenter can tell which build is loaded, rather than
# trusting that a normal (non-hard) reload fetched the current one (s367 —
# Allan's browser served a stale cached index.html on demo day).
BUILD_SHA = os.environ.get("BUILD_SHA", "unknown")
_INDEX_HTML = (
    (Path(__file__).parent / "static" / "index.html")
    .read_text()
    .replace("__BUILD_SHA__", BUILD_SHA)
)

_NO_STORE_HEADERS = {"Cache-Control": "no-store"}


@app.get("/", response_class=HTMLResponse)
@public
def index():
    return HTMLResponse(content=_INDEX_HTML, headers=_NO_STORE_HEADERS)


class NoStoreStaticFiles(StaticFiles):
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-store"
        return response


# Static demo page, served from the same origin as the mint/delegate/revoke
# API so the crossing view's same-origin calls are visibly same-origin, and
# the call to Org B is visibly the only cross-origin one. index.html itself
# is served by the explicit route above (for the build-marker substitution);
# this mount covers any other static assets, also with Cache-Control: no-store.
app.mount("/", NoStoreStaticFiles(directory="static", html=True), name="static")
