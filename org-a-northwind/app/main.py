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
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from google.cloud import firestore
from pydantic import BaseModel

from vaid_mint.issuer import ReferenceIssuer, RevocationBackend

import keyring_gcp
from actor_tags import public
from agent_registry import FirestoreAgentRegistry
from durable_store import FirestoreLineageStore, FirestoreRevocationCheck

TRUST_DOMAIN = os.environ["TRUST_DOMAIN"]  # the service's own Cloud Run hostname
TENANT_ID = os.environ.get("TENANT_ID", "northwind-platform")
VAID_TTL_HOURS = int(os.environ.get("VAID_TTL_HOURS", "1"))

app = FastAPI(title="Northwind Platform: VAID issuer")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_fs_client = firestore.Client()
_lineage = FirestoreLineageStore(_fs_client)
_revocation = FirestoreRevocationCheck(_fs_client)
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
    return {"org_b_url": os.environ.get("ORG_B_URL", "")}


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
