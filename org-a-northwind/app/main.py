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

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from google.cloud import firestore
from pydantic import BaseModel

from vaid_mint.issuer import ReferenceIssuer, RevocationBackend

import keyring_gcp
from actor_tags import public
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

app = FastAPI(title="Northwind Platform — VAID issuer")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_fs_client = firestore.Client()
_lineage = FirestoreLineageStore(_fs_client, collection=VAID_LINEAGE_COLLECTION)
_revocation = FirestoreRevocationCheck(_fs_client, collection=VAID_REVOKED_COLLECTION)
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
    scope_prefix: str = "harbor-ops/"
    capability_set: list[str] = ["deploy"]
    # Scenario 7 only. `issue_vaid_with_lineage` (the default path below)
    # generates its own keypair and DISCARDS the private half — by design,
    # for a demo where nothing afterwards ever proves possession. Proof of
    # possession (scenario 7's Gate 2 PoP check) needs the presenter to hold
    # the badge's private key, so the presenter must generate the keypair
    # itself and hand this service only the public half. Omitted, behaviour
    # is identical to before this field existed.
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
    if req.agent_public_key_b64:
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
    bundle = {"leaf": doc, "ancestors": []}
    _fs_client.collection("vaid_documents").document(doc["vaid_id"]).set(bundle)
    return bundle


@app.post("/delegate")
@public
def delegate(req: DelegateRequest):
    parent_doc = _fs_client.collection("vaid_documents").document(req.parent_vaid).get()
    if not parent_doc.exists:
        raise HTTPException(404, "unknown parent_vaid — mint it on this service first")
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
    bundle = {"leaf": child, "ancestors": ancestors}
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


# Static demo page, served from the same origin as the mint/delegate/revoke
# API so the crossing view's same-origin calls are visibly same-origin, and
# the call to Org B is visibly the only cross-origin one.
app.mount("/", StaticFiles(directory="static", html=True), name="static")
