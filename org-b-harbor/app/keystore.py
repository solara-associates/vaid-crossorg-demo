"""Public-key handling for Org B.

Two keys, kept apart on purpose:

- Org A's public key: fetched over HTTPS from a domain on Org B's own
  allowlist, cached for CACHE_WINDOW_SECONDS. Org B never holds any Org A
  private key, and this cache is the only thing standing between a request
  and a network round trip to Org A's /.well-known/vaid-keys.json.
- Org B's own key: generated once, kept in AWS Secrets Manager (eu-west-2),
  used to sign Org B's audit records. Published here at GET /pubkey so the
  verify page (scenario 5) can check Org B's audit trail using only a public
  key, fetched the same way Org B fetched Org A's.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.request

import boto3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

_region = os.environ.get("AWS_REGION", "eu-west-2")
_secrets = boto3.client("secretsmanager", region_name=_region)

_ORG_A_KEY_CACHE: dict[str, dict] = {}
_ORG_B_KEY_CACHE: dict | None = None


def get_org_a_public_key(trust_domain: str, cache_window_seconds: int) -> tuple[bytes, str, bool]:
    now = time.time()
    cached = _ORG_A_KEY_CACHE.get(trust_domain)
    if cached and (now - cached["fetched_at"]) < cache_window_seconds:
        return cached["der"], cached["key_id"], True

    # 10s, not 5s: CloudWatch evidence from session s499 showed a cold-start
    # Lambda (948ms init) plus a cold-start Cloud Run revision on the other
    # side together pushed this fetch to 5472ms total - just over the old
    # 5000ms ceiling - on the first real request after a double redeploy.
    # The very next request, both sides warm, took 1080ms. 10s stays well
    # inside this Lambda's own 15s function timeout (--timeout 15 in the
    # deploy script), leaving ~5s margin for the rest of handler.py, which
    # the warm-path data above shows normally takes well under 100ms.
    url = f"https://{trust_domain}/.well-known/vaid-keys.json"
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - fixed https scheme, allowlisted domain
        doc = json.loads(resp.read())
    key = doc["keys"][0]
    der = base64.b64decode(key["public_key_b64"])
    key_id = key["key_id"]
    _ORG_A_KEY_CACHE[trust_domain] = {"der": der, "key_id": key_id, "fetched_at": now}
    return der, key_id, False


def _org_b_private_key() -> Ed25519PrivateKey:
    secret_id = os.environ["ORG_B_SIGNING_KEY_SECRET"]
    value = _secrets.get_secret_value(SecretId=secret_id)["SecretString"]
    raw = base64.b64decode(json.loads(value)["private_key_b64"])
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_bytes(data: bytes) -> bytes:
    return _org_b_private_key().sign(data)


def org_b_public_key_document() -> dict:
    global _ORG_B_KEY_CACHE
    if _ORG_B_KEY_CACHE is None:
        pub = _org_b_private_key().public_key()
        der = pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        _ORG_B_KEY_CACHE = {
            "org": "harbor-ops",
            "keys": [
                {
                    "key_id": os.environ.get("ORG_B_KEY_ID", "harbor-ops-k1"),
                    "algorithm": "Ed25519",
                    "public_key_b64": base64.b64encode(der).decode(),
                }
            ],
        }
    return _ORG_B_KEY_CACHE
