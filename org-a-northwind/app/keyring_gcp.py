"""Org A's signing key: Secret Manager only. The private key is read once per
cold start; it is never logged, never returned by any endpoint, and no route
in main.py exposes it. Only the derived public key is ever served, at
/.well-known/vaid-keys.json.
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.cloud import secretmanager

_PROJECT = os.environ["GCP_PROJECT"]
_SECRET_NAME = os.environ.get("SIGNING_KEY_SECRET", "northwind-vaid-signing-key")
_KEY_ID = os.environ.get("ORG_A_KEY_ID", "northwind-k1")


def _secret_path(version: str = "latest") -> str:
    return f"projects/{_PROJECT}/secrets/{_SECRET_NAME}/versions/{version}"


def load_kernel_key() -> Ed25519PrivateKey:
    client = secretmanager.SecretManagerServiceClient()
    response = client.access_secret_version(name=_secret_path())
    payload = json.loads(response.payload.data.decode("utf-8"))
    raw = base64.b64decode(payload["private_key_b64"])
    return Ed25519PrivateKey.from_private_bytes(raw)


def key_id() -> str:
    return _KEY_ID
