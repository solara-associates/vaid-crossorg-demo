"""Fixtures for Harbor's handler tests.

Imports of `app/*.py` and of `synthera_gate1` / `synthera_gate2` /
`synthera_policy` happen INSIDE fixtures, after env vars are set and boto3 is
faked, because `gates.py` builds Gate 1 and Gate 2 at import time (by design
— see its module docstring) and would otherwise either make a real AWS call
or refuse to import for want of configuration.

No network: `GATE1_ENGINE=rule-based` is set here, so these tests never call
Bedrock. `test_bedrock_gate1.py` exercises the Bedrock adapter in isolation
with a faked `boto3` client instead.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import pathlib
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

# The committed, compiled demo policy. Reused rather than re-compiled here so
# these tests check the same program the deploy script verifies the digest
# of, the same way `synthera-gate2`'s own test suite does.
_CONFORMANCE_HEX = pathlib.Path(
    os.environ.get(
        "GATE2_CONFORMANCE_DIR",
        str(pathlib.Path(__file__).resolve().parents[3] / "synthera" / "conformance" / "gate2"),
    )
) / "northwind-infra-agent-3.1.0.bytecode.hex"

TENANT = "northwind-platform"
POLICY_NAME = "northwind-infra-agent"
SEMVER = "3.1.0"
POLICY_KEY_REF = "northwind-s409-test-k1"


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


class _FakeTable:
    def __init__(self, store: dict) -> None:
        self._store = store

    def get_item(self, Key):
        item = self._store.get(Key["record_key"])
        return {"Item": item} if item is not None else {}

    def put_item(self, Item):
        key = Item.get("record_key") or Item["record_id"]
        self._store[key] = Item

    def scan(self, Limit=None):
        return {"Items": list(self._store.values())}


class _FakeDynamoClient:
    def __init__(self, tables: dict) -> None:
        self._tables = tables

    def transact_write_items(self, TransactItems):
        from botocore.exceptions import ClientError

        for entry in TransactItems:
            put = entry["Put"]
            store = self._tables.setdefault(put["TableName"], {})
            key = put["Item"]["record_key"]
            cond = put.get("ConditionExpression")
            if cond == "attribute_not_exists(record_key)" and key in store:
                raise ClientError(
                    {"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems"
                )
            if cond == "last_seq = :expected":
                expected = put["ExpressionAttributeValues"][":expected"]
                if store.get(key, {}).get("last_seq") != expected:
                    raise ClientError(
                        {"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems"
                    )
        for entry in TransactItems:
            put = entry["Put"]
            self._tables[put["TableName"]][put["Item"]["record_key"]] = put["Item"]


class _FakeDynamoResource:
    def __init__(self) -> None:
        self.tables: dict = {}
        self.meta = SimpleNamespace(client=_FakeDynamoClient(self.tables))

    def Table(self, name):
        return _FakeTable(self.tables.setdefault(name, {}))


@pytest.fixture
def receiver_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def agent_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def policy_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def issuer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def bundle_path(tmp_path, policy_key: Ed25519PrivateKey) -> pathlib.Path:
    if not _CONFORMANCE_HEX.is_file():
        pytest.skip(f"conformance bytecode fixture not found: {_CONFORMANCE_HEX}")
    from synthera_policy import bytecode_digest, signing_payload

    bytecode = bytes.fromhex(_CONFORMANCE_HEX.read_text().strip())
    digest = bytecode_digest(bytecode)
    payload = signing_payload(bytecode_sha256=digest, semver=SEMVER, tenant_id=TENANT, name=POLICY_NAME)
    bundle = {
        "tenant_id": TENANT,
        "name": POLICY_NAME,
        "semver": SEMVER,
        "source": "# test fixture: see python/synthera-gate2/conformance/gate2 in synthera",
        "source_dsl": {"other": "statute-policy/v1"},
        "compiled_bytecode": list(bytecode),
        "bytecode_sha256": digest,
        "compiler_version": "synthera-policyc 0.1.0",
        "signing_key_ref": POLICY_KEY_REF,
        "signature_scheme": "ed25519",
        "signature": list(policy_key.sign(payload)),
    }
    path = tmp_path / "gate2_bundle.json"
    path.write_text(json.dumps(bundle))
    return path, digest


@pytest.fixture
def harbor(monkeypatch, bundle_path, policy_key, receiver_key, issuer_key):
    """Import `handler` with Gate 1 (rule-based) and Gate 2 fully wired, and
    boto3 faked so nothing here touches a real AWS account."""
    bundle_file, bytecode_sha256 = bundle_path

    monkeypatch.setenv("GATE1_ENGINE", "rule-based")
    monkeypatch.setenv("GATE1_REGION", "eu-west-2")
    monkeypatch.setenv("GATE2_POLICY_TENANT_ID", TENANT)
    monkeypatch.setenv("GATE2_POLICY_KEY_REF", POLICY_KEY_REF)
    monkeypatch.setenv(
        "GATE2_POLICY_PUBLIC_KEY_B64",
        base64.b64encode(_raw_public(policy_key)).decode(),
    )
    monkeypatch.setenv("GATE2_BUNDLE_PATH", str(bundle_file))
    monkeypatch.setenv("TRUST_DOMAIN_ALLOWLIST", "northwind.example")
    monkeypatch.setenv("GRANTED_TRUST_DOMAIN", "northwind.example")
    monkeypatch.setenv("GRANTED_RESOURCE_PREFIXES", "harbor-ops/deploy/")
    monkeypatch.setenv("MAX_DELEGATION_DEPTH", "1")

    fake_resource = _FakeDynamoResource()
    import boto3

    monkeypatch.setattr(boto3, "resource", lambda *a, **k: fake_resource)
    monkeypatch.setattr(boto3, "client", lambda *a, **k: SimpleNamespace())

    for mod_name in (
        "gates", "gate_audit", "audit", "keystore", "policy", "handler",
        "bedrock_gate1", "rule_based_gate1",
    ):
        sys.modules.pop(mod_name, None)

    importlib.invalidate_caches()
    keystore_mod = importlib.import_module("keystore")
    monkeypatch.setattr(keystore_mod, "sign_bytes", receiver_key.sign)
    monkeypatch.setattr(
        keystore_mod,
        "get_org_a_public_key",
        lambda trust_domain, window: (_raw_public(issuer_key), "test-issuer-k1", False),
    )

    revocation_client_mod = importlib.import_module("revocation_client")
    monkeypatch.setattr(revocation_client_mod, "check", lambda *a, **k: ("clean", False))

    handler_mod = importlib.import_module("handler")
    return SimpleNamespace(
        handler=handler_mod,
        receiver_key=receiver_key,
        issuer_key=issuer_key,
        bytecode_sha256=bytecode_sha256,
    )


@pytest.fixture
def make_leaf(issuer_key):
    """A real, validly-signed VAID leaf, minted with a caller-held key so the
    caller can present real proof of possession — `issue_vaid_with_key`, the
    same path `main.py`'s `/mint` now takes when `agent_public_key_b64` is
    given (see org-a-northwind/app/main.py)."""
    from vaid_mint.issuer import ReferenceIssuer

    def build(*, agent_key: Ed25519PrivateKey, capability_set: list[str], resource_prefix: str = "harbor-ops/deploy/"):
        issuer = ReferenceIssuer(issuer_key, 1, "northwind.example")
        return issuer.issue_vaid_with_key(
            agent_class="infra-deployer",
            version="1",
            tenant_id=TENANT,
            parent_vaid=None,
            scope_boundary=[{"kind": "prefix", "value": resource_prefix}],
            capability_set=capability_set,
            public_key_der=_raw_public(agent_key),
        )

    return build
