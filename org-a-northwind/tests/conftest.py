"""Fixtures for Northwind's `/mint` tests.

`main.py` builds its Firestore client, reads its signing key out of Secret
Manager and constructs its issuer at IMPORT time, so the fakes below are
installed before the import, not after — the same shape as
`org-b-harbor/tests/conftest.py`.

Nothing here reaches a network: Firestore and Secret Manager are both faked,
and the signing key is a locally generated Ed25519 key. The ISSUER is real
(`vaid_mint.ReferenceIssuer`), because a test that faked it could not tell a
minted badge apart from a rejection.
"""

from __future__ import annotations

import base64
import importlib
import json
import pathlib
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

SIGNING_KEY = Ed25519PrivateKey.generate()


class _FakeDoc:
    def __init__(self, store: dict, key: str) -> None:
        self._store, self._key = store, key

    def set(self, value):
        self._store[self._key] = value

    def get(self):
        value = self._store.get(self._key)
        return SimpleNamespace(exists=value is not None, to_dict=lambda: value)


class _FakeCollection:
    def __init__(self, store: dict) -> None:
        self._store = store

    def document(self, key=None):
        return _FakeDoc(self._store, key)

    def stream(self):
        return iter([])

    def where(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def limit(self, *a, **k):
        return self


class _FakeFirestore:
    def __init__(self, *a, **k) -> None:
        self._collections: dict[str, dict] = {}

    def collection(self, name):
        return _FakeCollection(self._collections.setdefault(name, {}))


class _FakeSecretClient:
    def access_secret_version(self, name):
        raw = SIGNING_KEY.private_bytes_raw()
        payload = json.dumps({"private_key_b64": base64.b64encode(raw).decode()}).encode()
        return SimpleNamespace(payload=SimpleNamespace(data=payload))


def _load_main(monkeypatch, *, allow_caller_held_key: bool, raw_flag: str | None = None):
    from google.cloud import firestore, secretmanager

    monkeypatch.setattr(firestore, "Client", _FakeFirestore)
    monkeypatch.setattr(secretmanager, "SecretManagerServiceClient", _FakeSecretClient)

    # `main.py` mounts StaticFiles(directory="static") with a path relative
    # to the process cwd — the container runs from app/, so the test must too.
    monkeypatch.chdir(APP_DIR)

    monkeypatch.setenv("TRUST_DOMAIN", "northwind.example")
    monkeypatch.setenv("GCP_PROJECT", "test-project-not-real")
    monkeypatch.setenv("SIGNING_KEY_SECRET", "test-signing-key")
    monkeypatch.setenv("ORG_A_KEY_ID", "test-k1")
    if raw_flag is not None:
        monkeypatch.setenv("ALLOW_CALLER_HELD_KEY", raw_flag)
    elif allow_caller_held_key:
        monkeypatch.setenv("ALLOW_CALLER_HELD_KEY", "true")
    else:
        monkeypatch.delenv("ALLOW_CALLER_HELD_KEY", raising=False)

    for mod in ("main", "keyring_gcp", "durable_store", "actor_tags"):
        sys.modules.pop(mod, None)
    importlib.invalidate_caches()
    return importlib.import_module("main")


@pytest.fixture
def load_main(monkeypatch):
    """The module loader itself, as a fixture rather than something a test
    imports from `conftest` — both services in this repo have a conftest,
    and `import conftest` resolves to whichever one pytest loaded first when
    the two suites run in the same session."""

    def load(*, raw_flag: str | None = None, allow_caller_held_key: bool = False):
        return _load_main(
            monkeypatch,
            allow_caller_held_key=allow_caller_held_key,
            raw_flag=raw_flag,
        )

    return load


@pytest.fixture
def client_flag_off(monkeypatch):
    """A Northwind with ALLOW_CALLER_HELD_KEY unset — the LIVE shape."""
    from fastapi.testclient import TestClient

    return TestClient(_load_main(monkeypatch, allow_caller_held_key=False).app)


@pytest.fixture
def client_flag_on(monkeypatch):
    """A Northwind with ALLOW_CALLER_HELD_KEY=true — the STAGING shape."""
    from fastapi.testclient import TestClient

    return TestClient(_load_main(monkeypatch, allow_caller_held_key=True).app)
