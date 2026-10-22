"""`/mint`'s caller-held badge key is behind ALLOW_CALLER_HELD_KEY.

Both states are tested, and the OFF state is tested as a negative control
(A8.fail-closed-negative): a flag that is never observed refusing anything is
indistinguishable from a flag that is not read at all.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _caller_public_key() -> tuple[bytes, str]:
    """A keypair the CALLER generates and keeps. Returns the raw public half
    and its base64 encoding — the wire form `/mint` takes."""
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return raw, base64.b64encode(raw).decode()


def _caller_public_key_b64() -> str:
    return _caller_public_key()[1]


BASE_REQUEST = {
    "agent_class": "infra-deployer",
    "scope_prefix": "harbor-ops/deploy/",
    "capability_set": ["deploy"],
}


# ── flag OFF: the live shape ────────────────────────────────────────────────

def test_flag_off_refuses_a_caller_held_key(client_flag_off):
    response = client_flag_off.post(
        "/mint", json={**BASE_REQUEST, "agent_public_key_b64": _caller_public_key_b64()}
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "ALLOW_CALLER_HELD_KEY" in detail
    assert "agent_public_key_b64" in detail


def test_flag_off_refuses_an_empty_string_too(client_flag_off):
    """Presence, not truthiness. An empty string is still a request for the
    caller-held path and must be refused, not silently served from the
    default path as though the field had been omitted."""
    response = client_flag_off.post("/mint", json={**BASE_REQUEST, "agent_public_key_b64": ""})
    assert response.status_code == 400
    assert "ALLOW_CALLER_HELD_KEY" in response.json()["detail"]


def test_flag_off_refuses_an_explicit_null_is_not_a_refusal(client_flag_off):
    """`null` is the field's own default — indistinguishable from omitting it,
    and so NOT a request for the caller-held path."""
    response = client_flag_off.post("/mint", json={**BASE_REQUEST, "agent_public_key_b64": None})
    assert response.status_code == 200


def test_flag_off_still_mints_normally(client_flag_off):
    response = client_flag_off.post("/mint", json=BASE_REQUEST)
    assert response.status_code == 200
    assert response.json()["leaf"]["vaid_id"]


# ── flag ON: the staging shape ──────────────────────────────────────────────

def test_flag_on_accepts_a_caller_held_key(client_flag_on):
    raw, public_key_b64 = _caller_public_key()
    response = client_flag_on.post(
        "/mint", json={**BASE_REQUEST, "agent_public_key_b64": public_key_b64}
    )
    assert response.status_code == 200
    leaf = response.json()["leaf"]
    assert leaf["vaid_id"]
    # The badge must carry the CALLER's key, not one this service generated.
    # That is the whole point of the flag, and the only thing that makes
    # Gate 2's proof-of-possession check reachable at all.
    assert leaf["public_key_der"] == list(raw)


def test_flag_on_without_the_field_does_not_carry_the_caller_key(client_flag_on):
    """The control for the test above: with the flag on but the field
    omitted, the badge carries a key this service generated and discarded,
    so a caller-held key in the badge can only have come from the field."""
    raw, _ = _caller_public_key()
    response = client_flag_on.post("/mint", json=BASE_REQUEST)
    assert response.status_code == 200
    assert response.json()["leaf"].get("public_key_der") != list(raw)


def test_flag_on_still_mints_without_the_field(client_flag_on):
    response = client_flag_on.post("/mint", json=BASE_REQUEST)
    assert response.status_code == 200


def test_flag_on_rejects_an_empty_string(client_flag_on):
    response = client_flag_on.post("/mint", json={**BASE_REQUEST, "agent_public_key_b64": ""})
    assert response.status_code == 400
    assert "empty" in response.json()["detail"]


def test_flag_on_rejects_non_base64(client_flag_on):
    response = client_flag_on.post(
        "/mint", json={**BASE_REQUEST, "agent_public_key_b64": "not base64 !!!"}
    )
    assert response.status_code == 400
    assert "base64" in response.json()["detail"]


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "  ", "maybe"])
def test_only_an_affirmative_value_enables_the_flag(load_main, value):
    """A deployment that sets the variable to something falsy has NOT opted
    in. A deploy script writing `ALLOW_CALLER_HELD_KEY=false` and getting the
    enabled behaviour would be the worst possible reading of this flag."""
    assert load_main(raw_flag=value).ALLOW_CALLER_HELD_KEY is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " true "])
def test_affirmative_spellings_all_enable_the_flag(load_main, value):
    assert load_main(raw_flag=value).ALLOW_CALLER_HELD_KEY is True
