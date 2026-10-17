"""Org B's signed audit trail. One DynamoDB table, eu-west-2, on-demand billing
(no idle cost). Every decision — accept or refuse — gets one record, signed
with Org B's own key so the evidence bundle (scenario 5) can be checked later
using only Org B's published public key.
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from decimal import Decimal

import boto3

import keystore

_region = os.environ.get("AWS_REGION", "eu-west-2")
_table_name = os.environ.get("AUDIT_TABLE", "harbor-ops-audit")
_dynamodb = boto3.resource("dynamodb", region_name=_region)


def _table():
    return _dynamodb.Table(_table_name)


def write_record(*, bundle_hash: str, agent_vaid_id: str | None, agent_class: str | None,
                  decision: str, reason: str, trace: list[dict]) -> dict:
    record = {
        "record_id": str(uuid.uuid4()),
        "ts": int(time.time() * 1000),
        "org": "harbor-ops",
        "credential_hash": bundle_hash,
        "agent_vaid_id": agent_vaid_id,
        "agent_class": agent_class,
        "decision": decision,
        "reason": reason,
        "trace": trace,
    }
    signing_bytes = json.dumps(record, sort_keys=True).encode()
    signature = keystore.sign_bytes(signing_bytes)
    record["signature_b64"] = base64.b64encode(signature).decode()
    record["key_id"] = os.environ.get("ORG_B_KEY_ID", "harbor-ops-k1")

    try:
        _table().put_item(Item=record)
    except Exception:  # noqa: BLE001 - audit write failure must not block the demo response
        record["audit_write_failed"] = True
    return record


def _undecimal(value):
    """DynamoDB returns every number as Decimal. Every number this table ever
    stores is really an int (timestamps, depths, counts), so this is a safe,
    lossless narrowing — and a necessary one: a Decimal neither serializes to
    JSON by default nor reproduces the exact bytes the original int signed."""
    if isinstance(value, Decimal):
        return int(value)
    if isinstance(value, dict):
        return {k: _undecimal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_undecimal(v) for v in value]
    return value


def list_records(limit: int = 50) -> list[dict]:
    resp = _table().scan(Limit=limit)
    items = sorted(resp.get("Items", []), key=lambda r: r["ts"])
    return [_undecimal(item) for item in items]
