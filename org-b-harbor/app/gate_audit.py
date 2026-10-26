"""Durable storage for Gate 1 + Gate 2's chained, signed audit (A7.audit-chain).

This is a SEPARATE table from Harbor's existing `audit.py` / `harbor-ops-audit`.
That table records one independent, individually-signed row per scenario-1-6
decision with no sequence number and no `prev_hash` — exactly the shape
`synthera_gate2.audit`'s own module docstring says resists signing but not
selective removal. Gate 2's audit format fixes that, and mixing the two shapes
in one table would make neither a complete chain. `/gate-audit` (below) is the
new, additive read surface; the existing `/audit` endpoint and table are
unchanged.

## Why a single global chain, and what that costs under concurrency

`seq` and `prev_hash` chain EVERY decision this Harbor staging deployment ever
makes, in one total order — not one chain per request. That is what makes
deleting a row detectable: a gap in `seq` or a `prev_hash` that matches
nothing. It is also why appending needs a single current chain head
(`_HEAD_KEY`) read-and-conditionally-advanced per write, via a DynamoDB
transaction: two concurrent requests must not both claim the same `seq`. A
transaction conflict here raises and is retried a bounded number of times;
exhausting the retries raises rather than appending without the lock, because
an audit chain write without the ordering guarantee is not worth having.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

from synthera_gate2 import AuditRecord, build_record

import keystore

_region = os.environ.get("AWS_REGION", "eu-west-2")
_table_name = os.environ.get("GATE_AUDIT_TABLE", "harbor-ops-gate-audit")
_dynamodb = boto3.resource("dynamodb", region_name=_region)

_HEAD_KEY = "chain_head"
_MAX_RETRIES = 5


def _table():
    return _dynamodb.Table(_table_name)


def _to_dynamo(value):
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_dynamo(v) for v in value]
    return value


def _from_dynamo(value):
    if isinstance(value, Decimal):
        f = float(value)
        return int(f) if f.is_integer() else f
    if isinstance(value, dict):
        return {k: _from_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_dynamo(v) for v in value]
    return value


@dataclass
class PendingRecord:
    """Everything `build_record` needs, except `seq` and `previous`, which
    this module assigns from the current chain head so callers never pick a
    sequence number themselves."""

    org: str
    agent_vaid_id: str | None
    verified_agent_class: str | None
    tool: str
    action: str
    resource: str
    decision: str
    reason: str
    policy: dict | None
    gate: str
    credential_hash: str
    extra: dict | None = None


def _read_head() -> tuple[int, AuditRecord | None]:
    resp = _table().get_item(Key={"record_key": _HEAD_KEY})
    item = resp.get("Item")
    if not item:
        return 0, None
    body = _from_dynamo(item["last_record_body"])
    return int(item["last_seq"]), AuditRecord(body)


def append(records: list[PendingRecord]) -> list[AuditRecord]:
    """Append one or more decisions to the chain, atomically, as one batch.

    All records in one call share one transaction: either every one of them
    is appended with its correct `seq`/`prev_hash`, or none is. That matters
    for a Gate 1 + Gate 2 pair specifically — the design note that "the pair
    cannot be separated" only holds if they cannot land half-written either.
    """
    if not records:
        return []

    for attempt in range(_MAX_RETRIES):
        last_seq, previous = _read_head()
        built: list[AuditRecord] = []
        for pending in records:
            seq = last_seq + len(built) + 1
            record = build_record(
                seq=seq,
                previous=previous if not built else built[-1],
                timestamp_ms=int(time.time() * 1000),
                org=pending.org,
                key_id=os.environ.get("ORG_B_KEY_ID", "harbor-ops-k1"),
                credential_hash=pending.credential_hash,
                agent_vaid_id=pending.agent_vaid_id,
                verified_agent_class=pending.verified_agent_class,
                tool=pending.tool,
                action=pending.action,
                resource=pending.resource,
                decision=pending.decision,
                reason=pending.reason,
                policy=pending.policy,
                gate=pending.gate,
                sign=keystore.sign_bytes,
                extra=pending.extra,
            )
            built.append(record)

        transact_items = [
            {
                "Put": {
                    "TableName": _table_name,
                    "Item": {
                        "record_key": f"seq#{record.seq:020d}",
                        "seq": record.seq,
                        "body": _to_dynamo(record.body),
                    },
                    "ConditionExpression": "attribute_not_exists(record_key)",
                }
            }
            for record in built
        ]
        head_item = {
            "record_key": _HEAD_KEY,
            "last_seq": built[-1].seq,
            "last_record_body": _to_dynamo(built[-1].body),
        }
        if previous is None:
            head_condition = "attribute_not_exists(record_key)"
        else:
            head_condition = "last_seq = :expected"
        head_put: dict = {
            "TableName": _table_name,
            "Item": head_item,
            "ConditionExpression": head_condition,
        }
        if previous is not None:
            head_put["ExpressionAttributeValues"] = {":expected": last_seq}
        transact_items.append({"Put": head_put})

        try:
            _dynamodb.meta.client.transact_write_items(TransactItems=transact_items)
            return built
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                continue  # another writer advanced the chain first; retry
            raise

    raise RuntimeError(
        f"could not append to the audit chain after {_MAX_RETRIES} attempts: "
        "lost every race for the chain head. A write that cannot establish "
        "its position in the chain must not be appended without one."
    )


def list_chain(limit: int = 200) -> list[dict]:
    """All chained records in order, as plain dicts, for `/gate-audit` and for
    a verifier to reconstruct `AuditRecord` objects and call `verify_chain`."""
    resp = _table().scan(Limit=limit + 1)
    items = [i for i in resp.get("Items", []) if i["record_key"] != _HEAD_KEY]
    items.sort(key=lambda i: int(i["seq"]))
    return [_from_dynamo(i["body"]) for i in items][:limit]
