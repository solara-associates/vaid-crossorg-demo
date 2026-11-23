"""`audit.list_records` must return the newest records, not an arbitrary
DynamoDB Scan slice (s875).

`Scan(Limit=N)` reads the first N items DynamoDB happens to examine in
storage order — not the most recent N, and not even a stable slice as the
table grows. On the live table (hundreds of items, written since Harbor's
most recent reset) this reproduced as a bundle verify showing ts values
spanning 24 days from a single call, instead of "the records from the
run you just did."
"""

from __future__ import annotations


def test_list_records_returns_the_newest_not_an_arbitrary_slice(harbor):
    import audit

    for i in range(60):
        audit.write_record(
            bundle_hash=f"stale-{i}",
            agent_vaid_id=None,
            agent_class=None,
            decision="accept",
            reason="stale",
            trace=[],
        )

    fresh = audit.write_record(
        bundle_hash="fresh-just-written",
        agent_vaid_id=None,
        agent_class=None,
        decision="accept",
        reason="fresh",
        trace=[],
    )

    records = audit.list_records(limit=10)
    assert len(records) == 10
    assert any(r["record_id"] == fresh["record_id"] for r in records), (
        "the record just written did not appear in the newest 10 — "
        "list_records is still returning an arbitrary slice"
    )


def test_list_records_signatures_still_verify(harbor):
    """The control for the test above, mirroring the demo's own check: every
    record `list_records` hands back must still verify against Harbor's
    published public key — proving the fix didn't touch what gets signed."""
    import audit

    for i in range(5):
        audit.write_record(
            bundle_hash=f"record-{i}",
            agent_vaid_id=None,
            agent_class=None,
            decision="accept",
            reason="ok",
            trace=[],
        )

    import base64
    import json

    from cryptography.exceptions import InvalidSignature

    public_key = harbor.receiver_key.public_key()
    for record in audit.list_records():
        body = {k: v for k, v in record.items() if k not in ("signature_b64", "key_id")}
        payload = json.dumps(body, sort_keys=True).encode()
        try:
            public_key.verify(base64.b64decode(record["signature_b64"]), payload)
        except InvalidSignature:
            raise AssertionError(f"record {record['record_id']} failed to verify")
