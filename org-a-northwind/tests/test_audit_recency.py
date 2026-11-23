"""`/audit` must return the newest records, not the oldest (s875).

Before this fix, `order_by("ts").limit(N)` returned the OLDEST N records in
the collection. On a long-lived demo project, those are stale history from a
predecessor deploy signed under a now-defunct key: a presenter who mints a
fresh badge and immediately clicks "Verify bundle" never sees that badge in
the evidence bundle at all, and the ancient records `/audit` hands back can
fail signature verification for reasons that have nothing to do with the
"flip one byte" tamper button — reproduced live against the demo on 2026-11-23
(0 of 50 Northwind records verified, before any tamper).
"""

from __future__ import annotations


def test_mint_then_verify_is_all_green(client_flag_off):
    """The golden path: mint a badge, fetch the evidence bundle exactly as
    the demo page's "Verify bundle" button does, and every record must
    verify — nothing flipped yet."""
    mint = client_flag_off.post(
        "/mint",
        json={
            "agent_class": "infra-agent",
            "scope_prefix": "harbor-ops/deploy/",
            "capability_set": ["deploy"],
        },
    )
    assert mint.status_code == 200

    keys = client_flag_off.get("/.well-known/vaid-keys.json").json()
    audit = client_flag_off.get("/audit").json()
    assert audit["records"], "the badge just minted must show up in /audit"

    result = client_flag_off.post(
        "/verify-bundle",
        json={
            "org_a_pubkey_b64": keys["keys"][0]["public_key_b64"],
            "org_b_pubkey_b64": keys["keys"][0]["public_key_b64"],
            "org_a_records": audit["records"],
            "org_b_records": [],
        },
    )
    results = result.json()["org_a"]
    assert results, "mint must have produced at least one audit record"
    assert all(r["signature_valid"] for r in results)


def test_tamper_is_caught(client_flag_off):
    """The control for the test above: flipping a byte in a real record's
    signature must make verification fail, proving the all-green result
    above is a real check and not a no-op."""
    client_flag_off.post(
        "/mint",
        json={
            "agent_class": "infra-agent",
            "scope_prefix": "harbor-ops/deploy/",
            "capability_set": ["deploy"],
        },
    )
    keys = client_flag_off.get("/.well-known/vaid-keys.json").json()
    records = client_flag_off.get("/audit").json()["records"]

    tampered = dict(records[0])
    sig = tampered["signature_b64"]
    i = len(sig) // 2
    tampered["signature_b64"] = sig[:i] + ("B" if sig[i] == "A" else "A") + sig[i + 1 :]

    result = client_flag_off.post(
        "/verify-bundle",
        json={
            "org_a_pubkey_b64": keys["keys"][0]["public_key_b64"],
            "org_b_pubkey_b64": keys["keys"][0]["public_key_b64"],
            "org_a_records": [tampered] + records[1:],
            "org_b_records": [],
        },
    )
    results = result.json()["org_a"]
    assert results[0]["signature_valid"] is False


def test_audit_returns_the_newest_records_not_the_oldest(client_flag_off):
    """Regression for the exact bug reported live: seed the collection with
    more records than the default `limit`, all older than a freshly minted
    one, and confirm the fresh one is the one `/audit` hands back."""
    for i in range(60):
        client_flag_off.post(
            "/revoke", json={"vaid_id": f"stale-vaid-{i}"}
        )

    mint = client_flag_off.post(
        "/mint",
        json={
            "agent_class": "infra-agent",
            "scope_prefix": "harbor-ops/deploy/",
            "capability_set": ["deploy"],
        },
    )
    fresh_vaid_id = mint.json()["leaf"]["vaid_id"]

    records = client_flag_off.get("/audit?limit=10").json()["records"]
    assert any(r.get("vaid_id") == fresh_vaid_id for r in records), (
        "the record just minted did not appear in the newest 10 — "
        "/audit is still returning stale history"
    )


def test_audit_excludes_records_signed_under_a_different_key(client_flag_off):
    """Regression for the part descending-order alone doesn't fix: a record
    that is genuinely the newest by `ts` but was signed under a predecessor
    deploy's (now unpublished) key must still be excluded — exactly what
    happened live, where `vaid_audit` outlived a prior service generation
    and its 191 leftover records outnumbered the 31 under the current key,
    so even the newest-50 window still pulled in 19 of them."""
    import main

    main._audit_col.document("legacy-but-newest").set(
        {
            "record_id": "legacy-but-newest",
            "ts": 9_999_999_999_999,
            "org": "northwind-platform",
            "action": "mint",
            "vaid_id": "legacy-vaid",
            "parent_vaid": None,
            "signature_b64": "not-a-real-signature",
            "key_id": "northwind-s409-k1",
        }
    )

    client_flag_off.post(
        "/mint",
        json={
            "agent_class": "infra-agent",
            "scope_prefix": "harbor-ops/deploy/",
            "capability_set": ["deploy"],
        },
    )

    records = client_flag_off.get("/audit?limit=50").json()["records"]
    assert all(r.get("key_id") != "northwind-s409-k1" for r in records), (
        "a record signed under a different (unpublished) key leaked into "
        "/audit despite being filtered to the current key_id"
    )
