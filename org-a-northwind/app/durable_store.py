"""Durable lineage + revocation stores for Org A, backed by Firestore.

Why this exists: Org A's Cloud Run service runs with min-instances=0 (required
by the brief, and the only way idle cost is actually zero). vaid_mint's
in-memory stores are empty after every cold start. Per the documented R.4.6
failure mode, persisting the revoked set but NOT the lineage resolver means
every delegated (child) credential starts reading UNAVAILABLE after a
restart while root credentials keep verifying — total for delegation,
invisible for roots, and easy to misdiagnose as a signing or clock bug.
Both halves are made durable together here, via Firestore, in the same
region family as the rest of Org A.

These two classes implement vaid_mint's own protocols (LineageStore,
RevocationCheck) — this is not a new revocation mechanism, it is the durable
backend the spec explicitly anticipates a self-hoster will plug in.
"""

from __future__ import annotations

from google.cloud import firestore

from vaid_mint.revocation import ParentResolution, RevocationStatus


class FirestoreLineageStore:
    def __init__(self, client: firestore.Client, collection: str = "vaid_lineage") -> None:
        self._col = client.collection(collection)

    def record(self, vaid_id: str, parent: str | None) -> None:
        self._col.document(vaid_id).set({"parent": parent})

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        doc = self._col.document(vaid_id).get()
        if not doc.exists:
            return ParentResolution.unknown()
        parent = doc.to_dict().get("parent")
        return ParentResolution.root() if parent is None else ParentResolution.of_parent(parent)


class FirestoreRevocationCheck:
    def __init__(self, client: firestore.Client, collection: str = "vaid_revoked") -> None:
        self._col = client.collection(collection)

    def revoke(self, vaid_id: str) -> None:
        self._col.document(vaid_id).set({"revoked_at": firestore.SERVER_TIMESTAMP})

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        try:
            revoked_ids = {d.id for d in self._col.stream()}
        except Exception:  # noqa: BLE001 - an unreachable store must fail closed, not raise
            return RevocationStatus.UNAVAILABLE
        if any(v in revoked_ids for v in lineage):
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED

    def all_revoked_ids(self) -> list[str]:
        try:
            return [d.id for d in self._col.stream()]
        except Exception:  # noqa: BLE001
            return []
