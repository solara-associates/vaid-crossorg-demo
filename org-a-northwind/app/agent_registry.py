"""Northwind's own agent registry: one stable id per named agent.

Not part of VAID. The VAID document's own ``agent_id`` field is, by spec
(vaid-mint's ``check_vaid_id_equals_agent_id`` conformance vector), always
equal to that document's ``vaid_id`` — it identifies *this credential*, fresh
on every mint, not a durable identity for the agent holding it. Confusing the
two is a demo bug, not a VAID property, and the fix does not touch vaid-mint:
Northwind keeps its own record of "the id we call infra-agent", assigned once
and returned unchanged on every later mint for that same named agent.
"""

from __future__ import annotations

import uuid

from google.cloud import firestore


class FirestoreAgentRegistry:
    def __init__(self, client: firestore.Client, collection: str = "vaid_agents") -> None:
        self._col = client.collection(collection)

    def get_or_create(self, agent_class: str) -> str:
        doc_ref = self._col.document(agent_class)
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()["agent_id"]
        agent_id = str(uuid.uuid4())
        doc_ref.set({"agent_id": agent_id, "agent_class": agent_class})
        return agent_id
