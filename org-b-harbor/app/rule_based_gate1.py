"""A real, non-stubbed Gate 1 decision server with no model call at all.

## This is the FALLBACK engine, not the intended path

`bedrock_gate1.BedrockDecisionServer` is the intended engine (Amazon Bedrock,
this Lambda's own IAM role, EU only — see that module). This module exists
for the case where Bedrock model access is not yet enabled for the target
model in the deploying AWS account: `gates.py` selects it via `GATE1_ENGINE`
at deploy time, never silently at request time, and the deploy report says
whether Bedrock access is enabled and, if not, the console step to enable it.

Gate 1 is a router, not an authority regardless of engine: nothing it returns
can cause a tool to run, and Gate 2 refuses the actual tool call against a
signed policy regardless of what Gate 1 said (`synthera_gate2.decision`). A
classifier mistake here can at worst waste a human's attention on an
escalation, or let a request reach Gate 2, which checks it anyway. This
implementation is a real classifier — keyword matching over the same closed
action vocabulary Gate 1 enforces — not a test stand-in: it has no access to
`request_text` ahead of time, it can be wrong, and it reports its own low
confidence honestly rather than guessing.

## Honesty requirement

`identity.engine_id` names what actually ran. It must never say
`bedrock-llm-classifier` or `vertex-llm-classifier`, because that would claim
a model call that did not happen, on screen and in the signed audit alike.
"""

from __future__ import annotations

from synthera_gate1 import ChoiceAnswer, ChoiceQuestion, EngineIdentity

ENGINE_ID = "rule-based-classifier"
ENGINE_VERSION = "1"

_KEYWORDS: dict[str, tuple[str, ...]] = {
    "deploy": (
        "deploy", "push", "release", "roll out", "rollout", "ship it",
        "ship to", "promote", "merge to main", "go live", "cut a release",
    ),
    "secrets/rotate": (
        "secret", "rotate", "credential", "api key", "apikey", "password",
        "rotate the key", "token",
    ),
    "read-logs": (
        "log", "logs", "trace", "traces", "metric", "metrics", "tail the",
        "search the logs", "audit trail",
    ),
}

#: Phrases that claim prior human authorization. Recorded as evidence
#: (`authority_claim_detected`); never grants anything on its own — see
#: `synthera_gate1.classifier` and the scenario 7 test for why.
_AUTHORITY_CLAIM_PHRASES = (
    "already approved", "already authorized", "already authorised",
    "i have approval", "i'm cleared", "im cleared", "signed off on this",
    "you already approved",
)


class RuleBasedDecisionServer:
    """Matches `synthera_gate1.port.DecisionServerPort`. Never raises on a
    request it cannot classify; it reports zero confidence instead, which
    Gate 1 reads as "escalate", the same outcome a raised error produces."""

    @property
    def identity(self) -> EngineIdentity:
        return EngineIdentity(
            engine_id=ENGINE_ID, engine_version=ENGINE_VERSION, prompt_id=None
        )

    def ask_choice(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer:
        text = state.lower()
        scores = {
            label: sum(1 for phrase in _KEYWORDS.get(label, ()) if phrase in text)
            for label in question.criteria
        }
        best_label = max(scores, key=lambda label: scores[label])
        best_hits = scores[best_label]
        ranked = sorted(scores.values(), reverse=True)
        runner_up = ranked[1] if len(ranked) > 1 else 0

        if best_hits == 0:
            # Nothing matched. Reported at confidence 0.0 rather than guessing
            # a label — Gate 1's threshold then escalates, which is correct:
            # "no match" is not evidence of a benign request.
            confidence = 0.0
        elif runner_up > 0:
            # More than one action's keywords matched: genuinely ambiguous.
            confidence = 0.5
        else:
            confidence = 0.9

        probabilities = {label: 0.0 for label in question.criteria}
        probabilities[best_label] = confidence
        claim_detected = any(phrase in text for phrase in _AUTHORITY_CLAIM_PHRASES)

        answer = ChoiceAnswer(
            choice=best_label, probabilities=probabilities, confidence=confidence
        )
        # Carried as an attribute, matching `synthera_gate1.vertex`'s own
        # convention — see that module for why it is not a constructor field.
        object.__setattr__(answer, "authority_claim_detected", claim_detected)
        return answer
