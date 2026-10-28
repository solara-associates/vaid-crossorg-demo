"""A real, non-stubbed Gate 1 decision server using Amazon Bedrock.

## Why Bedrock, and not Vertex AI

Harbor runs on AWS. Calling Vertex AI from here would mean holding a GCP
credential inside this AWS Lambda to cross the cloud boundary, for a decision
that `synthera_gate1`'s own design states is never load-bearing (Gate 2 is
what actually enforces, against a signed policy). Bedrock stays inside AWS:
this Lambda's own execution role is granted `bedrock:InvokeModel` on exactly
one model, nothing is stored and nothing is rotated, because there is no key
to begin with.

## EU only

Gate 1 reads request text, so where it is invoked is a residency decision,
the same property `synthera_gate1.vertex.VertexDecisionServer` enforces for
Vertex AI. `is_us_region` is the estate's one implementation of that check
(from `synthera_gate1.config`) and is reused here rather than re-implemented,
so a region that is United States by that definition is refused identically
across both providers. This covers a plain region (`eu-west-2`) and an EU
cross-region inference profile (an id prefixed `eu.`), provided the id or
region string passed in is itself EU — a profile ID that silently routed
outside the EU would not be caught by this check, which is why the deploy
script pins a specific, named EU profile rather than letting one be chosen
at the console.

## Why boto3 is imported at module scope, unlike `vertex.py`'s lazy import

Harbor's Lambda package already bundles boto3 for DynamoDB and Secrets
Manager (`org-b-harbor/deploy.sh`); it is not an optional extra the way the
Vertex AI SDK is for a package with otherwise zero required dependencies.

## Honesty requirement

`identity.engine_id` names what actually ran, and must carry the model id so
a decision is reconstructable (A7.ai-reconstructable) without a second lookup.
"""

from __future__ import annotations

import json

import boto3
import botocore.config

from synthera_gate1 import (
    ChoiceAnswer,
    ChoiceQuestion,
    ConfigError,
    DecisionServerError,
    EngineIdentity,
    is_us_region,
    parse_choice_response,
)

ENGINE_ID = "bedrock-llm-classifier"
ENGINE_VERSION = "1"


class BedrockDecisionServer:
    """Matches `synthera_gate1.port.DecisionServerPort`. Invokes one Bedrock
    model, in one EU region or EU cross-region inference profile, via this
    Lambda's own IAM role — no API key, no stored credential."""

    def __init__(self, *, region: str, model_id: str, timeout_ms: int = 5_000) -> None:
        if is_us_region(region):
            raise ConfigError(
                f"Bedrock invocation region {region!r} is a United States "
                "region. Gate 1 reads request text, so its invocation region "
                "is a residency decision; this deployment requires EU only."
            )
        # Bedrock cross-region inference profile ids are prefixed with a
        # geography marker ("us.", "eu.", "apac.", ...), distinct from
        # `is_us_region`'s region-name markers, which is why this is a
        # separate, explicit check rather than reusing that function on a
        # string it was not written to parse.
        prefix = model_id.split(".", 1)[0].lower()
        if prefix in {"us", "us-gov"}:
            raise ConfigError(
                f"Bedrock model id {model_id!r} is a United States cross-"
                "region inference profile; this deployment requires an "
                "EU-only model id or EU inference profile (prefixed 'eu.')."
            )
        self._model_id = model_id
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=botocore.config.Config(
                connect_timeout=timeout_ms / 1000, read_timeout=timeout_ms / 1000
            ),
        )

    @property
    def identity(self) -> EngineIdentity:
        return EngineIdentity(
            engine_id=f"{ENGINE_ID}:{self._model_id}",
            engine_version=ENGINE_VERSION,
            prompt_id=None,
        )

    def ask_choice(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer:
        instruction = (
            f"{question.instructions}\n\n"
            "Reply with JSON only, matching exactly this shape:\n"
            '{"action": "<one of ' + ", ".join(question.criteria) + '>", '
            '"confidence": <number between 0 and 1>, '
            '"authority_claim_detected": <true or false>}'
        )
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 200,
                "temperature": 0.0,
                "messages": [
                    {"role": "user", "content": f"{instruction}\n\nRequest:\n{state}"}
                ],
            }
        )
        try:
            response = self._client.invoke_model(
                modelId=self._model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            payload = json.loads(response["body"].read())
        except Exception as exc:  # noqa: BLE001 - every provider failure is "no answer"
            raise DecisionServerError(f"bedrock call failed: {exc}") from exc

        text = "".join(
            block.get("text", "")
            for block in payload.get("content", [])
            if isinstance(block, dict)
        )
        if not text:
            raise DecisionServerError("bedrock returned an empty response")
        return parse_choice_response(text, tuple(question.criteria))
