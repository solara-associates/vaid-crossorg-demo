"""Construction of Gate 1 and Gate 2 for Harbor's handler.

Everything here is built once, at import time (cold start), and raises if it
cannot be built. That is deliberate (A5.13, and the estate's own pattern that
an absent control must fail startup rather than degrade silently): a
misconfigured Lambda that started anyway would accept tool calls with no
Gate 1 and no Gate 2, which is a worse outcome than refusing to boot.

## What is NOT durable here, and why that is a stated limit, not an oversight

`InMemoryNonceStore` (proof-of-possession replay protection) is process-local.
Lambda may run more than one instance, and any instance restarts on a cold
start; a replayed proof that lands on a different warm instance than the one
that saw it first is not caught. For a single-tenant staging demo exercised by
a smoke test immediately after deploy, in one warm instance, this is adequate;
it is NOT the shape a receiver fielding real traffic should keep. The durable
replacement is a shared store (e.g. DynamoDB with a conditional put keyed on
the nonce) behind the same `NonceStorePort`, which this module can switch to
without any change to `handler.py`.

## The policy bundle: a public, signed artefact baked into the deploy

The compiled bytecode and its signature are not secret: anyone with the
tenant's public key can already verify them, and the design doc is explicit
that the bundle is meant to be mirrored freely. It is deployed as a plain JSON
file written into the Lambda package by the deploy script (see
`deploy-scenario7-staging.sh`), never as an environment variable holding a
secret, because it isn't one.
"""

from __future__ import annotations

import json
import os
import pathlib

from synthera_gate1 import Gate1, Gate1Config
from synthera_gate2 import InMemoryBundleMirror, InMemoryNonceStore
from synthera_policy import PolicyKeyRegistry

from bedrock_gate1 import BedrockDecisionServer
from rule_based_gate1 import RuleBasedDecisionServer

_HERE = pathlib.Path(__file__).resolve().parent


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value.strip():
        raise RuntimeError(
            f"{name} is not set. Gate 1 and Gate 2 have no default "
            "configuration by design (A5.13): a Lambda that started with no "
            "policy or classifier configuration would accept tool calls with "
            "neither gate actually enforcing anything."
        )
    return value


#: Which engine answers Gate 1's classification. "bedrock" is the intended
#: path (Amazon Bedrock, this Lambda's own IAM role, EU only). "rule-based"
#: is a STATED fallback, selected here at deploy time — never chosen silently
#: at request time — for the case where Bedrock model access is not yet
#: enabled for the target model in this AWS account. See REPORT-s409.md for
#: whether that is the case today and the console step to enable it.
GATE1_ENGINE = os.environ.get("GATE1_ENGINE", "bedrock")


def _build_gate1() -> Gate1:
    if GATE1_ENGINE == "bedrock":
        decision_server = BedrockDecisionServer(
            region=_require_env("GATE1_BEDROCK_REGION"),
            model_id=_require_env("GATE1_BEDROCK_MODEL_ID"),
        )
        model_label = os.environ["GATE1_BEDROCK_MODEL_ID"]
        region_label = os.environ["GATE1_BEDROCK_REGION"]
    elif GATE1_ENGINE == "rule-based":
        decision_server = RuleBasedDecisionServer()
        model_label = "rule-based-classifier-v1"
        region_label = os.environ.get("GATE1_REGION", "eu-west-2")
    else:
        raise RuntimeError(
            f"GATE1_ENGINE={GATE1_ENGINE!r} is not recognised. Must be "
            "'bedrock' or 'rule-based'; there is no default engine because a "
            "silently wrong one is worse than a Lambda that refuses to boot."
        )

    config = Gate1Config(
        region=region_label,
        project=os.environ.get("GATE1_PROJECT", "harbor-ops-staging"),
        model=model_label,
        confidence_threshold=float(os.environ.get("GATE1_CONFIDENCE_THRESHOLD", "0.75")),
    )
    return Gate1(config=config, decision_server=decision_server)


def _build_policy_keys() -> PolicyKeyRegistry:
    import base64

    tenant_id = _require_env("GATE2_POLICY_TENANT_ID")
    key_ref = _require_env("GATE2_POLICY_KEY_REF")
    public_key_b64 = _require_env("GATE2_POLICY_PUBLIC_KEY_B64")
    return PolicyKeyRegistry({(tenant_id, key_ref): base64.b64decode(public_key_b64)})


def _build_mirror() -> InMemoryBundleMirror:
    bundle_path = pathlib.Path(os.environ.get("GATE2_BUNDLE_PATH", str(_HERE / "gate2_bundle.json")))
    if not bundle_path.is_file():
        raise RuntimeError(
            f"the signed policy bundle is missing at {bundle_path}. Gate 2 has "
            "nothing to check a tool call against without it, so this is a "
            "refuse-to-boot condition rather than a per-request refusal."
        )
    bundle = json.loads(bundle_path.read_text())
    mirror = InMemoryBundleMirror()
    mirror.put(bundle)
    return mirror


GATE1 = _build_gate1()
POLICY_KEYS = _build_policy_keys()
MIRROR = _build_mirror()
NONCE_STORE = InMemoryNonceStore()

#: The logical method/path PoP signs over. Not an HTTP route on this Lambda;
#: it names the MCP tool-call surface the badge's proof is scoped to, matching
#: what `vaid_pop.RequestSigner` on the calling side signs — see
#: `python/synthera-gate2/tests/test_scenario7_end_to_end.py`.
POP_METHOD = "POST"
POP_PATH = "/mcp/call"
