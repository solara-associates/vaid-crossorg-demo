"""`bedrock_gate1.BedrockDecisionServer` in isolation, with a fake Bedrock
client. No network, no AWS account, no region actually invoked — see
conftest.py's `harbor` fixture for why these modules are imported lazily.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

from synthera_gate1 import ChoiceQuestion, ConfigError, DecisionServerError  # noqa: E402

QUESTION = ChoiceQuestion(
    instructions="which action is this?",
    criteria={
        "deploy": "releasing or rolling out code",
        "secrets/rotate": "changing a credential",
        "read-logs": "reading logs",
    },
)


class _FakeBody:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()


class _FakeBedrockClient:
    def __init__(self, response_text: str | None = None, error: Exception | None = None) -> None:
        self._response_text = response_text
        self._error = error
        self.last_call: dict | None = None

    def invoke_model(self, **kwargs):
        self.last_call = kwargs
        if self._error is not None:
            raise self._error
        return {"body": _FakeBody({"content": [{"type": "text", "text": self._response_text}]})}


def _server(monkeypatch, fake_client, region="eu-west-2", model_id="eu.anthropic.claude-3-haiku-v1"):
    import bedrock_gate1

    monkeypatch.setattr(bedrock_gate1.boto3, "client", lambda *a, **k: fake_client)
    return bedrock_gate1.BedrockDecisionServer(region=region, model_id=model_id)


def test_refuses_a_us_region_at_construction(monkeypatch):
    import bedrock_gate1

    monkeypatch.setattr(bedrock_gate1.boto3, "client", lambda *a, **k: _FakeBedrockClient())
    with pytest.raises(ConfigError):
        bedrock_gate1.BedrockDecisionServer(region="us-east-1", model_id="eu.anthropic.claude-3-haiku-v1")


def test_refuses_a_us_cross_region_inference_profile(monkeypatch):
    import bedrock_gate1

    monkeypatch.setattr(bedrock_gate1.boto3, "client", lambda *a, **k: _FakeBedrockClient())
    with pytest.raises(ConfigError):
        bedrock_gate1.BedrockDecisionServer(region="eu-west-2", model_id="us.anthropic.claude-3-haiku-v1")


def test_parses_a_well_formed_response(monkeypatch):
    fake = _FakeBedrockClient(
        response_text=json.dumps(
            {"action": "deploy", "confidence": 0.93, "authority_claim_detected": False}
        )
    )
    server = _server(monkeypatch, fake)
    answer = server.ask_choice("push to prod", QUESTION)
    assert answer.choice == "deploy"
    assert answer.confidence == 0.93
    assert fake.last_call["modelId"] == "eu.anthropic.claude-3-haiku-v1"


def test_honestly_names_the_engine_with_the_model_id(monkeypatch):
    server = _server(monkeypatch, _FakeBedrockClient(response_text="{}"))
    identity = server.identity
    assert identity.engine_id == "bedrock-llm-classifier:eu.anthropic.claude-3-haiku-v1"
    assert "vertex" not in identity.engine_id


def test_a_bedrock_call_failure_raises_decision_server_error_not_a_default_answer(monkeypatch):
    server = _server(monkeypatch, _FakeBedrockClient(error=RuntimeError("access denied")))
    with pytest.raises(DecisionServerError):
        server.ask_choice("push to prod", QUESTION)


def test_an_empty_response_raises_rather_than_guessing(monkeypatch):
    server = _server(monkeypatch, _FakeBedrockClient(response_text=""))
    with pytest.raises(DecisionServerError):
        server.ask_choice("push to prod", QUESTION)


def test_a_malformed_json_response_raises(monkeypatch):
    server = _server(monkeypatch, _FakeBedrockClient(response_text="not json"))
    with pytest.raises(DecisionServerError):
        server.ask_choice("push to prod", QUESTION)
