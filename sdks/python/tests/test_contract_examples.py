"""Parse the committed contract examples so model drift from the schema fails here."""
import json
import os

from trust_infra import canonical
from trust_infra.models import AuthorizeRequest, Decision, Verdict

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "..", "contracts", "examples")


def _load(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return json.load(f)


def test_authorize_request_example_round_trips():
    raw = _load("authorize-request.example.json")
    req = AuthorizeRequest.coerce(raw)
    assert req.agent_id == "procurement-agent-v2"
    assert req.amount == "5000.00"  # money stays a string
    assert req.counter_snapshot.counters[0].window == "month"
    # to_dict reproduces every field the example carries
    assert req.to_dict() == raw


def test_decision_approve_example_parses_and_preserves_signed_fields():
    raw = _load("decision-approve.example.json")
    decision = Decision.from_dict(raw)
    assert decision.verdict == Verdict.APPROVE
    assert decision.obligations[0].type == "capture_within"
    assert decision.signature.canonicalization == "ti-decision-canon/1"
    # The allowlisted signed bytes are stable regardless of excluded fields.
    assert canonical.decision_signing_bytes(raw) == canonical.decision_signing_bytes(decision.to_dict())


def test_decision_deny_example_parses():
    raw = _load("decision-deny.example.json")
    decision = Decision.from_dict(raw)
    assert decision.verdict == Verdict.DENY
