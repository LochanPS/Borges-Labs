"""Fail-mode behavior -- the core safety contract: an upstream failure is NEVER
turned into a silent APPROVE."""
import pytest

from trust_infra import Client, DecisionDeniedError, OnUnavailable
from trust_infra.exceptions import ServiceUnavailableError, TransportError
from trust_infra.models import Verdict

from _helpers import FakeTransport, json_response, sample_txn

KEYS = {"keys": []}  # never reached on the unavailable path


def _client(mode, script):
    return Client(
        api_key="azn_test_abc",
        public_keys=KEYS,
        on_unavailable=mode,
        transport=FakeTransport(script),
    )


def test_fail_closed_network_error_denies():
    c = _client(OnUnavailable.FAIL_CLOSED, [TransportError("connection refused")])
    d = c.authorize(sample_txn())
    assert d.verdict == Verdict.DENY
    assert d.degraded is True
    assert d.signature is None
    with pytest.raises(DecisionDeniedError):
        d.enforce()


def test_fail_closed_503_denies():
    problem = {"type": "about:blank", "title": "Unavailable", "status": 503, "code": "unavailable"}
    c = _client(OnUnavailable.FAIL_CLOSED, [json_response(503, problem)])
    d = c.authorize(sample_txn())
    assert d.verdict == Verdict.DENY
    assert d.degraded is True


def test_fail_open_approves_but_marks_degraded_and_unsigned():
    c = _client(OnUnavailable.FAIL_OPEN, [TransportError("timeout")])
    d = c.authorize(sample_txn())
    assert d.verdict == Verdict.APPROVE
    assert d.degraded is True  # explicit + loud, not a silent approve
    assert d.signature is None
    assert d.signature_verified is False
    d.enforce()  # explicit opt-in: does not raise


def test_local_cache_hit_replays_prior_decision():
    # First call succeeds and seeds the cache; second call (plane down) replays it.
    from _helpers import make_keypair, sign_decision, sample_decision, jwks_for

    priv, pub = make_keypair()
    signed = sign_decision(sample_decision("APPROVE"), priv, "k1")
    transport = FakeTransport([json_response(200, signed), TransportError("down")])
    c = Client(
        api_key="azn_test_abc",
        public_keys=jwks_for(pub, "k1"),
        on_unavailable=OnUnavailable.LOCAL_CACHE,
        transport=transport,
    )
    first = c.authorize(sample_txn())
    assert first.verdict == Verdict.APPROVE and first.signature_verified is True

    second = c.authorize(sample_txn())  # same idempotency_key
    assert second.verdict == Verdict.APPROVE
    assert second.served_from_cache is True
    assert second.degraded is True


def test_local_cache_miss_fails_closed():
    c = _client(OnUnavailable.LOCAL_CACHE, [TransportError("down")])
    d = c.authorize(sample_txn())  # nothing cached for this key
    assert d.verdict == Verdict.DENY  # never APPROVE on a miss
    assert d.degraded is True


@pytest.mark.parametrize("mode", [OnUnavailable.FAIL_CLOSED, OnUnavailable.LOCAL_CACHE])
def test_unavailable_never_silently_approves(mode):
    c = _client(mode, [TransportError("down")])
    d = c.authorize(sample_txn())
    assert d.verdict != Verdict.APPROVE
