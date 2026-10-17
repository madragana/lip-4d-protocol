"""Stable project vectors anchored to draft Sections 10 and 11."""
import json
from pathlib import Path

import pytest
from lip4d import canonicalize, digest_intent, compare_intent_digests, ProtocolError

VECTOR = Path(__file__).parents[3] / "test-vectors" / "intent-digest-ascii.json"

def test_ascii_digest_known_answer():
    payload = json.loads(VECTOR.read_text(encoding="utf-8"))
    assert digest_intent(payload["binding"]) == payload["expected_digest"]
    assert compare_intent_digests(digest_intent(payload["binding"]), payload["expected_digest"])

def test_canonicalisation_is_independent_of_member_order():
    a = {"z": 1, "a": {"q": "yes", "b": True}}
    b = {"a": {"b": True, "q": "yes"}, "z": 1}
    assert canonicalize(a) == canonicalize(b)

def test_digest_ignores_unbound_envelope_fields():
    p = json.loads(VECTOR.read_text(encoding="utf-8"))
    b = p["binding"]
    changed = {**b, "message_id": "urn:example:another-message", "proof": {"jws": "ignored"}}
    assert digest_intent(changed) == p["expected_digest"]

def test_digest_changes_when_a_dimension_changes():
    p = json.loads(VECTOR.read_text(encoding="utf-8"))
    b = p["binding"]
    b["dimensions"]["physis"]["revision"] = 2
    assert digest_intent(b) != p["expected_digest"]

def test_malformed_digest_is_rejected():
    with pytest.raises(ProtocolError):
        compare_intent_digests("sha-256:bad", "sha-256:bad")
