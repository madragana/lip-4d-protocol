"""Schema and published fixture regression checks."""
import copy
import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from lip4d import verify_message_ed25519, ProtocolError

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "schemas" / "lip-4d-v0.3.schema.json"
VECTOR = ROOT / "test-vectors" / "detached-jws-ed25519.json"

@pytest.fixture
def schema():
    jsonschema = pytest.importorskip("jsonschema")
    raw = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(raw)
    return jsonschema.Draft202012Validator(raw, format_checker=jsonschema.FormatChecker())

@pytest.fixture
def signed():
    return json.loads(VECTOR.read_text(encoding="utf-8"))

def test_fixed_detached_jws_vector(signed):
    import base64
    pub = base64.urlsafe_b64decode(signed["public_key_raw_base64url"] + "==")
    key = Ed25519PublicKey.from_public_bytes(pub)
    verify_message_ed25519(signed["message"], key, expected_kid="test-vector-key-1")

def test_fixed_jws_tampering_rejected(signed):
    import base64
    key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(signed["public_key_raw_base64url"] + "=="))
    tampered = copy.deepcopy(signed["message"])
    tampered["authorization"]["reason_codes"] = ["granted"]
    with pytest.raises(ProtocolError):
        verify_message_ed25519(tampered, key, expected_kid="test-vector-key-1")

def test_schema_accepts_signed_denial(schema, signed):
    schema.validate(signed["message"])

@pytest.mark.parametrize("message_type", ["intent", "challenge", "attestation", "grant", "denial", "revocation", "invocation"])
def test_schema_requires_reply_reference(schema, signed, message_type):
    m = copy.deepcopy(signed["message"])
    m["message_type"] = message_type
    m.pop("in_reply_to", None)
    if message_type != "intent":
        assert not schema.is_valid(m)

@pytest.mark.parametrize("field", ["intent", "dimensions"])
def test_schema_requires_intent_and_dimensions(schema, signed, field):
    m = copy.deepcopy(signed["message"])
    m["message_type"] = "intent"
    m.pop(field, None)
    assert not schema.is_valid(m)

def test_schema_rejects_missing_proof(schema, signed):
    m = copy.deepcopy(signed["message"])
    m.pop("proof")
    assert not schema.is_valid(m)

def test_schema_allows_extensions(schema, signed):
    m = copy.deepcopy(signed["message"])
    m["org.example.extra"] = {"value": True}
    schema.validate(m)
