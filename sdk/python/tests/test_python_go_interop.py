"""A fixed signature checked by both Python and Go (test-only deterministic key)."""
import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from lip4d import sign_message_ed25519, verify_message_ed25519, ProtocolError

F = Path(__file__).resolve().parents[3] / "test-vectors" / "python-go-intent-ed25519.json"

def fixture():
    return json.loads(F.read_text(encoding="utf-8"))

def test_python_generates_exact_go_fixture():
    f = fixture()
    unsigned = {k: v for k, v in f["message"].items() if k != "proof"}
    seed = bytes.fromhex("1f" * 32)  # TEST ONLY, never use for real keys
    signing_key = Ed25519PrivateKey.from_private_bytes(seed)
    signed = sign_message_ed25519(unsigned, signing_key, kid="interop-test-key-1")
    assert signed == f["message"]
    pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(f["public_key_raw_base64url"] + "=="))
    verify_message_ed25519(signed, pub, expected_kid="interop-test-key-1")

def test_python_rejects_fixture_tampering():
    f = fixture()
    msg = copy.deepcopy(f["message"])
    msg["dimensions"]["logos"]["rationale"] = "Changed"
    pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(f["public_key_raw_base64url"] + "=="))
    with pytest.raises(ProtocolError):
        verify_message_ed25519(msg, pub, expected_kid="interop-test-key-1")
