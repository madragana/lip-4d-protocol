import copy
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lip4d import create_intent,validate_message,digest_intent,sign_message_ed25519,verify_message_ed25519,ProtocolError

@pytest.fixture
def intent():
    return create_intent(issuer="spiffe://example.org/agent/a",audience="https://guardian.example.org",action="org.example.read",resource="https://api.example.org/record/1",purpose="Read requested record",rationale="User request",trust_domain="example.org")

def test_schema(intent):
    validate_message(intent,require_proof=False,now=datetime.now(timezone.utc))

def test_bad_dimension(intent):
    del intent["dimensions"]["topos"]
    with pytest.raises(ProtocolError): validate_message(intent,require_proof=False)

def test_expiry(intent):
    with pytest.raises(ProtocolError): validate_message(intent,require_proof=False,now=datetime.now(timezone.utc)+timedelta(days=1))

def test_digest_binding(intent):
    original=digest_intent(intent)
    intent["intent"]["purpose"]="Modified"
    assert original!=digest_intent(intent)

def test_signature_and_tampering(intent):
    key=Ed25519PrivateKey.generate()
    signed=sign_message_ed25519(intent,key,kid="demo-key")
    verify_message_ed25519(signed,key.public_key(),expected_kid="demo-key")
    altered=copy.deepcopy(signed)
    altered["intent"]["resource"]="https://attacker.example.org/"
    with pytest.raises(ProtocolError): verify_message_ed25519(altered,key.public_key(),expected_kid="demo-key")

def test_wrong_key(intent):
    signed=sign_message_ed25519(intent,Ed25519PrivateKey.generate(),kid="demo-key")
    with pytest.raises(ProtocolError): verify_message_ed25519(signed,Ed25519PrivateKey.generate().public_key(),expected_kid="demo-key")
