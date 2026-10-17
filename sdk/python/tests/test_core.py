import copy
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from lip4d import create_intent,validate_message,digest_intent,sign_message_ed25519,verify_message_ed25519,compare_intent_digests,ProtocolError

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

def test_digest_compare(intent):
    d = digest_intent(intent)
    assert compare_intent_digests(d, d)
    other = copy.deepcopy(intent)
    other["intent"]["purpose"] = "Different"
    assert not compare_intent_digests(d, digest_intent(other))
    with pytest.raises(ProtocolError):
        compare_intent_digests("sha-256:invalid", d)

def test_revocation_required_fields(intent):
    now = datetime.now(timezone.utc)
    later = now + timedelta(seconds=60)
    revocation = {
        "lip_version":"0.3", "message_type":"revocation",
        "message_id":"urn:uuid:11111111-1111-4111-8111-111111111111",
        "issuer":"https://guardian.example.org",
        "audience":"https://api.example.org",
        "in_reply_to":intent["message_id"],
        "issued_at":now.isoformat(), "expires_at":later.isoformat(),
        "authorization":{
            "grant_id":"urn:uuid:22222222-2222-4222-8222-222222222222",
            "intent_digest":digest_intent(intent),
            "effective_at":now.isoformat(),
            "reason_code":"policy-revoked"
        }
    }
    validate_message(revocation, require_proof=False)
    for key in ("grant_id","intent_digest","effective_at","reason_code"):
        invalid = copy.deepcopy(revocation)
        del invalid["authorization"][key]
        with pytest.raises(ProtocolError):
            validate_message(invalid, require_proof=False)
