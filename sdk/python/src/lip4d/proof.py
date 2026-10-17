"""Detached JWS EdDSA helpers; signature verification is not authorization."""
import base64
import json
from cryptography.exceptions import InvalidSignature
from .core import ProtocolError, canonicalize, validate_message

def _b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _decode(s): return base64.urlsafe_b64decode(s+"="*(-len(s)%4))

def sign_message_ed25519(message, private_key, *, kid):
    validate_message(message, require_proof=False)
    if not kid: raise ProtocolError("kid required")
    bare = {k:v for k,v in message.items() if k != "proof"}
    header = _b64(json.dumps({"alg":"EdDSA","kid":kid,"typ":"application/lip+json"},separators=(",",":")).encode())
    sig = _b64(private_key.sign((header+"."+_b64(canonicalize(bare))).encode("ascii")))
    return {**bare,"proof":{"type":"jws-detached","jws":header+".."+sig}}

def verify_message_ed25519(message, public_key, *, expected_kid, now=None):
    validate_message(message,now=now)
    parts = message["proof"]["jws"].split(".")
    if len(parts)!=3 or parts[1]: raise ProtocolError("JWS must be detached")
    try:
        header = json.loads(_decode(parts[0]))
        if (header.get("alg"),header.get("typ"),header.get("kid")) != ("EdDSA","application/lip+json",expected_kid):
            raise ProtocolError("JWS header not accepted")
        bare = {k:v for k,v in message.items() if k!="proof"}
        public_key.verify(_decode(parts[2]),(parts[0]+"."+_b64(canonicalize(bare))).encode("ascii"))
    except (InvalidSignature, ValueError, TypeError, UnicodeDecodeError, KeyError) as exc:
        raise ProtocolError("signature verification failed") from exc
