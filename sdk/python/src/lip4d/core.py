"""Experimental LIP-4D envelope, binding digest and builder (draft-ovidi-lip-4d-00)."""
import base64
import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import uuid4

class ProtocolError(ValueError): pass

def canonicalize(value):
    import rfc8785
    return rfc8785.dumps(value)

def _uri(value, field):
    if not isinstance(value, str) or not urlsplit(value).scheme:
        raise ProtocolError(field + " must be URI")

def _time(value, field):
    try:
        parsed = datetime.fromisoformat(value.replace("Z","+00:00"))
        if parsed.utcoffset() is None: raise ValueError()
        return parsed
    except (AttributeError, ValueError, TypeError):
        raise ProtocolError(field + " must be RFC3339")

def validate_message(message, *, require_proof=True, now=None):
    if not isinstance(message, dict) or message.get("lip_version") != "0.3":
        raise ProtocolError("unsupported version or envelope")
    kind = message.get("message_type")
    if kind not in {"intent","challenge","attestation","grant","denial","revocation","invocation"}:
        raise ProtocolError("unknown message type")
    for field in ("message_id","issuer","audience"):
        _uri(message.get(field),field)
    if kind != "intent": _uri(message.get("in_reply_to"),"in_reply_to")
    a,b = _time(message.get("issued_at"),"issued_at"),_time(message.get("expires_at"),"expires_at")
    if b <= a or (now is not None and (now.tzinfo is None or now >= b)):
        raise ProtocolError("invalid or expired message")
    if kind in {"intent","attestation","invocation"}:
        i,d = message.get("intent"),message.get("dimensions")
        if not isinstance(i,dict) or not isinstance(d,dict): raise ProtocolError("intent and dimensions required")
        if not isinstance(i.get("action"),str) or not i["action"]: raise ProtocolError("action required")
        _uri(i.get("resource"),"resource")
        if not isinstance(i.get("purpose"),str) or not i["purpose"]: raise ProtocolError("purpose required")
        for key in ("parameters","constraints"):
            if key in i and not isinstance(i[key],dict): raise ProtocolError(key+" must be object")
        if not all(isinstance(d.get(k),dict) for k in ("chronos","logos","topos","physis")):
            raise ProtocolError("missing dimensions")
        c,l,t,p = (d[k] for k in ("chronos","logos","topos","physis"))
        n,x = _time(c.get("not_before"),"not_before"),_time(c.get("not_after"),"not_after")
        if x <= n or (now is not None and not n <= now < x): raise ProtocolError("chronos interval")
        if type(c.get("sequence")) is not int or c["sequence"] < 0: raise ProtocolError("sequence")
        if not isinstance(l.get("rationale"),str) or not l["rationale"]: raise ProtocolError("rationale")
        if "confidence" in l and (type(l["confidence"]) not in (int,float) or not 0 <= l["confidence"] <= 1):
            raise ProtocolError("confidence")
        if not isinstance(t.get("trust_domain"),str) or not t["trust_domain"]: raise ProtocolError("trust_domain")
        _uri(p.get("intent_id"),"intent_id")
        if type(p.get("revision")) is not int or p["revision"] < 1: raise ProtocolError("revision")
    if kind == "challenge":
        if not isinstance(message.get("requirements"),dict) or not message.get("nonce"):
            raise ProtocolError("challenge requirements and nonce required")
    if kind == "attestation" and not message.get("nonce"): raise ProtocolError("attestation nonce")
    if kind in {"grant","denial","revocation","invocation"}:
        auth = message.get("authorization")
        if not isinstance(auth,dict): raise ProtocolError("authorization required")
        if kind == "grant":
            if auth.get("status") != "granted": raise ProtocolError("grant status")
            _uri(auth.get("grant_id"),"grant_id")
            _uri(auth.get("audience"),"grant audience")
            _time(auth.get("expires_at"),"grant expires_at")
            _digest(auth.get("intent_digest"))
            if not isinstance(auth.get("constraints"),dict) or "confirmation" not in auth:
                raise ProtocolError("incomplete grant")
        if kind == "denial" and auth.get("status") != "denied": raise ProtocolError("denial status")
        if kind == "revocation":
            _uri(auth.get("grant_id"),"grant_id")
            _digest(auth.get("intent_digest"))
            _time(auth.get("effective_at"),"effective_at")
            if not isinstance(auth.get("reason_code"),str) or not auth["reason_code"]:
                raise ProtocolError("revocation reason_code required")
        if kind == "invocation":
            _uri(auth.get("grant_id"),"grant_id")
            _digest(auth.get("intent_digest"))
    if "evidence" in message:
        if not isinstance(message["evidence"],list): raise ProtocolError("evidence array")
        for ev in message["evidence"]:
            if not isinstance(ev,dict) or not ev.get("type") or not ev.get("format") or (("value" in ev) == ("uri" in ev)):
                raise ProtocolError("invalid evidence descriptor")
    if require_proof:
        proof = message.get("proof")
        if not isinstance(proof,dict) or proof.get("type") != "jws-detached" or not isinstance(proof.get("jws"),str):
            raise ProtocolError("detached JWS required")

def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha-256:[A-Za-z0-9_-]{43}", value):
        raise ProtocolError("invalid sha-256 digest encoding")

def compare_intent_digests(expected, actual):
    """Compare prevalidated, encoded intent digests in constant time."""
    _digest(expected)
    _digest(actual)
    return hmac.compare_digest(expected.encode("ascii"), actual.encode("ascii"))

def digest_intent(message):
    binding = {key:message[key] for key in ("issuer","audience","intent","dimensions")}
    return "sha-256:" + base64.urlsafe_b64encode(hashlib.sha256(canonicalize(binding)).digest()).decode().rstrip("=")

def create_intent(*, issuer, audience, action, resource, purpose, rationale, trust_domain, validity_seconds=120, parameters=None, constraints=None):
    if type(validity_seconds) is not int or not 1 <= validity_seconds <= 3600:
        raise ProtocolError("invalid validity_seconds")
    n = datetime.now(timezone.utc)
    a,b = (x.isoformat().replace("+00:00","Z") for x in (n,n+timedelta(seconds=validity_seconds)))
    message = {"lip_version":"0.3","message_type":"intent","message_id":"urn:uuid:"+str(uuid4()),
      "issuer":issuer,"audience":audience,"issued_at":a,"expires_at":b,
      "intent":{"action":action,"resource":resource,"purpose":purpose,"parameters":parameters or {},"constraints":constraints or {}},
      "dimensions":{"chronos":{"not_before":a,"not_after":b,"sequence":1},
       "logos":{"rationale":rationale},"topos":{"trust_domain":trust_domain},
       "physis":{"intent_id":"urn:uuid:"+str(uuid4()),"revision":1}}}
    validate_message(message,require_proof=False)
    return message
