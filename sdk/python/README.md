# Experimental Python SDK — LIP-4D protocol 0.3

Install from this directory:

```bash
python -m pip install -e '.[test]'
pytest -q
```

Features: basic envelope and intent validation, RFC 8785 canonicalisation, SHA-256 intent digest and detached Ed25519 JWS signing/verification.

**Security boundary:** This is **not** a Guardian, identity system, policy engine, replay cache or grant enforcement system. Callers MUST authenticate issuers and bind signing keys to them independently. An authenticated intent does not imply authorisation.

Draft: https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html
