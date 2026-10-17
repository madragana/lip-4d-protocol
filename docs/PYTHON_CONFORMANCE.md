# Python SDK conformance baseline

Reference: [draft-ovidi-lip-4d-00](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html), Sections 5–11. The Internet-Draft is **work in progress**. This is a project-maintained test suite, not an official IETF certification.

## Implemented and checked
- Envelope version and known message types
- Structural checks of core intent and dimensions
- RFC 8785 JSON canonicalisation via the `rfc8785` dependency
- Section 10 binding digest over **exactly** `issuer`, `audience`, `intent`, `dimensions`
- Section 11 compact detached Ed25519 JWS; signing includes the entire envelope without `proof`
- Signature tampering and wrong-key rejection
- Digest comparison using `hmac.compare_digest`

## Still outstanding before calling this conformant
- Formal JSON Schema for each of seven messages (including extension allowance)
- Complete per-type validation and stateful challenge/attestation correlation
- RFC 3339/URI/nonce grammar and replay cache hardening
- Key-to-issuer binding, trusted key discovery and key rotation
- Required Guardian policy and trusted evidence verification
- Grant/invocation resource enforcement, revision and audience binding
- Comprehensive JWS adversarial vectors and JSON canonicalisation edge cases
- Cross-language verification with the Go implementation

## Local checks

```sh
cd sdk/python
python -m pip install -e '.[test]'
python -m pytest -q
```

The fixture at `test-vectors/intent-digest-ascii.json` is deliberately ASCII-only, allowing the expected digest to be independently computed with JSON key ordering and SHA-256; future vectors must cover full RFC 8785 numerical and Unicode rules. Signing tests generate ephemeral Ed25519 keys and independently check tamper rejection; a fixed-key cross-language JWS fixture is still needed.

**Security warning:** Structural validation and cryptographic proof verification do not constitute an authorisation decision.
