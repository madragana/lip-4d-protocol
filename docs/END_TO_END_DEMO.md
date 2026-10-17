# PR #7 — Experimental end-to-end flow

This milestone connects signed intent verification, the in-memory challenge lifecycle, signed attestation verification, trusted evidence checking, experimental grant issuance, and the resource-side grant gate.

The Go test generates an Ed25519 key and signs the same wire-field structure as the Python SDK. It uses a frozen clock, shared Python/Go intent fixture for message content, and an **explicitly configured local** evidence-verification callback.

## Test flow

1. Agent produces Ed25519 detached-JWS signed intent.
2. Go Guardian verifies the signed intent against configured issuer, audience, key, basic policy and validity.
3. Guardian issues a random challenge, bound to verified intent digest.
4. Agent signs an attestation containing the challenge reference, nonce and the identical intent/dimensions.
5. Guardian verifies the attestation signature, correlation and evidence callback.
6. Guardian issues an experimental local Ed25519 signed grant.
7. Protected-resource gate independently validates and consumes it once.

## Limitations

- **This is an in-process demonstration, not an HTTP or MCP service.**
- The grant is still the non-normative `SignedGrant` local profile, not a complete LIP-4D v0.3 JWS grant envelope.
- Go canonicalisation currently supports only the repository's restricted ASCII/integer subset, not all RFC 8785 encodings.
- Trust configuration and evidence-verifier callbacks are injected by the host application, not discovered securely.
- The Go signature verifier and sample policy rules are not sufficiently hardened for deployment.
- Replay databases are in-memory, and there is no distributed state, revocation or key rotation.
- This demonstrates the Python SDK **compatible signing format**, using Go-generated keys; it does **not** prove that a running Python process and a running Go Guardian communicated over a network.
- Neither a model-generated rationale nor successful signature verification alone is evidence of authorisation.

To run locally: `cd guardian/go && go test -race ./...`.

Before using this in production: full IETF wire-format conformance, secure HTTP bindings, workload identity/key binding, independent evidence validation, durable atomic grant-use enforcement, and a security review are required.
