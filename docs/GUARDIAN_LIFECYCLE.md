# Guardian challenge lifecycle: first experimental slice

This branch adds an in-process, fail-closed challenge store to the Go Guardian.

## Supported
- CSPRNG-generated opaque challenge identifiers and nonces
- Configurable short time-to-live, maximum 5 minutes
- Correlation to a previously verified intent: message ID, issuer, audience and digest
- Atomic one-time consumption, mismatch/expiry rejection, concurrent replay prevention
- Independent evidence verifier callback with deny-by-default behaviour

## Security boundary
`VerifiedIntent` and `VerifiedAttestation` are trusted-input types by convention **only**. They do not themselves verify a detached JWS, a caller's workload identity, or the IETF message schema. Only adapters that have authenticated both objects and their provenance may construct them. Public HTTP clients MUST NOT be allowed to submit these structs directly.

Successful attestation merely completes a challenge. **It is not authorisation, and no grant is issued.**

## Not yet implemented
- Wire-format challenge and attestation builders/verifiers
- Robust authenticated coupling to the Go signed-intent validator
- Full RFC 8785 canonicalisation
- Auditable policy decisions and signed, audience-bound grants
- Persistent/distributed replay state and multi-instance resilience
- Protected resource enforcement, revocation and operational key management

Use `cd guardian/go && go test -race ./...` for concurrency tests. Do not deploy this code as a production Guardian.
