# Experimental signed-grant slice — PR #6

This milestone adds an isolated **local Go signed grant profile**, not yet the full LIP-4D `grant` envelope defined in the IETF draft.

## Flow
1. A trusted caller supplies an **already verified and policy-approved** request to `GrantIssuer.Issue`.
2. The issuer signs a JSON claims structure with Ed25519 using an externally managed private key.
3. A protected resource uses `GrantGate.Authorize` to check signature, trusted issuer, subject, audience, intent digest, exact action/resource and expiry.
4. The gate atomically marks the grant used before returning approval. A second invocation is denied.

## Security limitations / work remaining
- This proof-of-concept is **NOT** a protocol-conformant LIP-4D grant: it uses a simplified `claims`/`signature` wrapper and Go's struct JSON encoder, not detached JWS/JCS over a v0.3 envelope.
- The `approved` boolean is a trusted internal input, not a policy engine. Public callers MUST NOT supply it.
- There is no wiring from the challenge lifecycle's evidence verifier to grant issuance.
- The replay store is in memory only; process restart or multiple resource replicas permits replay.
- There is no revocation, key rotation, durable audit, challenge linkage or network authentication.
- Time is encoded as Unix seconds in this prototype; formal protocol messages require the draft's timestamp format.
- No production APIs, HTTP middleware or public network endpoint should expose these primitives.

Next: model draft-compliant grant/denial envelopes, detached JWS with complete RFC 8785 canonicalisation, durable atomic replay state, verified-attestation policy decisions and enforcement integration.

Run `cd guardian/go && go test -race ./...`.
