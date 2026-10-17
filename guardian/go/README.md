# Experimental Go Guardian: initial verification and policy slice

This module is **not a complete Guardian implementation** and issues **no authorisation grants**.

Current functionality: inspect an `intent` envelope, restrict issuer/audience and validity window, verify an Ed25519 detached JWS using a configured trusted public key, check a minimal allowlist for actions and resource-prefix policy, reject duplicate JSON members.

## Security limitations
- **Not RFC 8785 conformant**: this initial strict ASCII/no-floats JSON profile exists only to bootstrap development. A standards-compliant cross-language canonicaliser must replace it before interoperability is claimed.
- The policy decision does not authorise protected resources.
- No persisted replay/nonce store, grant binding, challenge/attestation, revocation or full dimensional validation.
- Public keys must be obtained and authenticated by the application operator; never use untrusted `kid` discovery.
- Resource-prefix policy is simplistic and must be replaced with parsed resource identity/explicit allowlists.
- Do not deploy as production authorisation infrastructure.

Run: `cd guardian/go && go test ./...`.

Next: verify an actual Python SDK-generated signed intent, implement RFC 8785, comprehensive schema/semantic checks and an enforced protected-resource gate.
