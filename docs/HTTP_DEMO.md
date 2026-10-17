# PR #8 — Localhost Python ↔ Go HTTP demonstration

This is a **development-only demonstration**. It starts two Go HTTP listeners on `127.0.0.1:8765` (Guardian) and `127.0.0.1:8766` (protected resource), then runs a Python SDK client using a fresh ephemeral Ed25519 key.

## Run

From the repository root, with Python 3.10+ and Go 1.22+:

```bash
python -m pip install -e './sdk/python[test]'
python sdk/python/http_demo.py
```

The Python driver starts and terminates the Go process, exchanges signed intent/challenge/attestation/grant over HTTP, performs one protected operation, and expects replay to be rejected with HTTP 403.

## Security boundaries

- Bindings are fixed to loopback; **do not expose these ports outside localhost**.
- Guardian stores challenge/session state on the server, not in mutable client-supplied fields.
- This is not a complete protocol implementation: the experimental grant is Go-specific and not a detached-JWS LIP-4D v0.3 grant envelope.
- Demo evidence checks are intentionally superficial and must never be used for real authorisation.
- No TLS, trusted workload identity, durable replay state, revocation, independent policy, rate limiting, or operational key management.
- Go JSON signing/canonicalisation is not fully RFC 8785 compatible. Only constrained ASCII/integer messages are supported.
- The endpoints are for local testing only; **not safe to deploy**.

## Remaining acceptance gates

- CI must run the Python↔Go HTTP demo and Go unit tests.
- Add tests for altered challenge references, invalid agent keys and action/resource mismatch.
- Remove dependence on client-supplied structured session state.
- Replace this with a secure implementation once exact IETF grant wire-format conformance is established.
