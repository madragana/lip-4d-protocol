# Python ↔ Go interoperability milestone

The test fixture at `test-vectors/python-go-intent-ed25519.json` represents an **intent signed with the Python SDK-compatible Ed25519 detached JWS profile** and independently verified by the Go Guardian.

The fixture uses a deterministic **test-only** private seed, held in the Python regression test, and must never be reused as a real signing key.

Run tests:

```sh
cd sdk/python && python -m pip install -e '.[test]' && python -m pytest -q
cd ../../guardian/go && go test ./...
```

## Claims and limits

- Positive verification uses a fixed issuance time and trusted static public key.
- Changing issuer, audience, intent, dimensions or proof must be rejected.
- This proves **only an intentionally limited ASCII/integer JSON profile**, not full RFC 8785/JCS.
- Go `encoding/json` is not a substitute for RFC 8785 on arbitrary JSON values. Unicode, floats and escape edge cases require a reviewed canonicalisation dependency and extra vectors.
- The Go Guardian currently returns a local policy result, **not** a LIP-4D grant.
- The service still needs full dimensional validation, nonce persistence, URI-safe resource policy, key/issuer binding, grant and invocation enforcement.

Until these are implemented, do not deploy the Go Guardian as an authorisation service.
