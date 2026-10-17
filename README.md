# LIP-4D — Intent Context and Authorization Dialogue Protocol

[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html)
[![Python SDK](https://github.com/madragana/lip-4d-protocol/actions/workflows/python-sdk.yml/badge.svg)](https://github.com/madragana/lip-4d-protocol/actions/workflows/python-sdk.yml)
[![Go Guardian](https://github.com/madragana/lip-4d-protocol/actions/workflows/go-guardian.yml/badge.svg)](https://github.com/madragana/lip-4d-protocol/actions/workflows/go-guardian.yml)
[![HTTP demo](https://github.com/madragana/lip-4d-protocol/actions/workflows/http-demo.yml/badge.svg)](https://github.com/madragana/lip-4d-protocol/actions/workflows/http-demo.yml)

**LIP-4D** is an experimental protocol for expressing and evaluating the **intent** behind an autonomous agent's requested action, with a challenge–attestation–authorisation dialogue and resource-side enforcement.

**Author:** Angelo Ovidi  
**Specification:** [IETF Internet-Draft `draft-ovidi-lip-4d-00`](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html) (30 July 2026; draft protocol version `0.3`)  
**Implementation status:** Working **localhost Python ↔ Go HTTP demonstration**, experimental SDK and Guardian components; **not production-ready or fully protocol-conformant**.

LIP-4D **complements**, rather than replaces, workload identity, authentication, OAuth and existing authorisation systems. A signed statement of intent is not itself permission to execute an operation.

## Why intent-aware authorisation?

Authenticating an agent establishes *who* is asking. Authorising a particular operation also requires understanding *what* it wants to do, *why*, *where*, *when*, and under which restrictions. LIP-4D models these assertions explicitly and gives a Guardian an opportunity to challenge them before a protected resource acts.

The protocol considers four dimensions:

| Dimension | Question | Examples |
| --- | --- | --- |
| **Chronos** | **When?** | Validity window, sequencing, freshness |
| **Logos** | **Why?** | Purpose, rationale, supporting evidence |
| **Topos** | **Where / in which context?** | Trust domain, resource and execution context |
| **Physis** | **How does intent evolve?** | Intent identity, revisions and lifecycle |

These fields carry *claims requiring validation*, not automatically trustworthy facts.

## Protocol exchange

```text
Python agent               Go Guardian                Protected resource
     |                          |                              |
     | ---- signed intent ----> |                              |
     | <------ challenge ------ |                              |
     | ---- attestation ------> |                              |
     |                          |-- evidence and local policy  |
     | <---- grant / denial --- |                              |
     | -------- scoped grant + requested operation -----------> |
     |                          |             verify & enforce |
     | <------------------ operation or denial --------------- |
```

This is the **intended protocol model**. The repository's HTTP demo implements a narrower, experimental version: its grant representation and evidence checker are **not yet normative LIP-4D implementations**.

## What works today

Following the repository's initial SDK, Guardian, interoperability and lifecycle milestones, it includes:

- **Python SDK (alpha):** intent construction, basic message validation, RFC 8785 canonicalisation in Python, intent binding digest, detached Ed25519 JWS signing and verification helpers.
- **Go Guardian (experimental):** signed-intent checking against configured issuer, audience, time and basic policy; restricted JSON signature compatibility; one-time challenge issuance and attestation correlation.
- **Experimental signed grants:** short-lived Ed25519 claims bound to subject, audience, intent digest, action and exact resource; independently validated by a protected-resource gate.
- **Replay-denial tests:** in-process challenge and grant consumption with concurrency/negative tests. Replay state is **in memory only**.
- **Local HTTP integration:** real Python and Go processes exchange signed intent, challenge, attestation and an experimental grant over loopback HTTP, with a protected endpoint denying reuse.
- **GitHub Actions:** Python SDK, Go Guardian and HTTP demo workflows.

**Demonstrated:** The HTTP exchange has completed successfully on Windows, including a second clean run and denial of grant reuse. This is a **proof of concept**, not a security certification.

## Quick start: Python ↔ Go HTTP demo

Requirements: **Python 3.10+**, **Go 1.22+**, Git, and free local TCP ports **8765** and **8766**.

Clone and install:

```bash
git clone https://github.com/madragana/lip-4d-protocol.git
cd lip-4d-protocol
python -m pip install -e './sdk/python[test]'
python sdk/python/http_demo.py
```

### Windows PowerShell (recommended: virtual environment)

```powershell
git clone https://github.com/madragana/lip-4d-protocol.git
cd lip-4d-protocol
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e "./sdk/python[test]"
.\.venv\Scripts\python.exe sdk/python/http_demo.py
```

The Python script compiles a temporary Go demo executable when needed, launches a Guardian at `127.0.0.1:8765` and a protected resource at `127.0.0.1:8766`, and shuts down the server afterward. Each run generates a fresh test signing key.

A successful execution looks like:

```text
First invocation: {'result': 'protected example operation executed'}
Replay denied: HTTP 403
Local demonstration succeeded; no normative LIP-4D grant is claimed.
```

You can run it twice in succession to verify that the server releases its ports. If either port is already occupied, stop the previous local demo process before retrying. **Do not expose either listener to other computers or the Internet.**

See [HTTP demo instructions and boundaries](docs/HTTP_DEMO.md).

## Run tests

```bash
# From repository root
python -m pip install -e './sdk/python[test]'
python -m pytest sdk/python/tests -q

cd guardian/go
go test -race ./...
```

The test suite includes shared Python/Go signature fixtures, rejected unsigned/tampered messages, challenge replay denial, grant binding checks and concurrent one-time consumption. The GitHub Actions HTTP workflow also runs the Python-to-Go localhost demonstration.

## Repository map

| Path | Contents |
| --- | --- |
| `sdk/python/` | Experimental Python agent SDK, tests and HTTP demo client |
| `guardian/go/` | Go intent evaluator, challenge lifecycle, grant gate and tests |
| `guardian/go/cmd/httpdemo/` | Local-only Guardian and protected-resource HTTP servers |
| `schemas/` | Experimental JSON schemas, including v0.3 and historical material |
| `test-vectors/` | Interoperability fixtures and cryptographic test data |
| `docs/` | Architecture, migration, interoperability and security limitations |
| `reference-agent/` | Earlier experimental reference agent; assess separately for v0.3 |
| `examples/` | Additional examples and historical material |

## Current security and conformance limits

> **EXPERIMENTAL ONLY — Do not deploy the current Guardian or HTTP demonstration as a production authorisation service.**

In particular:

1. **RFC 8785:** Python uses the RFC 8785 library; the Go path uses a **restricted ASCII/integer JSON subset**. It is **not** general RFC 8785/JCS conformance.
2. **Grant wire format:** The Go `SignedGrant` structure is a **local proof-of-concept format**, not the complete signed `grant` envelope from the Internet-Draft.
3. **Identity and keys:** Static demo keys and caller-supplied verification configuration do not provide operational workload-identity lifecycle or trusted issuer-to-key discovery.
4. **Evidence and policy:** Example attestation evidence validation is deliberately superficial; real decisions require independently validated evidence and an enforceable policy engine.
5. **Replay and revocation:** Challenge/grant replay stores are in memory, not durable across restarts or coordinated across distributed replicas. Revocation and rotation are incomplete.
6. **HTTP transport:** The two listeners use loopback HTTP without TLS, production authentication, rate limiting, secure service configuration or a complete threat model.

See [Security policy](SECURITY.md), [Guardian lifecycle](docs/GUARDIAN_LIFECYCLE.md), [Signed grant limitations](docs/SIGNED_GRANTS.md) and [End-to-end demonstration](docs/END_TO_END_DEMO.md).

## Roadmap

- **Protocol conformance:** Full RFC 8785/JCS interoperability, independent cryptographic test vectors and exact v0.3 message schema semantics.
- **Authorisation:** Normative signed grant/denial envelopes, identity/key binding, stronger evidence validation and an independently enforceable policy model.
- **Operational safety:** Durable atomic replay protection, revocation, expiry, key rotation, audit and a formal security review.
- **Integration:** Hardened Guardian API with secure transport, MCP and HTTP adapters; broader TypeScript and .NET SDK work once the foundational interoperability guarantees are stable.

Progress on these milestones should be measured by testable guarantees rather than feature claims.

## Documentation

- [IETF Internet-Draft](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html)
- [SDK and Guardian blueprint](docs/BLUEPRINT.md)
- [Python conformance notes](docs/PYTHON_CONFORMANCE.md)
- [Python ↔ Go interoperability](docs/PYTHON_GO_INTEROP.md)
- [HTTP demonstration](docs/HTTP_DEMO.md)
- [Migration from historical material](docs/MIGRATION.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## Related project

[route.fast](https://route.fast) explores related ideas and is **not** a required dependency for implementing LIP-4D.

## Licensing

The repository identifies **Apache-2.0** for its source; consult the existing [LICENSE](LICENSE) and repository notices. Code Components extracted from an IETF Internet-Draft may have additional IETF Trust licensing requirements; check the draft's copyright statement before reusing them.

Copyright © 2025–2026 Angelo Ovidi and contributors, subject to applicable licences.
