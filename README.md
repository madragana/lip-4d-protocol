# LIP-4D — Intent Context and Authorization Dialogue Protocol

[![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html)

**LIP-4D** is an experimental JSON protocol for expressing, evaluating and authorising the intent of autonomous software agents. It complements workload identity and OAuth rather than replacing them.

**Author:** Angelo Ovidi · **Current specification:** [IETF Internet-Draft draft-ovidi-lip-4d-00](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html) (published 30 July 2026; protocol version `0.3`; work in progress).

## The four dimensions

| Dimension | Scope |
|---|---|
| Chronos | Validity windows, sequencing and replay protection |
| Logos | Purpose, rationale claims and evidence |
| Topos | Trust domain, resource and operational context |
| Physis | Revision, mutation, retry and intent lifecycle |

## How the exchange works

```text
Agent                 Guardian                  Resource
  |--- intent ---------->|                          |
  |<-- challenge? -------|                          |
  |--- attestation? ---->|                          |
  |<-- grant / denial ---|                          |
  |--- invocation + grant + intent digest --------->|
  |                         validation/enforcement |
```

Authorization **must never** rely on an agent's asserted intent alone. Receivers authenticate the sender, validate evidence and enforce local policy; resources validate audience, action, intent binding, expiry and constraints before execution.

## Documentation and development

- [Official Internet-Draft](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html) — normative reference for experimental protocol v0.3.
- [SDK & Guardian blueprint](docs/BLUEPRINT.md) — implementation roadmap, not a claim of released features.
- [Repository migration](docs/MIGRATION.md) — how to preserve the 2025 v0.2 material.
- [Security policy](SECURITY.md) — vulnerability reporting and security limitations.
- [Contributing](CONTRIBUTING.md) — contributions and interoperability priorities.

### Planned SDK order

Python (agent SDK) → Go (Guardian and SDK) → TypeScript → .NET → Rust.

**Current relaunch status:** Documentation and scaffolding only. No new production-ready SDK or cryptographic conformance claim is made here. Older `reference-agent` and v0.2 schema files must be treated as **legacy experimental material**, not v0.3 compatible, until independently reviewed and tested.

## Related application

[route.fast](https://route.fast) is an application exploring related ideas, **not** a dependency or prerequisite of LIP-4D.

## Licensing

Existing repository source has been published under Apache-2.0. Preserve the existing `LICENSE` in the GitHub repository. Code Components extracted from the IETF Internet-Draft have separate IETF Trust licensing obligations; consult the draft's copyright notice before importing such code.

Copyright © 2025–2026 Angelo Ovidi and contributors, subject to the applicable licences.
