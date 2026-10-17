# LIP-4D — SDK & Guardian Development Blueprint

**Status:** Proposed implementation blueprint  
**Date:** 17 October 2026  
**Protocol reference:** [IETF Internet-Draft — draft-ovidi-lip-4d-00](https://www.ietf.org/archive/id/draft-ovidi-lip-4d-00.html)  
**Reference application:** [route.fast](https://route.fast)

> This is an implementation strategy, not a claim that the listed packages, APIs, integrations, or capabilities have already been released. Detailed normative protocol behaviour must be checked against the current Internet-Draft before implementation.

## 1. Executive vision

Turn **LIP-4D**, a protocol for expressing and evaluating the intent of autonomous software agents, into an independent, vendor-neutral ecosystem of libraries, SDKs, middleware and a Guardian authorisation engine. Keep **route.fast** as a potential reference implementation and commercial showcase rather than making it a mandatory dependency.

The central objective is **intent-aware authorisation**: evaluating not only *who* is requesting an operation, but *what* they intend to do, *why*, *where*, *when*, and under which constraints. LIP-4D complements rather than replaces identity, OAuth and conventional access-control infrastructure.

## 2. Protocol concepts

LIP-4D models agent intent through four dimensions:

| Dimension | Core question | Implementation concern |
|---|---|---|
| **Chronos** | When is the action valid? | Validity windows, expiry, replay protection |
| **Logos** | Why is the action requested? | Purpose, rationale, supporting evidence |
| **Topos** | Where and in what context? | Resource, operational context, trust boundaries |
| **Physis** | How does the intent evolve? | Lifecycle, revision, revocation, changing intent |

The draft describes structured messages, Agent/Guardian exchanges, cryptographic integrity, challenges and grants. Implementers must follow the draft's precise message types and wire representation rather than assuming illustrative SDK examples are normative.

### Design principles

- **Protocol-first:** stable, testable wire contracts before convenience APIs.
- **Vendor-neutral:** no dependency on route.fast for interoperable implementations.
- **Secure by default:** fail closed when evidence, grants or verification are insufficient.
- **Separation of duties:** agents express intent; Guardians evaluate it; resource layers enforce decisions.
- **Transport-aware, not transport-locked:** start with the draft's specified HTTP binding; add other transports through explicit profiles.
- **Observable:** auditable decision trail without unnecessary exposure of sensitive intent content.
- **Composable:** fit existing OAuth, workload identity, API gateways and MCP applications.

## 3. Target languages and order

| Order | Language | Intended audience | Packaging |
|---|---|---|---|
| 1 | **Python** | Agent frameworks, LLM developers, research | PyPI |
| 2 | **Go** | Guardian service, gateways, distributed infrastructure | Go modules |
| 3 | **TypeScript** | Node.js agents, MCP and web service backends | npm |
| 4 | **C# / .NET** | Enterprise integrations and ASP.NET Core middleware | NuGet |
| 5 | **Rust** | High-assurance/native implementations | crates.io |

**Initial recommended combination:** Python Agent SDK + Go Guardian and Go protocol core. Extend only after cross-language conformance works.

## 4. Logical architecture

```text
+-----------------------+         +---------------------------+
| AI Agent              |         | Guardian                  |
| Python / TypeScript   |-------->| Identity + evidence       |
| LIP-4D Agent SDK      | Intent  | Policy evaluation         |
|                       |<--------| Challenge / grant / deny  |
+-----------+-----------+ Decision+-------------+-------------+
            |                                       |
            | grant + request                       | policy / grant state
            v                                       v
+---------------------------------------------------------------+
| Protected API / MCP tool / service                            |
| Resource enforcement middleware: validate grant and action    |
+---------------------------------------------------------------+

Shared protocol core: schemas, canonicalisation, signing, digests,
validation, versioning, error handling, audit/test fixtures.
```

A Guardian decision alone is insufficient: the **resource side must verify and enforce** the relevant grant and constraints before execution.

## 5. Proposed packages

| Package | Purpose |
|---|---|
| `lip4d-core` | Message models, schemas, canonicalisation, semantic validation, intent digests |
| `lip4d-crypto` | Signature creation/verification, detached JWS, key-resolution interfaces |
| `lip4d-agent` | Intent construction, Guardian dialogue, challenge handling, grant consumption |
| `lip4d-guardian` | Guardian protocol endpoint, policy decisions, evidence verification, issuance/revocation |
| `lip4d-middleware` | Enforcement adapters for HTTP APIs, agent tools and MCP |
| `lip4d-audit` | Decision records, revisions, expiry, traceability and safe logging |
| `lip4d-conformance` | Shared test vectors, negative tests and interoperability runner |

Names are provisional and may be adapted to language ecosystem conventions.

## 6. Repository structure

```text
lip4d/
  README.md
  LICENSE
  CONTRIBUTING.md
  SECURITY.md
  specification/
    draft-reference.md
    schemas/
    test-vectors/
  sdk/
    python/
    go/
    typescript/
    dotnet/
    rust/                 # later phase
  guardian/
    server/
    policies/
    evidence-providers/
  integrations/
    mcp/
    fastapi/
    express/
    aspnetcore/
  examples/
    agent-tool-call/
    challenge-response/
    agent-delegation/
    api-gateway/
    route-fast/
  conformance/
    runner/
    fixtures/
```

## 7. Suggested developer experience

This API is **illustrative**, not a representation of any published SDK or authoritative wire-format fields:

```python
from lip4d import Agent, GuardianClient, Intent

agent = Agent(
    identity="spiffe://example.org/agent/assistant",
    signing_key=agent_key,
)
guardian = GuardianClient(endpoint="https://guardian.example.org")

intent = Intent(
    action="org.example.records.read",
    resource="https://api.example.org/records/123",
    purpose="Retrieve an authorised customer record",
    trust_domain="example.org",
    expires_in=120,
    constraints={"max_uses": 1},
)

decision = guardian.authorize(agent=agent, intent=intent)

if decision.granted:
    response = agent.invoke(
        "https://api.example.org/records/123",
        grant=decision.grant,
    )
```

The SDK should abstract message serialization, signatures, canonicalisation, digests, challenge processing and errors **without concealing decisions or overriding enforcement**. Where additional evidence is required, the SDK should call a configured evidence provider rather than fabricate claims from an LLM response.

## 8. First flagship integration: MCP

Build `lip4d-mcp` as an adapter for protected Model Context Protocol tool execution:

1. An agent proposes a tool call and expresses its intent.
2. The SDK serialises/signs the request as required by LIP-4D.
3. A Guardian authenticates the requester and evaluates independent policy/evidence.
4. The Guardian may challenge, reject or issue a scoped, time-limited grant.
5. MCP middleware validates the grant and ensures it covers the *specific* tool, resource and argument constraints.
6. The protected tool executes only after successful enforcement.
7. The decision and outcome are audited, and grant usage/revocation state is updated as required.

**Security invariant:** natural-language rationale supplied by an agent is *not itself proof of authorisation*.

Other candidate integrations: API gateways, FastAPI, Express, ASP.NET Core, agent delegation and service-to-service systems.

## 9. Guardian design

Start with a Go Guardian service exposing the protocol-defined HTTP interactions and clear interfaces for:

- Request parsing, schema and semantic validation.
- Identity binding and signature verification.
- Pluggable policy evaluation (a simple reference policy first).
- Trusted evidence providers and challenge/attestation state.
- Grant issuance, scope checking, lifecycle, revocation and replay tracking.
- Audit logging with correlation identifiers and sensitive-data minimisation.
- Key rotation and configurable trust anchors.

A Guardian should distinguish **intent expression**, **evidence verification**, **policy decision**, **grant issuance**, and **resource enforcement** as separate trust operations.

## 10. Security and interoperability checklist

- [ ] Confirm the exact protocol version and message types in the current draft.
- [ ] Publish formal JSON Schemas for each wire message.
- [ ] Publish cross-language canonical JSON (JCS), SHA-256 digest and JWS vectors where required by the draft.
- [ ] Test signed payload verification, key binding, algorithm restrictions and key rotation.
- [ ] Specify challenge/response state transitions, retries, ordering and timeouts.
- [ ] Specify grant audience, scope, resource/action binding and maximum uses.
- [ ] Test replay prevention, expiry, revocation and concurrent grant consumption.
- [ ] Standardise error codes and distinguish invalid, unauthorised and untrusted requests.
- [ ] Require resource-side policy enforcement; never accept a bare Boolean from an agent.
- [ ] Test negative/adversarial cases across all SDK languages.
- [ ] Document privacy-safe logs and evidence minimisation.
- [ ] Clarify the relationship between draft protocol version `0.3` and route.fast's `v1.0` terminology, if both remain in use.
- [ ] Review IETF Trust licensing requirements for reused specification content.

## 11. Implementation roadmap

### Phase 1 — Protocol core and conformance

**Deliverables:** machine-readable schemas; fixtures and negative cases; reference algorithms; interoperability rules; protocol compliance matrix.  
**Exit criterion:** identical canonical messages/digests/signature decisions across initial implementations.

### Phase 2 — Python Agent SDK

**Deliverables:** intent builder, validation, signer, Guardian client, challenge and grant handlers, worked examples.  
**Exit criterion:** Python sample can complete a documented Guardian exchange with explicit, inspectable outcomes.

### Phase 3 — Go Guardian + Go SDK

**Deliverables:** protocol HTTP server, reference policy engine, identity/evidence adapters, grant management, Go client.  
**Exit criterion:** the Python and Go implementations pass shared positive and negative conformance tests.

### Phase 4 — MCP and HTTP middleware

**Deliverables:** protected MCP tool example, HTTP/API middleware, enforcement tests, deployment guide.  
**Exit criterion:** an unauthorised action reliably fails and an authorised, correctly scoped operation succeeds.

### Phase 5 — TypeScript and .NET

**Deliverables:** native developer SDKs, framework adapters, full multi-language conformance CI.  
**Exit criterion:** independently implemented SDKs interoperate across language boundaries.

### Phase 6 — Rust and advanced profiles (optional)

Explore hardened native Guardian components, delegation profiles and specialised transport bindings where demand justifies the complexity.

## 12. First demonstration

**Scenario:** Python AI agent → Go Guardian → protected MCP tool.

Demonstrate the lifecycle:

```text
intent -> (optional) challenge -> attestation -> grant ->
verified protected invocation -> audit / expiry or revocation
```

Show both successful and denied requests, including an expired grant, mismatched resource, tampered signature and repeated-use attempt. Publish a runnable example and concise architecture explanation, with no dependency on route.fast.

## 13. Open-source and commercial positioning

**Open-source foundation:** SDKs, protocol models, cryptographic/reference helpers, test vectors, conformance runner, reference middleware and a minimal Guardian. Evaluate permissive licences such as Apache-2.0 or MIT for original implementation code, subject to dependency and IETF Trust reviews.

**Potential commercial layer:** hosted Guardian management, policy administration, integrations, audit dashboards, operational monitoring, managed trust/key infrastructure and enterprise support. route.fast can demonstrate the protocol in autonomous networking while remaining a separate product.

## 14. Immediate next steps

1. Inventory route.fast's existing LIP-4D implementation and distinguish reusable protocol components from application-specific logic.
2. Establish an independent `lip4d` repository, contribution policy and licence approach.
3. Align the draft's version numbers, schemas and terminology with the test suite.
4. Implement the first Python client and Go Guardian vertical slice.
5. Publish a working MCP example and invite interoperability feedback from other implementers.

## 15. Definition of success

LIP-4D should be understandable and adoptable by developers **without installing route.fast**. Success means an independent Python client, Go Guardian and protected tool can exchange valid protocol messages, enforce scoped authorisation, fail safely under adversarial tests and produce verifiable conformance results.

---

*Blueprint prepared from the prior LIP-4D SDK strategy discussion; update as the Internet-Draft evolves.*
