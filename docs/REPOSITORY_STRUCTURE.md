# Proposed future repository layout

```text
schemas/                # legacy v0.2 remains until migration; future v0.3 schemas after validation
specification/          # links to IETF draft, editorial notes (avoid undocumented forks)
test-vectors/           # signature, canonicalisation, digest and negative cases
sdk/python/             # planned
sdk/go/                 # planned
sdk/typescript/         # planned
sdk/dotnet/             # planned
guardian/go/            # planned
integrations/mcp/       # planned
integrations/http/      # planned
examples/               # existing examples pending audit
docs/                   # planning, migrations and documentation
legacy/                 # eventual archive of earlier v0.2 examples
```

Directories listed as planned are **not** included as functioning SDKs in this overlay.
