# Migration plan: 2025 repository to IETF draft v0.3

This overlay updates public-facing documentation and adds planning material. It does **not** delete history or imply that older code is v0.3 conformant.

## Observed original repository (public listing, 17 October 2026)

- `README.md`: described LIP-4D as authentication based on intention rather than credentials; **replace** with the updated README.
- `lip-spec.md`: older local protocol specification; **preserve**, add a prominent legacy banner or move to `legacy/v0.2/` after inspecting its full contents.
- `schemas/lip-4d-v0.2.json`: **preserve as legacy**; do not rename as v0.3.
- `reference-agent/`: **inspect and label legacy**; do not present as the v0.3 SDK.
- `examples/`: review examples against the draft; keep historical examples in a legacy folder.
- `LICENSE`: **retain existing Apache-2.0 licence** and honour IETF document licensing for extracted Code Components.

## Suggested safe Git procedure

1. Clone repository, create a `archive/pre-relaunch-2026` tag at current HEAD and push the tag.
2. Create `relaunch/v0.3-foundation` branch from `main`.
3. Copy overlay files into the working tree (overwrite `README.md`; add other files).
4. Inspect old files and commit a separate legacy reorganisation if appropriate.
5. Run markdown link checks, schema validation and security tests as implementation develops.
6. Open a pull request into `main` rather than force-pushing. Preserve commit history.

## Versioning

Protocol `0.3` refers to the published Internet-Draft's wire format. SDK releases use independent semantic versions, e.g. `0.1.0`, and are **not** necessarily protocol versions. route.fast product versioning is separate again.

## Release gates

- No release until semantic schema validation, JCS/JWS test vectors, canonical digest interoperability, audience binding, replay protection, grant enforcement and denial-path tests succeed.
- No insecure 'allow' fallback on evidence/signature verification failures.
- Do not treat model-generated explanations as authorization evidence by themselves.
