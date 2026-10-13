# provenance/

This is the optional build-provenance capability (bomsh / OmniBOR).

Planned contents (see `docs/PLAN.md`):

- `wolfssl-compliance-tooling-bomsh` — a build-system-agnostic wrapper that traces a build.
- `bomsh_verify.py` — the provenance verifier.

Rules:

- Run bomsh on Linux only.
- Depend on the external `bomtrace3` and bomsh scripts. Pin their version.
- Enable bomsh per product on demand. Most products do not need it.
- Run bomsh at release time or nightly, not on each pull request.
