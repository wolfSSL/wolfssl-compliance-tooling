# wolfGlass

## What is wolfGlass?

wolfGlass is the shared software-transparency toolkit for the wolfSSL product
family. The name is the point: it's what turns a product from a black box
into something you can see straight through. SBOM is the first and current
pillar; VEX/CSAF security advisories and build provenance (bomsh) are the
same idea applied to two more questions a customer eventually asks — "what's
in it," "does a given CVE actually affect me," and "can you prove this
artifact was built from what you say it was."

**Today, wolfGlass's shipped, working capability is SBOM generation.** The
rest of this document — and the rest of the toolkit's product-facing
workflow — is scoped to that. The advisory/VEX tooling (`central/`) and the
provenance verifier (`provenance/`) already live in the repository, but
they're not yet wired into the same product-adoption path as the SBOM
engine. Treat them as where wolfGlass is headed, not what a product
integrates against today.

Rather than every repository implementing and maintaining its own SBOM
generator, wolfGlass provides:

- one common SBOM engine
- one common validation pipeline
- thin adapters for each supported build system

Each product contributes only the information unique to its build, while
sharing the same generator — so output stays consistent, reproducible, and a
fix in one place reaches every repository.

```
   wolfBoot          wolfSSH           wolfHSM
      │                 │                 │
   sbom.mk           sbom.am      compile_commands.json
      │                 │                 │
      └────────────┬────┴─────────────────┘
                    ▼
              sbom-driver
                    │
                    ▼
                gen-sbom
                    │
                    ▼
       CycloneDX 1.6  +  SPDX 2.3
```

Every product feeds the same driver two things — its build configuration and
its build output — and gets the same validated SBOM shape back. That picture
is most of the design.

## Why wolfGlass exists

wolfSSL ships 28+ products across autotools, CMake, plain Make, IDE projects,
Kconfig builds, and five language ecosystems. Before wolfGlass, each product
hand-copied its own SBOM script. Without a shared toolkit:

- every repository implemented its own SBOM logic
- bug fixes had to be ported manually, repository by repository
- feature support drifted over time between copies
- validating output meant duplicating CI in every repo
- embedded and IDE-based products had no common approach at all

wolfGlass centralizes the implementation while leaving build-specific
knowledge inside small frontends. Fix a defect once in the generator, and
every product picks it up on its next sync — no per-product patch required.

## Why only two inputs

Every build system, however it's invoked, ultimately has to answer only two
questions:

1. **What configuration was compiled?** (which features, which macros)
2. **What software was actually produced?** (a library, a source set, a
   declared dependency, an as-built artifact)

Everything else — autotools vs. CMake vs. an IAR project vs. a Zephyr
module — is just a different way of discovering the answers to those same
two questions. wolfGlass's generator only ever sees the normalized answers,
never the build system that produced them. That's what makes it possible for
one generator to serve every product without knowing anything about any of
them.

| Axis | Values | Passed to `gen-sbom` as |
|---|---|---|
| Configuration | `options.h`, `user_settings.h`, `config.h`, kernel `.config` | `--options-h` / `--user-settings` / `--source-only` |
| Composition | built library, compiled source set, declared dependency, as-built artifact | `--lib` / `--srcs-file` / `--dep-wolfssl` / `--lib --no-artifact-hash` |

One constraint cuts across every product: a FIPS canister or a kernel module
is always hashed **as shipped**. No frontend may substitute a source list for
a certified binary, no matter how convenient that would be.

## Frontends: one per build system

A frontend's only job is producing those two inputs for one build system and
handing them to `sbom-driver`. **Frontends never generate SBOMs themselves** —
that separation is what lets one product use several frontends (one per build
system it ships) while all of them converge on the same engine.

| Frontend | Build system | What it extracts |
|---|---|---|
| `sbom.am` | Autotools | Stages a private `make install`, discovers the installed library/binary, hashes it; config from `AM_CPPFLAGS`/`config.h`. |
| `build/sbom.cmake` | CMake | Same shape, called as `wolfglass_add_sbom()` with `NAME`/`TARGETS`/`DEFS`. Also adds `install-sbom` and `uninstall-sbom`. |
| `build/sbom.mk` | Plain Make | Product sets `SBOM_NAME`/`SBOM_SRCS`/`SBOM_CFLAGS` (plus `SBOM_SETTINGS_H` when a `user_settings.h` derives the config), includes the fragment. |
| `frontends/compdb_sbom.py` | Any `compile_commands.json` | The universal fallback — TI CCS, MPLAB X, Renesas e2studio, or anything wrappable with `bear -- make ...`. |
| `frontends/iar_sbom.py` | IAR Embedded Workbench `.ewp` | Parses the project XML directly — there's no build step to hook into. |
| `frontends/zephyr_sbom.py` | Zephyr module | Reads `zephyr_library_sources(...)` since west owns the actual build. |

## Products can occupy more than one tier

`docs/TIERS.md` is the authoritative product-by-frontend matrix. Products
group into tiers by how they relate to wolfSSL — root, linker, embedder,
standalone, language binding, feature, or kit — but **a product may occupy
multiple tiers at once**. wolfHSM is the clearest case: its core library is
Tier S (`LIB`), its tests/examples are Tier E (`SRC`), and its restricted
vendor ports are a separate, currently-unwired category of their own.

## Design principles

- One generator. It never becomes aware of build systems.
- Thin build adapters. Each knows exactly one build system.
- No duplicated SBOM logic, anywhere.
- Reproducible output — the same config and composition always produce a
  byte-identical SBOM.
- Air-gap friendly — no network fetch at generation time.
- Product-specific build knowledge stays inside the product's frontend, never
  leaks into the shared engine.

## Document identity

The CycloneDX `serialNumber` and the SPDX `documentNamespace` are derived from
the package name, the version, and a digest of the build configuration, so two
SBOMs for one release but different configurations (FIPS vs non-FIPS, a
different `--srcs` set, a different feature-flag or dependency set, a different
supplier or component type) get distinct identifiers. SPDX 2.3 section 6.5 requires
`documentNamespace` to be unique, and a CycloneDX `version: 1` document sharing
a `serialNumber` with differing content is self-contradictory.

The rule the generator holds to: **every input that can change the document
body reaches the identity digest.** `tests/test_sbom_identity.py` enforces it
over the whole option set, so a new option cannot land without being
classified identity-relevant or identity-exempt.

Reproducibility is unaffected: an identical configuration still produces
byte-identical output, including the identifiers.

**One-time rotation.** Identifiers changed once when the configuration digest
was introduced, and again whenever a new input is folded in. SBOMs published
before that carry the old values. This is a rotation, not a break: the
identifiers were previously wrong (colliding across configurations), and
nothing downstream should pin a literal `serialNumber`.

**Identity follows the artefact on the `--lib` path.** The library's SHA-256
is part of the digest, so rebuilding identical sources with a different
toolchain moves the `serialNumber` even though no configuration input changed.
That is deliberate. An SBOM generated from `--lib` describes one specific
binary, and two binaries with different hashes are two artefacts; giving them
one identifier would be the same collision in a different disguise. The
`--srcs` and `--no-artifact-hash` paths do not have this property, because
neither hashes a compiler output.

## Distribution: vendor a snapshot, not a dependency

Products vendor a snapshot of the toolkit into their own tree (`tools/sbom/`
by default) via `tools/wolfglass-sync`, and pin the exact version and source
commit they copied. This is deliberate over a git submodule: a submodule
breaks source tarballs, needs network access at clone time, and adds files to
what should be a frozen, air-gapped-buildable tree. A CI drift check
(`wolfglass-sync --check`) confirms a product's vendored copy still matches
the source.

## Using wolfGlass

Typical integration for a new product:

1. Vendor wolfGlass: `tools/wolfglass-sync --dest /path/to/product`.
2. Add the one frontend that matches your build system.
3. Provide the configuration input (`--options-h`, `--user-settings`, or
   `--source-only`).
4. Provide the composition input (`--lib`, `--srcs-file`, or `--dep-wolfssl`).
5. Run `sbom-driver` (directly, or through the Make/CMake/autotools fragment).
6. Validate in CI with `validate_sbom.py` and the reusable
   `sbom-reusable.yml` workflow

## The bigger picture: SBOM is pillar one, not the whole toolkit

wolfGlass is organized around three transparency pillars, and the repository
layout already reflects this even though only the first is fully built out:

| Pillar | Answers | Lives in | Status |
|---|---|---|---|
| SBOM | What's actually in this build? | `share/` | Built, vendored, in production use |
| Advisory / VEX (CSAF 2.0) | Does CVE-X actually affect this product? | `central/` | Tooling exists (`gen-advisory`); run centrally per-CVE, not vendored into products |
| Provenance (bomsh / OmniBOR) | Can we prove this artifact came from this source, this way? | `provenance/` | Verifier exists (`bomsh_verify.py`); the build-tracing wrapper itself is still planned |
do
The advisory and provenance pillars are deliberately **not** vendored into
each product the way the SBOM engine is — they're meant to run centrally
(advisories are authored once per CVE, not once per product) or opt-in per
release (provenance tracing is expensive to run on every PR). As those
pillars mature, expect this document to grow a second and third "Using
wolfGlass" walkthrough alongside the SBOM one above — but that's future work,
not something to design against yet.

## Current limitations

- No offline schema bundle yet for CDX 1.6 / SPDX 2.3 validation.
- The `wolfglass-bomsh` build-tracing wrapper is planned; only the verifier
  (`bomsh_verify.py`) exists today.
- A Kbuild/DKMS frontend for Linux kernel modules is planned, not yet built.

For the full product-by-frontend matrix, the program plan, and maintainer-level
notes on the current state of the repository, see [`docs/PLAN.md`](docs/PLAN.md),
[`docs/TIERS.md`](docs/TIERS.md), and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).e sent us the sboms he generated, can we check the
