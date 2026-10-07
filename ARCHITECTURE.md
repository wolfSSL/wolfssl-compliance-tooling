# wolfssl-compliance-tooling Architecture & Current-State Notes

This is the maintainer-facing companion to the README. The README explains what
wolfssl-compliance-tooling is and why it exists; this document goes one level deeper — the exact
driver contract, the full tier mapping, the CI model, and the specific things
this checkout showed that the team should act on. Reviewed against
`wolfSSL/wolfssl-compliance-tooling.git` @ `3ab77f9` (2026-07-24).

**Scope note:** wolfssl-compliance-tooling is a three-pillar transparency toolkit — SBOM,
advisory/VEX (CSAF), and build provenance (bomsh) — but only the SBOM pillar
(`share/`) is built out to the point of having a product-adoption workflow,
CI, and a sync/pin/drift-check mechanism. Everything below is written
against that pillar specifically. `central/` (advisories) and `provenance/`
(bomsh) exist in the tree but are intentionally centralized/opt-in rather
than vendored, and don't yet have the same maturity — see `docs/PLAN.md` §13
and §14 for their intended (not yet fully implemented) operating model.

## 1.  contract, precisely

`share/gen-sbom` never sees a build system — only normalized inputs, exactly
one from each axis:

- **Composition** (pick one): `--srcs-file PATH` (tier E — hash the compiled
  source set as an OmniBOR-style gitoid Merkle hash), `--lib PATH` (tier
  R/L/S — hash the built artifact), or `--no-artifact-hash` (record the
  artifact as-built and do not re-derive — for a FIPS canister or kernel
  module; never substitute a source list here).
- **Config** (pick one): `--cflags="..."` (driver expands `-D` tokens through
  the host compiler), `--options-h PATH` (a pre-expanded flat `#define`
  header, used verbatim), `--user-settings PATH` (captured by the generator
  itself), or `--source-only` (Kconfig-driven builds with no macro set).
- **Dependency** (linkers/bindings only): `--dep-wolfssl`, `--dep-openssl`,
  `--dep-version` — passed through only when the generator advertises support
  for them (feature-detected against `gen-sbom --help`).

`share/sbom-driver` (with `sbom-drivere actual engine, and a thin
shell wrapper for portability) captures macros using the **host** compiler,
never the cross-compiler, which is what makes output reproducible across
toolchains — the same config produces a byte-identical SBOM whether the
product was built with gcc, clang, IAR, armcl, or ccrx. It also scrubs
absolute host paths out of captured macros before they reach `gen-sbom`
(disable with `--no-scrub`, debug only) — this is what the reusable CI
workflow's path-leak grep is a backstop for, not the primary defense.

## 2. Full tier-to-composition mapping

`docs/TIERS.md` is authoritative here — treat it as canonical over
`PLAN.md`'s product list, since every fact in it is marked ✔ (verified in a
workspace) or ✘ (not verified, confirm at source) rather than asserted.

| Tier | Example products | Composition |
|---|---|---|
| R — Root/generator | wolfSSL itself | `LIB` — hash `libwolfssl` |
| L — Linker | wolfSSH, wolfTPM, wolfMQTT, wolfProvider, wolfCLU | `LIB` (own artifact) + `-| E — Embedder | wolfBoot, wolfHSM (core + tests) | `SRC` — source Merkle hash, no separate binary |
| S — Standalone | wolfSentry, wolfIP, wolfHSM core library | `LIB`, sometimes `SRC` |
| B — Language binding | JNI/JSSE, Python, Go, Rust, C# wrappers | `DEP` — declared dependency only, no rebuild |
| Feature | wolfCrypt, SSL/TLS Sniffer | none — covered inside wolfSSL's own SBOM |
| Kit | CRA Kit | two-level composition (kit + its wolfSSL dependency nested) |

wolfHSM straddles three of these at once: Tier S for its core library
(`LIB`, plain Make), Tier E for its tests/examples (`SRC`), and its six vendor
ports sit outside the matrix entirely — `▢` restricted stubs with no public
build files, so no frontend can be wired until each port owner confirms
whether a private build exists and what form it takes.

## 3. Distribution mechanics

`tools/wolfssl-compliance-tooling-sync` is a plain byte-for-byte copier — confirmed by reading
the script, not just its docstring. No templating, no path rewriting. It:

1e under `share/` into the product at `tools/sbom/`
   (default, overridable with `--subdir`).
2. Writes `VERSION` (toolkit release) and `.wolfssl-compliance-tooling-rev` (exact git commit
   synced from) next to the copy.
3. In `--check` mode, diffs the vendored copy against the source and exits
   non-zero on drift — the mechanism a product's own CI drift check calls.

This is deliberate over a git submodule (`PLAN.md` §10): a submodule breaks
source tarballs, needs network access at clone time, and adds files to what
should be a frozen, air-gapped-buildable tree.

## 4. CI model

Two workflows live centrally in wolfssl-compliance-tooling, not duplicated per product:

- **`.github/workflows/selftest.yml`** — runs in wolfssl-compliance-tooling itself, on every
  push/PR: syntax-checks all vendored Python, runs the generator unit tests,
  runs the integration self-test.
- **`.github/workflows/sbom-reusable.yml`** — a reusable workflow a product
  calls with its own build command and name prefix. It optionally re-clones
  wolfssl-compliance-tooling at a pinned ref to rdrift check, builds the SBOM,
  validates it with `validate_sbom.py --name-prefix`, and greps the output
  for absolute host paths (`/home/`, `/Users/`, `/root/`) as a hard CI gate
  backstopping the driver's own scrub.

## 5. Current-state findings (act on these)

These are things this checkout showed directly, not inferred from the docs:

- **A downstream pin can reference a commit that doesn't exist upstream.**
  This checkout's `HEAD` is `3ab77f9`. A `.wolfssl-compliance-tooling-rev` pinned to `a7d769a`
  in a downstream product does not exist in this repository (confirmed with
  `git cat-file -e`). Any product vendored against an unpushed wolfssl-compliance-tooling
  commit has an unverifiable pin, and the reusable workflow's drift check
  would fail against the real remote until that commit is pushed. Action:
  push the commits those pins depend on, or re-sync and re-pin against
  `3ab77f9`.
- **The sync tool doesn't rewrite relative-path prose, so it can
  self-contradict once vendored.** `share/README.md` says "the shared driver
  ... calls the vendored `share/gen-sbom` by default" — true in wfGlass
  itself, but `wolfssl-compliance-tooling-sync` copies that sentence verbatim into every
  product's `tools/sbom/README.md`, where the file actually lives at
  `tools/sbom/gen-sbom`. Action: reword the source doc to say "the sibling
  `gen-sbom`" (not a path) so every future sync is correct by construction.
- **Stray empty `ci/workflows/` directory** at the repo root (just
  `.gitkeep`), not in the documented layout and not referenced anywhere.
  Looks like scaffolding left over from before `.github/workflows/` was
  settled on. Action: delete it, or document why it's kept if intentional.
- **Confirmed present and matching README claims:** `share/` is complete
  (driver, generator, three build fragments, three frontends, validator),
  both CI workflow files exist and run what they claim to.
- **Confirmed absent, and correctly marked pending:** `schemas/` (only
  `.gitkeep`) and the `wolfssl-compliance-tooling-bomsh` tracer wrapper (only the verifier,
  `bomsh_verify.py`, exists). The docs are honest about both gaps.

## 6. Recommended next steps

1. Push the wolfssl-compliance-tooling commits the downstream pins already depend on, or
   re-sync those products against `3ab77f9` and update their pins.
2. Fix the `share/gen-sbom` → sibling-path wording in `share/README.md`
   before the next sync round.
3. Delete the empty `ci/workflo/` directory, or document its purpose.
4. Keep `docs/TIERS.md` as the single source of truth for "does product X
   support build system Y"; consider having `PLAN.md`'s tier list just link
   to it instead of maintaining a second, looser copy.
5. For the six restricted wolfHSM vendor ports, get an explicit answer from
   each port owner before wiring any frontend — finding no build files in the
   public tree is evidence of "no in-ee build," not proof no private build
   exists elsewhere.
