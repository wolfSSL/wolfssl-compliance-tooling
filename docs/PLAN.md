# wolfssl-compliance-tooling Program Plan

This plan follows ASD-STE100 Simplified Technical English: short sentences,
active voice, one idea per sentence, imperative for steps, vertical lists, and
one term for one thing.

## 1. Scope

This plan describes the wolfssl-compliance-tooling project. wolfssl-compliance-tooling is one toolkit that makes
software transparency artifacts for all wolfSSL products. The artifacts are the
SBOM, the security advisory, the VEX, and the build provenance.

## 2. Terminology

Use these terms with one meaning only.

| Term | Meaning |
|---|---|
| toolkit | The wolfssl-compliance-tooling repository and its tools. |
| the generator | The `gen-sbom` script that makes an SBOM. |
| the fragment | A shared build recipe (`sbom.am`, `sbom.cmake`, or `sbom.mk`). |
| product repository | A repository that ships a wolfSSL product. |
| to vendor | To copy a controlled toolkit file into a product repository. |
| the pin | The `VERSION` value that records the toolkit release in use. |
| central | Made one time in one place, not in each product repository. |
| out-of-tree | Run against a checkout, but write no file into that checkout. |
| SBOM | Software Bill of Materials (CycloneDX 1.6 and SPDX 2.3). |
| CSAF | Common Security Advisory Framework 2.0 advisory. |
| VEX | Vulnerability Exploitability eXchange statement. |
| bomsh | The OmniBOR build-trace tool that adds provenance. |

## 3. Problem

The EU Cyber Resilience Act starts full obligations on 11 December 2027. The Act
requires a machine-readable SBOM for each product with digital elements. wolfSSL
ships more than 30 products. The products use many build systems: autotools,
CMake, plain Make, `user_settings.h`, and language package managers.

Today the SBOM tools live inside the wolfSSL repository. Each product repository
copies the fragment by hand. There is no version pin and no drift check. This
causes three problems:

- The copied fragments drift apart.
- The CMake products and the plain-Make products duplicate about 120 to 150 lines each.
- The hard cases have no clean home: air-gapped builds, embedded builds, and FIPS-certified bundles.

## 4. Solution

Create wolfssl-compliance-tooling as one standalone repository. Make wolfssl-compliance-tooling the single source
of truth for the SBOM tools. Keep the generator unchanged, because it is already
product-agnostic. Add two design elements:

- One vendorable set of files that each product copies with a pin.
- One out-of-tree mode for bundles that you must not modify.

Give each build system one shared fragment:

- `sbom.am` for autotools.
- `sbom.cmake` with `sbom_run.cmake` for CMake.
- `sbom.mk` for plain Make.

Keep the advisory tool and the provenance tool central. Do not vendor them into
each product.

## 5. Benefits

- Fix a defect one time. Then all products get the fix.
- The output stays reproducible, because the pin and `SOURCE_DATE_EPOCH` control it.
- The SBOM maps upstream CVEs onto each downstream product.
- The tools run on air-gapped Linux, embedded hosts, and Windows.
- The out-of-tree mode keeps FIPS-certified bundles bit-identical.
- A shared GPLv3 license matches the current wolfSSL repositories and removes a
  license mismatch when code moves between wolfssl-compliance-tooling, wolfSSL, and wolfBoot.

## 6. Product tiers

Each product belongs to one tier. The tier shows how the product uses wolfSSL.
The tier sets the SBOM method.

| Tier | Name | Build system | wolfSSL link | SBOM method |
|---|---|---|---|---|
| R | Root / generator | autotools, CMake, user_settings | Root | Hash `libwolfssl`. Capture `options.h`. |
| L | Linker | autotools, some CMake | Yes (`--dep-wolfssl`) | Hash own library or binary. |
| E | Embedder | plain Make | No (wolfcrypt inside) | Hash a source merkle (`--srcs-file`). |
| S | Standalone | Make, autotools, CMake | Only if linked | Hash own library. |
| B | Language binding | Maven, pip, cargo, go, .NET | Declares wolfSSL | Hash the wrapper package. |
| Feature | Part of wolfSSL | via wolfSSL | Inside wolfSSL | Covered by the wolfSSL SBOM. |
| External | External consumer | autotools, CMake | Declares wolfSSL | Out-of-tree. |
| Kit | Customer demo | CMake, user_settings | References wolfSSL | Two-level composition. |

The tier is not the whole story. One product can use many build systems, and the
SBOM method has two independent axes: the config (what the build enabled) and the
composition (what artifact the build produced). One constraint sits across both:
a FIPS canister and a kernel module must be hashed as-built and must not use a
substituted source list. `docs/TIERS.md` holds the full product-by-front-end
matrix, the two axes, the as-built constraint, and the dictionary. Treat
`docs/TIERS.md` as the authoritative roster.

## 7. Product list by tier

**Tier R (root):**

- wolfSSL (autotools and CMake).
- wolfCrypt (same source tree as wolfSSL).

**Tier L (links libwolfssl):**

- wolfSSH.
- wolfProvider (autotools only; also OpenSSL).
- wolfEngine (autotools only; also OpenSSL).
- wolfCLU (hashes the wolfssl binary).
- wolfSCEP (autotools only; GPLv2-or-later).
- wolfTPM (autotools and CMake).
- wolfMQTT (autotools and CMake).
- wolfPKCS11 (not in this workspace; verify at the source).

The wolfSSL kernel modules (`linuxkm` and `bsdkm`) and wolfGuard are the as-built
`LIB*` case. Hash the module as built. Do not substitute a source list. wolfGuard
links `linuxkm`; its tier is still unset. See `docs/TIERS.md`.

**Tier E (embeds wolfcrypt sources):**

- wolfBoot.
- wolfHSM (tests and examples).

**Tier S (standalone library):**

- wolfSentry (plain Make only; CMake in one example).
- wolfHSM (core library; vendor ports are restricted stubs).
- wolfIP.

**Tier B (language binding):**

- wolfSSL JNI/JSSE.
- wolfCrypt JNI/JCE.
- wolfSSL Python.
- wolfCrypt Python.
- wolfCrypt rustls provider.
- wolfSSL Go.
- wolfSSL C# (in-tree wrapper).

**Feature (part of wolfSSL):**

- wolfCrypt.
- SSL/TLS Sniffer.
- wolfEntropy.
- wolfFE.

**External:**

- curl (candidate; confirm scope before you attest).
- tinycurl (candidate; confirm scope before you attest).

**Kit:**

- CRA Kit (base).
- CRA Kit (CMake and embedded).

## 8. Repository design

Use this structure for the wolfssl-compliance-tooling repository.

```
wolfssl-compliance-tooling/
├── README.md
├── LICENSE                 (GPLv3; aligned with wolfSSL repos)
├── VERSION                 (toolkit release; products pin to this)
├── share/                  (the ONLY vendorable set)               [DONE]
│   ├── sbom-driver.py      (product-neutral Python engine)
│   ├── sbom-driver         (thin shell wrapper)
│   ├── validate_sbom.py    (structural validator; --name-prefix)
│   ├── frontends/
│   │   ├── compdb_sbom.py  (compile_commands.json extractor)
│   │   ├── iar_sbom.py     (IAR .ewp extractor)
│   │   └── zephyr_sbom.py  (Zephyr module extractor)
│   ├── build/
│   │   ├── sbom.mk         (plain-Make fragment)
│   │   └── sbom.cmake      (CMake: wolfssl_compliance_tooling_add_sbom())
│   ├── gen-sbom            (populated after the engine-home sign-off) [PENDING]
│   └── sbom.am             (autotools fragment; lifted from wolfSSL) [PENDING]
├── central/                (never vendored; runs for wolfSSL only)  [PENDING]
│   ├── gen-advisory
│   ├── advisory-vex-overlay.schema.json
│   └── advisory-vex-overlay.example.json
├── provenance/             (opt-in; Linux CI; all products on demand)[PENDING]
│   ├── wolfssl-compliance-tooling-bomsh
│   └── bomsh_verify.py
├── schemas/                (CDX 1.6 and SPDX 2.3, for offline validation)[PENDING]
├── tools/
│   ├── wolfssl-compliance-tooling-sync      (copies share/ into a product; supports --src) [DONE]
│   └── wolfssl-compliance-tooling           (out-of-tree driver)                    [PENDING]
├── .github/workflows/
│   ├── selftest.yml        (wolfssl-compliance-tooling CI: unit + integration)      [DONE]
│   └── sbom-reusable.yml   (reusable workflow for products)        [DONE]
├── tests/
│   └── test_sbom.py        (unit + integration self-test)          [DONE]
└── docs/
```

Vendor only the `share/` files. Do not put a `share/` folder into a product. The
synced files go into the product `tools/sbom/` folder. The driver, the
extractors, and the fragments keep their relative layout, so a product needs no
path configuration.

## 9. Name

Use the name wolfssl-compliance-tooling.

## 10. Distribution model

Use the copy-sync method as the standard method for products that wolfSSL owns.

- Run `wolfssl-compliance-tooling-sync` to copy the needed files.
- Write the pin next to the files (`VERSION` and `.wolfssl-compliance-tooling-rev`).
- Add `make sbom-selfcheck` to detect drift.

Use the out-of-tree mode for bundles that you must not change.

- Run `wolfssl-compliance-tooling --src <checkout> --out <sibling>`.
- Use this mode for FIPS bundles, external consumers, and the CRA Kit.

Do not use a git submodule as the standard method. A submodule breaks source
tarballs. A submodule needs network access at clone time. A submodule adds files
to a frozen tree.

Do not pull the latest generator at build time. A network pull breaks
reproducibility. A network pull fails on air-gapped hosts. A network pull adds
supply-chain risk.

Vendor the generator into the release tarballs. Then an air-gapped customer has a
self-contained build. Keep the `WOLFSSL_DIR` reference for day-to-day work.

## 11. Changes to the current tools

Do not change how the generator makes an SBOM. The generator is already generic.
It accepts `--name`, `--version`, `--supplier`, and the dependency flags. It
accepts `--options-h`, `--user-settings`, `--lib`, `--srcs-file`, and
`--no-artifact-hash`.

Add one required behavior to the shared driver: scrub absolute host paths from
the captured macros. A path-valued define, for example
`-DPICO_SDK_PATH=$(PICO_SDK_PATH)` from `arch.mk`, otherwise makes the SBOM
machine-specific and leaks a local path into a shipped artifact. wolfBoot already
implements this scrub in `tools/scripts/wolfboot-sbom.sh`. Promote that scrub to
the shared driver so every product gets it. Keep a `--no-scrub` flag for debug
only.

Decide these two items one time:

- Keep wolfssl-compliance-tooling under GPLv3 to match wolfSSL and wolfBoot. This removes license
  friction when code moves between the repositories.
- Choose whether to rename the producer identity. A rename changes every SBOM one time. If you rename it, also raise the generator version in the same commit.

## 12. Shared build fragments

Give the two build systems that lack a shared fragment their own fragment.

- `sbom.cmake` replaces about 150 duplicated lines in the CMake products.
- `sbom.mk` gives the plain-Make products one common recipe.

Make the CMake fragment a function, not a per-product target. Today three CMake
copies exist and drift: wolfMQTT (inline in `CMakeLists.txt`), wolfTPM (inline in
`CMakeLists.txt`), and wolfBoot (`cmake/sbom.cmake`). Each copy re-parses the
version header, re-checks the wolfSSL path, and re-detects python. Provide one
`wolfssl_compliance_tooling_add_sbom()` function in `sbom.cmake`. Each product calls it with its
name, its version header, its targets, and its define variables. Do not bless
wolfBoot's `cmake/sbom.cmake` as canonical, because that makes a fourth copy.
Converge the three copies onto the one function.

Reduce the per-product wiring to a manifest. For autotools this is already true:
a product sets a few `SBOM_*` variables and includes `sbom.am`. Match that model
for Make and CMake. Keep only the true product knowledge in the product: the
route-through script, the module extractor, and the HAL source selector.

Centralize version detection and generator discovery in the shared layer. The
manifest passes two strings (the version header path and the version macro name).
The manifest does not re-implement the regex or the search path.

Note: `user_settings.h` already solves the config capture. The gap is the recipe,
not the config. Standardize the options mode on "direct" to match `sbom.am`. Then
the CMake SBOM stays byte-comparable with the autotools SBOM.

## 13. Advisories (CSAF and VEX)

Keep the advisory tool central. The `gen-advisory` tool is already multi-product.
It builds the PURL and the CPE per product, the same as the generator.

- Author the CSAF advisory one time per CVE. wolfSSL Inc. is one manufacturer.
- Make one VEX per product. The VEX answer depends on the build of each product.
- Do not add a build step to each product for advisories. The security team makes the advisory from CVE records.

Publish the per-product VEX next to the per-product SBOM if a customer needs it.
This is a publish choice, not a tool change. The customer makes the VEX for the
customer end product.

## 14. Provenance (bomsh)

Host bomsh in wolfssl-compliance-tooling under `provenance/`. bomsh is reusable, because it traces
build syscalls. The trace works for any build system on Linux.

- Depend on the external `bomtrace3` and bomsh scripts. Pin their version. Do not vendor them.
- Run bomsh on Linux only. Use Linux CI, WSL2, or a container for other hosts.
- Enable bomsh per product on demand. Most products do not need it.
- Run bomsh at release time or nightly. Do not run bomsh on each pull request, because it needs a full traced rebuild.

## 15. CI strategy

Keep the CI logic central in wolfssl-compliance-tooling as reusable workflows. Let each product
repository call the workflows. This removes the current duplicate `sbom.yml`
files.

| Job | Runs in | Trigger |
|---|---|---|
| Tool unit tests and reproducibility | wolfssl-compliance-tooling | each pull request to wolfssl-compliance-tooling |
| Integration canary (one product per tier) | wolfssl-compliance-tooling | each pull request to wolfssl-compliance-tooling and nightly |
| Drift check (`sbom-selfcheck`) | each product repository | each pull request |
| SBOM build and validate | each product repository | each pull request, filtered by path |
| SBOM release artifact | each product repository | on a tag or release |
| bomsh provenance | product or wolfssl-compliance-tooling | on release, nightly, or on demand |
| Version-bump propagation | automation | on a wolfssl-compliance-tooling release |

Generate the SBOM in the product repository, because the build lives there.
Validate on each pull request. Attach the real SBOM at release time. Do not
commit generated SBOMs on each pull request, because they cause churn.

## 16. Update and version management

- Pin each product to one wolfssl-compliance-tooling `VERSION`.
- Release wolfssl-compliance-tooling with a version number and a changelog.
- Open a bot pull request on each release. The pull request re-syncs `share/` and raises the pin.
- Let each product CI validate the bump.
- Never auto-update at build time.

Protect against a bad change with two controls:

- Run the canary in wolfssl-compliance-tooling before a release.
- Move a product only after its own CI passes.

## 17. Tests

- Keep the generator tests and the advisory tests in wolfssl-compliance-tooling.
- Run the unit tests on each wolfssl-compliance-tooling pull request.
- Run the reproducibility test to confirm byte-equal output.
- Validate sample output against the pinned schemas.
- Never vendor the tests into a product.

## 18. Constraints

The tools must meet these constraints.

- Run with pure Python 3 and no required third-party package.
- Use no network at generation time.
- Validate offline with the pinned schemas.
- Support the no-library and no-`options.h` cases with `--srcs-file` and `--no-artifact-hash`.
- Write no file into a FIPS-certified bundle.

## 19. Migration plan

Migrate in the order of lowest risk. Decide first. Prove the hard path once with
wolfBoot. Then move the easy products in a batch. Then do the hard tail.

wolfBoot already ships the reference implementation (commit that adds
`tools/scripts/wolfboot-sbom.sh`, the IDE extractors, `cmake/sbom.cmake`, the
validator, and a CI canary). The tools are written to be product-neutral. So the
work is mostly relocation and de-branding, plus one real refactor of the CMake
layer.

**Phase 0 — Decide (unblocks everything).**

1. Choose the driver language. Prefer Python for Windows and air-gap parity.
   Keep a thin shell wrapper.
2. Choose the vendored path name. Use one name in every product.
3. Confirm the generator home and get a named owner's sign-off. See §21.

**Phase 1 — Scaffold wolfssl-compliance-tooling `share/`.**

1. Define the manifest contract (the `SBOM_*` variables for Make and the
   `wolfssl_compliance_tooling_add_sbom()` arguments for CMake).
2. Lift the driver and the extractors into `share/`. De-brand the wolfBoot
   defaults (name, version header, generator path, name prefix).
3. Promote the path scrub to the shared driver.

**Phase 2 — wolfBoot (the reference migration).**

1. Refactor the CMake target into the shared `wolfssl_compliance_tooling_add_sbom()` function.
2. Keep the product knowledge in wolfBoot: the route-through script, the Zephyr
   extractor, and the HAL selector.
3. Re-vendor `share/` back into wolfBoot. Prove the round trip.

**Phase 3 — wolfSSL (the canonical source).**

1. Make wolfssl-compliance-tooling canonical for the generator and `sbom.am`.
2. Make wolfSSL a `wolfssl-compliance-tooling-sync` target that keeps its own vendored copy.
3. Add no build-time dependency on wolfssl-compliance-tooling.

**Phase 4 — Batch the easy products.**

1. Re-point the autotools products to the vendored `sbom.am` (wolfSSH,
   wolfMQTT, wolfEngine, wolfCLU, wolfSCEP). This is near-free.
2. Collapse the CMake products (wolfMQTT, wolfTPM) onto the shared function.
   This deletes about 150 duplicated lines each.

**Phase 5 — Add the shared tools and CI.**

1. Write `wolfssl-compliance-tooling-sync` and stamp the pin into each vendored copy.
   The pin is `VERSION` plus `.wolfssl-compliance-tooling-rev`.
2. Write the `wolfssl-compliance-tooling` out-of-tree driver.
3. Write `wolfssl-compliance-tooling-bomsh` from the current bomsh recipe.
4. Write the reusable workflows. Add the canary matrix. Add the drift check that
   validates the call site, not only the file hashes.

**Phase 6 — The hard tail.**

1. wolfHSM: add per-port source-list extractors; mark the restricted stubs.
2. wolfSSL kernel (linuxkm and bsdkm) and wolfGuard: add the Kbuild extractor and
   the as-built `LIB*` rule.
3. Assign the wolfGuard tier and owner.

**Phase 7 — Propagate and pin.**

1. Release wolfssl-compliance-tooling v1.0.
2. Open the bump pull requests.
3. Confirm each product CI passes.

## 20. Risks and mitigations

| Risk | Mitigation |
|---|---|
| A toolkit change breaks a product SBOM. | Run the canary before each release. |
| A vendored fragment drifts. | Run the drift check on each pull request. |
| A rename rotates every SBOM. | Rename one time and raise the generator version. |
| An air-gapped build has no generator. | Vendor the generator into the release tarball. |
| The CMake and autotools output differ. | Standardize the options mode on "direct". |

## 21. Open decisions

Decide these before Phase 1. They block the code work or set its shape.

- Choose the driver language. Prefer Python for Windows and air-gap parity. Keep
  a thin shell wrapper. Decide this before the lift, because it is cheapest then.
- Choose the vendored path name. Use one name in every product, for example
  `tools/sbom/`. The sync tool and the drift check depend on one convention.
- Confirm the generator home. wolfssl-compliance-tooling is canonical. wolfSSL keeps a vendored
  copy and gains no build-time dependency. This touches licensing and the FIPS
  release process, so it needs a named owner's sign-off.

Decide these before Phase 7. They do not block the code work.

- License choice is set: GPLv3 to match wolfSSL repositories.
- Choose the location of the CRA Kit. Keep it in the examples repository and reference wolfssl-compliance-tooling.
- Choose whether to rename the producer identity now or later.
- Assign the wolfGuard tier and owner.
