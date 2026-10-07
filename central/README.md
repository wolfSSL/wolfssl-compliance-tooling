# central/

These tools run for wolfSSL only. Do not vendor them into a product.

- `gen-advisory` — the CSAF 2.0 and CycloneDX VEX generator.
- `advisory-completeness` — the release gate. Each product release is one
  directory under `advisories/releases/<version>/` (`cves`, `ChangeLog.md`,
  optional `prior-release.cves`, `mentions.cves`, `supplemental.cves`).
  CI loops those directories; it does not name a version.

      python3 central/advisory-completeness --release-dir advisories/releases/5.9.2

      python3 central/advisory-completeness --release 5.9.2 \
          --changelog ../wolfssl/ChangeLog.md

  It checks completeness only; it cannot judge whether a determination is
  correct — that is human analysis. Count ChangeLog bullets of the form
  `* [High] CVE-…` as members. The tool also computes a loose set of every
  CVE id in the Vulnerabilities section and fails if the strict rule dropped
  an id that is not listed in `mentions.cves`. `supplemental.cves` holds ids
  fixed in this release but not a ChangeLog bullet here (late disclosure).
  `--release` must match the CVE-list path when both flags are set.
- `csaf-publish` — assemble the `.well-known/csaf` directory (hashes, index,
  provider-metadata, optional OpenPGP signatures via pgpy). Sign at deploy,
  not in git. Honors `SOURCE_DATE_EPOCH`.
- `csaf-verify` — consumer-side check. Walks `index.txt` and hash sidecars.
  Signature checks require `--fingerprint` matching provider-metadata.json.
- `csaf-fetch` — download a published provider directory by `index.txt`.
  The folder URL returns 403, so this does not list the folder. A monthly
  workflow runs this against the website and then runs `csaf-verify`.
  It does not pass `--fingerprint` until the site publishes `.asc` files.

      python3 central/csaf-fetch \
          --url https://www.wolfssl.com/.well-known/csaf \
          --out /tmp/csaf \
          --vex
      python3 central/csaf-verify --root /tmp/csaf

  `--vex` also fetches `name.cdx.json` beside each CSAF file. The command
  fails when that file is missing, when its CVE ids differ, or when a VEX
  entry has no CVSS v4 score.
- `advisory-vex-overlay.schema.json` — the per-CVE overlay schema.
- `advisory-vex-overlay.example.json` — an overlay example.

The advisory tool is already multi-product. It keys the PURL and the CPE per
product. The security team makes the advisory from CVE records. No product needs
a build step for advisories.
