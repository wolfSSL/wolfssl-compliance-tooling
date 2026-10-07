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
  provider-metadata, optional OpenPGP signatures). `--gpg-key` takes the full
  40-hex fingerprint and signs with the gpg keyring
  (`gpg --local-user --armor --detach-sign`). `--default-key` is not used:
  an unusable key must fail, not fall back to another key. A short key id
  is rejected. The secret key is not written to a file. `--key-file` is the
  pgpy path for a test key.
  Sign at deploy, not in git. Honors `SOURCE_DATE_EPOCH`.
- `csaf-verify` — consumer-side check. Walks `index.txt` and hash sidecars.
  Signature checks require `--fingerprint` matching provider-metadata.json.
- `advisory-vex-overlay.schema.json` — the per-CVE overlay schema.
- `advisory-vex-overlay.example.json` — an overlay example.

The advisory tool is already multi-product. It keys the PURL and the CPE per
product. The security team makes the advisory from CVE records. No product needs
a build step for advisories.
