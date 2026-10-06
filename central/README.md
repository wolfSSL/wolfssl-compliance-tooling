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
- `advisory-overlay-draft` — write missing overlay keys from the ChangeLog.
  It does not publish. It leaves an existing key unchanged unless you pass
  `--replace`, which rewrites that key in the file (one copy). Read every
  REVIEW line, then run `advisory-completeness`.

  A macro is recorded when it sits next to a gate (`--enable-foo (MACRO)`,
  `(MACRO / --enable-foo)`, `define MACRO`). "MACRO is defined" is not a
  gate. Put one machine line on a bullet when the prose is not that shape.
  `defines=` with no names means the default build is affected, and the
  script does not guess. A line that starts with `VEX:` is machine input.
  Spaces around commas are allowed. Any other shape stops the command and
  writes nothing.

      VEX: fixed=5.9.4; defines=HAVE_ALPN
      VEX: fixed=5.9.4; defines=HAVE_ALPN, OPENSSL_EXTRA
      VEX: fixed=5.9.4; defines=

      python3 central/advisory-overlay-draft --release 5.9.4 \
          --changelog ../wolfssl/ChangeLog.md

      python3 central/advisory-overlay-draft --release 5.9.4 \
          --changelog ../wolfssl/ChangeLog.md --dry-run

      python3 central/advisory-overlay-draft --release 5.9.4 \
          --changelog ../wolfssl/ChangeLog.md --replace
- `csaf-publish` — assemble the `.well-known/csaf` directory (hashes, index,
  provider-metadata, optional OpenPGP signatures via pgpy). Sign at deploy,
  not in git. Honors `SOURCE_DATE_EPOCH`.
- `csaf-verify` — consumer-side check. Walks `index.txt` and hash sidecars.
  Signature checks require `--fingerprint` matching provider-metadata.json.
- `advisory-vex-overlay.schema.json` — the per-CVE overlay schema.
- `advisory-vex-overlay.example.json` — an overlay example.

The advisory tool is already multi-product. It keys the PURL and the CPE per
product. The security team makes the advisory from CVE records. No product needs
a build step for advisories.
