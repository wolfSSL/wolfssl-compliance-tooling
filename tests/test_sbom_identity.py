#!/usr/bin/env python3
"""SBOM identity uniqueness: the CycloneDX serialNumber and SPDX
documentNamespace must be unique per build configuration, not just per
name+version, while an identical configuration still reproduces byte-for-byte.

The invariant is one-directional: a change to the document body must move the
serialNumber, not the reverse.  So every case establishes that the body
changed before demanding that the identity did.

Unit tests cover the digest fields, an end-to-end table covers one row per
identity-relevant CLI option, and an ast canary over gen-sbom's add_argument
calls stops a new option landing unclassified.
"""

import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_SBOM = os.path.join(REPO, "share", "gen-sbom")

# Fixed clock for every generator invocation in this file.  Without it two
# runs differ in `metadata.timestamp` / `creationInfo.created` alone, every
# "did the body change?" precondition passes vacuously, and the table below
# would report success while proving nothing.
SOURCE_DATE_EPOCH = "1700000000"

# uuid5(NAMESPACE_URL, 'https://wolfssl.com/sbom/').  Pinned as a literal: the
# PR that introduced config_identity claims the UUID namespace is unchanged,
# and a claim nothing asserts is a claim that rots.  Deriving the expected
# value from gen-sbom instead would make the constant its own oracle.
EXPECTED_UUID_NAMESPACE = "56864c8d-3868-5725-af0e-7e273d90b385"


def _load_gen_sbom():
    """Import share/gen-sbom as a module.

    It has no .py suffix, so spec_from_file_location cannot infer a loader;
    hand it a SourceFileLoader explicitly.  exec_module rather than
    SourceFileLoader.load_module(), which is deprecated -- Python 3.11 warns
    it is slated for removal, and CI floats on `python-version: '3.x'`.
    tests/test_gen_sbom.py uses this same shape."""
    loader = SourceFileLoader("gen_sbom", GEN_SBOM)
    spec = importlib.util.spec_from_loader("gen_sbom", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


gs = _load_gen_sbom()


# The declared split of gen-sbom's option set.  Relevant: the option can change
# the document body, so it must reach the seed, directly (--name, --version) or
# via config_identity.  Exempt: it cannot, and says why -- exempt is the side
# that reintroduces the collision if used to silence the canary.
IDENTITY_RELEVANT = frozenset({
    "--name",
    "--version",
    "--supplier",
    "--component-type",
    "--copyright-start",
    "--license-file",
    "--license-override",
    "--license-text",
    "--options-h",
    "--user-settings",
    "--user-settings-include",
    "--user-settings-define",
    "--lib",
    "--srcs",
    "--srcs-file",
    "--no-artifact-hash",
    "--dep-wolfssl",
    "--dep-wolfcrypt",
    "--dep-openssl",
    "--dep-libz",
    "--crypto-only",
    "--dep-version",
})

IDENTITY_EXEMPT = {
    "--document-namespace":
        "Operator-supplied replacement for the derived documentNamespace. An "
        "identifier, not a property of the build: seeding it from itself is "
        "circular, and two documents differing only here already differ in "
        "the field that identifies them.",
    "--cdx-out":
        "Output path. Names where the document is written, not what is in it.",
    "--spdx-out":
        "Output path. Names where the document is written, not what is in it.",
}


class TestConfigIdentityUnit(unittest.TestCase):
    BASE = dict(lib_hash="a" * 64, license_id="GPL-2.0-only",
                build_props=[("HAVE_AES", "1")], enabled_deps=["wolfssl"],
                dep_versions={"wolfssl": "5.9.1"})

    def _id(self, **overrides):
        """Call config_identity with the five positional inputs plus any
        keyword-only fields under test.  The positional-only call must stay
        valid, which is why the added fields are keyword-only with defaults."""
        kw = dict(self.BASE)
        extra = {k: v for k, v in overrides.items() if k not in kw}
        kw.update({k: v for k, v in overrides.items() if k in kw})
        return gs.config_identity(kw["lib_hash"], kw["license_id"],
                                  kw["build_props"], kw["enabled_deps"],
                                  kw["dep_versions"], **extra)

    def test_identical_inputs_reproduce(self):
        self.assertEqual(self._id(), self._id())

    def test_differs_on_build_props(self):
        self.assertNotEqual(
            self._id(),
            self._id(build_props=[("HAVE_AES", "1"), ("HAVE_FIPS", "1")]))

    def test_differs_on_lib_hash(self):
        self.assertNotEqual(self._id(), self._id(lib_hash="b" * 64))

    def test_differs_on_deps_and_versions(self):
        self.assertNotEqual(self._id(), self._id(enabled_deps=[]))
        self.assertNotEqual(self._id(),
                            self._id(dep_versions={"wolfssl": "5.9.2"}))

    def test_differs_on_license(self):
        self.assertNotEqual(self._id(),
                            self._id(license_id="LicenseRef-wolfSSL-Commercial"))

    def test_build_prop_order_independent(self):
        # build_props is sorted inside config_identity.
        self.assertEqual(
            self._id(build_props=[("A", "1"), ("B", "2")]),
            self._id(build_props=[("B", "2"), ("A", "1")]))

    def test_positional_call_still_valid(self):
        # The added fields are keyword-only with defaults precisely so this
        # call shape survives.
        self.assertEqual(
            gs.config_identity("a" * 64, "GPL-2.0-only", [("HAVE_AES", "1")],
                               ["wolfssl"], {"wolfssl": "5.9.1"}),
            self._id())

    def test_differs_on_supplier(self):
        self.assertNotEqual(self._id(), self._id(supplier="Acme Ltd."))

    def test_differs_on_component_type(self):
        self.assertNotEqual(self._id(), self._id(component_type="firmware"))

    def test_differs_on_license_text(self):
        # Same SPDX identifier, different embedded text: two LicenseRef-*
        # builds under one commercial identifier are distinct documents.
        self.assertNotEqual(self._id(license_text="terms A"),
                            self._id(license_text="terms B"))

    def test_differs_on_hash_kind_and_source(self):
        self.assertNotEqual(self._id(hash_kind="library-binary"),
                            self._id(hash_kind="source-merkle-omnibor"))
        self.assertNotEqual(self._id(hash_source="lib"),
                            self._id(hash_source="srcs"))

    def test_differs_on_file_names(self):
        # The --lib rename with identical bytes: lib_hash cannot see it,
        # because lib_hash covers bytes only.
        self.assertNotEqual(self._id(file_names=["libwolfssl.a"]),
                            self._id(file_names=["libwolfssl-fips.a"]))

    def test_file_name_order_independent(self):
        self.assertEqual(self._id(file_names=["b.c", "a.c"]),
                         self._id(file_names=["a.c", "b.c"]))

    def test_differs_on_subset_and_basis(self):
        self.assertNotEqual(self._id(),
                            self._id(wolfssl_subset="wolfcrypt-only"))
        # Same claim, different provenance: operator assertion vs macro read.
        self.assertNotEqual(self._id(subset_basis="declared"),
                            self._id(subset_basis="captured"))

    def test_fields_do_not_alias(self):
        # Tagged, NUL-delimited framing: a value moved from one field to
        # another must not produce the same digest.
        self.assertNotEqual(self._id(supplier="x", component_type=None),
                            self._id(supplier=None, component_type="x"))


class TestOptionSetCanary(unittest.TestCase):
    """Every gen-sbom CLI option is classified identity-relevant or
    identity-exempt.  Adding an option without touching this file fails here,
    so the next option cannot silently reintroduce a serialNumber collision
    the way --supplier, --component-type and --crypto-only did.

    Reads the source with ast because gen-sbom builds its parser inline
    inside main(): there is no parser object to inspect without running it."""

    @staticmethod
    def _declared_options():
        with open(GEN_SBOM) as f:
            tree = ast.parse(f.read(), filename=GEN_SBOM)
        flags = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute):
                continue
            if fn.attr != "add_argument":
                continue
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    continue
                if isinstance(arg.value, str) and arg.value.startswith("--"):
                    flags.add(arg.value)
        return flags

    def test_every_option_is_classified(self):
        declared = self._declared_options()
        self.assertTrue(declared, "found no add_argument calls in gen-sbom")
        classified = IDENTITY_RELEVANT | set(IDENTITY_EXEMPT)
        unclassified = declared - classified
        self.assertFalse(
            unclassified,
            "gen-sbom options with no identity classification: "
            f"{sorted(unclassified)}.\n"
            "Decide whether each can change the emitted document body. If it "
            "can, add it to IDENTITY_RELEVANT, make sure it reaches "
            "config_identity, and add a row to IDENTITY_ROWS below. If it "
            "cannot, add it to IDENTITY_EXEMPT with the reason.")

    def test_no_stale_classifications(self):
        declared = self._declared_options()
        classified = IDENTITY_RELEVANT | set(IDENTITY_EXEMPT)
        stale = classified - declared
        self.assertFalse(
            stale,
            f"classified options gen-sbom no longer defines: {sorted(stale)}")

    def test_relevant_and_exempt_are_disjoint(self):
        self.assertFalse(IDENTITY_RELEVANT & set(IDENTITY_EXEMPT))

    def test_every_exemption_carries_a_reason(self):
        for flag, reason in IDENTITY_EXEMPT.items():
            self.assertTrue(reason.strip(), f"{flag} is exempt with no reason")

    def test_uuid_namespace_unchanged(self):
        # The PR folding config_identity into the seed claims the UUID
        # namespace is untouched; nothing else asserts it.
        self.assertEqual(str(gs.SBOM_UUID_NAMESPACE), EXPECTED_UUID_NAMESPACE)


class _GeneratorFixture(unittest.TestCase):
    """Shared corpus and runner for the end-to-end cases."""

    @classmethod
    def _write(cls, name, data, mode="w"):
        path = os.path.join(cls.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, mode) as f:
            f.write(data)
        return path

    @classmethod
    def _build_corpus(cls):
        w = cls._write
        cls.opts_h = w("opts.h", "#define HAVE_AES 1\n")
        cls.opts_h_alt = w("opts-alt.h",
                           "#define HAVE_AES 1\n#define HAVE_FIPS 1\n")
        # detect_license reads the abbreviated GPLvN form.
        cls.lic_gpl2 = w("LICENSING-gpl2", "Licensed under GPLv2.\n")
        cls.lic_gpl3 = w("LICENSING-gpl3", "Licensed under GPLv3.\n")
        cls.lic_text_a = w("terms-a.txt", "Commercial terms, revision A.\n")
        cls.lic_text_b = w("terms-b.txt", "Commercial terms, revision B.\n")
        # Identical bytes under two names: the rename the byte hash cannot see.
        archive = b"!<arch>\n" + b"\0" * 32
        cls.lib = w("libwolfssl.a", archive, "wb")
        cls.lib_renamed = w("libwolfssl-fips.a", archive, "wb")
        cls.src_a = w("aes.c", "int aes(void) { return 0; }\n")
        cls.src_b = w("sha.c", "int sha(void) { return 0; }\n")
        cls.src_c = w("rsa.c", "int rsa(void) { return 0; }\n")
        cls.srcs_list_a = w("srcs-a.txt", f"{cls.src_a}\n{cls.src_b}\n")
        cls.srcs_list_b = w("srcs-b.txt", f"{cls.src_a}\n{cls.src_c}\n")
        # settings.h pulls the customer's user_settings.h in through the
        # standard WOLFSSL_USER_SETTINGS gate, mirroring the real embedded
        # entry point (see TestParseUserSettings in tests/test_gen_sbom.py).
        gate = ('#ifdef WOLFSSL_USER_SETTINGS\n'
                '#include "user_settings.h"\n'
                '#endif\n')
        cls.settings_h = w("settings.h", gate)
        cls.settings_h_alt = w("settings-alt.h",
                               gate + "#define WOLFSSL_ALT_SETTINGS 1\n")
        w("inc-a/user_settings.h", "#define HAVE_AES 1\n")
        w("inc-b/user_settings.h", "#define HAVE_AES 1\n#define HAVE_ECC 1\n")
        cls.inc_a = os.path.join(cls.dir, "inc-a")
        cls.inc_b = os.path.join(cls.dir, "inc-b")

    @classmethod
    def _base_opts(cls):
        return {
            "--name": "wolfssl",
            "--version": "5.9.1",
            "--options-h": cls.opts_h,
            "--lib": cls.lib,
            "--license-file": cls.lic_gpl2,
        }

    @classmethod
    def _user_settings_opts(cls):
        """Baseline shifted to the embedded (pcpp) entry point, which is
        mutually exclusive with --options-h."""
        opts = cls._base_opts()
        opts["--options-h"] = None
        opts["--user-settings"] = cls.settings_h
        opts["--user-settings-include"] = [cls.inc_a]
        opts["--user-settings-define"] = ["WOLFSSL_USER_SETTINGS"]
        return opts

    @staticmethod
    def _argv(opts):
        argv = []
        for flag, value in opts.items():
            if value is None or value is False:
                continue
            if value is True:
                argv.append(flag)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    argv += [flag, str(item)]
            else:
                argv += [flag, str(value)]
        return argv

    def _generate(self, tag, overrides=None, opts=None):
        """Run gen-sbom and return (serial, documentNamespace, cdx, spdx).

        cdx/spdx are the parsed documents with the identity fields removed, so
        a caller asking "did the body change?" is not answered by the identity
        field itself.  SOURCE_DATE_EPOCH is fixed so the timestamp does not
        answer it either."""
        merged = dict(opts if opts is not None else self._base_opts())
        merged.update(overrides or {})
        cdx_path = os.path.join(self.dir, f"{tag}.cdx.json")
        spdx_path = os.path.join(self.dir, f"{tag}.spdx.json")
        env = dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH)
        proc = subprocess.run(
            [sys.executable, GEN_SBOM] + self._argv(merged)
            + ["--cdx-out", cdx_path, "--spdx-out", spdx_path],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0,
                         f"gen-sbom failed for {tag}:\n{proc.stderr}")
        with open(cdx_path) as f:
            cdx = json.load(f)
        with open(spdx_path) as f:
            spdx = json.load(f)
        serial = cdx["serialNumber"]
        namespace = spdx["documentNamespace"]
        cdx.pop("serialNumber", None)
        spdx.pop("documentNamespace", None)
        return serial, namespace, cdx, spdx


# One row per identity-relevant option: (label, left overrides, right
# overrides, baseline selector).  Empty `left` means the baseline; an option
# replacing a mutually exclusive baseline choice clears it with None.
def _identity_rows(f):
    base, us = f._base_opts, f._user_settings_opts
    return [
        ("--name", {}, {"--name": "wolfssh"}, base),
        ("--version", {}, {"--version": "5.9.2"}, base),
        ("--supplier", {}, {"--supplier": "Acme Ltd."}, base),
        ("--component-type", {}, {"--component-type": "firmware"}, base),
        ("--copyright-start", {}, {"--copyright-start": "2020"}, base),
        ("--license-file", {}, {"--license-file": f.lic_gpl3}, base),
        ("--license-override",
         {},
         {"--license-override": "LicenseRef-wolfSSL-Commercial",
          "--license-text": f.lic_text_a},
         base),
        ("--license-text",
         {"--license-override": "LicenseRef-wolfSSL-Commercial",
          "--license-text": f.lic_text_a},
         {"--license-override": "LicenseRef-wolfSSL-Commercial",
          "--license-text": f.lic_text_b},
         base),
        ("--options-h", {}, {"--options-h": f.opts_h_alt}, base),
        ("--user-settings", {}, {"--user-settings": f.settings_h_alt}, us),
        ("--user-settings-include", {},
         {"--user-settings-include": [f.inc_b]}, us),
        ("--user-settings-define", {},
         {"--user-settings-define": ["WOLFSSL_USER_SETTINGS", "HAVE_ECC=1"]},
         us),
        ("--lib", {}, {"--lib": f.lib_renamed}, base),
        ("--srcs",
         {"--lib": None, "--srcs": [f.src_a, f.src_b]},
         {"--lib": None, "--srcs": [f.src_a, f.src_c]},
         base),
        ("--srcs-file",
         {"--lib": None, "--srcs-file": f.srcs_list_a},
         {"--lib": None, "--srcs-file": f.srcs_list_b},
         base),
        ("--no-artifact-hash", {},
         {"--lib": None, "--no-artifact-hash": True}, base),
        ("--dep-wolfssl", {}, {"--dep-wolfssl": "yes"}, base),
        ("--dep-wolfcrypt", {}, {"--dep-wolfcrypt": "yes"}, base),
        ("--dep-openssl", {}, {"--dep-openssl": "yes"}, base),
        ("--dep-libz", {}, {"--dep-libz": "yes"}, base),
        ("--crypto-only", {}, {"--crypto-only": "yes"}, base),
        ("--dep-version",
         {"--dep-wolfssl": "yes"},
         {"--dep-wolfssl": "yes", "--dep-version": "wolfssl=9.9.9"},
         base),
    ]


class TestSerialUniquenessEndToEnd(_GeneratorFixture):
    @classmethod
    def setUpClass(cls):
        try:
            import pcpp  # noqa: F401
        except ImportError:
            raise AssertionError(
                "pcpp is not installed but is required by the --user-settings "
                "rows of the identity table (the embedded entry point). "
                "Install with: 'python3 -m pip install --user pcpp'. CI "
                "installs it in the unit job; see "
                ".github/workflows/selftest.yml.") from None
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = cls._tmp.name
        cls._build_corpus()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_different_config_distinct_same_config_reproducible(self):
        nonfips = self._generate("nonfips")
        fips = self._generate("fips", {"--options-h": self.opts_h_alt})
        again = self._generate("again")
        self.assertNotEqual(nonfips[0], fips[0], "serialNumber collided")
        self.assertNotEqual(nonfips[1], fips[1], "documentNamespace collided")
        self.assertEqual(nonfips[0], again[0], "same config not reproducible")
        self.assertEqual(nonfips[1], again[1], "same config not reproducible")

    def test_every_identity_relevant_option_moves_the_serial(self):
        rows = _identity_rows(self)
        covered = {label for label, _, _, _ in rows}
        self.assertEqual(
            covered, set(IDENTITY_RELEVANT),
            "identity table does not cover every identity-relevant option; "
            f"missing {sorted(set(IDENTITY_RELEVANT) - covered)}, "
            f"unexpected {sorted(covered - set(IDENTITY_RELEVANT))}")

        for index, (label, left, right, baseline) in enumerate(rows):
            with self.subTest(option=label):
                a = self._generate(f"row{index}a", left, opts=baseline())
                b = self._generate(f"row{index}b", right, opts=baseline())
                body_changed = (a[2] != b[2]) or (a[3] != b[3])
                self.assertTrue(
                    body_changed,
                    f"{label} no longer changes the document body; the row "
                    "proves nothing as written and needs updating")
                self.assertNotEqual(
                    a[0], b[0],
                    f"{label} changes the document body but not the "
                    "CycloneDX serialNumber: two documents with differing "
                    "content share one identifier")
                self.assertNotEqual(
                    a[1], b[1],
                    f"{label} changes the document body but not the SPDX "
                    "documentNamespace (SPDX 2.3 6.5 requires uniqueness)")

    def test_bom_refs_are_not_perturbed_by_the_identity_fold(self):
        """The PR folding config_identity into the serial seed claims bom-refs
        are unchanged.  bom-refs derive from name/version/role/dep-key only,
        so two configurations of one release must produce identical bom-refs
        while producing different serialNumbers."""
        def bom_refs(doc):
            refs = set()

            def walk(component):
                ref = component.get("bom-ref")
                if ref:
                    refs.add(ref)
                for child in component.get("components", []):
                    walk(child)

            metadata_component = doc.get("metadata", {}).get("component")
            if metadata_component:
                walk(metadata_component)
            for component in doc.get("components", []):
                walk(component)
            return refs

        base = self._generate("refs-base", {"--dep-wolfssl": "yes"})
        varied = self._generate("refs-varied",
                                {"--dep-wolfssl": "yes",
                                 "--options-h": self.opts_h_alt,
                                 "--supplier": "Acme Ltd."})
        self.assertNotEqual(base[0], varied[0],
                            "configurations did not diverge; test is vacuous")
        self.assertTrue(bom_refs(base[2]), "no bom-refs found to compare")
        self.assertEqual(bom_refs(base[2]), bom_refs(varied[2]),
                         "config_identity leaked into bom-refs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
