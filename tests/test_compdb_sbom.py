#!/usr/bin/env python3
"""Tests for the compilation-database frontend (share/frontends/compdb_sbom.py)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPDB = os.path.join(REPO, "share", "frontends", "compdb_sbom.py")

# Stands in for sbom-driver and writes its argv, one per line, to STUB_ARGV.
_STUB = """import os, sys
with open(os.environ['STUB_ARGV'], 'w') as f:
    f.write('\\n'.join(sys.argv[1:]))
"""


class CompdbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.db = os.path.join(self.d, "compile_commands.json")
        self.stub = os.path.join(self.d, "stub-driver")
        with open(self.stub, "w") as f:
            f.write("#!" + sys.executable + "\n" + _STUB)
        os.chmod(self.stub, 0o755)
        self.argv_path = os.path.join(self.d, "argv.txt")

    def tearDown(self):
        self.tmp.cleanup()

    def write_db(self, entries):
        db = []
        for name, flags in entries:
            src = os.path.join(self.d, name)
            open(src, "w").close()
            db.append({"directory": self.d, "file": name,
                       "arguments": ["cc", *flags, "-c", name]})
        with open(self.db, "w") as f:
            json.dump(db, f)

    def run_compdb(self, *extra):
        return subprocess.run(
            [sys.executable, COMPDB, self.db, "--name", "t",
             "--driver", self.stub, *extra],
            capture_output=True, text=True,
            env=dict(os.environ, STUB_ARGV=self.argv_path))

    def driver_argv(self):
        with open(self.argv_path) as f:
            return f.read().splitlines()


class TestConflictingDefines(CompdbCase):
    def test_different_values_fail(self):
        self.write_db([("a.c", ["-DFOO=10"]), ("b.c", ["-DFOO=2"])])
        r = self.run_compdb("--print-only")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FOO", r.stderr)
        self.assertIn("-DFOO=10", r.stderr)
        self.assertIn("-DFOO=2", r.stderr)
        self.assertIn("a.c", r.stderr)
        self.assertIn("b.c", r.stderr)
        self.assertIn("--include/--exclude", r.stderr)

    def test_bare_define_equals_value_one(self):
        self.write_db([("a.c", ["-DFOO"]), ("b.c", ["-DFOO=1"])])
        r = self.run_compdb("--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_empty_value_conflicts_with_bare_define(self):
        self.write_db([("a.c", ["-DFOO"]), ("b.c", ["-DFOO="])])
        r = self.run_compdb("--print-only")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FOO", r.stderr)

    def test_options_h_ignores_conflicting_defines(self):
        self.write_db([("a.c", ["-DUNIT_ID=1"]), ("b.c", ["-DUNIT_ID=2"])])
        r = self.run_compdb("--options-h", "options.h")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--options-h", self.driver_argv())

    def test_exclude_resolves_conflict(self):
        self.write_db([("a.c", ["-DFOO=10"]), ("b.c", ["-DFOO=2"])])
        r = self.run_compdb("--exclude", r"b\.c$", "--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-DFOO=10", r.stdout)
        self.assertNotIn("-DFOO=2", r.stdout)

    def test_undef_in_one_entry_is_not_a_conflict(self):
        self.write_db([("a.c", ["-DFOO=1"]), ("b.c", ["-DFOO=1", "-UFOO"])])
        r = self.run_compdb("--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-DFOO=1", r.stdout)

    def test_partial_defines_are_merged(self):
        self.write_db([("a.c", ["-DFOO=1", "-DONLY_A"]),
                       ("b.c", ["-DFOO=1", "-DONLY_B=2"])])
        r = self.run_compdb("--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("# 2 sources (0 included), 3 defines", r.stdout)
        for tok in ("-DFOO=1", "-DONLY_A", "-DONLY_B=2"):
            self.assertIn(tok, r.stdout)


class TestForwarding(CompdbCase):
    def test_identity_and_dependency_flags_reach_driver(self):
        self.write_db([("a.c", ["-DFOO=1"])])
        r = self.run_compdb(
            "--license-override", "GPL-3.0-or-later",
            "--license-text", "/lic.txt",
            "--supplier", "Example Inc.",
            "--component-type", "firmware",
            "--dep-wolfssl", "yes", "--dep-wolfcrypt", "yes",
            "--dep-openssl", "no",
            "--dep-version", "wolfssl=5.9.2",
            "--dep-version", "wolfcrypt=5.9.2")
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = self.driver_argv()
        pairs = list(zip(argv, argv[1:]))
        for pair in (("--license-override", "GPL-3.0-or-later"),
                     ("--license-text", "/lic.txt"),
                     ("--supplier", "Example Inc."),
                     ("--component-type", "firmware"),
                     ("--dep-wolfssl", "yes"),
                     ("--dep-wolfcrypt", "yes"),
                     ("--dep-openssl", "no"),
                     ("--dep-version", "wolfssl=5.9.2"),
                     ("--dep-version", "wolfcrypt=5.9.2")):
            self.assertIn(pair, pairs)
        self.assertIn("--cflags=-DFOO=1", argv)

    def test_options_h_replaces_cflags(self):
        self.write_db([("a.c", ["-DFOO=1"])])
        opts = os.path.join(self.d, "options.h")
        open(opts, "w").close()
        r = self.run_compdb("--options-h", opts)
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = self.driver_argv()
        self.assertIn(("--options-h", opts), list(zip(argv, argv[1:])))
        self.assertFalse(any(a.startswith("--cflags") for a in argv), argv)

    def test_options_h_with_capture_inputs_fails(self):
        self.write_db([("a.c", ["-DFOO=1"])])
        for extra in (["--settings-h", "settings.h"], ["--include-dir", "."]):
            r = self.run_compdb("--options-h", "options.h", *extra)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--options-h", r.stderr)
            self.assertFalse(os.path.exists(self.argv_path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
