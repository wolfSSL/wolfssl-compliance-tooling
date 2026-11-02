#!/usr/bin/env python3
"""share/build/sbom.mk: no literal tabs, and the recipes it builds still run."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SBOM_MK = ROOT / "share" / "build" / "sbom.mk"
MAKE = shutil.which("make")

STUB_DRIVER = """#!/bin/sh
for a in "$@"; do printf '%s\\n' "$a"; done > "$STUB_OUT"
"""


class NoTabTests(unittest.TestCase):
    def test_sbom_mk_has_no_literal_tab(self):
        # wolfSSL's source check rejects literal tabs in .mk files.
        for number, line in enumerate(
                SBOM_MK.read_text().splitlines(), start=1):
            self.assertNotIn("\t", line, f"sbom.mk:{number} has a tab")


class RecipeTests(unittest.TestCase):
    def setUp(self):
        if not MAKE:
            self.skipTest("make is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        driver = self.dir / "stub-driver"
        driver.write_text(STUB_DRIVER)
        driver.chmod(0o755)
        self.out = self.dir / "args.txt"

    def _make(self, body, *args, after=""):
        (self.dir / "Makefile").write_text(
            f"SBOM_DRIVER := {self.dir / 'stub-driver'}\n"
            f"{body}\n"
            f"include {SBOM_MK}\n"
            f"{after}\n")
        env = os.environ.copy()
        env["STUB_OUT"] = str(self.out)
        return subprocess.run(
            [MAKE, "--no-print-directory", *args], cwd=self.dir, env=env,
            text=True, capture_output=True, check=False)

    def _args(self):
        return self.out.read_text().splitlines()

    def test_default_target_forwards_the_driver_arguments(self):
        result = self._make(
            "SBOM_NAME := demo\n"
            "SBOM_SRCS := a.c b.c\n"
            "SBOM_CFLAGS := -DFOO=1 -DSIZE=$$(( 4 - 1 ))\n"
            "SBOM_VERSION := 1.2.3\n"
            "SBOM_DEP_VERSION := one=1 two=2\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self._args()
        self.assertEqual(args[:2], ["--name", "demo"])
        self.assertIn("--srcs-file", args)
        # The shell does the arithmetic. Make must not read $(( as a
        # variable reference.
        self.assertIn("--cflags=-DFOO=1 -DSIZE=3", args)
        self.assertEqual(args[args.index("--version") + 1], "1.2.3")
        joined = " ".join(args)
        self.assertIn("--dep-version one=1 --dep-version two=2", joined)
        self.assertNotIn("--lib", args)

    def test_second_target_from_call(self):
        result = self._make(
            "SBOM_NAME := demo\n"
            "SBOM_LIB := libdemo.a\n"
            "SBOM_HAL_NAME := demo-hal\n"
            "SBOM_HAL_LIB := libhal.a\n",
            "sbom-hal",
            after="$(eval $(call wolfssl_compliance_tooling_sbom_rule,"
                  "sbom-hal,SBOM_HAL_))")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self._args()
        self.assertEqual(args[:2], ["--name", "demo-hal"])
        self.assertEqual(args[args.index("--lib") + 1], "libhal.a")

    def test_command_line_sbom_tab_does_not_break_the_rule(self):
        result = self._make(
            "SBOM_NAME := demo\nSBOM_LIB := libdemo.a\n", "SBOM_TAB=x")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--lib", self._args())

    def test_shell_without_printf_stops_with_a_clear_error(self):
        false = shutil.which("false")
        if not false:
            self.skipTest("false is not installed")
        result = self._make(
            "SBOM_NAME := demo\nSBOM_LIB := libdemo.a\n", f"SHELL={false}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs a POSIX shell with printf", result.stderr)

    def test_missing_name(self):
        result = self._make("SBOM_LIB := libdemo.a\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: set SBOM_NAME", result.stdout)
        self.assertFalse(self.out.exists())

    def test_missing_composition(self):
        result = self._make("SBOM_NAME := demo\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: set SBOM_SRCS or SBOM_LIB", result.stdout)
        self.assertFalse(self.out.exists())

    def test_no_artifact_hash_stands_alone(self):
        result = self._make(
            "SBOM_NAME := demo\nSBOM_LIB := libdemo.a\n"
            "SBOM_NO_ARTIFACT_HASH := 1\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SBOM_NO_ARTIFACT_HASH stands alone", result.stdout)
        self.assertFalse(self.out.exists())

    def test_no_artifact_hash_alone(self):
        result = self._make(
            "SBOM_NAME := demo\nSBOM_NO_ARTIFACT_HASH := 1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self._args()
        self.assertIn("--no-artifact-hash", args)
        self.assertNotIn("--lib", args)
        self.assertNotIn("--srcs-file", args)


if __name__ == "__main__":
    unittest.main()
