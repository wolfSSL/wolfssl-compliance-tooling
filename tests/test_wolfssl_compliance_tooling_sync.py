#!/usr/bin/env python3
"""Tests for tools/wolfssl-compliance-tooling-sync, focused on the --subdir containment guard.

--subdir is joined onto --dest and then written into, so an absolute value or
one containing .. must be refused rather than allowed to place/overwrite files
outside the product's vendoring path."""

import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNC = os.path.join(REPO, "tools", "wolfssl-compliance-tooling-sync")


def _run(dest, subdir):
    return subprocess.run(
        [sys.executable, SYNC, "--dest", dest, "--subdir", subdir],
        capture_output=True, text=True)


class TestSubdirContainment(unittest.TestCase):
    def test_relative_subdir_copies_inside_dest(self):
        with tempfile.TemporaryDirectory() as dest:
            r = _run(dest, "tools/sbom")
            self.assertEqual(r.returncode, 0, r.stderr)
            # gen-sbom is part of share/, so it must land under the subdir.
            self.assertTrue(
                os.path.isfile(os.path.join(dest, "tools", "sbom", "gen-sbom")),
                os.listdir(dest))

    def test_absolute_subdir_rejected(self):
        with tempfile.TemporaryDirectory() as dest, \
                tempfile.TemporaryDirectory() as outside:
            target = os.path.join(outside, "pwned")
            r = _run(dest, target)               # absolute path
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--subdir", r.stderr)
            self.assertFalse(os.path.exists(target),
                             "absolute --subdir wrote outside --dest")

    def test_dotdot_subdir_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            dest = os.path.join(parent, "product")
            os.mkdir(dest)
            r = _run(dest, "../escape")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("escapes --dest", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(parent, "escape")),
                             "../ --subdir wrote outside --dest")

    def test_subdir_symlink_outside_rejected(self):
        with tempfile.TemporaryDirectory() as dest, \
                tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(dest, "link"))
            r = _run(dest, "link")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("escapes --dest", r.stderr)
            self.assertEqual(os.listdir(outside), [],
                             "symlinked --subdir wrote outside --dest")

    def test_root_dest_accepts_nested_subdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.relpath(os.path.join(tmp, "a", "b"), os.sep)
            r = _run(os.sep, sub)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(
                os.path.isfile(os.path.join(tmp, "a", "b", "gen-sbom")))


class TestSymlinkInsideDest(unittest.TestCase):
    """A symlink already present under --subdir must not redirect writes."""

    def test_file_symlink_escape_refused(self):
        with tempfile.TemporaryDirectory() as dest, \
                tempfile.TemporaryDirectory() as outside:
            victim = os.path.join(outside, "victim")
            with open(victim, "w") as f:
                f.write("original\n")
            sbom = os.path.join(dest, "tools", "sbom")
            os.makedirs(sbom)
            os.symlink(victim, os.path.join(sbom, "gen-sbom"))
            r = _run(dest, "tools/sbom")
            self.assertNotEqual(r.returncode, 0)
            with open(victim) as f:
                self.assertEqual(f.read(), "original\n")
            self.assertEqual(os.listdir(outside), ["victim"])

    def test_dir_symlink_escape_refused(self):
        with tempfile.TemporaryDirectory() as dest, \
                tempfile.TemporaryDirectory() as outside:
            sbom = os.path.join(dest, "tools", "sbom")
            os.makedirs(sbom)
            os.symlink(outside, os.path.join(sbom, "frontends"))
            r = _run(dest, "tools/sbom")
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(os.listdir(outside), [],
                             "symlinked dir under --subdir wrote outside")


if __name__ == "__main__":
    unittest.main(verbosity=2)
