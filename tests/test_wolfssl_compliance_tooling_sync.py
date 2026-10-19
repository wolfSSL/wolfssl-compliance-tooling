#!/usr/bin/env python3
"""Tests for tools/wolfssl-compliance-tooling-sync: the --subdir containment
guard and the --check drift report.

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



def _sync(dest, *extra):
    return subprocess.run(
        [sys.executable, SYNC, "--dest", dest, *extra],
        capture_output=True, text=True)


class TestCheckAndPrune(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = self._tmp.name
        self.sbom = os.path.join(self.dest, "tools", "sbom")
        r = _sync(self.dest)
        self.assertEqual(r.returncode, 0, r.stderr)

    def tearDown(self):
        self._tmp.cleanup()

    def _add_stale(self):
        stale = os.path.join(self.sbom, "frontends", "old_sbom.py")
        with open(stale, "w") as f:
            f.write("# removed upstream\n")
        return stale

    def test_clean_copy_passes_check(self):
        r = _sync(self.dest, "--check")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_check_reports_stale_file(self):
        self._add_stale()
        r = _sync(self.dest, "--check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("old_sbom.py (not in share/)", r.stderr)

    def test_check_ignores_bytecode(self):
        cache = os.path.join(self.sbom, "frontends", "__pycache__")
        os.makedirs(cache)
        with open(os.path.join(cache, "x.cpython-312.pyc"), "wb") as f:
            f.write(b"\0")
        r = _sync(self.dest, "--check")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_check_reports_lost_executable_bit(self):
        gen = os.path.join(self.sbom, "gen-sbom")
        os.chmod(gen, 0o644)
        r = _sync(self.dest, "--check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gen-sbom (executable bit)", r.stderr)

    def test_sync_restores_executable_bit(self):
        gen = os.path.join(self.sbom, "gen-sbom")
        os.chmod(gen, 0o644)
        r = _sync(self.dest)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.access(gen, os.X_OK))

    def test_sync_without_prune_keeps_stale_file(self):
        stale = self._add_stale()
        r = _sync(self.dest)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--prune", r.stderr)
        self.assertTrue(os.path.isfile(stale))

    def test_prune_deletes_stale_file(self):
        stale = self._add_stale()
        olddir = os.path.join(self.sbom, "olddir")
        os.makedirs(olddir)
        with open(os.path.join(olddir, "gone.py"), "w") as f:
            f.write("\n")
        r = _sync(self.dest, "--prune")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(stale))
        self.assertFalse(os.path.exists(olddir))
        self.assertTrue(os.path.isfile(os.path.join(self.sbom, "VERSION")))
        r = _sync(self.dest, "--check")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_stale_directory_symlink_reported_and_pruned(self):
        with tempfile.TemporaryDirectory() as target:
            with open(os.path.join(target, "keep.py"), "w") as f:
                f.write("\n")
            link = os.path.join(self.sbom, "old-frontends")
            os.symlink(target, link)
            r = _sync(self.dest, "--check")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("old-frontends (not in share/)", r.stderr)
            r = _sync(self.dest, "--prune")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(os.path.lexists(link))
            self.assertTrue(os.path.isfile(os.path.join(target, "keep.py")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
