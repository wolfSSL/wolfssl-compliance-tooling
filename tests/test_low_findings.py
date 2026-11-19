#!/usr/bin/env python3
"""Regression tests for the low-severity review-findings bundle (gpex.20)."""

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARE = os.path.join(REPO, "share")
GEN_SBOM = os.path.join(SHARE, "gen-sbom")
VALIDATE = os.path.join(SHARE, "validate_sbom.py")

def _load(name, path):
    loader = SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


gs = _load("gen_sbom", GEN_SBOM)
drv = _load("sbom_driver", os.path.join(SHARE, "sbom-driver.py"))
compdb = _load("compdb_sbom",
               os.path.join(SHARE, "frontends", "compdb_sbom.py"))


class TestAtomicWrite(unittest.TestCase):
    def test_writes_content_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            gs.write_json_atomic({"a": 1}, p)
            with open(p) as f:
                self.assertEqual(json.load(f), {"a": 1})
            self.assertFalse(os.path.exists(p + ".tmp"))

    def test_dev_stdout_redirected_to_file(self):
        # `--cdx-out /dev/stdout > out.json`: /dev/stdout is a symlink to the
        # redirected file and must be written through, not replaced.
        code = ("import importlib.util as u; "
                "from importlib.machinery import SourceFileLoader as L; "
                "l = L('g', %r); m = u.module_from_spec("
                "u.spec_from_loader('g', l)); l.exec_module(m); "
                "m.write_json_atomic({'a': 1}, '/dev/stdout')" % GEN_SBOM)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.json")
            with open(out, "w") as f:
                r = subprocess.run([sys.executable, "-c", code], stdout=f,
                                   stderr=subprocess.PIPE, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as f:
                self.assertEqual(json.load(f), {"a": 1})

    def test_symlinked_output_is_followed(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "target.json")
            link = os.path.join(d, "link.json")
            with open(target, "w") as f:
                f.write("old")
            os.symlink(target, link)
            gs.write_json_atomic({"a": 1}, link)
            self.assertTrue(os.path.islink(link))
            with open(target) as f:
                self.assertEqual(json.load(f), {"a": 1})

    def test_existing_mode_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            open(p, "w").close()
            os.chmod(p, 0o640)
            gs.write_json_atomic({"a": 1}, p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o640)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses file permissions")
    def test_read_only_output_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            with open(p, "w") as f:
                f.write("keep")
            os.chmod(p, 0o444)
            with self.assertRaises(PermissionError):
                gs.write_json_atomic({"a": 1}, p)
            with open(p) as f:
                self.assertEqual(f.read(), "keep")
            self.assertEqual(os.listdir(d), ["out.json"])

    def test_fifo_written_directly(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.fifo")
            os.mkfifo(p)
            reader = subprocess.Popen(["cat", p], stdout=subprocess.PIPE)
            gs.write_json_atomic({"a": 1}, p)
            out, _ = reader.communicate(timeout=10)
            self.assertEqual(json.loads(out), {"a": 1})
            self.assertTrue(stat.S_ISFIFO(os.lstat(p).st_mode))


class TestSrcsRealpathDedup(unittest.TestCase):
    def test_same_file_two_spellings_collapses(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "foo.c")
            open(f, "w").close()
            got = gs._collect_srcs([f, os.path.join(d, ".", "foo.c")], None)
            self.assertEqual(len(got), 1, got)

    def test_symlink_alias_stays_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "foo.c")
            alias = os.path.join(d, "bar.c")
            open(f, "w").close()
            os.symlink(f, alias)
            got = gs._collect_srcs([f, alias], None)
            self.assertEqual(got, [f, alias])


class TestValidateSbomRobustness(unittest.TestCase):
    def _run(self, content_or_none, name="x.cdx.json"):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, name)
            if content_or_none is not None:
                with open(p, "w") as f:
                    f.write(content_or_none)
            return subprocess.run([sys.executable, VALIDATE, p],
                                  capture_output=True, text=True)

    def test_non_dict_json_rejected_cleanly(self):
        r = self._run("[1, 2, 3]")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not an object", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_missing_file_no_traceback(self):
        r = self._run(None)  # file never created
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)

    def test_non_utf8_rejected_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.cdx.json")
            with open(p, "wb") as f:
                f.write(b'{"bomFormat": "\xff\xfe"}')
            r = subprocess.run([sys.executable, VALIDATE, p],
                               capture_output=True, text=True,
                               env=dict(os.environ, PYTHONUTF8="1"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_directory_input_rejected_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, VALIDATE, d],
                               capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


class TestScrubWindowsPath(unittest.TestCase):
    def test_windows_abs_path_redacted(self):
        out = drv.scrub_defines('#define SDK "C:\\Users\\me\\sdk"\n')
        self.assertNotIn("Users", out)
        self.assertIn("SDK", out)


class TestReadVersionEmptyMacro(unittest.TestCase):
    def test_empty_macro_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            h = os.path.join(d, "v.h")
            with open(h, "w") as f:
                f.write('#define COPYRIGHT "2026 wolfSSL"\n')
            self.assertEqual(drv.read_version(h, ""), "")


class TestCompdbUndefine(unittest.TestCase):
    def test_later_undef_cancels_define(self):
        got = compdb.extract_defines(["-DFOO", "-DBAR=1", "-UFOO"])
        self.assertIn("BAR=1", got)
        self.assertNotIn("FOO", got)

    def test_separate_arg_forms(self):
        got = compdb.extract_defines(["-D", "A=1", "-U", "A"])
        self.assertNotIn("A=1", got)

    def test_function_like_macro_undef(self):
        got = compdb.extract_defines(["-DF(a)=a", "-DG(x)", "-UF", "-UG"])
        self.assertEqual(got, [])


class TestCompdbRootSlash(unittest.TestCase):
    def test_root_slash_keeps_sources(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.c")
            open(src, "w").close()
            db = os.path.join(d, "compile_commands.json")
            with open(db, "w") as f:
                json.dump([{"directory": d, "file": src,
                            "arguments": ["cc", "-c", src]}], f)
            r = subprocess.run(
                [sys.executable,
                 os.path.join(SHARE, "frontends", "compdb_sbom.py"), db,
                 "--name", "t", "--root", "/", "--print-only"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("# 1 sources", r.stdout)
            self.assertIn(src, r.stdout)


# A gen-sbom stand-in: --help lists the flags and counts the calls; a run
# records the SOURCE_DATE_EPOCH it got.
_FAKE_GEN = """\
import os, sys
here = os.path.dirname(os.path.abspath(__file__))
if "--help" in sys.argv:
    with open(os.path.join(here, "help-calls"), "a") as f:
        f.write("x")
    print("--document-namespace --component-type --dep-wolfssl --dep-version")
    sys.exit(0)
with open(os.path.join(here, "sde"), "w") as f:
    f.write(os.environ.get("SOURCE_DATE_EPOCH", ""))
"""


def _need_git(test):
    if shutil.which("git") is None:
        test.skipTest("git is not installed")


def _git(cwd, *argv):
    return subprocess.run(["git", *argv], cwd=cwd, capture_output=True,
                          text=True, check=True).stdout.strip()


def _commit(repo):
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "sbom@example.invalid")
    _git(repo, "config", "user.name", "sbom")
    with open(os.path.join(repo, "a.c"), "w") as f:
        f.write("int a;\n")
    _git(repo, "add", "a.c")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init",
         "--date", "@1600000000")
    return _git(repo, "log", "-1", "--format=%ct")


class TestDriverGenSbomCalls(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self.gen = os.path.join(self.dir, "gen-sbom")
        with open(self.gen, "w") as f:
            f.write(_FAKE_GEN)
        drv._gen_sbom_help.cache_clear()

    def _read(self, name):
        path = os.path.join(self.dir, name)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return f.read()

    def test_help_is_read_once(self):
        for flag in ("--dep-wolfssl", "--dep-version", "--dep-libz"):
            drv.gen_sbom_supports(sys.executable, self.gen, flag)
        self.assertTrue(drv.gen_sbom_supports(sys.executable, self.gen,
                                              "--component-type"))
        self.assertFalse(drv.gen_sbom_supports(sys.executable, self.gen,
                                               "--dep-libz"))
        self.assertEqual(self._read("help-calls"), "x")

    def _run_driver(self, root, env, pass_root=True, cwd=None):
        srcs = os.path.join(self.dir, "srcs.txt")
        with open(srcs, "w") as f:
            f.write(os.path.join(root, "a.c") + "\n")
        if not os.path.exists(os.path.join(root, "a.c")):
            open(os.path.join(root, "a.c"), "w").close()
        license_file = os.path.join(self.dir, "LICENSE")
        with open(license_file, "w") as f:
            f.write("GPLv3\n")
        cmd = [sys.executable, os.path.join(SHARE, "sbom-driver.py"),
               "--name", "t", "--version", "1.0", "--srcs-file", srcs,
               "--source-only"]
        if pass_root:
            cmd += ["--root", root]
        return subprocess.run(
            [*cmd, "--gen-sbom", self.gen,
             "--license-file", license_file,
             "--dep-wolfssl", "yes", "--dep-version", "wolfssl=5.0.0",
             "--component-type", "library",
             "--cdx-out", os.path.join(self.dir, "o.cdx.json"),
             "--spdx-out", os.path.join(self.dir, "o.spdx.json")],
            capture_output=True, text=True, env=env, cwd=cwd)

    def test_driver_reads_help_once_per_run(self):
        root = os.path.join(self.dir, "src")
        os.mkdir(root)
        r = self._run_driver(root, dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._read("help-calls"), "x")

    def test_unset_value_uses_the_commit_time(self):
        _need_git(self)
        root = os.path.join(self.dir, "repo")
        os.mkdir(root)
        stamp = _commit(root)
        env = dict(os.environ)
        env.pop("SOURCE_DATE_EPOCH", None)
        r = self._run_driver(root, env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._read("sde"), stamp)

    def test_set_value_wins_over_git(self):
        _need_git(self)
        root = os.path.join(self.dir, "repo")
        os.mkdir(root)
        _commit(root)
        r = self._run_driver(root, dict(os.environ, SOURCE_DATE_EPOCH="111"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._read("sde"), "111")

    def test_omitted_root_does_not_use_the_working_directory(self):
        # cwd is this checkout. With no --root the driver must not take
        # its commit time.
        root = os.path.join(self.dir, "src")
        os.mkdir(root)
        env = dict(os.environ)
        env.pop("SOURCE_DATE_EPOCH", None)
        r = self._run_driver(root, env, pass_root=False, cwd=REPO)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._read("sde"), "")

    def test_untracked_root_inside_a_checkout_gets_no_value(self):
        # A release tarball unpacked inside another checkout must not take
        # that checkout's commit time.
        _need_git(self)
        outer = os.path.join(self.dir, "repo")
        os.mkdir(outer)
        _commit(outer)
        root = os.path.join(outer, "unpacked")
        os.mkdir(root)
        self.assertEqual(drv.default_source_date_epoch(root), "")
        env = dict(os.environ)
        env.pop("SOURCE_DATE_EPOCH", None)
        r = self._run_driver(root, env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._read("sde"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
