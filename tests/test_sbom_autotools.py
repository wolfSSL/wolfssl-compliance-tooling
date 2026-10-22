#!/usr/bin/env python3
"""End-to-end test for share/sbom.am: `make sbom` must record the SHA-256 of
the library that `make install` lays down."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARE = os.path.join(REPO, "share")

CONFIGURE_AC = """\
AC_INIT([fixture], [1.0.0])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_PROG_GREP
AC_PATH_PROG([PYTHON3], [python3])
AC_PATH_PROG([PYSPDXTOOLS], [pyspdxtools])
AC_PATH_PROG([GIT], [git])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
"""

MAKEFILE_AM = """\
ACLOCAL_AMFLAGS = -I m4
CLEANFILES =
lib_LTLIBRARIES = libfixture.la
libfixture_la_SOURCES = fixture.c
SBOM_PKGNAME = fixture
SBOM_LICENSE_FILE = $(srcdir)/LICENSING
include tools/sbom/sbom.am
"""

FIXTURE_C = "int fixture_answer(void) { return 42; }\n"

LICENSING = ("fixture is licensed under the GPLv3 (or at your option any "
             "later version).\n")


def _libtoolize():
    return shutil.which("libtoolize") or shutil.which("glibtoolize")


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestSbomAmHashesInstalledLibrary(unittest.TestCase):
    def setUp(self):
        missing = [t for t in ("autoreconf", "automake", "make", "cc",
                               "pyspdxtools")
                   if not shutil.which(t)]
        if not _libtoolize():
            missing.append("libtoolize")
        if missing:
            self.skipTest("missing tools: " + ", ".join(missing))
        self.tmp = tempfile.mkdtemp(prefix="sbom-autotools-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run(self, cmd, cwd, env):
        r = subprocess.run(cmd, cwd=cwd, env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         f"{' '.join(cmd)} failed\n{r.stdout}\n{r.stderr}")

    def _configure_fixture(self):
        src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(src, "m4"))
        for name, text in (("configure.ac", CONFIGURE_AC),
                           ("Makefile.am", MAKEFILE_AM),
                           ("fixture.c", FIXTURE_C),
                           ("LICENSING", LICENSING)):
            with open(os.path.join(src, name), "w", encoding="utf-8") as f:
                f.write(text)
        shutil.copytree(SHARE, os.path.join(src, "tools", "sbom"),
                        ignore=shutil.ignore_patterns("__pycache__"))

        env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000",
                   LIBTOOLIZE=os.path.basename(_libtoolize()))
        self._run(["autoreconf", "-fi"], src, env)
        self._run(["./configure", "--prefix=/usr/local"], src, env)
        self._run(["make"], src, env)
        return src, env

    def test_sbom_hash_matches_installed_library(self):
        src, env = self._configure_fixture()
        self._run(["make", "sbom"], src, env)
        destdir = os.path.join(self.tmp, "destdir")
        self._run(["make", "install", "DESTDIR=" + destdir], src, env)

        libdir = os.path.join(destdir, "usr", "local", "lib")
        shared = [n for n in ("libfixture.so", "libfixture.dylib")
                  if os.path.exists(os.path.join(libdir, n))]
        self.assertTrue(shared, os.listdir(libdir))
        want = _sha256(os.path.realpath(os.path.join(libdir, shared[0])))
        static = os.path.join(libdir, "libfixture.a")
        if os.path.isfile(static):
            self.assertNotEqual(want, _sha256(static))

        with open(os.path.join(src, "fixture-1.0.0.cdx.json"),
                  encoding="utf-8") as f:
            cdx = json.load(f)
        cdx_hashes = {h["alg"]: h["content"]
                      for h in cdx["metadata"]["component"]["hashes"]}
        self.assertEqual(cdx_hashes.get("SHA-256"), want)

        with open(os.path.join(src, "fixture-1.0.0.spdx.json"),
                  encoding="utf-8") as f:
            spdx = json.load(f)
        pkg = next(p for p in spdx["packages"] if p["name"] == "fixture")
        spdx_hashes = {c["algorithm"]: c["checksumValue"]
                       for c in pkg["checksums"]}
        self.assertEqual(spdx_hashes.get("SHA256"), want)


    def test_macro_prefix_and_user_settings_checks(self):
        src, env = self._configure_fixture()
        self._run(["make", "sbom", "SBOM_MACRO_PREFIX=HAVE_ STDC_"], src, env)
        with open(os.path.join(src, "fixture-1.0.0.cdx.json"),
                  encoding="utf-8") as f:
            props = {p["name"]: p["value"] for p in
                     json.load(f)["metadata"]["component"]["properties"]}
        self.assertEqual(props.get("wolfssl:sbom:macro-prefix"),
                         "HAVE_,STDC_")
        build = [k for k in props if k.startswith("wolfssl:build:")]
        self.assertTrue(build)
        self.assertTrue(all(k[len("wolfssl:build:"):].startswith(
            ("HAVE_", "STDC_")) for k in build), build)

        for args, error in (
                (["SBOM_USER_SETTINGS=s.h", "SBOM_OPTIONS_H=o.h"],
                 "not both"),
                (["SBOM_USER_SETTINGS=s.h"],
                 "needs SBOM_USER_SETTINGS_INCLUDES"),
                (["SBOM_USER_SETTINGS=s.h", "SBOM_USER_SETTINGS_INCLUDES=.",
                  "SBOM_USER_SETTINGS_DEFINES=HAVE_X"],
                 "must include WOLFSSL_USER_SETTINGS")):
            with self.subTest(args=args):
                r = subprocess.run(["make", "sbom", *args], cwd=src, env=env,
                                   capture_output=True, text=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(error, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
