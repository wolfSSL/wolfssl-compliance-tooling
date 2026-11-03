#!/usr/bin/env python3
"""CMake install-sbom / uninstall-sbom and build-time SOURCE_DATE_EPOCH."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "share" / "build"
CMAKE = shutil.which("cmake")


def run(cmd, env=None, cwd=None):
    return subprocess.run(
        cmd, cwd=cwd, env=env, text=True, capture_output=True, check=False)


class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        if not CMAKE:
            self.skipTest("cmake is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _install(self, extra, destdir=None):
        env = os.environ.copy()
        if destdir is None:
            env.pop("DESTDIR", None)
        else:
            env["DESTDIR"] = destdir
        cmd = [CMAKE, *extra, "-P", str(BUILD / "install-sbom.cmake")]
        return run(cmd, env=env)

    def test_destdir_and_tag_value_and_config_tag_name(self):
        # wolfBoot writes a config tag into the file name. The install copies
        # that name. A missing tag-value file is skipped.
        cdx = self.dir / "wolfboot-stm32h7-1.2.3.cdx.json"
        spdx = self.dir / "wolfboot-stm32h7-1.2.3.spdx.json"
        stale = self.dir / "wolfboot-stm32h7-1.2.3.spdx"
        cdx.write_text("{}\n")
        spdx.write_text("{}\n")
        # A leftover tag-value file must stay out of the install when TV
        # was not passed.
        stale.write_text("stale\n")
        stage = self.dir / "stage"
        # The doc dir is the absolute install path. DESTDIR is prepended.
        doc = Path("/usr/local/share/doc/wolfboot")
        result = self._install([
            f"-DWOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR={doc}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX={cdx}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX={spdx}",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_TV=",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME=wolfboot",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR=" + str(self.dir),
        ], destdir=str(stage))
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = stage / "usr" / "local" / "share" / "doc" / "wolfboot"
        self.assertTrue((installed / cdx.name).is_file())
        self.assertTrue((installed / spdx.name).is_file())
        self.assertFalse((installed / stale.name).exists())

        tv = self.dir / "wolfboot-stm32h7-1.2.3.spdx"
        tv.write_text("SPDX\n")
        result = self._install([
            f"-DWOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR={doc}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX={cdx}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX={spdx}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_TV={tv}",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME=wolfboot",
        ], destdir=str(stage))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((installed / tv.name).is_file())

        env = os.environ.copy()
        env["DESTDIR"] = str(stage)
        result = run([
            CMAKE,
            f"-DWOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR={doc}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX={cdx}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX={spdx}",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_TV={tv}",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME=wolfboot",
            "-P", str(BUILD / "uninstall-sbom.cmake"),
        ], env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((installed / cdx.name).exists())
        self.assertFalse((installed / spdx.name).exists())
        self.assertFalse((installed / tv.name).exists())

    def test_version_header_names_match_the_driver_default(self):
        header = self.dir / "version.h"
        header.write_text('#define LIBWOLFTPM_VERSION_STRING "3.4.5"\n')
        bindir = self.dir / "build"
        bindir.mkdir()
        cdx = bindir / "wolftpm-3.4.5.cdx.json"
        spdx = bindir / "wolftpm-3.4.5.spdx.json"
        cdx.write_text("{}\n")
        spdx.write_text("{}\n")
        doc = self.dir / "doc"
        result = self._install([
            f"-DWOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR={doc}",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX=",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX=",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_TV=",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME=wolftpm",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION=",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_FILE={header}",
            "-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_MACRO=LIBWOLFTPM_VERSION_STRING",
            f"-DWOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR={bindir}",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((doc / cdx.name).is_file())
        self.assertTrue((doc / spdx.name).is_file())


class SdeScriptTests(unittest.TestCase):
    def setUp(self):
        if not CMAKE:
            self.skipTest("cmake is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _print_sde(self, root, env):
        code = "import os; print(os.environ.get('SOURCE_DATE_EPOCH',''))"
        return run([
            CMAKE, f"-DSBOM_ROOT={root}",
            "-P", str(BUILD / "sbom-with-sde.cmake"),
            "--", os.sys.executable, "-c", code,
        ], env=env)

    def test_build_time_value_wins_over_git(self):
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = "111"
        result = self._print_sde(self.dir, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "111")

    def test_empty_value_uses_git_commit_time(self):
        git = shutil.which("git")
        if not git:
            self.skipTest("git is not installed")
        run([git, "init"], cwd=self.dir)
        run([git, "config", "user.email", "sbom@example.invalid"], cwd=self.dir)
        run([git, "config", "user.name", "sbom"], cwd=self.dir)
        (self.dir / "README").write_text("x\n")
        run([git, "add", "README"], cwd=self.dir)
        run([git, "commit", "-m", "init"], cwd=self.dir)
        stamp = run([git, "log", "-1", "--format=%ct"], cwd=self.dir)
        self.assertEqual(stamp.returncode, 0, stamp.stderr)
        env = os.environ.copy()
        env.pop("SOURCE_DATE_EPOCH", None)
        result = self._print_sde(self.dir, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), stamp.stdout.strip())

    def test_nested_directory_does_not_use_the_outer_commit(self):
        # A release tarball unpacked inside another checkout must not
        # take that checkout's commit time.
        git = shutil.which("git")
        if not git:
            self.skipTest("git is not installed")
        run([git, "init"], cwd=self.dir)
        run([git, "config", "user.email", "sbom@example.invalid"], cwd=self.dir)
        run([git, "config", "user.name", "sbom"], cwd=self.dir)
        (self.dir / "README").write_text("x\n")
        run([git, "add", "README"], cwd=self.dir)
        run([git, "commit", "-m", "init"], cwd=self.dir)
        nested = self.dir / "unpacked"
        nested.mkdir()
        env = os.environ.copy()
        env.pop("SOURCE_DATE_EPOCH", None)
        result = self._print_sde(nested, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class HelperConfigureTests(unittest.TestCase):
    def setUp(self):
        if not CMAKE:
            self.skipTest("cmake is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _configure(self, body):
        src = self.dir / "src"
        src.mkdir()
        (src / "CMakeLists.txt").write_text(body)
        (src / "opts.h").write_text("#define DEMO 1\n")
        (src / "LICENSE").write_text("demo\n")
        build = self.dir / "build"
        result = run([
            CMAKE, "-S", str(src), "-B", str(build), "-G", "Unix Makefiles",
        ])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return build

    def _build_text(self, build):
        parts = []
        for path in build.rglob("*"):
            if path.suffix in {".make", ".cmake"} or path.name == "Makefile":
                parts.append(path.read_text(errors="replace"))
        return "\n".join(parts)

    def test_default_call_records_install_targets(self):
        build = self._configure(f"""
cmake_minimum_required(VERSION 3.16)
project(sbomtest NONE)
include("{BUILD / "sbom.cmake"}")
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1.2.3
    LIB ${{CMAKE_CURRENT_BINARY_DIR}}/libdemo.a
    OPTIONS_H ${{CMAKE_CURRENT_SOURCE_DIR}}/opts.h
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE
    INSTALL_DIR ${{CMAKE_CURRENT_BINARY_DIR}}/doc)
""")
        text = self._build_text(build)
        self.assertNotIn("--dep-libz", text)
        self.assertNotIn("--document-namespace", text)
        self.assertIn("sbom-with-sde.cmake", text)
        # CMake before 3.24 treats a separate "--version" after -P as its
        # own flag. The driver version stays one argument.
        self.assertIn("--version=1.2.3", text)
        self.assertNotIn("--version 1.2.3", text)
        self.assertIn("install-sbom", text)
        self.assertIn("uninstall-sbom", text)
        self.assertIn("demo-1.2.3.cdx.json", text)
        # Omitted dependency options must not appear. An unquoted CMake
        # guard would emit a bare --dep-wolfssl.
        self.assertNotIn("--dep-wolfssl", text)
        self.assertNotIn("--dep-openssl", text)
        self.assertNotIn("--crypto-only", text)

    def test_wolftpm_style_install_depends_on_the_public_target(self):
        # The helper target is not the public sbom target. install-sbom
        # must wait for the target that writes the tag-value file.
        build = self._configure(f"""
cmake_minimum_required(VERSION 3.16)
project(sbomtest NONE)
include("{BUILD / "sbom.cmake"}")
add_custom_target(sbom COMMAND ${{CMAKE_COMMAND}} -E echo public-sbom)
wolfssl_compliance_tooling_add_sbom(
    NAME wolftpm
    VERSION 3.4.5
    TARGET_NAME wolftpm-sbom-gen
    NO_INSTALL
    LIB ${{CMAKE_CURRENT_BINARY_DIR}}/libwolftpm.a
    OPTIONS_H ${{CMAKE_CURRENT_SOURCE_DIR}}/opts.h
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE
    CDX_OUT ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.cdx.json
    SPDX_OUT ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.spdx.json)
wolfssl_compliance_tooling_add_sbom_install(
    NAME wolftpm
    DEPENDS sbom
    CDX ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.cdx.json
    SPDX ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.spdx.json
    TV ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.spdx
    INSTALL_DIR ${{CMAKE_CURRENT_BINARY_DIR}}/doc)
""")
        text = self._build_text(build)
        self.assertIn("wolftpm-3.4.5.spdx", text)
        # Makefile2 holds the add_dependencies edge. A match against
        # install-sbom: CMakeFiles/install-sbom is the target's own rule.
        makefile2 = (build / "CMakeFiles" / "Makefile2").read_text()
        self.assertIn(
            "CMakeFiles/install-sbom.dir/all: CMakeFiles/sbom.dir/all",
            makefile2)

    def test_source_only_sbom_target_builds(self):
        # A string search for sbom-with-sde.cmake still passes when the
        # directory prefix is empty. Building the target runs that script.
        src = self.dir / "src"
        src.mkdir()
        (src / "x.c").write_text("int x(void) { return 1; }\n")
        (src / "LICENSE").write_text("demo\n")
        (src / "CMakeLists.txt").write_text(f"""
cmake_minimum_required(VERSION 3.16)
project(sbomtest C)
add_library(x STATIC x.c)
include("{BUILD / "sbom.cmake"}")
wolfssl_compliance_tooling_add_sbom(
    NAME t
    VERSION 1
    TARGETS x
    SOURCE_ONLY
    ROOT ${{CMAKE_CURRENT_SOURCE_DIR}}
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE)
""")
        build = self.dir / "build"
        configured = run([
            CMAKE, "-S", str(src), "-B", str(build), "-G", "Unix Makefiles",
        ])
        self.assertEqual(configured.returncode, 0,
                         configured.stderr + configured.stdout)
        built = run([CMAKE, "--build", str(build), "--target", "sbom"])
        self.assertEqual(built.returncode, 0, built.stderr + built.stdout)
        self.assertTrue((build / "t-1.cdx.json").is_file())
        self.assertTrue((build / "t-1.spdx.json").is_file())

    def test_second_call_keeps_its_install_target_name(self):
        build = self._configure(f"""
cmake_minimum_required(VERSION 3.16)
project(sbomtest NONE)
include("{BUILD / "sbom.cmake"}")
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1
    LIB ${{CMAKE_CURRENT_BINARY_DIR}}/libdemo.a
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE)
wolfssl_compliance_tooling_add_sbom(
    NAME extra
    VERSION 1
    TARGET_NAME sbom-extra
    INSTALL_TARGET install-sbom-extra
    UNINSTALL_TARGET uninstall-sbom-extra
    LIB ${{CMAKE_CURRENT_BINARY_DIR}}/libextra.a
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE)
""")
        text = self._build_text(build)
        self.assertIn("install-sbom-extra", text)
        self.assertIn("uninstall-sbom-extra", text)


FAKE_PYSPDXTOOLS = """#!{python}
import json, sys
args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
doc = json.load(open(args["--infile"]))
if doc.get("spdxVersion") != "SPDX-2.3" or "{fail}" == "yes":
    sys.exit("invalid SPDX")
open(args["--outfile"], "w").write("SPDXVersion: SPDX-2.3\\n")
"""


class HelperBuildTests(unittest.TestCase):
    """Build the sbom and install-sbom targets of a small C project."""

    def setUp(self):
        if not CMAKE:
            self.skipTest("cmake is not installed")
        if not shutil.which("cc"):
            self.skipTest("cc is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.src = self.dir / "src"
        self.src.mkdir()
        (self.src / "x.c").write_text("int x(void) { return 1; }\n")
        (self.src / "opts.h").write_text("#define DEMO 1\n")
        (self.src / "LICENSE").write_text("demo\n")
        self.build = self.dir / "build"
        self.env = os.environ.copy()
        self.env.pop("DESTDIR", None)
        self.env["SOURCE_DATE_EPOCH"] = "1700000000"

    def _fake_pyspdxtools(self, fail=False):
        tool = self.dir / "pyspdxtools"
        tool.write_text(FAKE_PYSPDXTOOLS.format(
            python=sys.executable, fail="yes" if fail else "no"))
        tool.chmod(0o755)
        return tool

    def _project(self, call, prelude=""):
        (self.src / "CMakeLists.txt").write_text(f"""
cmake_minimum_required(VERSION 3.16)
project(demo C)
include(GNUInstallDirs)
{prelude}
add_library(demo SHARED x.c)
install(TARGETS demo
    LIBRARY DESTINATION ${{CMAKE_INSTALL_LIBDIR}}
    ARCHIVE DESTINATION ${{CMAKE_INSTALL_LIBDIR}}
    RUNTIME DESTINATION ${{CMAKE_INSTALL_BINDIR}})
include("{BUILD / "sbom.cmake"}")
{call}
""")

    def _configure(self, *args):
        result = run([
            CMAKE, "-S", str(self.src), "-B", str(self.build),
            "-G", "Unix Makefiles", *args,
        ], env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def _build(self, *targets, env=None):
        cmd = [CMAKE, "--build", str(self.build)]
        for target in targets:
            cmd += ["--target", target]
        return run(cmd, env=env or self.env)

    def test_missing_python_fails_at_build_time(self):
        self._project("""
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1
    STAGE_TARGET demo
    OPTIONS_H ${CMAKE_CURRENT_SOURCE_DIR}/opts.h)
""")
        self._configure("-DCMAKE_DISABLE_FIND_PACKAGE_Python3=ON")
        built = self._build("sbom")
        self.assertNotEqual(built.returncode, 0)
        self.assertIn("python3 was not found", built.stdout + built.stderr)
        installed = self._build("install-sbom")
        self.assertNotEqual(installed.returncode, 0)

    def test_validate_without_pyspdxtools_fails_at_build_time(self):
        # The compiler and make are found first. Then no search path is
        # left, so a pyspdxtools on this host is not found either.
        self._project("""
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1
    STAGE_TARGET demo
    VALIDATE
    OPTIONS_H ${CMAKE_CURRENT_SOURCE_DIR}/opts.h)
""", prelude="""
set(CMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH OFF)
set(CMAKE_FIND_USE_CMAKE_SYSTEM_PATH OFF)
""")
        self._configure(f"-DPython3_EXECUTABLE={sys.executable}")
        built = self._build("sbom")
        self.assertNotEqual(built.returncode, 0)
        self.assertIn("pyspdxtools was not found",
                      built.stdout + built.stderr)
        self.assertFalse((self.build / "demo-1.cdx.json").exists())

    def test_stage_validate_and_install(self):
        # An absolute libdir must stay inside the staging tree, and a
        # DESTDIR meant for install-sbom must not move the staging.
        abs_libdir = self.dir / "abs-libdir"
        docdir = self.dir / "doc"
        self._project(f"""
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1
    STAGE_TARGET demo
    VALIDATE
    PYSPDXTOOLS {self._fake_pyspdxtools()}
    OPTIONS_H ${{CMAKE_CURRENT_SOURCE_DIR}}/opts.h
    INSTALL_DIR {docdir})
""")
        self._configure(f"-DCMAKE_INSTALL_LIBDIR={abs_libdir}",
                        f"-DCMAKE_INSTALL_PREFIX={self.dir / 'prefix'}")
        self.assertEqual(self._build().returncode, 0)

        dest = self.dir / "dest"
        env = dict(self.env, DESTDIR=str(dest))
        built = self._build("install-sbom", env=env)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)

        self.assertFalse(abs_libdir.exists())
        self.assertFalse((self.build / "_sbom_staging").exists())
        for name in ("demo-1.cdx.json", "demo-1.spdx.json", "demo-1.spdx"):
            self.assertTrue((self.build / name).is_file(), name)
            staged = Path(str(dest) + str(docdir)) / name
            self.assertTrue(staged.is_file(), staged)

        # The recorded hash is the hash of an installed copy.
        real = self.dir / "real"
        installed = run([CMAKE, "--install", str(self.build)],
                        env=dict(self.env, DESTDIR=str(real)))
        self.assertEqual(installed.returncode, 0, installed.stderr)
        libs = [p for p in Path(str(real) + str(abs_libdir)).iterdir()
                if p.is_file() and not p.is_symlink()]
        self.assertEqual(len(libs), 1, libs)
        digest = hashlib.sha256(libs[0].read_bytes()).hexdigest()
        self.assertIn(digest, (self.build / "demo-1.cdx.json").read_text())

    def test_failed_validation_fails_the_target(self):
        self._project(f"""
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1
    STAGE_TARGET demo
    VALIDATE
    PYSPDXTOOLS {self._fake_pyspdxtools(fail=True)}
    OPTIONS_H ${{CMAKE_CURRENT_SOURCE_DIR}}/opts.h)
""")
        self._configure()
        self.assertEqual(self._build().returncode, 0)
        built = self._build("install-sbom")
        self.assertNotEqual(built.returncode, 0)
        self.assertIn("SPDX validation failed", built.stdout + built.stderr)
        self.assertFalse((self.build / "demo-1.spdx").exists())
        self.assertFalse((self.build / "_sbom_staging").exists())

    def test_staging_without_a_build_fails_and_cleans_up(self):
        self._project("""
wolfssl_compliance_tooling_add_sbom(
    NAME demo
    VERSION 1
    STAGE_TARGET demo
    OPTIONS_H ${CMAKE_CURRENT_SOURCE_DIR}/opts.h)
add_executable(other x.c)
install(TARGETS other RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
""")
        self._configure()
        built = self._build("sbom")
        self.assertNotEqual(built.returncode, 0)
        self.assertIn("SBOM staging install failed",
                      built.stdout + built.stderr)
        self.assertFalse((self.build / "_sbom_staging").exists())


if __name__ == "__main__":
    unittest.main()
