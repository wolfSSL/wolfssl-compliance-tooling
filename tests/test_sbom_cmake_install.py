#!/usr/bin/env python3
"""CMake install-sbom / uninstall-sbom and build-time SOURCE_DATE_EPOCH."""

import os
import shutil
import subprocess
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
        cdx.write_text("{}\n")
        spdx.write_text("{}\n")
        stage = self.dir / "stage"
        # The doc dir is the absolute install path. DESTDIR is prepended.
        doc = Path("/usr/local/share/doc/wolfboot")
        result = self._install([
            f"-DWOLFGLASS_INSTALL_DIR={doc}",
            f"-DWOLFGLASS_SBOM_CDX={cdx}",
            f"-DWOLFGLASS_SBOM_SPDX={spdx}",
            "-DWOLFGLASS_SBOM_TV=",
            "-DWOLFGLASS_SBOM_NAME=wolfboot",
            "-DWOLFGLASS_SBOM_BINDIR=" + str(self.dir),
        ], destdir=str(stage))
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = stage / "usr" / "local" / "share" / "doc" / "wolfboot"
        self.assertTrue((installed / cdx.name).is_file())
        self.assertTrue((installed / spdx.name).is_file())
        self.assertFalse((installed / "wolfboot-stm32h7-1.2.3.spdx").exists())

        tv = self.dir / "wolfboot-stm32h7-1.2.3.spdx"
        tv.write_text("SPDX\n")
        result = self._install([
            f"-DWOLFGLASS_INSTALL_DIR={doc}",
            f"-DWOLFGLASS_SBOM_CDX={cdx}",
            f"-DWOLFGLASS_SBOM_SPDX={spdx}",
            f"-DWOLFGLASS_SBOM_TV={tv}",
            "-DWOLFGLASS_SBOM_NAME=wolfboot",
        ], destdir=str(stage))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((installed / tv.name).is_file())

        env = os.environ.copy()
        env["DESTDIR"] = str(stage)
        result = run([
            CMAKE,
            f"-DWOLFGLASS_INSTALL_DIR={doc}",
            f"-DWOLFGLASS_SBOM_CDX={cdx}",
            f"-DWOLFGLASS_SBOM_SPDX={spdx}",
            f"-DWOLFGLASS_SBOM_TV={tv}",
            "-DWOLFGLASS_SBOM_NAME=wolfboot",
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
            f"-DWOLFGLASS_INSTALL_DIR={doc}",
            "-DWOLFGLASS_SBOM_CDX=",
            "-DWOLFGLASS_SBOM_SPDX=",
            "-DWOLFGLASS_SBOM_TV=",
            "-DWOLFGLASS_SBOM_NAME=wolftpm",
            "-DWOLFGLASS_SBOM_VERSION=",
            f"-DWOLFGLASS_SBOM_VERSION_FILE={header}",
            "-DWOLFGLASS_SBOM_VERSION_MACRO=LIBWOLFTPM_VERSION_STRING",
            f"-DWOLFGLASS_SBOM_BINDIR={bindir}",
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

    def test_default_call_records_libz_and_install_targets(self):
        build = self._configure(f"""
cmake_minimum_required(VERSION 3.16)
project(sbomtest NONE)
include("{BUILD / "sbom.cmake"}")
wolfglass_add_sbom(
    NAME demo
    VERSION 1.2.3
    LIB ${{CMAKE_CURRENT_BINARY_DIR}}/libdemo.a
    OPTIONS_H ${{CMAKE_CURRENT_SOURCE_DIR}}/opts.h
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE
    DEP_LIBZ yes
    DOCUMENT_NAMESPACE https://example.invalid/sbom/demo
    INSTALL_DIR ${{CMAKE_CURRENT_BINARY_DIR}}/doc)
""")
        text = self._build_text(build)
        self.assertIn("--dep-libz", text)
        self.assertIn("yes", text)
        self.assertIn("--document-namespace", text)
        self.assertIn("sbom-with-sde.cmake", text)
        self.assertIn("install-sbom", text)
        self.assertIn("uninstall-sbom", text)
        self.assertIn("demo-1.2.3.cdx.json", text)

    def test_wolftpm_style_install_depends_on_the_public_target(self):
        # The helper target is not the public sbom target. install-sbom
        # must wait for the target that writes the tag-value file.
        build = self._configure(f"""
cmake_minimum_required(VERSION 3.16)
project(sbomtest NONE)
include("{BUILD / "sbom.cmake"}")
add_custom_target(sbom COMMAND ${{CMAKE_COMMAND}} -E echo public-sbom)
wolfglass_add_sbom(
    NAME wolftpm
    VERSION 3.4.5
    TARGET_NAME wolftpm-sbom-gen
    NO_INSTALL
    LIB ${{CMAKE_CURRENT_BINARY_DIR}}/libwolftpm.a
    OPTIONS_H ${{CMAKE_CURRENT_SOURCE_DIR}}/opts.h
    LICENSE ${{CMAKE_CURRENT_SOURCE_DIR}}/LICENSE
    DEP_LIBZ no
    CDX_OUT ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.cdx.json
    SPDX_OUT ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.spdx.json)
wolfglass_add_sbom_install(
    NAME wolftpm
    DEPENDS sbom
    CDX ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.cdx.json
    SPDX ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.spdx.json
    TV ${{CMAKE_CURRENT_BINARY_DIR}}/wolftpm-3.4.5.spdx
    INSTALL_DIR ${{CMAKE_CURRENT_BINARY_DIR}}/doc)
""")
        text = self._build_text(build)
        self.assertIn("--dep-libz", text)
        self.assertIn("wolftpm-3.4.5.spdx", text)
        # The install rule depends on the public sbom target.
        self.assertRegex(text, r"install-sbom:.*\bsbom\b")


if __name__ == "__main__":
    unittest.main()
