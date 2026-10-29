#!/usr/bin/env python3
"""Tests for the Zephyr frontend (share/frontends/zephyr_sbom.py).

Focus: the source set must be exactly what the west build compiled into the
module's library, and the settings capture must record the module's
configuration without Kconfig symbols or host built-ins."""

import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZEPHYR = os.path.join(REPO, "share", "frontends", "zephyr_sbom.py")

_spec = importlib.util.spec_from_file_location("zephyr_sbom", ZEPHYR)
zephyr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zephyr)

LIB = "modules/mod/CMakeFiles/..__mod__zephyr.dir/"
APP = "CMakeFiles/app.dir/"

# Stands in for sbom-driver: writes its argv, and the --options-h header it
# was handed, to files named by STUB_OUT.
_STUB = """import os, sys
out = os.environ['STUB_OUT']
with open(out + '.argv', 'w') as f:
    f.write('\\n'.join(sys.argv[1:]))
if '--options-h' in sys.argv:
    src = sys.argv[sys.argv.index('--options-h') + 1]
    with open(src) as f, open(out + '.opts', 'w') as g:
        g.write(src + '\\n' + f.read())
"""


class _ZephyrTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mod = os.path.join(self.tmp.name, "mod")
        self.build = os.path.join(self.tmp.name, "build")
        os.makedirs(os.path.join(self.mod, "zephyr"))
        os.makedirs(self.build)
        self.write("zephyr/module.yml", "name: mod\n")
        for rel in ("src/core.c", "src/est.c", "src/scep.c", "zephyr/glue.c",
                    "tests/app.c"):
            self.write(rel, "")
        self.outside = os.path.join(self.tmp.name, "other.c")
        open(self.outside, "w").close()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        path = os.path.join(self.mod, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def write_compdb(self, entries, flags=()):
        db = [{"directory": self.build,
               "file": src if os.path.isabs(src)
               else os.path.join(self.mod, src),
               "arguments": ["cc", *flags, "-c", src],
               "output": out + os.path.basename(src) + ".obj"}
              for src, out in entries]
        path = os.path.join(self.build, "compile_commands.json")
        with open(path, "w") as f:
            json.dump(db, f)
        return path

    def run_frontend(self, *extra):
        return subprocess.run(
            [sys.executable, ZEPHYR, "--name", "mod", "--root", self.mod,
             *extra], capture_output=True, text=True,
            env=dict(os.environ, STUB_OUT=os.path.join(self.tmp.name, "stub")))

    def rels(self, entries):
        return sorted(os.path.relpath(src, self.mod) for src, _ in entries)


class TestModuleName(_ZephyrTest):
    def test_module_yml_name(self):
        self.write("zephyr/module.yml",
                   "build:\n  cmake: zephyr\nname: 'mod'  # pinned\n")
        self.assertEqual(zephyr.module_name(self.mod), "mod")

    def test_directory_name_without_module_yml_name(self):
        self.write("zephyr/module.yml", "build:\n  cmake: zephyr\n")
        self.assertEqual(zephyr.module_name(self.mod), "mod")
        os.rename(self.mod, self.mod + "-x")
        self.assertEqual(zephyr.module_name(self.mod + "-x"), "mod-x")


class TestSourceSelection(_ZephyrTest):
    def test_only_module_library_sources_under_root(self):
        compdb = self.write_compdb([
            ("src/core.c", LIB), ("src/est.c", LIB), ("zephyr/glue.c", LIB),
            ("src/core.c", LIB),
            ("tests/app.c", APP),
            ("src/scep.c", "modules/mod-extra/CMakeFiles/x.dir/"),
            (self.outside, LIB)])
        entries, outside = zephyr.compdb_entries(compdb, self.mod, "mod")
        self.assertEqual(self.rels(entries),
                         ["src/core.c", "src/core.c", "src/est.c",
                          "zephyr/glue.c"])
        self.assertEqual(outside, [self.outside])

    def test_unnormalized_build_directory(self):
        compdb = self.write_compdb([("src/core.c", LIB)])
        with open(compdb) as f:
            db = json.load(f)
        db[0]["directory"] = self.build + "/./"
        with open(compdb, "w") as f:
            json.dump(db, f)
        entries, _ = zephyr.compdb_entries(compdb, self.mod, "mod")
        self.assertEqual(self.rels(entries), ["src/core.c"])

    def test_makefile_generator_layout(self):
        compdb = self.write_compdb([("src/core.c", LIB)])
        with open(compdb) as f:
            db = json.load(f)
        db[0]["directory"] = os.path.join(self.build, "modules", "mod")
        with open(compdb, "w") as f:
            json.dump(db, f)
        entries, _ = zephyr.compdb_entries(compdb, self.mod, "mod")
        self.assertEqual(self.rels(entries), ["src/core.c"])

    def test_missing_output_field_fails(self):
        compdb = self.write_compdb([("src/core.c", LIB)])
        with open(compdb) as f:
            db = json.load(f)
        del db[0]["output"]
        with open(compdb, "w") as f:
            json.dump(db, f)
        with self.assertRaises(zephyr.ParseError):
            zephyr.compdb_entries(compdb, self.mod, "mod")

    def test_no_module_entries_fails(self):
        compdb = self.write_compdb([("src/core.c", APP)])
        r = self.run_frontend("--compdb", compdb, "--print-only")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--module-name", r.stderr)

    def test_source_outside_root_is_warned(self):
        compdb = self.write_compdb([("src/core.c", LIB), (self.outside, LIB)])
        r = self.run_frontend("--compdb", compdb, "--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("outside --root", r.stderr)
        self.assertNotIn("other.c", r.stdout)


class TestCommandSplitting(unittest.TestCase):
    def test_windows_rules(self):
        cmd = ('C:\\sdk\\gcc.exe -DSTR=\\"x\\" -DX="a b" '
               '-I"C:\\My Dir" -c a.c')
        self.assertEqual(zephyr.split_windows_command(cmd), [
            "C:\\sdk\\gcc.exe", '-DSTR="x"', "-DX=a b", "-IC:\\My Dir",
            "-c", "a.c"])
        self.assertEqual(zephyr.split_windows_command('a\\\\"b c" d'),
                         ["a\\b c", "d"])


class TestDefines(unittest.TestCase):
    def entry(self, *flags):
        return ("x.c", {"arguments": ["cc", "-c", "x.c", *flags]})

    def test_bare_define_equals_value_one_and_last_wins(self):
        self.assertEqual(
            zephyr._defines([self.entry("-DA", "-UB", "-DB=2", "-D"),
                             self.entry("-DA=1")]),
            ["-D", "A=1", "-D", "B=2"])

    def test_define_and_undefine_disagree(self):
        with self.assertRaises(zephyr.ParseError):
            zephyr._defines([self.entry("-DA"), self.entry("-UA")])


class TestUserSettings(_ZephyrTest):
    def setUp(self):
        super().setUp()
        self.autoconf = os.path.join(self.build, "autoconf.h")
        with open(self.autoconf, "w") as f:
            f.write("#define CONFIG_MOD_X 1\n")
        self.toolchain = os.path.join(self.build, "toolchain.h")
        with open(self.toolchain, "w") as f:
            f.write("#define TOOLCHAIN_ONLY 1\n")
        self.write("cfg/extra.h", "#define HAVE_Y 2\n")
        self.settings = self.write(
            "zephyr/user_settings.h",
            "#ifdef CONFIG_MOD_X\n#define HAVE_X 1\n#endif\n"
            "#ifdef MOD_DEBUG\n#define HAVE_DEBUG_LOG 1\n#endif\n"
            "#ifdef TOOLCHAIN_ONLY\n#define SAW_TOOLCHAIN 1\n#endif\n"
            "#ifdef __STDC_VERSION__\n#define HAVE_C99 1\n#endif\n"
            "#include SETTINGS_FILE\n")
        self.flags = ["-std=c89", "-DMOD_DEBUG", '-DSETTINGS_FILE="extra.h"',
                      "-imacros", self.autoconf, f"-imacros{self.toolchain}",
                      "-I", os.path.join(self.mod, "cfg"),
                      "-o", "core.c.obj", "-MD", "-MF", "core.c.d"]

    def capture(self, flags, *extra):
        compdb = self.write_compdb([("src/core.c", LIB)], flags)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings, *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.split("macros from", 1)[1]

    def test_build_compiler_and_flags(self):
        macros = self.capture(self.flags)
        for line in ("#define HAVE_X 1", "#define HAVE_Y 2",
                     "#define HAVE_DEBUG_LOG 1", "#define MOD_DEBUG 1",
                     '#define SETTINGS_FILE "extra.h"',
                     "#define SAW_TOOLCHAIN 1"):
            self.assertIn(line, macros)
        for name in ("CONFIG_MOD_X", "TOOLCHAIN_ONLY", "HAVE_C99",
                     "__STDC__", "__VERSION__"):
            self.assertNotIn(name, macros)

    def test_hostcc_keeps_only_portable_flags(self):
        macros = self.capture(self.flags, "--hostcc", "cc")
        for line in ("#define HAVE_X 1", "#define HAVE_Y 2",
                     "#define MOD_DEBUG 1", "#define HAVE_C99 1"):
            self.assertIn(line, macros)
        self.assertNotIn("SAW_TOOLCHAIN", macros)

    def test_joined_flag_forms(self):
        flags = ["-DMOD_DEBUG", '-DSETTINGS_FILE="extra.h"',
                 f"-imacros{self.autoconf}",
                 f"-I{os.path.join(self.mod, 'cfg')}"]
        macros = self.capture(flags)
        self.assertIn("#define HAVE_X 1", macros)
        self.assertIn("#define HAVE_Y 2", macros)

    def test_command_string_form(self):
        compdb = self.write_compdb([("src/core.c", LIB)], self.flags)
        with open(compdb) as f:
            db = json.load(f)
        db[0]["command"] = shlex.join(db[0].pop("arguments"))
        with open(compdb, "w") as f:
            json.dump(db, f)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#define MOD_DEBUG 1", r.stdout)
        self.assertIn('#define SETTINGS_FILE "extra.h"', r.stdout)

    def test_force_included_header_is_still_recorded(self):
        macros = self.capture(self.flags + ["-include", self.settings])
        self.assertIn("#define HAVE_X 1", macros)
        self.assertIn("#define HAVE_Y 2", macros)

    def test_defines_merge_across_entries(self):
        compdb = self.write_compdb([("src/core.c", LIB)], self.flags)
        with open(compdb) as f:
            db = json.load(f)
        other = dict(db[0], file=os.path.join(self.mod, "src/est.c"),
                     output=LIB + "est.c.obj",
                     arguments=db[0]["arguments"] + ["-DEST_ONLY",
                                                     "-UMOD_DEBUG"])
        with open(compdb, "w") as f:
            json.dump(db + [other], f)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("disagree on MOD_DEBUG", r.stderr)
        other["arguments"] = other["arguments"][:-1]
        with open(compdb, "w") as f:
            json.dump(db + [other], f)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#define EST_ONLY 1", r.stdout)
        self.assertIn("#define MOD_DEBUG 1", r.stdout)

    def test_same_source_in_two_targets_disagrees(self):
        compdb = self.write_compdb([("src/core.c", LIB)], self.flags)
        with open(compdb) as f:
            db = json.load(f)
        other = dict(db[0], output=LIB.replace("mod__zephyr", "mod_b")
                     + "core.c.obj",
                     arguments=db[0]["arguments"] + ["-UMOD_DEBUG"])
        with open(compdb, "w") as f:
            json.dump(db + [other], f)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("disagree on MOD_DEBUG", r.stderr)
        r = self.run_frontend("--compdb", compdb, "--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("# mod: 1 sources", r.stdout)

    def test_header_already_included_as_copy_fails(self):
        text = "#ifndef US_H\n#define US_H\n#define HAVE_X 1\n#endif\n"
        self.write("zephyr/user_settings.h", text)
        copy = os.path.join(self.build, "user_settings.h")
        with open(copy, "w") as f:
            f.write(text)
        compdb = self.write_compdb([("src/core.c", LIB)],
                                   ["-include", copy])
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("adds no macros", r.stderr)

    def test_asm_entry_first_is_skipped(self):
        self.write("src/start.S", "")
        compdb = self.write_compdb([("src/start.S", LIB),
                                    ("src/core.c", LIB)], self.flags)
        with open(compdb) as f:
            db = json.load(f)
        db[0]["arguments"] = ["/nonexistent/as", "-c", "src/start.S"]
        with open(compdb, "w") as f:
            json.dump(db, f)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#define HAVE_X 1", r.stdout)

    def test_hostcc_needs_user_settings(self):
        compdb = self.write_compdb([("src/core.c", LIB)])
        r = self.run_frontend("--compdb", compdb, "--hostcc", "cc")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--hostcc only applies", r.stderr)

    def test_response_file_fails(self):
        compdb = self.write_compdb([("src/core.c", LIB)], ["@flags.rsp"])
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("response file", r.stderr)

    def test_missing_compiler_is_an_error(self):
        compdb = self.write_compdb([("src/core.c", LIB)], self.flags)
        with open(compdb) as f:
            db = json.load(f)
        db[0]["arguments"][0] = "/nonexistent/cc"
        with open(compdb, "w") as f:
            json.dump(db, f)
        r = self.run_frontend("--compdb", compdb, "--print-only",
                              "--user-settings", self.settings)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ERROR: cannot run", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_options_h_excludes_user_settings(self):
        compdb = self.write_compdb([("src/core.c", LIB)])
        r = self.run_frontend("--compdb", compdb, "--options-h", "o.h",
                              "--user-settings", self.settings)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("only one of", r.stderr)


class TestDriverForwarding(_ZephyrTest):
    def run_main(self, extra, flags=()):
        stub = os.path.join(self.tmp.name, "stub-driver.py")
        with open(stub, "w") as f:
            f.write(f"#!{sys.executable}\n" + _STUB)
        os.chmod(stub, 0o755)
        compdb = self.write_compdb([("src/core.c", LIB)], flags)
        r = self.run_frontend("--compdb", compdb, "--driver", stub, *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tmp.name, "stub.argv")) as f:
            return f.read().splitlines()

    def test_identity_license_and_dependency_flags(self):
        argv = self.run_main([
            "--license-override", "GPL-3.0-or-later",
            "--license-text", "LICENSE.txt",
            "--supplier", "Example Inc.",
            "--component-type", "firmware",
            "--dep-wolfssl", "yes", "--dep-wolfcrypt", "yes",
            "--dep-openssl", "no",
            "--dep-version", "wolfssl=5.9.2",
            "--dep-version", "wolfcrypt=5.9.2"])
        pairs = list(zip(argv, argv[1:]))
        for pair in (("--license-override", "GPL-3.0-or-later"),
                     ("--license-text", "LICENSE.txt"),
                     ("--supplier", "Example Inc."),
                     ("--component-type", "firmware"),
                     ("--dep-wolfssl", "yes"),
                     ("--dep-wolfcrypt", "yes"),
                     ("--dep-openssl", "no"),
                     ("--dep-version", "wolfssl=5.9.2"),
                     ("--dep-version", "wolfcrypt=5.9.2"),
                     ("--root", self.mod)):
            self.assertIn(pair, pairs)
        self.assertIn("--source-only", argv)

    def test_options_h_replaces_source_only(self):
        opts = self.write("options.h", "#define HAVE_X 1\n")
        argv = self.run_main(["--options-h", opts])
        self.assertIn(("--options-h", opts), list(zip(argv, argv[1:])))
        self.assertNotIn("--source-only", argv)

    def test_user_settings_header_reaches_driver(self):
        settings = self.write("zephyr/user_settings.h", "#define HAVE_X 1\n")
        argv = self.run_main(["--user-settings", settings], ["-DMOD_DEBUG"])
        self.assertNotIn("--source-only", argv)
        with open(os.path.join(self.tmp.name, "stub.opts")) as f:
            path, text = f.read().split("\n", 1)
        self.assertIn("#define HAVE_X 1", text)
        self.assertIn("#define MOD_DEBUG 1", text)
        self.assertFalse(os.path.exists(path), "temporary header left behind")


if __name__ == "__main__":
    unittest.main(verbosity=2)
