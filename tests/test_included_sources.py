#!/usr/bin/env python3
"""Tests for share/frontends/included_sources.py and its use by the
compilation-database frontend: a .c file compiled in through #include must
reach the source list, a header must not."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTENDS = os.path.join(REPO, "share", "frontends")
COMPDB = os.path.join(FRONTENDS, "compdb_sbom.py")

_spec = importlib.util.spec_from_file_location(
    "included_sources", os.path.join(FRONTENDS, "included_sources.py"))
inc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inc)


class TestParsing(unittest.TestCase):
    def test_dependency_command_keeps_only_preprocessor_flags(self):
        cmd = inc.dependency_command(
            ["cc", "-DX", "-I", "inc", "-mcpu=m7", "-o", "a.o", "-MD", "-MF",
             "a.d", "-Wp,-MD,k.d", "--output", "b.o", "-Xclang", "-MT",
             "-Xclang", "a.o", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["cc", "-M", "-DX", "-I", "inc", "-mcpu=m7",
                               "a.c"])

    def test_dependency_command_drops_split_options(self):
        cmd = inc.dependency_command(
            ["clang", "-Xclang", "-include-pch", "-Xclang", "p.pch",
             "-Xclang", "-fno-pch-timestamp", "-mllvm", "-opt=1",
             "--param", "x=1", "-Xarch_arm64", "-DY", "-ftime-trace",
             "-fdiagnostics-format=sarif-file", "-fPIC", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["clang", "-M", "-Xclang", "-include-pch",
                               "-Xclang", "p.pch", "-fPIC", "a.c"])

    def test_dependency_command_keeps_wp_and_specs(self):
        cmd = inc.dependency_command(
            ["gcc", "-Wp,-DINL,-MD,k.d,-o,x.i", "-Wp,-MMD,j.d",
             "--specs=nano.specs",
             "-undef", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["gcc", "-M", "-Wp,-DINL", "--specs=nano.specs",
                               "-undef", "a.c"])

    def test_dependency_command_launcher_and_arch(self):
        cmd = inc.dependency_command(
            ["ccache", "cc", "-arch", "x86_64", "-arch", "arm64", "-c",
             "a.c"], "a.c")
        self.assertEqual(cmd, ["cc", "-M", "-arch", "x86_64", "a.c"])

    def test_dependency_command_drops_linker_pairs(self):
        cmd = inc.dependency_command(
            ["cc", "-undefined", "dynamic_lookup", "-framework", "Security",
             "-isystem-after", "sys", "-DZ", "-o", "prog", "a.c"], "a.c")
        self.assertEqual(cmd, ["cc", "-M", "-isystem-after", "sys", "-DZ",
                               "a.c"])

    def test_dependency_command_keeps_only_listed_f_flags(self):
        cmd = inc.dependency_command(
            ["gcc", "-fshort-wchar", "-fno-builtin-memcpy", "-fPIC",
             "-fdiagnostics-set-output=sarif", "-fmodules-cache-path=mc",
             "-fdeps-file=x.ddi", "-fproc-stat-report=s.csv", "-c", "a.c"],
            "a.c")
        self.assertEqual(cmd, ["gcc", "-M", "-fshort-wchar",
                               "-fno-builtin-memcpy", "-fPIC", "a.c"])

    def test_dependency_command_xarch_of_scanned_arch(self):
        cmd = inc.dependency_command(
            ["cc", "-Xarch_arm64", "-DNEON", "-arch", "arm64",
             "-Xarch_x86_64", "-DSSE", "-arch", "x86_64", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["cc", "-M", "-DNEON", "-arch", "arm64", "a.c"])

    def test_dependency_command_forwards_wrapped_preprocessor_flags(self):
        cmd = inc.dependency_command(
            ["clang", "-Xpreprocessor", "-DINL", "-Xclang", "-include",
             "-Xclang", "cfg.h", "-Xclang", "-main-file-name", "-Xclang",
             "a.c", "-fabi-version=11", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["clang", "-M", "-Xpreprocessor", "-DINL",
                               "-Xclang", "-include", "-Xclang", "cfg.h",
                               "-fabi-version=11", "a.c"])

    def test_dependency_command_per_arch(self):
        tokens = ["cc", "-arch", "x86_64", "-Xarch_arm64", "-DNEON",
                  "-arch", "arm64", "-c", "a.c"]
        self.assertEqual(inc.dependency_command(tokens, "a.c", "arm64"),
                         ["cc", "-M", "-DNEON", "-arch", "arm64", "a.c"])
        self.assertEqual(inc.dependency_command(tokens, "a.c"),
                         ["cc", "-M", "-arch", "x86_64", "a.c"])

    def test_dependency_command_wp_joined_output(self):
        cmd = inc.dependency_command(
            ["gcc", "-Wp,-ok.i", "-Wp,--output=j.i,-DY", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["gcc", "-M", "-Wp,-DY", "a.c"])

    def test_dependency_command_m_pairs(self):
        cmd = inc.dependency_command(
            ["clang", "-meabi", "gnu", "-mmlir", "-x=1", "-mcpu=m4",
             "-module-dependency-dir", "md", "-DFOO", "-c", "a.c"], "a.c")
        self.assertEqual(cmd, ["clang", "-M", "-meabi", "gnu", "-mcpu=m4",
                               "-DFOO", "a.c"])

    def test_parse_make_deps(self):
        text = ("a.o: a.c b\\ c.c \\\n  /x/y.h \\\n z$$.c\n")
        self.assertEqual(inc.parse_make_deps(text),
                         ["a.c", "b c.c", "/x/y.h", "z$.c"])

    def test_parse_several_rules_and_escapes(self):
        self.assertEqual(inc.parse_make_deps("a.o: a\\#b.c\nb.c:\n"),
                         ["a#b.c"])

    def test_parse_windows_target(self):
        self.assertEqual(inc.parse_make_deps("C:\\b\\a.o: C:\\s\\a.c\n"),
                         ["C:\\s\\a.c"])


class TestCompdb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "mod")
        os.makedirs(os.path.join(self.root, "src"))
        self.write("src/ssl.c", '#include "ssl_api.c"\n#include "ssl.h"\n'
                                '#include "../../outside.c"\n')
        self.write("src/ssl_api.c", "int api(void) { return 0; }\n")
        self.write("src/ssl.h", "#define SSL_H 1\n")
        with open(os.path.join(self.tmp.name, "outside.c"), "w") as f:
            f.write("int outside;\n")
        self.db = os.path.join(self.tmp.name, "compile_commands.json")
        self.write_db("cc")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), "w") as f:
            f.write(text)

    def write_db(self, cc, *extra):
        self.write_entries([cc, "-DX", "-o", "ssl.o", "-MD", "-c",
                            "src/ssl.c"], *extra)

    def write_entries(self, *commands):
        with open(self.db, "w") as f:
            json.dump([{"directory": self.root, "file": c[-1],
                        "arguments": c} for c in commands], f)

    def run_compdb(self, *extra):
        return subprocess.run(
            [sys.executable, COMPDB, self.db, "--name", "t",
             "--root", self.root, "--print-only", "--included-sources",
             *extra],
            capture_output=True, text=True)

    def test_included_c_file_is_listed(self):
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("(1 included)", r.stdout)
        self.assertIn(os.path.join(self.root, "src", "ssl_api.c"), r.stdout)
        self.assertNotIn("ssl.h", r.stdout)
        self.assertNotIn("outside.c", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "ssl.d")))

    def test_exclude_applies_to_included_files(self):
        r = self.run_compdb("--exclude", "ssl_api")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ssl_api.c", r.stdout)

    def test_root_slash(self):
        r = subprocess.run(
            [sys.executable, COMPDB, self.db, "--name", "t", "--root", "/",
             "--print-only", "--included-sources"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ssl_api.c", r.stdout)

    def test_entry_without_command_is_warned(self):
        with open(self.db) as f:
            db = json.load(f)
        del db[0]["arguments"]
        with open(self.db, "w") as f:
            json.dump(db, f)
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not scanned", r.stderr)

    def test_compiler_error_fails(self):
        cc = os.path.join(self.tmp.name, "badcc")
        with open(cc, "w") as f:
            f.write("#!/bin/sh\necho nope >&2\nexit 1\n")
        os.chmod(cc, 0o755)
        self.write_db(cc)
        r = self.run_compdb()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nope", r.stderr)

    def test_module_import_without_frontends_on_path(self):
        code = ("import importlib.util as u; s = u.spec_from_file_location("
                f"'c', {COMPDB!r}); m = u.module_from_spec(s); "
                "s.loader.exec_module(m); print(m.SRC_EXTS)")
        r = subprocess.run([sys.executable, "-I", "-c", code],
                           capture_output=True, text=True, cwd="/")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_off_by_default(self):
        r = subprocess.run(
            [sys.executable, COMPDB, self.db, "--name", "t",
             "--root", self.root, "--print-only"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ssl_api.c", r.stdout)

    def test_every_entry_for_a_file_is_scanned(self):
        self.write("src/ssl.c", '#ifdef INL\n#include "misc.c"\n#endif\n')
        self.write("src/misc.c", "int misc;\n")
        self.write_entries(["cc", "-c", "src/ssl.c"],
                           ["cc", "-DINL", "-c", "src/ssl.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("misc.c", r.stdout)

    def test_response_file(self):
        os.makedirs(os.path.join(self.root, "inc"))
        self.write("inc/extra.c", "int extra;\n")
        self.write("src/ssl.c", "#include <extra.c>\n")
        self.write("flags.rsp", "-Iinc -o ssl.o\n")
        self.write_entries(["cc", "@flags.rsp", "-c", "src/ssl.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("extra.c", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.root, "ssl.o")))

    def test_nested_response_file(self):
        os.makedirs(os.path.join(self.root, "inc"))
        self.write("inc/extra.c", "int extra;\n")
        self.write("src/ssl.c", "#include <extra.c>\n")
        self.write("outer.rsp", "@inner.rsp\n")
        self.write("inner.rsp", "-Iinc\n")
        self.write_entries(["cc", "@outer.rsp", "-c", "src/ssl.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("extra.c", r.stdout)

    def test_missing_response_file_fails(self):
        self.write_entries(["cc", "@gone.rsp", "-c", "src/ssl.c"])
        r = self.run_compdb()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gone.rsp", r.stderr)

    def test_hardlink_of_listed_source_is_not_added(self):
        os.link(os.path.join(self.root, "src", "ssl_api.c"),
                os.path.join(self.root, "src", "alias.c"))
        self.write("src/ssl.c", '#include "alias.c"\n')
        self.write_entries(["cc", "-c", "src/ssl.c"],
                           ["cc", "-c", "src/ssl_api.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("(0 included)", r.stdout)

    def test_path_through_symlink_is_resolved(self):
        os.makedirs(os.path.join(self.root, "real", "sub"))
        self.write("real/y.c", "int real_y;\n")
        os.symlink(os.path.join(self.root, "real", "sub"),
                   os.path.join(self.root, "src", "link"))
        self.write("src/ssl.c", '#include "link/../y.c"\n')
        self.write_entries(["cc", "-c", "src/ssl.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(os.path.join("real", "y.c"), r.stdout)

    def test_case_variant_include_is_listed_once(self):
        if not os.path.exists(os.path.join(self.root, "SRC")):
            self.skipTest("case-sensitive filesystem")
        self.write("src/ssl.c", '#include "SSL_API.c"\n')
        self.write_entries(["cc", "-c", "src/ssl.c"],
                           ["cc", "-c", "src/ssl_api.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("(0 included)", r.stdout)

    def test_assembly_entry_is_not_scanned(self):
        self.write("src/a.s", "nop\n")
        self.write_entries(["/nonexistent/as", "-c", "src/a.s"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_basename_clash_names_the_included_file(self):
        os.makedirs(os.path.join(self.root, "other"))
        self.write("other/ssl_api.c", "int other;\n")
        self.write_db("cc", ["cc", "-c", "other/ssl_api.c"])
        r = self.run_compdb()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("same basename", r.stderr)
        self.assertIn(os.path.join("src", "ssl_api.c") + ", #include'd",
                      r.stderr)

    def test_every_arch_is_scanned(self):
        self.write("src/ssl.c", '#ifdef __aarch64__\n#include "arm.c"\n'
                                '#else\n#include "x86.c"\n#endif\n')
        self.write("src/arm.c", "int arm;\n")
        self.write("src/x86.c", "int x86;\n")
        cc = os.path.join(self.tmp.name, "archcc")
        with open(cc, "w") as f:
            f.write('#!/bin/sh\nfor a; do case "$p" in -arch) arch=$a;; '
                    'esac; p=$a; src=$a; done\n'
                    'if [ "$arch" = arm64 ]; then d=arm.c; else d=x86.c; fi\n'
                    'echo "ssl.o: $src src/$d"\n')
        os.chmod(cc, 0o755)
        self.write_entries([cc, "-arch", "x86_64", "-arch", "arm64", "-c",
                            "src/ssl.c"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("arm.c", r.stdout)
        self.assertIn("x86.c", r.stdout)

    def test_assembler_entry_is_not_run(self):
        self.write("src/s.S", "nop\n")
        self.write_entries(["/nonexistent/arm-none-eabi-as", "-c", "src/s.S"])
        r = self.run_compdb()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_empty_dependency_output_fails(self):
        cc = os.path.join(self.tmp.name, "quietcc")
        with open(cc, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(cc, 0o755)
        self.write_db(cc)
        r = self.run_compdb()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("printed no dependencies", r.stderr)

    def test_missing_compiler_fails(self):
        self.write_db("/nonexistent/cc")
        r = self.run_compdb()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cannot run", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
