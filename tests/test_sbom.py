#!/usr/bin/env python3
"""wolfssl-compliance-tooling self-test.

Two layers:

  * Unit tests always run. They need no gen-sbom. They cover the path scrub, the
    version parser, and the structural validator.
  * Integration tests run when gen-sbom is found (vendored, via --gen-sbom,
    GEN_SBOM, or WOLFSSL_DIR). They cover a full generate for the source-embedded and the
    library paths, the path-scrub end to end, byte-reproducibility, and
    feature-detected forwarding of dependency and namespace flags.

Usage:
  tests/test_sbom.py [--gen-sbom PATH]
  GEN_SBOM=/path/to/gen-sbom tests/test_sbom.py
  python3 tests/test_sbom.py
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARE = os.path.join(REPO, "share")
DRIVER = os.path.join(SHARE, "sbom-driver")
VALIDATE = os.path.join(SHARE, "validate_sbom.py")

_fail = 0


def check(cond, msg):
    global _fail
    if cond:
        print(f"  ok: {msg}")
    else:
        print(f"  FAIL: {msg}", file=sys.stderr)
        _fail += 1


def load_driver_module():
    spec = importlib.util.spec_from_file_location(
        "sbom_driver", os.path.join(SHARE, "sbom-driver.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def unit_tests():
    print("[unit] scrub / version / validate")
    drv = load_driver_module()

    scrubbed = drv.scrub_defines(
        '#define PICO_SDK_PATH "/home/secret/pico-sdk"\n'
        '#define HAVE_AES 1\n')
    check("secret" not in scrubbed, "scrub removes absolute path")
    check("PICO_SDK_PATH" in scrubbed, "scrub keeps the macro name")
    check("HAVE_AES 1" in scrubbed, "scrub keeps non-path macros")

    scrubbed = drv.scrub_defines(
        '#define SDK_PATH "C:\\\\Users\\\\ci\\\\sdk"\n'
        '#define SDK_SHARE "\\\\\\\\server\\\\share\\\\sdk"\n')
    check("Users\\\\ci" not in scrubbed, "scrub removes Windows drive paths")
    check("server\\\\share" not in scrubbed, "scrub removes Windows UNC paths")
    check(scrubbed.count("<redacted-path>") == 2,
          "scrub redacts both Windows absolute paths")

    with tempfile.TemporaryDirectory() as d:
        vh = os.path.join(d, "version.h")
        with open(vh, "w") as f:
            f.write('#define LIBWOLFBOOT_VERSION_STRING "2.4.0"\n')
        check(drv.read_version(vh, "LIBWOLFBOOT_VERSION_STRING") == "2.4.0",
              "version parser reads the macro")
        check(drv.read_version(vh, "NOPE") == "", "version parser misses cleanly")

    print("[unit] config capture")
    # The capture must see BOTH halves of the configuration: the -D tokens and
    # the settings header that interprets them.  Regression: capturing -D
    # tokens alone against an empty translation unit dropped every derived
    # macro, so a wolfBoot SBOM listed a signing bootloader with no signature
    # algorithm.  The reverse omission (header, no -D) is equally wrong, so
    # both directions are pinned here.
    with tempfile.TemporaryDirectory() as d:
        inc = os.path.join(d, "inc")
        os.mkdir(inc)
        with open(os.path.join(inc, "derived.h"), "w") as f:
            f.write("#ifdef SIGN_ECC256\n"
                    "#define HAVE_ECC 1\n"
                    "#define ECC_CURVE 256\n"
                    "#endif\n")
        settings = os.path.join(d, "settings.h")
        with open(settings, "w") as f:
            f.write("#include <derived.h>\n")

        out = drv.capture_macros("cc", f"-DSIGN_ECC256 -I{inc}",
                                 settings_h=settings)
        check("#define HAVE_ECC 1" in out,
              "capture records macros the settings header derives")
        check("#define ECC_CURVE 256" in out,
              "capture keeps derived macro values")
        check("#define SIGN_ECC256 1" in out,
              "capture still records the -D tokens themselves")

        out = drv.capture_macros("cc", f"-I{inc}", settings_h=settings)
        check("HAVE_ECC" not in out,
              "derived macro is absent when its -D gate is absent")

        out = drv.capture_macros("cc", "-DSIGN_ECC256")
        check("HAVE_ECC" not in out and "#define SIGN_ECC256 1" in out,
              "no settings header means -D tokens only (back-compatible)")

        # -I may also arrive out of band, and the separated '-I dir' spelling
        # must work as well as '-Idir'.
        out = drv.capture_macros("cc", "-DSIGN_ECC256", settings_h=settings,
                                 include_dirs=[inc])
        check("#define HAVE_ECC 1" in out, "--include-dir feeds the capture")
        out = drv.capture_macros("cc", f"-DSIGN_ECC256 -I {inc}",
                                 settings_h=settings)
        check("#define HAVE_ECC 1" in out, "separated '-I dir' is forwarded")

        # A capture that cannot preprocess must abort, never fall back to a
        # partial dump: a silently truncated config is the failure mode this
        # whole path exists to prevent.
        with open(settings, "w") as f:
            f.write("#include <no-such-header.h>\n")
        try:
            drv.capture_macros("cc", "", settings_h=settings)
            check(False, "capture aborts when the settings header fails")
        except SystemExit:
            check(True, "capture aborts when the settings header fails")

    # CFLAGS arrive already shell-processed, so the split must not re-lex them.
    # shlex would eat the backslashes out of a Windows SDK path, which both
    # corrupts the recorded value and defeats the absolute-path scrub that
    # keeps host paths out of the SBOM.
    win = r'-DPICO_SDK_PATH=C:\Users\ci\sdk -DHAVE_AES'
    check(drv.split_cflags(win) == [r'-DPICO_SDK_PATH=C:\Users\ci\sdk',
                                    '-DHAVE_AES'],
          "cflags split preserves backslashes in Windows paths")
    check(drv.is_absolute_path_token(r'C:\Users\ci\sdk'),
          "a preserved Windows path is still recognised by the scrub")

    # Validator: a good CycloneDX passes with the right prefix; a wrong prefix
    # fails.
    with tempfile.TemporaryDirectory() as d:
        good = os.path.join(d, "x.cdx.json")
        with open(good, "w") as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6",
                       "metadata": {"component": {"name": "wolftpm",
                                                  "version": "3.9.0",
                                                  "properties": [{"a": "b"}]}}},
                      f)
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--name-prefix", "wolftpm", good],
                             stdout=subprocess.DEVNULL)
        check(rc == 0, "validator accepts a good CycloneDX")
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--name-prefix", "wolfssh", good],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check(rc != 0, "validator rejects a wrong name prefix")

        # wolfcrypt ships nested inside the wolfssl component, so a
        # --require-dep-version check that read only the top level would call
        # it missing.
        nested = os.path.join(d, "n.cdx.json")
        with open(nested, "w") as f:
            json.dump({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"name": "wolfboot",
                                           "version": "2.9.0",
                                           "properties": [{"a": "b"}]}},
                "components": [{
                    "name": "wolfssl", "version": "5.9.1",
                    "cpe": "cpe:2.3:a:wolfssl:wolfssl:5.9.1:*:*:*:*:*:*:*",
                    "components": [{
                        "name": "wolfcrypt", "version": "5.9.1",
                        "purl": "pkg:github/wolfssl/wolfssl@v5.9.1-stable#wolfcrypt",
                    }],
                }],
            }, f)
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--require-dep-version", "wolfssl",
                              "--require-dep-version", "wolfcrypt", nested],
                             stdout=subprocess.DEVNULL)
        check(rc == 0, "validator finds a nested dependency component")

        no_purl = os.path.join(d, "no-purl.cdx.json")
        with open(no_purl, "w") as f:
            json.dump({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"name": "wolfboot",
                                           "version": "2.9.0",
                                           "properties": [{"a": "b"}]}},
                "components": [{
                    "name": "wolfssl", "version": "5.9.1",
                    "cpe": "cpe:2.3:a:wolfssl:wolfssl:5.9.1:*:*:*:*:*:*:*",
                    "components": [{
                        "name": "wolfcrypt", "version": "5.9.1",
                    }],
                }],
            }, f)
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--require-dep-version", "wolfcrypt", no_purl],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        check(rc != 0, "validator rejects nested wolfcrypt without a PURL")

        no_cpe = os.path.join(d, "no-cpe.cdx.json")
        with open(no_cpe, "w") as f:
            json.dump({
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "metadata": {"component": {"name": "wolfboot",
                                           "version": "2.9.0",
                                           "properties": [{"a": "b"}]}},
                "components": [{
                    "name": "wolfssl", "version": "5.9.1",
                }],
            }, f)
        rc = subprocess.call([sys.executable, VALIDATE,
                              "--require-dep-version", "wolfssl", no_cpe],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        check(rc != 0, "validator still requires a CPE on wolfssl")

    print("[unit] user-settings contract")
    driver_py = os.path.join(SHARE, "sbom-driver.py")
    with tempfile.TemporaryDirectory() as d:
        lib = os.path.join(d, "lib.a")
        with open(lib, "wb") as f:
            f.write(b"x")
        settings = os.path.join(d, "settings.h")
        with open(settings, "w") as f:
            f.write("/* settings */\n")
        base = [sys.executable, driver_py, "--name", "selftest",
                "--version", "1.0.0", "--lib", lib, "--user-settings", settings]
        r = subprocess.run(base, capture_output=True, text=True)
        check(r.returncode != 0 and "--user-settings-include" in r.stderr,
              "user-settings requires an include directory")
        r = subprocess.run(base + ["--user-settings-include", d],
                           capture_output=True, text=True)
        check(r.returncode != 0 and "WOLFSSL_USER_SETTINGS" in r.stderr,
              "user-settings requires WOLFSSL_USER_SETTINGS")


def find_gen_sbom(explicit):
    if explicit and os.path.isfile(explicit):
        return explicit
    env = os.environ.get("GEN_SBOM")
    if env and os.path.isfile(env):
        return env
    vendored = os.path.join(SHARE, "gen-sbom")
    if os.path.isfile(vendored):
        return vendored
    wd = os.environ.get("WOLFSSL_DIR")
    if wd:
        cand = os.path.join(wd, "scripts", "gen-sbom")
        if os.path.isfile(cand):
            return cand
    return None


def run_driver(workdir, gen_sbom, extra, env=None):
    cmd = [DRIVER, "--name", "selftest", "--version", "1.0.0",
           "--license-file", os.path.join(workdir, "LICENSE"),
           "--gen-sbom", gen_sbom, "--root", workdir] + extra
    return subprocess.run(cmd, cwd=workdir, capture_output=True, text=True,
                          env=env)


def write_stub_generator(path):
    """A generator whose --help omits the feature-detected flags.

    The driver must skip --document-namespace, --dep-libz, and --dep-version
    when the generator does not advertise them, and must still run.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "import os, sys\n"
            "if '--help' in sys.argv:\n"
            "    sys.stdout.write('usage: stub\\n')\n"
            "    sys.exit(0)\n"
            "with open(os.environ['STUB_ARGV'], 'w', encoding='utf-8') as out:\n"
            "    out.write('\\n'.join(sys.argv))\n"
            "sys.exit(0)\n"
        )


def integration_tests(gen_sbom):
    print(f"[integration] gen-sbom = {gen_sbom}")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "LICENSE"), "w") as f:
            f.write("MIT License\n")
        a = os.path.join(d, "a.c")
        b = os.path.join(d, "b.c")
        for p in (a, b):
            with open(p, "w") as f:
                f.write("int f(void){return 0;}\n")
        srcs = os.path.join(d, "srcs.txt")
        with open(srcs, "w") as f:
            f.write(a + "\n" + b + "\n")

        # Source-embedded path with a path-valued define.
        r = run_driver(d, gen_sbom, [
            "--srcs-file", srcs,
            "--cflags=-DHAVE_AES -DPICO_SDK_PATH=/home/secret/sdk",
            "--cdx-out", "e.cdx.json", "--spdx-out", "e.spdx.json"])
        check(r.returncode == 0, "source-embedded generate succeeds")
        cdx = os.path.join(d, "e.cdx.json")
        check(os.path.isfile(cdx), "CycloneDX written")
        check(os.path.isfile(os.path.join(d, "e.spdx.json")), "SPDX written")
        if os.path.isfile(cdx):
            text = open(cdx).read()
            check("secret" not in text, "no host path leaks into the SBOM")
            check("PICO_SDK_PATH" in text, "config macro name retained")
            rc = subprocess.call([sys.executable, VALIDATE,
                                  "--name-prefix", "selftest", cdx],
                                 stdout=subprocess.DEVNULL)
            check(rc == 0, "generated CycloneDX validates")

        # Library path (tier R/L/S): hash a built artifact.
        lib = os.path.join(d, "libselftest.a")
        with open(lib, "wb") as f:
            f.write(b"!<arch>\n" + b"\x00" * 64)
        r = run_driver(d, gen_sbom, [
            "--lib", lib, "--cflags=-DHAVE_AES",
            "--cdx-out", "l.cdx.json", "--spdx-out", "l.spdx.json"])
        check(r.returncode == 0, "library generate succeeds")

        # Reproducibility: same inputs + SOURCE_DATE_EPOCH => byte-identical.
        env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
        outs = []
        for i in (1, 2):
            cmd = [DRIVER, "--name", "selftest", "--version", "1.0.0",
                   "--license-file", os.path.join(d, "LICENSE"),
                   "--gen-sbom", gen_sbom, "--root", d,
                   "--srcs-file", srcs, "--cflags=-DHAVE_AES",
                   "--cdx-out", f"r{i}.cdx.json", "--spdx-out", f"r{i}.spdx.json"]
            subprocess.run(cmd, cwd=d, env=env, capture_output=True, text=True)
            p = os.path.join(d, f"r{i}.cdx.json")
            outs.append(open(p).read() if os.path.isfile(p) else f"<missing {i}>")
        check(outs[0] == outs[1], "byte-reproducible CycloneDX")

        # Feature-detected forwarding. The real generator advertises the
        # flags, so the dependency version and the namespace must land in
        # the document. A stub whose --help omits them must still succeed,
        # and those flags must not appear on its command line.
        ns = "https://example.com/sbom/selftest-1.0.0"
        r = run_driver(d, gen_sbom, [
            "--lib", lib, "--cflags=-DHAVE_AES",
            "--dep-libz", "yes",
            "--dep-version", "libz=1.2.13",
            "--document-namespace", ns,
            "--cdx-out", "fwd.cdx.json", "--spdx-out", "fwd.spdx.json"])
        check(r.returncode == 0,
              "advertised dependency and namespace flags generate\n"
              + r.stderr)
        fwd = os.path.join(d, "fwd.spdx.json")
        if r.returncode == 0 and os.path.isfile(fwd):
            spdx = json.load(open(fwd, encoding="utf-8"))
            check(spdx.get("documentNamespace") == ns,
                  "document namespace is forwarded")
            blob = json.dumps(spdx)
            check("zlib" in blob and "1.2.13" in blob,
                  "libz name and version are forwarded")

        stub = os.path.join(d, "stub-gen-sbom.py")
        write_stub_generator(stub)
        argv_path = os.path.join(d, "stub-argv.txt")
        env = dict(os.environ, STUB_ARGV=argv_path)
        r = run_driver(d, stub, [
            "--lib", lib, "--cflags=-DHAVE_AES",
            "--dep-libz", "yes",
            "--dep-version", "libz=1.2.13",
            "--document-namespace", ns,
            "--cdx-out", "stub.cdx.json", "--spdx-out", "stub.spdx.json"],
            env=env)
        check(r.returncode == 0,
              "unsupported generator flags are skipped\n" + r.stderr)
        argv = []
        if os.path.isfile(argv_path):
            argv = open(argv_path, encoding="utf-8").read().splitlines()
        check("--dep-libz" not in argv, "omitted --dep-libz is not forwarded")
        check("--dep-version" not in argv,
              "omitted --dep-version is not forwarded")
        check("--document-namespace" not in argv,
              "omitted --document-namespace is not forwarded")
        check("--lib" in argv, "the library checksum source is still forwarded")

        # --lib names the as-built artifact. gen-sbom accepts one checksum
        # source, so the driver must not forward --lib with --no-artifact-hash.
        if os.path.isfile(argv_path):
            os.remove(argv_path)
        r = run_driver(d, stub, [
            "--lib", lib, "--no-artifact-hash", "--cflags=-DHAVE_AES",
            "--cdx-out", "nah.cdx.json", "--spdx-out", "nah.spdx.json"],
            env=env)
        check(r.returncode == 0, "no-artifact-hash reaches the generator\n"
              + r.stderr)
        argv = []
        if os.path.isfile(argv_path):
            argv = open(argv_path, encoding="utf-8").read().splitlines()
        check("--no-artifact-hash" in argv, "--no-artifact-hash is forwarded")
        check("--lib" not in argv,
              "--lib is not a second checksum source")

        settings = os.path.join(d, "settings.h")
        with open(settings, "w", encoding="utf-8") as f:
            f.write("/* settings */\n")
        if os.path.isfile(argv_path):
            os.remove(argv_path)
        r = run_driver(d, stub, [
            "--lib", lib,
            "--user-settings", settings,
            "--user-settings-include", d,
            "--user-settings-define", "WOLFSSL_USER_SETTINGS",
            "--cdx-out", "us.cdx.json", "--spdx-out", "us.spdx.json"],
            env=env)
        check(r.returncode == 0, "settings.h route is forwarded\n" + r.stderr)
        argv = []
        if os.path.isfile(argv_path):
            argv = open(argv_path, encoding="utf-8").read().splitlines()
        check(settings in argv, "settings.h path is forwarded")
        check("--user-settings-include" in argv,
              "user-settings include directory is forwarded")
        check("WOLFSSL_USER_SETTINGS" in argv,
              "WOLFSSL_USER_SETTINGS is forwarded")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen-sbom", default="")
    args = ap.parse_args()

    unit_tests()
    gen_sbom = find_gen_sbom(args.gen_sbom)
    if gen_sbom:
        integration_tests(gen_sbom)
    else:
        print("[integration] SKIP: gen-sbom not found "
              "(vendored copy missing; set GEN_SBOM or WOLFSSL_DIR)")

    if _fail:
        print(f"\n{_fail} check(s) FAILED", file=sys.stderr)
        sys.exit(1)
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
