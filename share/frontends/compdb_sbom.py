#!/usr/bin/env python3
"""Generate an SBOM from a Clang compilation database (compile_commands.json).

This is the universal IDE/toolchain fallback and is product-neutral. Any build
that can emit a compilation database gives an exact, ground-truth list of the
files that were compiled and the -D configuration they were compiled with,
independent of the build system or compiler. That covers cases with no Make or
CMake SBOM path:

  * CMake builds            (-DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
  * TI Code Composer Studio (armcl, via `bear -- make ...`)
  * Microchip MPLAB X       (xc32, via `bear -- make ...`)
  * Renesas e2studio / CCRX (via a build wrapper that records commands)
  * Xilinx SDK / Vitis      (via `bear -- make ...`)

A source a file compiles in through #include, such as wolfSSL's
src/ssl_api_*.c, is not an entry of its own. `--included-sources` adds those
by rerunning the selected commands with -M, which needs a gcc- or clang-style
compiler and runs the compilers the database names.

The extracted sources + defines are handed to the shared driver (sbom-driver),
so the resulting CycloneDX 1.6 / SPDX 2.3 SBOM is identical in shape to the Make,
CMake, and IAR paths.

Usage:
  compdb_sbom.py --name NAME build/compile_commands.json [options]
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

SRC_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.s', '.asm')
# Only these are preprocessed, so only these are rerun with -M.
SCAN_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.S')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# The shared driver is the sibling of this frontends/ directory.
DEFAULT_DRIVER = os.path.join(os.path.dirname(SCRIPT_DIR), "sbom-driver")


def entry_tokens(entry):
    if entry.get('arguments'):
        return list(entry['arguments'])
    if entry.get('command'):
        try:
            return shlex.split(entry['command'])
        except ValueError:
            return entry['command'].split()
    return []


def file_id(path):
    st = os.stat(path)
    return st.st_dev, st.st_ino


def macro_name(d):
    """Macro name of a -D/-U operand: the text before the first '=' or '(',
    so a function-like 'F(a)=a' is keyed as 'F'."""
    return re.split(r'[=(]', d, maxsplit=1)[0]


def extract_defines(tokens):
    """Net -D macros for one compile command, honouring a later -U that cancels
    an earlier -D of the same name (the compiler applies them in order, so a
    macro undefined on the command line was not compiled in)."""
    active = {}   # macro name -> full 'NAME' or 'NAME=VALUE' token; last -D wins
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == '-D' and i + 1 < len(tokens):
            d = tokens[i + 1]
            active[macro_name(d)] = d
            i += 2
            continue
        if t.startswith('-D'):
            d = t[2:]
            active[macro_name(d)] = d
            i += 1
            continue
        if t == '-U' and i + 1 < len(tokens):
            active.pop(macro_name(tokens[i + 1]), None)
            i += 2
            continue
        if t.startswith('-U'):
            active.pop(macro_name(t[2:]), None)
            i += 1
            continue
        i += 1
    return list(active.values())


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('compdb', help='Path to compile_commands.json')
    ap.add_argument('--name', required=True, help='Package name for the SBOM.')
    ap.add_argument('--include', action='append', default=[])
    ap.add_argument('--exclude', action='append', default=[])
    ap.add_argument('--driver', default=DEFAULT_DRIVER,
                    help='Path to the shared sbom-driver.')
    ap.add_argument('--gen-sbom', default=None)
    ap.add_argument('--version', default=None)
    ap.add_argument('--version-file', default=None)
    ap.add_argument('--version-macro', default=None)
    ap.add_argument('--root', default=None)
    ap.add_argument('--license-file', default=None)
    ap.add_argument('--copyright-start', default=None)
    # A compilation database lists the -D tokens the compiler was given, not
    # the macros a settings header derives from them. Without these two the
    # capture reads an empty translation unit and the recorded configuration
    # is the -D list alone.
    ap.add_argument('--settings-h', default=None,
                    help='Settings header to -include during macro capture '
                         '(e.g. wolfssl/wolfcrypt/settings.h).')
    ap.add_argument('--include-dir', action='append', default=[],
                    help='Include directory for the capture (repeatable), '
                         'typically the directory holding user_settings.h.')
    ap.add_argument('--crypto-only', default=None,
                    help='auto|yes|no, forwarded to the generator.')
    ap.add_argument('--cdx-out', default=None)
    ap.add_argument('--spdx-out', default=None)
    ap.add_argument('--srcs-out', default=None)
    ap.add_argument('--print-only', action='store_true')
    ap.add_argument('--included-sources', action='store_true',
                    help='Rerun the compile commands with -M and add the '
                         'source files they #include. Runs the compilers '
                         'the database names; needs one that supports -M.')
    args = ap.parse_args()

    if not os.path.isfile(args.compdb):
        sys.exit(f"ERROR: compilation database not found: {args.compdb}")
    with open(args.compdb) as f:
        try:
            db = json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f"ERROR: cannot parse {args.compdb}: {e}")

    inc = [re.compile(p) for p in args.include]
    exc = [re.compile(p) for p in args.exclude]

    # When --root is given, only hash sources inside it; a compile_commands.json
    # is untrusted input, so a crafted entry naming an absolute path outside the
    # product must not pull an unrelated file (and its path) into the SBOM.
    root_abs = os.path.realpath(args.root) if args.root else None

    srcs, defines, seen, selected = [], set(), set(), []
    for entry in db:
        fpath = entry.get('file')
        if not fpath:
            continue
        directory = entry.get('directory', os.getcwd())
        if not os.path.isabs(fpath):
            fpath = os.path.join(directory, fpath)
        fpath = os.path.normpath(fpath)
        if not fpath.lower().endswith(SRC_EXTS):
            continue
        if root_abs:
            real = os.path.realpath(fpath)
            if os.path.commonpath([real, root_abs]) != root_abs:
                sys.stderr.write(
                    f"WARNING: skipping source outside --root: {fpath}\n")
                continue
        if inc and not any(r.search(fpath) for r in inc):
            continue
        if exc and any(r.search(fpath) for r in exc):
            continue
        for d in extract_defines(entry_tokens(entry)):
            defines.add(d)
        if not os.path.isfile(fpath):
            continue
        if fpath not in seen:
            seen.add(fpath)
            srcs.append(fpath)
        ext = os.path.splitext(fpath)[1]
        if ext in SCAN_EXTS or ext.lower() in SCAN_EXTS:
            selected.append((fpath, entry))

    if not srcs:
        sys.exit("ERROR: no matching source files found in compilation database")

    included = []
    if args.included_sources:
        sys.path.insert(0, SCRIPT_DIR)
        from included_sources import ScanError, included_sources
        try:
            scan_root = root_abs or os.path.commonpath(
                [os.path.dirname(s) for s in srcs])
        except ValueError:
            sys.exit("ERROR: sources share no common directory; pass --root")
        known = {file_id(s) for s in srcs}
        names = {os.path.basename(s): s for s in srcs}
        scanned = set()
        for fpath, entry in selected:
            tokens = entry_tokens(entry)
            key = (fpath, entry.get('directory'), tuple(tokens))
            if key in scanned:
                continue
            scanned.add(key)
            if not tokens:
                sys.stderr.write(f"WARNING: no compile command for {fpath}; "
                                 f"its #include'd sources are not scanned\n")
                continue
            try:
                found = included_sources(
                    tokens, entry.get('directory', os.getcwd()), fpath,
                    scan_root, SRC_EXTS)
            except ScanError as e:
                sys.exit(f"ERROR: {e}")
            for path in found:
                if (not os.path.isfile(path) or file_id(path) in known
                        or (inc and not any(r.search(path) for r in inc))
                        or (exc and any(r.search(path) for r in exc))):
                    continue
                name = os.path.basename(path)
                if name in names:
                    sys.exit(f"ERROR: {path}, #include'd by {fpath}, has the "
                             f"same basename as {names[name]}; --exclude "
                             f"one of them")
                known.add(file_id(path))
                names[name] = path
                included.append(path)
        srcs += included

    defines = sorted(defines)
    cflags = ' '.join(f'-D{d}' for d in defines)

    if args.print_only:
        print(f"# {len(srcs)} sources ({len(included)} included), "
              f"{len(defines)} defines")
        print("\n[defines]")
        for d in defines:
            print(f"  -D{d}")
        print("\n[sources]")
        for s in srcs:
            print(f"  {s}")
        return

    srcs_out, tmp = args.srcs_out, None
    if not srcs_out:
        fd, srcs_out = tempfile.mkstemp(prefix='wolfssl-compliance-tooling-compdb-srcs-', suffix='.txt')
        os.close(fd)
        tmp = srcs_out
    with open(srcs_out, 'w') as f:
        f.write('\n'.join(srcs) + '\n')

    cmd = [args.driver, '--srcs-file', srcs_out, f'--cflags={cflags}',
           '--name', args.name]
    for flag, val in (('--version', args.version),
                      ('--version-file', args.version_file),
                      ('--version-macro', args.version_macro),
                      ('--root', args.root),
                      ('--license-file', args.license_file),
                      ('--copyright-start', args.copyright_start),
                      ('--settings-h', args.settings_h),
                      ('--crypto-only', args.crypto_only),
                      ('--gen-sbom', args.gen_sbom),
                      ('--cdx-out', args.cdx_out),
                      ('--spdx-out', args.spdx_out)):
        if val:
            cmd += [flag, val]
    for inc in args.include_dir:
        cmd += ['--include-dir', inc]

    print(f"compdb SBOM: {len(srcs)} sources ({len(included)} included), "
          f"{len(defines)} defines")
    try:
        rc = subprocess.call(cmd)
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
    sys.exit(rc)


if __name__ == '__main__':
    main()
