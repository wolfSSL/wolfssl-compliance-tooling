#!/usr/bin/env python3
"""Unit tests for central/release-advisory.

Run:
    python3 -m unittest central/test_release_advisory.py
"""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / 'release-advisory'

CHANGELOG = textwrap.dedent("""\
    # wolfSSL Release 5.9.4 (Sep 17, 2026)
    ## Vulnerabilities
    * [High] CVE-2026-11310
      This affects only builds with --enable-opensslextra (OPENSSL_EXTRA).
    """)


def _load():
    loader = SourceFileLoader('release_advisory', str(SCRIPT))
    spec = importlib.util.spec_from_loader('release_advisory', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


rel = _load()


class ArgvTests(unittest.TestCase):
    def test_draft_argv_stops_at_the_overlay_tool(self):
        argv = rel.draft_argv('python3', '5.9.4', 'ChangeLog.md', None,
                              False, True)
        self.assertEqual(argv[1], str(HERE / 'advisory-overlay-draft'))
        self.assertIn('--dry-run', argv)
        self.assertNotIn('gen-advisory', ' '.join(argv))
        self.assertNotIn('csaf-publish', ' '.join(argv))

    def test_publish_steps_sign_inside_csaf_publish_and_keep_the_tree(self):
        steps = rel.publish_steps(
            'python3', '5.9.4', 'advisories/vex-overlay.json',
            'advisories/records', 'advisories/releases',
            'advisories/out/wolfssl-5.9.4', 'advisories/publish',
            'ABCDEF0123456789ABCDEF0123456789ABCDEF01', None,
            '/tmp/pin-records')
        flat = [' '.join(step) for step in steps]
        self.assertEqual(len(steps), 4)
        self.assertIn('gen-advisory', flat[0])
        self.assertIn('--advisory-id wolfssl-5.9.4', flat[0])
        self.assertIn('--records-dir /tmp/pin-records', flat[1])
        self.assertIn('csaf-publish', flat[2])
        self.assertIn('--keep', flat[2])
        self.assertIn('--gpg-key ABCDEF0123456789ABCDEF0123456789ABCDEF01',
                      flat[2])
        self.assertNotIn('gpg --armor', flat[2])
        self.assertIn('csaf-verify', flat[3])
        self.assertIn('--fingerprint ABCDEF0123456789ABCDEF0123456789ABCDEF01',
                      flat[3])

    def test_completeness_uses_the_release_directory(self):
        argv = rel.completeness_argv(
            'python3', '5.9.4', 'ChangeLog.md', None,
            'advisories/records', 'advisories/releases')
        self.assertIn('--release-dir', argv)
        self.assertIn('advisories/releases/5.9.4', argv)
        self.assertIn('--changelog', argv)


class CliTests(unittest.TestCase):
    def test_draft_rejects_another_product(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), 'draft',
             '--release', '5.9.4',
             '--changelog', 'ChangeLog.md',
             '--product', 'wolfSSH'],
            check=False, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('wolfSSL only', result.stderr)
        self.assertIn('product profile', result.stderr)

    def test_draft_prints_review_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            changelog = root / 'ChangeLog.md'
            changelog.write_text(CHANGELOG)
            overlay = root / 'vex-overlay.json'
            overlay.write_text('{}\n')
            result = subprocess.run(
                [sys.executable, str(SCRIPT), 'draft',
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay),
                 '--dry-run'],
                check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('REVIEW', result.stdout)
            self.assertIn('Stop here', result.stdout)
            self.assertIn('does not judge the determination', result.stdout)
            self.assertEqual(overlay.read_text(), '{}\n')
            self.assertFalse((root / 'publish').exists())

    def test_publish_rejects_another_product_before_it_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            out = root / 'out'
            result = subprocess.run(
                [sys.executable, str(SCRIPT), 'publish',
                 '--release', '5.9.4',
                 '--changelog', 'ChangeLog.md',
                 '--product', 'wolfTPM',
                 '--out-dir', str(out),
                 '--releases-root', str(root / 'releases'),
                 '--records-dir', str(root / 'records')],
                check=False, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('wolfSSL only', result.stderr)
            self.assertFalse(out.exists())
