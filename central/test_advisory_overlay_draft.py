#!/usr/bin/env python3
"""Unit tests for central/advisory-overlay-draft.

Run:
    python3 -m unittest central/test_advisory_overlay_draft.py
"""

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / 'advisory-overlay-draft'


def _load():
    loader = SourceFileLoader('aod', str(SCRIPT))
    spec = importlib.util.spec_from_loader('aod', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


aod = _load()

# The second paragraph names the real gate. A later sentence names a macro
# only to say the default path is not affected. The drafter must keep the
# first and drop the second. That was the 5.9.2 review miss.
CHANGELOG = textwrap.dedent("""\
    # wolfSSL Release 5.9.4 (Sep 17, 2026)
    ## Vulnerabilities
    * [High] CVE-2026-11310
      X.509 trust-chain bypass in the OpenSSL compatibility certificate verifier.

      This affects only builds with --enable-opensslextra (OPENSSL_EXTRA).
      The default wolfSSL TLS handshake (WOLFSSL_VERIFY_PEER) is not affected.
      Manual verification also requires --enable-sessioncerts.
    * [High] CVE-2026-55960
      Raw public key accepted without a chain. Only affects builds with Raw Public Key support (HAVE_RPK) enabled - disabled by default.
    * [Med] CVE-2026-1111, CVE-2026-2222
      Two ids on one bullet. Builds that define WOLFSSL_SNIFFER are affected.

    # wolfSSL Release 5.9.2 (Jun 23, 2026)
    ## Vulnerabilities
    * [Low] CVE-2026-1000
      Old.
    """)


class GuessTests(unittest.TestCase):
    def test_keeps_enable_macro_and_drops_not_affected_macro(self):
        text = (
            'This affects only builds with --enable-opensslextra (OPENSSL_EXTRA). '
            'The default wolfSSL TLS handshake (WOLFSSL_VERIFY_PEER) is not affected. '
            'Manual verification also requires --enable-sessioncerts.'
        )
        macros, flags = aod.guess_defines(text)
        self.assertEqual(macros, ['OPENSSL_EXTRA'])
        self.assertEqual(flags, ['--enable-sessioncerts'])

    def test_paren_support_macro_and_default_off(self):
        text = ('Only affects builds with Raw Public Key support (HAVE_RPK) '
                'enabled - disabled by default.')
        macros, flags = aod.guess_defines(text)
        self.assertEqual(macros, ['HAVE_RPK'])
        self.assertEqual(flags, [])
        self.assertEqual(aod.guess_default_status(text), 'off')

    def test_define_keyword_before_a_bare_macro(self):
        macros, _flags = aod.guess_defines(
            'Builds that define WOLFSSL_SNIFFER are affected.')
        self.assertEqual(macros, ['WOLFSSL_SNIFFER'])

    def test_does_not_take_a_macro_that_is_not_defined(self):
        macros, _flags = aod.guess_defines(
            'Builds where WOLFSSL_SNIFFER is not defined are safe.')
        self.assertEqual(macros, [])

    def test_unless_defined_is_not_the_gate(self):
        macros, flags = aod.guess_defines(
            'The check applies unless ALLOW_INVALID_CERTSIGN is defined. '
            'Note this only affects builds with SM2 support (--enable-sm2 or --enable-all).')
        self.assertNotIn('ALLOW_INVALID_CERTSIGN', macros)
        self.assertEqual(flags, ['--enable-sm2'])

    def test_is_defined_is_not_a_gate(self):
        text = (
            'Without NO_SESSION_CACHE_REF, wolfSSL_get_session() does not '
            'return a session object. The bug is gone when '
            'NO_SESSION_CACHE_REF is defined.'
        )
        macros, _flags = aod.guess_defines(text)
        self.assertNotIn('NO_SESSION_CACHE_REF', macros)

    def test_paren_pair_either_order(self):
        macros, flags = aod.guess_defines(
            'Only builds with ALPN (HAVE_ALPN / --enable-alpn) are affected.')
        self.assertEqual(macros, ['HAVE_ALPN'])
        self.assertEqual(flags, [])
        macros, flags = aod.guess_defines(
            'Only builds with ALPN (--enable-alpn / HAVE_ALPN) are affected.')
        self.assertEqual(macros, ['HAVE_ALPN'])
        self.assertEqual(flags, [])

    def test_paren_pair_after_without_is_not_a_gate(self):
        macros, _flags = aod.guess_defines(
            'The bug is present without (HAVE_ALPN / --enable-alpn).')
        self.assertEqual(macros, [])


class VexLineTests(unittest.TestCase):
    def test_vex_line_is_used_and_prose_is_not_guessed(self):
        body = [
            'Without NO_SESSION_CACHE_REF, the getter returns a reference.',
            'VEX: fixed=5.9.4; defines=',
            '',
            'Later text mentions --enable-opensslextra (OPENSSL_EXTRA).',
        ]
        entry, notes = aod.draft_entry('wolfSSL', '5.9.4', body)
        self.assertNotIn('requires_defines', entry)
        self.assertNotIn('VEX:', entry['detail'])
        self.assertTrue(any('default build' in line for line in notes))
        self.assertNotIn('OPENSSL_EXTRA', entry.get('requires_defines', []))

    def test_vex_line_sets_the_macro(self):
        body = [
            'ALPN parsing.',
            'VEX: fixed=5.9.4; defines=HAVE_ALPN',
        ]
        entry, notes = aod.draft_entry('wolfSSL', '5.9.4', body)
        self.assertEqual(entry['requires_defines'], ['HAVE_ALPN'])
        self.assertTrue(any('VEX line' in line for line in notes))

    def test_vex_line_allows_spaces_around_commas(self):
        body = [
            'ALPN parsing overread.',
            'VEX: fixed=5.9.4; defines=HAVE_ALPN, OPENSSL_EXTRA',
            '',
            'Builds that define WOLFSSL_SNIFFER are affected.',
        ]
        entry, notes = aod.draft_entry('wolfSSL', '5.9.4', body)
        self.assertEqual(entry['requires_defines'], ['HAVE_ALPN', 'OPENSSL_EXTRA'])
        self.assertEqual(entry['detail'], 'ALPN parsing overread.')
        self.assertNotIn('VEX:', entry['detail'])
        self.assertNotIn('WOLFSSL_SNIFFER', entry['requires_defines'])
        self.assertTrue(any('VEX line' in line for line in notes))

    def test_malformed_vex_line_is_rejected(self):
        body = [
            'ALPN parsing overread.',
            'VEX: fixed=5.9.4 defines=HAVE_ALPN, OPENSSL_EXTRA',
        ]
        with self.assertRaises(SystemExit) as cm:
            aod.draft_entry('wolfSSL', '5.9.4', body)
        self.assertIn('malformed VEX line', str(cm.exception))


class BulletTests(unittest.TestCase):
    def setUp(self):
        self.block = aod.ac.release_block(CHANGELOG, 'wolfSSL', '5.9.4')

    def test_strict_bullets_and_extra_id(self):
        bullets = aod.bullet_bodies(self.block)
        self.assertEqual([b['cve'] for b in bullets],
                         ['CVE-2026-11310', 'CVE-2026-55960', 'CVE-2026-1111'])
        extra = bullets[2]['extra_ids']
        self.assertEqual(extra, ['CVE-2026-2222'])

    def test_detail_is_the_first_paragraph_only(self):
        bullets = aod.bullet_bodies(self.block)
        entry, _notes = aod.draft_entry('wolfSSL', '5.9.4', bullets[0]['body'])
        self.assertEqual(
            entry['detail'],
            'X.509 trust-chain bypass in the OpenSSL compatibility certificate verifier.')
        self.assertEqual(entry['fixed_versions'], ['5.9.4'])
        self.assertEqual(entry['remediation'], 'Update to wolfSSL 5.9.4 or later.')
        self.assertEqual(entry['requires_defines'], ['OPENSSL_EXTRA'])
        self.assertNotIn('default_status', entry)

    def test_default_off_is_recorded(self):
        bullets = aod.bullet_bodies(self.block)
        entry, _notes = aod.draft_entry('wolfSSL', '5.9.4', bullets[1]['body'])
        self.assertEqual(entry['requires_defines'], ['HAVE_RPK'])
        self.assertEqual(entry['default_status'], 'off')


class SpliceTests(unittest.TestCase):
    def test_append_keeps_existing_escape_bytes(self):
        original = textwrap.dedent("""\
            {
              "_comment": "keep",
              "CVE-2026-1000": {
                "state": "exploitable",
                "detail": "API\\u2019s stay escaped"
              }
            }
            """)
        entry = {
            'state': 'exploitable',
            'response': ['update'],
            'detail': 'New.',
            'fixed_versions': ['5.9.4'],
            'remediation': 'Update to wolfSSL 5.9.4 or later.',
        }
        out = aod.splice_entries(original, [('CVE-2026-11310', entry)])
        self.assertIn('API\\u2019s stay escaped', out)
        data = json.loads(out)
        self.assertEqual(data['CVE-2026-1000']['detail'], 'API\u2019s stay escaped')
        self.assertEqual(data['CVE-2026-11310']['fixed_versions'], ['5.9.4'])
        self.assertEqual(list(data)[0], '_comment')

    def test_build_drafts_does_not_replace_an_existing_key(self):
        actions, notes = aod.build_drafts(
            CHANGELOG, 'wolfSSL', '5.9.4', {'CVE-2026-11310'}, replace=False)
        cves = [cve for cve, _entry in actions]
        self.assertNotIn('CVE-2026-11310', cves)
        self.assertIn('CVE-2026-55960', cves)
        self.assertTrue(any(line.startswith('kept ')
                            for line in notes['CVE-2026-11310']))
        self.assertTrue(any('CVE-2026-2222' in line for line in notes['CVE-2026-1111']))


class CliTests(unittest.TestCase):
    def test_dry_run_writes_nothing_and_live_run_appends(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            changelog = root / 'ChangeLog.md'
            changelog.write_text(CHANGELOG)
            overlay = root / 'vex-overlay.json'
            overlay.write_text('{}\n')
            dry = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay),
                 '--dry-run'],
                check=False, capture_output=True, text=True)
            self.assertEqual(dry.returncode, 0, dry.stderr)
            self.assertIn('dry run: file not written', dry.stdout)
            self.assertIn('REVIEW', dry.stdout)
            self.assertEqual(overlay.read_text(), '{}\n')

            live = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay)],
                check=False, capture_output=True, text=True)
            self.assertEqual(live.returncode, 0, live.stderr)
            data = json.loads(overlay.read_text())
            self.assertIn('CVE-2026-11310', data)
            self.assertNotIn('CVE-2026-2222', data)
            self.assertNotIn('CVE-2026-1000', data)

            again = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay)],
                check=False, capture_output=True, text=True)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertIn('nothing to add', again.stdout)
            self.assertEqual(json.loads(overlay.read_text()), data)

    def test_replace_rewrites_the_key_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            changelog = root / 'ChangeLog.md'
            changelog.write_text(
                '# wolfSSL Release 5.9.2 (Jun 23, 2026)\n'
                '## Vulnerabilities\n'
                '* [High] CVE-2026-55967\n'
                '  New text.\n'
            )
            overlay = root / 'vex-overlay.json'
            overlay.write_text(json.dumps({
                '_comment': 'keep',
                'CVE-2026-55967': {
                    'state': 'exploitable',
                    'detail': 'Old text.',
                },
                'CVE-2026-1000': {
                    'state': 'exploitable',
                    'detail': 'Leave this key.',
                },
            }, indent=2) + '\n')
            run = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.2',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay),
                 '--replace'],
                check=False, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            text = overlay.read_text()
            self.assertEqual(text.count('"CVE-2026-55967"'), 1)
            data = json.loads(text)
            self.assertEqual(data['CVE-2026-55967']['detail'], 'New text.')
            self.assertEqual(data['CVE-2026-1000']['detail'], 'Leave this key.')
            self.assertEqual(data['_comment'], 'keep')

    def test_malformed_vex_line_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            changelog = root / 'ChangeLog.md'
            changelog.write_text(
                '# wolfSSL Release 5.9.4 (Sep 17, 2026)\n'
                '## Vulnerabilities\n'
                '* [High] CVE-2026-99991\n'
                '  ALPN parsing overread.\n'
                '  VEX: fixed=5.9.4 defines=HAVE_ALPN, OPENSSL_EXTRA\n'
            )
            overlay = root / 'vex-overlay.json'
            overlay.write_text('{}\n')
            run = subprocess.run(
                [sys.executable, str(SCRIPT),
                 '--release', '5.9.4',
                 '--changelog', str(changelog),
                 '--overlay', str(overlay)],
                check=False, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('malformed VEX line', run.stderr)
            self.assertEqual(overlay.read_text(), '{}\n')


if __name__ == '__main__':
    unittest.main()
