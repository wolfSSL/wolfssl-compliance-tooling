#!/usr/bin/env python3
"""Unit tests for central/csaf-publish (unsigned directory layout).

Run:
    python3 -m unittest central/test_csaf_publish.py
"""

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent
PUBLISH = HERE / 'csaf-publish'
VERIFY = HERE / 'csaf-verify'
KEYGEN = HERE / 'csaf-keygen'
GEN = HERE / 'gen-advisory'
TESTDATA = HERE / 'testdata'
EXAMPLE_OVERLAY = HERE / 'advisory-vex-overlay.example.json'


def _load(path, name):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


pub = _load(PUBLISH, 'csaf_publish')
ver = _load(VERIFY, 'csaf_verify')
keygen = _load(KEYGEN, 'csaf_keygen')
ga = _load(GEN, 'ga')


def _sha(path, algo):
    return hashlib.new(algo, path.read_bytes()).hexdigest()


class CanonicalNameTests(unittest.TestCase):
    def test_cve_id(self):
        self.assertEqual(pub.canonical_filename('CVE-2026-5501'),
                         'cve-2026-5501.json')

    def test_bundle_id(self):
        self.assertEqual(pub.canonical_filename('wolfssl-5.9.2'),
                         'wolfssl-5_9_2.json')


class UnsignedPublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.docs = self.root / 'docs'
        self.out = self.root / 'publish'
        self.docs.mkdir()
        adv = ga.parse_record(json.loads(
            (TESTDATA / 'CVE-2026-5501.json').read_text()))
        ov = json.loads(EXAMPLE_OVERLAY.read_text())
        csaf = ga.generate_csaf([adv], ov, adv['cve'], '2026-01-02T00:00:00Z')
        (self.docs / 'CVE-2026-5501.csaf.json').write_text(
            json.dumps(csaf, indent=2) + '\n')

    def tearDown(self):
        self.tmp.cleanup()

    def _publish(self):
        # Drive the CLI through the same argv path CI will use.
        import sys
        argv = sys.argv
        try:
            sys.argv = [
                'csaf-publish',
                '--docs-dir', str(self.docs),
                '--out-root', str(self.out),
                '--base-url', 'https://www.wolfssl.com/.well-known/csaf',
            ]
            pub.main()
        finally:
            sys.argv = argv
        return self.out / '.well-known' / 'csaf'

    def test_layout_hashes_and_self_url(self):
        csaf_root = self._publish()
        dest = csaf_root / 'white' / '2026' / 'cve-2026-5501.json'
        self.assertTrue(dest.is_file())
        doc = json.loads(dest.read_text())
        selfs = [r['url'] for r in doc['document']['references']
                 if r.get('category') == 'self']
        self.assertEqual(
            selfs,
            ['https://www.wolfssl.com/.well-known/csaf/white/2026/cve-2026-5501.json'])
        for algo in ('sha256', 'sha512'):
            side = dest.with_name(dest.name + '.' + algo)
            want = side.read_text().split()[0]
            self.assertEqual(want, _sha(dest, algo))
        index = csaf_root.joinpath('index.txt').read_text().splitlines()
        self.assertEqual(index, ['white/2026/cve-2026-5501.json'])
        md = json.loads((csaf_root / 'provider-metadata.json').read_text())
        self.assertEqual(md['role'], 'csaf_provider')
        self.assertNotIn('public_openpgp_keys', md)
        md_path = csaf_root / 'provider-metadata.json'
        for algo in ('sha256', 'sha512'):
            side = md_path.with_name(md_path.name + '.' + algo)
            self.assertEqual(side.read_text().split()[0], _sha(md_path, algo))

    def test_rerun_drops_stale_files(self):
        csaf_root = self._publish()
        stale = csaf_root / 'white' / '2026' / 'cve-1999-0001.json'
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text('{}\n')
        self._publish()
        self.assertFalse(stale.exists())
        json_docs = sorted(p.name for p in (csaf_root / 'white' / '2026').glob('*.json'))
        self.assertEqual(json_docs, ['cve-2026-5501.json'])

    def test_source_date_epoch_pins_metadata_timestamp(self):
        saved = os.environ.get('SOURCE_DATE_EPOCH')
        os.environ['SOURCE_DATE_EPOCH'] = '1700000000'
        try:
            csaf_root = self._publish()
        finally:
            if saved is None:
                os.environ.pop('SOURCE_DATE_EPOCH', None)
            else:
                os.environ['SOURCE_DATE_EPOCH'] = saved
        md = json.loads((csaf_root / 'provider-metadata.json').read_text())
        self.assertEqual(md['last_updated'], '2023-11-14T22:13:20Z')

    def test_case_colliding_tracking_ids_fail(self):
        # A second document whose tracking id differs only in case must not
        # silently overwrite the first canonical filename.
        first = json.loads((self.docs / 'CVE-2026-5501.csaf.json').read_text())
        (self.docs / 'CVE-2026-5501.csaf.json').unlink()
        one = json.loads(json.dumps(first))
        one['document']['tracking']['id'] = 'WolfSSL-SA-1'
        two = json.loads(json.dumps(first))
        two['document']['tracking']['id'] = 'wolfssl-sa-1'
        (self.docs / 'one.csaf.json').write_text(json.dumps(one, indent=2) + '\n')
        (self.docs / 'two.csaf.json').write_text(json.dumps(two, indent=2) + '\n')
        with self.assertRaises(SystemExit) as cm:
            self._publish()
        self.assertIn('canonicalize', str(cm.exception))

    def test_unsigned_verify_walks_index(self):
        csaf_root = self._publish()
        import sys
        argv = sys.argv
        try:
            sys.argv = ['csaf-verify', '--root', str(csaf_root)]
            with self.assertRaises(SystemExit) as cm:
                ver.main()
            self.assertEqual(cm.exception.code, 0)
        finally:
            sys.argv = argv

    def test_verify_detects_index_without_file(self):
        csaf_root = self._publish()
        index = csaf_root / 'index.txt'
        index.write_text(index.read_text() + 'white/2026/cve-1999-0001.json\n')
        import sys
        argv = sys.argv
        try:
            sys.argv = ['csaf-verify', '--root', str(csaf_root)]
            with self.assertRaises(SystemExit) as cm:
                ver.main()
            self.assertEqual(cm.exception.code, 1)
        finally:
            sys.argv = argv


_FAKE_GPG = """#!/usr/bin/env python3
import os, sys
log = os.environ.get('GPG_ARGV_LOG')
if log:
    with open(log, 'a', encoding='utf-8') as fh:
        fh.write('\\t'.join(sys.argv[1:]) + '\\n')
args = sys.argv[1:]
if '--export-secret-keys' in args:
    sys.stderr.write('refusing to export a secret key\\n')
    sys.exit(3)
if '--fingerprint' in args:
    sys.stdout.write(
        'fpr:::::::::ABCDEF0123456789ABCDEF0123456789ABCDEF01:\\n')
    sys.exit(0)
if '--export' in args:
    sys.stdout.buffer.write(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\\n\\n')
    sys.exit(0)
if '--detach-sign' in args:
    out = args[args.index('--output') + 1]
    with open(out, 'w', encoding='utf-8') as fh:
        fh.write('-----BEGIN PGP SIGNATURE-----\\n\\n')
    sys.exit(0)
sys.stderr.write('unexpected gpg args\\n')
sys.exit(2)
"""


class GpgSignTests(unittest.TestCase):
    def test_parse_primary_fingerprint(self):
        text = (
            'pub:u:255:22:5CA29677::::::::\n'
            'fpr:::::::::abcdef0123456789abcdef0123456789abcdef01:\n'
            'sub:u:255:18:::::::::\n'
            'fpr:::::::::1111111111111111111111111111111111111111:\n'
        )
        self.assertEqual(
            pub.parse_gpg_fingerprints(text),
            ['ABCDEF0123456789ABCDEF0123456789ABCDEF01',
             '1111111111111111111111111111111111111111'])

    def test_rejects_a_key_that_is_not_a_fingerprint(self):
        with self.assertRaises(SystemExit):
            pub.validate_gpg_key('--export-secret-keys')
        with self.assertRaises(SystemExit):
            pub.validate_gpg_key('../secret.asc')
        for short in ('5CA29677', '5CA296775CA29677', '0x5CA29677'):
            with self.assertRaises(SystemExit) as cm:
                pub.validate_gpg_key(short)
            self.assertIn('40-hex', str(cm.exception))

    def test_accepts_a_40_hex_fingerprint(self):
        fp = 'abcdef0123456789abcdef0123456789abcdef01'
        self.assertEqual(pub.validate_gpg_key(fp), fp.upper())
        self.assertEqual(pub.validate_gpg_key('0x' + fp), fp.upper())

    def test_gpg_key_signs_with_the_keyring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            bindir = root / 'bin'
            bindir.mkdir()
            gpg = bindir / 'gpg'
            gpg.write_text(_FAKE_GPG)
            gpg.chmod(0o755)
            log = root / 'gpg-argv.log'
            docs = root / 'docs'
            docs.mkdir()
            adv = ga.parse_record(json.loads(
                (TESTDATA / 'CVE-2026-5501.json').read_text()))
            ov = json.loads(EXAMPLE_OVERLAY.read_text())
            csaf = ga.generate_csaf(
                [adv], ov, adv['cve'], '2026-01-02T00:00:00Z')
            (docs / 'CVE-2026-5501.csaf.json').write_text(
                json.dumps(csaf, indent=2) + '\n')
            out = root / 'publish'
            saved_path = os.environ.get('PATH')
            saved_log = os.environ.get('GPG_ARGV_LOG')
            os.environ['PATH'] = str(bindir) + os.pathsep + (saved_path or '')
            os.environ['GPG_ARGV_LOG'] = str(log)
            import sys
            argv = sys.argv
            try:
                sys.argv = [
                    'csaf-publish',
                    '--docs-dir', str(docs),
                    '--out-root', str(out),
                    '--gpg-key', 'ABCDEF0123456789ABCDEF0123456789ABCDEF01',
                ]
                pub.main()
            finally:
                sys.argv = argv
                if saved_path is None:
                    os.environ.pop('PATH', None)
                else:
                    os.environ['PATH'] = saved_path
                if saved_log is None:
                    os.environ.pop('GPG_ARGV_LOG', None)
                else:
                    os.environ['GPG_ARGV_LOG'] = saved_log

            csaf_root = out / '.well-known' / 'csaf'
            doc = csaf_root / 'white' / '2026' / 'cve-2026-5501.json'
            self.assertTrue((doc.with_name(doc.name + '.asc')).is_file())
            md = csaf_root / 'provider-metadata.json'
            self.assertTrue((md.with_name(md.name + '.asc')).is_file())
            meta = json.loads(md.read_text())
            self.assertEqual(
                meta['public_openpgp_keys'][0]['fingerprint'],
                'ABCDEF0123456789ABCDEF0123456789ABCDEF01')
            pubkey = (csaf_root / 'openpgp-key.asc').read_text()
            self.assertIn('BEGIN PGP PUBLIC KEY BLOCK', pubkey)
            recorded = log.read_text()
            self.assertNotIn('export-secret-keys', recorded)
            self.assertIn(
                '--default-key\tABCDEF0123456789ABCDEF0123456789ABCDEF01'
                '\t--detach-sign',
                recorded)
            self.assertIn(
                '--export\tABCDEF0123456789ABCDEF0123456789ABCDEF01',
                recorded)

    def test_gpg_key_and_key_file_together_fail(self):
        import sys
        argv = sys.argv
        try:
            sys.argv = [
                'csaf-publish',
                '--gpg-key', 'ABCDEF0123456789ABCDEF0123456789ABCDEF01',
                '--key-file', '/tmp/secret.asc',
                '--docs-dir', '/tmp/does-not-matter']
            with self.assertRaises(SystemExit) as cm:
                pub.main()
            self.assertIn('only one', str(cm.exception))
        finally:
            sys.argv = argv


def _write_sample_csaf(docs):
    docs.mkdir(parents=True, exist_ok=True)
    adv = ga.parse_record(json.loads(
        (TESTDATA / 'CVE-2026-5501.json').read_text()))
    ov = json.loads(EXAMPLE_OVERLAY.read_text())
    csaf = ga.generate_csaf([adv], ov, adv['cve'], '2026-01-02T00:00:00Z')
    (docs / 'CVE-2026-5501.csaf.json').write_text(json.dumps(csaf, indent=2) + '\n')


class RealGpgRoundTripTests(unittest.TestCase):
    def test_publish_signs_and_gpg_verifies(self):
        if shutil.which('gpg') is None:
            self.skipTest('gpg is not installed')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            home = root / 'gnupg'
            home.mkdir(mode=0o700)
            home.chmod(0o700)
            (home / 'gpg.conf').write_text('batch\nno-tty\n')
            saved_home = os.environ.get('GNUPGHOME')
            os.environ['GNUPGHOME'] = str(home)
            try:
                gen = subprocess.run(
                    ['gpg', '--batch', '--homedir', str(home), '--generate-key'],
                    input=(
                        '%no-protection\n'
                        'Key-Type: RSA\n'
                        'Key-Length: 2048\n'
                        'Key-Usage: sign\n'
                        'Name-Real: CSAF Test\n'
                        'Name-Email: csaf-test@example.invalid\n'
                        'Expire-Date: 0\n'
                        '%commit\n'
                    ),
                    text=True, capture_output=True, check=False)
                self.assertEqual(gen.returncode, 0, gen.stderr)
                shown = subprocess.run(
                    ['gpg', '--batch', '--homedir', str(home),
                     '--with-colons', '--fingerprint'],
                    capture_output=True, text=True, check=False)
                self.assertEqual(shown.returncode, 0, shown.stderr)
                fingerprints = pub.parse_gpg_fingerprints(shown.stdout)
                self.assertEqual(len(fingerprints[0]), 40, shown.stdout)
                fingerprint = fingerprints[0]

                docs = root / 'docs'
                _write_sample_csaf(docs)
                out = root / 'publish'
                import sys
                argv = sys.argv
                try:
                    sys.argv = [
                        'csaf-publish',
                        '--docs-dir', str(docs),
                        '--out-root', str(out),
                        '--gpg-key', fingerprint,
                    ]
                    pub.main()
                finally:
                    sys.argv = argv

                csaf_root = out / '.well-known' / 'csaf'
                doc = csaf_root / 'white' / '2026' / 'cve-2026-5501.json'
                for path in (doc, csaf_root / 'provider-metadata.json'):
                    asc = path.with_name(path.name + '.asc')
                    verified = subprocess.run(
                        ['gpg', '--batch', '--homedir', str(home),
                         '--verify', str(asc), str(path)],
                        capture_output=True, text=True, check=False)
                    self.assertEqual(verified.returncode, 0, verified.stderr)
                meta = json.loads(
                    (csaf_root / 'provider-metadata.json').read_text())
                self.assertEqual(
                    meta['public_openpgp_keys'][0]['fingerprint'],
                    fingerprint)

                try:
                    import pgpy  # noqa: F401
                except ImportError:
                    return
                try:
                    sys.argv = [
                        'csaf-verify', '--root', str(csaf_root),
                        '--fingerprint', fingerprint,
                    ]
                    with self.assertRaises(SystemExit) as cm:
                        ver.main()
                    self.assertEqual(cm.exception.code, 0)
                finally:
                    sys.argv = argv
            finally:
                subprocess.run(
                    ['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'],
                    check=False, capture_output=True)
                if saved_home is None:
                    os.environ.pop('GNUPGHOME', None)
                else:
                    os.environ['GNUPGHOME'] = saved_home


class KeygenPermTests(unittest.TestCase):
    def test_secret_written_mode_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / 'secret.asc'
            keygen.write_secret(str(path), 'SECRET\n')
            mode = path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)


if __name__ == '__main__':
    unittest.main()
