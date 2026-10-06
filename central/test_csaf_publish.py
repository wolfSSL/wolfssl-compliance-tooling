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


class KeygenPermTests(unittest.TestCase):
    def test_secret_written_mode_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / 'secret.asc'
            keygen.write_secret(str(path), 'SECRET\n')
            mode = path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)


if __name__ == '__main__':
    unittest.main()
