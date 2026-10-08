#!/usr/bin/env python3
"""Unit tests for central/csaf-fetch.

Run:
    python3 -m unittest central/test_csaf_fetch.py
"""

import hashlib
import http.server
import json
import pathlib
import tempfile
import threading
import unittest
from importlib.machinery import SourceFileLoader

HERE = pathlib.Path(__file__).resolve().parent


def _load():
    loader = SourceFileLoader('csaf_fetch', str(HERE / 'csaf-fetch'))
    import importlib.util
    spec = importlib.util.spec_from_loader('csaf_fetch', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


fetch = _load()


def _sha(data, algo):
    return (hashlib.new(algo, data).hexdigest() + '  name\n').encode()


class FetchTests(unittest.TestCase):
    def test_rejects_parent_path(self):
        with self.assertRaises(fetch.FetchError):
            fetch.safe_rel('../secret.json')
        with self.assertRaises(fetch.FetchError):
            fetch.safe_rel('/etc/passwd')
        self.assertIsNone(fetch.safe_rel(''))
        self.assertIsNone(fetch.safe_rel('# comment'))
        self.assertEqual(fetch.safe_rel('white/2026/cve-2026-1.json'),
                         'white/2026/cve-2026-1.json')

    def test_downloads_index_and_rejects_escape(self):
        doc = b'{"document":{"title":"t"}}\n'
        meta = json.dumps({'role': 'csaf_provider'}).encode()
        files = {
            'provider-metadata.json': meta,
            'provider-metadata.json.sha256': _sha(meta, 'sha256'),
            'provider-metadata.json.sha512': _sha(meta, 'sha512'),
            'index.txt': b'white/2026/cve-2026-1.json\n',
            'changes.csv': b'white/2026/cve-2026-1.json,2026-01-01T00:00:00Z\n',
            'white/2026/cve-2026-1.json': doc,
            'white/2026/cve-2026-1.json.sha256': _sha(doc, 'sha256'),
            'white/2026/cve-2026-1.json.sha512': _sha(doc, 'sha512'),
        }

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                rel = self.path.split('?', 1)[0].lstrip('/')
                if rel == '' or rel.endswith('/') or rel not in files:
                    code = 403 if rel == '' or rel.endswith('/') else 404
                    self.send_error(code)
                    return
                body = files[rel]
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

        url = f'http://127.0.0.1:{port}'
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            files['index.txt'] = b'../secret.json\n'
            with self.assertRaises(fetch.FetchError):
                fetch.fetch_tree(url, root / 'escape', timeout=5)
            files['index.txt'] = b'white/2026/cve-2026-1.json\n'
            out = root / 'ok'
            n = fetch.fetch_tree(url, out, timeout=5)
            self.assertEqual(n, 1)
            self.assertEqual((out / 'white/2026/cve-2026-1.json').read_bytes(), doc)
            self.assertEqual((out / 'provider-metadata.json').read_bytes(), meta)

    def test_cvss_v4_score_is_a_number_from_0_to_10(self):
        self.assertTrue(fetch.has_cvss_v4_score(
            [{'method': 'CVSSv4', 'score': 0}]))
        self.assertTrue(fetch.has_cvss_v4_score(
            [{'method': 'CVSSv4', 'score': 10}]))
        self.assertTrue(fetch.has_cvss_v4_score(
            [{'method': 'CVSSv4', 'score': 7.5}]))
        for bad in (None, False, True, '', '7.5', -0.1, 10.1):
            self.assertFalse(
                fetch.has_cvss_v4_score([{'method': 'CVSSv4', 'score': bad}]),
                bad)
        self.assertFalse(fetch.has_cvss_v4_score(
            [{'method': 'CVSSv3', 'score': 7.5}]))

    def test_vex_must_match_the_csaf_cve_list(self):
        csaf = {
            'vulnerabilities': [
                {'cve': 'CVE-2026-1'},
                {'cve': 'CVE-2026-2'},
            ],
        }
        vex = {
            'vulnerabilities': [
                {'id': 'CVE-2026-1', 'ratings': [{'method': 'CVSSv4', 'score': 1.0}]},
                {'id': 'CVE-2026-2', 'ratings': [{'method': 'CVSSv4', 'score': 2.0}]},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            rel = 'white/2026/cve-2026-1.json'
            (root / 'white/2026').mkdir(parents=True)
            (root / rel).write_text(json.dumps(csaf))
            vex_path = root / fetch.vex_rel(rel)
            vex_path.write_text(json.dumps(vex))
            fetch.check_vex_tree(root, [rel])
            vex['vulnerabilities'].pop()
            vex_path.write_text(json.dumps(vex))
            with self.assertRaises(fetch.FetchError):
                fetch.check_vex_tree(root, [rel])

    def test_fetch_fails_when_vex_is_missing(self):
        doc = json.dumps({'vulnerabilities': [{'cve': 'CVE-2026-1'}]}).encode()
        meta = json.dumps({'role': 'csaf_provider'}).encode()
        files = {
            'provider-metadata.json': meta,
            'provider-metadata.json.sha256': _sha(meta, 'sha256'),
            'provider-metadata.json.sha512': _sha(meta, 'sha512'),
            'index.txt': b'white/2026/cve-2026-1.json\n',
            'changes.csv': b'white/2026/cve-2026-1.json,2026-01-01T00:00:00Z\n',
            'white/2026/cve-2026-1.json': doc,
            'white/2026/cve-2026-1.json.sha256': _sha(doc, 'sha256'),
            'white/2026/cve-2026-1.json.sha512': _sha(doc, 'sha512'),
        }

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                rel = self.path.split('?', 1)[0].lstrip('/')
                body = files.get(rel)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        url = f'http://127.0.0.1:{server.server_address[1]}'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(fetch.FetchError) as cm:
                fetch.fetch_tree(url, pathlib.Path(tmp) / 'out', timeout=5, with_vex=True)
            self.assertIn('404', str(cm.exception))


if __name__ == '__main__':
    unittest.main()
