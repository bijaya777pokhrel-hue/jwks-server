"""Test suite for the SQLite-backed JWKS server."""

import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import jwt

import server


class HelperTests(unittest.TestCase):
    """Unit tests for key and database helpers."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        server.init_db(self.db)

    def tearDown(self):
        os.remove(self.db)

    def test_table_schema(self):
        with sqlite3.connect(self.db) as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(keys)")]
        self.assertEqual(cols, ["kid", "key", "exp"])

    def test_serialize_roundtrip(self):
        key = server.generate_key()
        pem = server.serialize_key(key)
        self.assertIn(b"BEGIN RSA PRIVATE KEY", pem)
        again = server.deserialize_key(pem.decode())
        self.assertEqual(key.private_numbers(), again.private_numbers())

    def test_int_to_base64url(self):
        self.assertEqual(server.int_to_base64url(65537), "AQAB")

    def test_get_key_empty(self):
        self.assertIsNone(server.get_key(False, self.db))
        self.assertIsNone(server.issue_token(db_file=self.db))

    def test_seed_and_get(self):
        server.seed_keys(self.db)
        valid = server.get_key(False, self.db)
        expired = server.get_key(True, self.db)
        self.assertGreater(valid[2], time.time())
        self.assertLessEqual(expired[2], time.time())

    def test_jwks_only_valid(self):
        server.seed_keys(self.db)
        jwks = server.build_jwks(self.db)
        self.assertEqual(len(jwks["keys"]), 1)
        self.assertEqual(jwks["keys"][0]["e"], "AQAB")


class EndpointTests(unittest.TestCase):
    """Black-box tests of the running HTTP server."""

    @classmethod
    def setUpClass(cls):
        fd, cls.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        cls.httpd = server.create_server("localhost", 0, cls.db)
        cls.base = f"http://localhost:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        os.remove(cls.db)

    def _req(self, path, method="GET", data=None, headers=None):
        req = urllib.request.Request(self.base + path, data=data,
                                     method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def _jwks(self):
        _, body = self._req("/.well-known/jwks.json")
        return json.loads(body)

    def test_jwks_endpoint(self):
        status, body = self._req("/.well-known/jwks.json")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["keys"]), 1)

    def test_auth_valid_token_verifies(self):
        status, token = self._req("/auth", "POST", b"")
        self.assertEqual(status, 200)
        kid = jwt.get_unverified_header(token)["kid"]
        jwk = next(k for k in self._jwks()["keys"] if k["kid"] == kid)
        public = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(token, public, algorithms=["RS256"])
        self.assertEqual(claims["user"], "userABC")

    def test_auth_json_body(self):
        body = json.dumps({"username": "userABC",
                           "password": "password123"}).encode()
        status, _ = self._req("/auth", "POST", body,
                              {"Content-Type": "application/json"})
        self.assertEqual(status, 200)

    def test_auth_expired(self):
        status, token = self._req("/auth?expired=true", "POST", b"")
        self.assertEqual(status, 200)
        kid = jwt.get_unverified_header(token)["kid"]
        kids = [k["kid"] for k in self._jwks()["keys"]]
        self.assertNotIn(kid, kids)
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertLessEqual(claims["exp"], time.time())

    def test_bad_paths_and_methods(self):
        self.assertEqual(self._req("/nope")[0], 405)
        self.assertEqual(self._req("/nope", "POST", b"")[0], 405)
        self.assertEqual(self._req("/auth", "PUT", b"")[0], 405)
        self.assertEqual(self._req("/auth", "DELETE")[0], 405)

    def test_no_key_returns_500(self):
        original = server.JWKSHandler.db_file
        fd, empty = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        server.init_db(empty)
        server.JWKSHandler.db_file = empty
        try:
            self.assertEqual(self._req("/auth", "POST", b"")[0], 500)
        finally:
            server.JWKSHandler.db_file = original
            os.remove(empty)


if __name__ == "__main__":
    unittest.main()
