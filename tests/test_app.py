"""Regresné testy skutočných SQL dotazov aj HTTP rozhrania."""

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from app import authenticate, init_database, make_server, verify_password


class SQLInjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.database = Path(cls.temp.name) / "test.sqlite3"
        init_database(cls.database)
        cls.server = make_server(0, cls.database)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def login(self, username, password, secure):
        return authenticate(username, password, secure=secure, database=self.database)

    def request(self, method, path, body=None, content_type="application/json"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=body, headers={"Content-Type": content_type})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_valid_and_invalid_passwords_in_both_versions(self):
        for secure in (False, True):
            for username, password in (("admin", "Admin2026!"), ("student", "Studium2026!")):
                with self.subTest(secure=secure, username=username):
                    result = self.login(username, password, secure)
                    self.assertTrue(result["authenticated"])
                    self.assertEqual(result["user"]["username"], username)
                    self.assertNotIn("password_hash", result["user"])
                    self.assertFalse(self.login(username, "nespravne-heslo", secure)["authenticated"])

    def test_comment_bypasses_password_only_in_vulnerable_version(self):
        result = self.login("admin' -- ", "nespravne-heslo", False)
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["user"]["role"], "administrátor")
        self.assertFalse(self.login("admin' -- ", "nespravne-heslo", True)["authenticated"])

    def test_tautology_injection(self):
        self.assertTrue(self.login("' OR 1=1 -- ", "", False)["authenticated"])
        self.assertFalse(self.login("' OR 1=1 -- ", "", True)["authenticated"])

    def test_password_field_is_also_parameterized(self):
        attack = "x', password_hash) = 1 OR 1=1 -- "
        self.assertTrue(self.login("admin", attack, False)["authenticated"])
        self.assertFalse(self.login("admin", attack, True)["authenticated"])

    def test_legitimate_apostrophe_account(self):
        self.assertEqual(self.login("o'connor", "Apostrof2026!", False)["status"], "error")
        self.assertTrue(self.login("o'connor", "Apostrof2026!", True)["authenticated"])

    def test_malformed_quote_is_not_server_error(self):
        self.assertEqual(self.login("admin'", "wrong", False)["status"], "error")
        self.assertEqual(self.login("admin'", "wrong", True)["status"], "denied")

    def test_secure_query_shape_is_independent_of_input(self):
        baseline = self.login("student", "wrong", True)["query"]
        for username in ("admin' -- ", "' OR 1=1 -- ", "o'connor", "<script>alert(1)</script>"):
            result = self.login(username, "wrong", True)
            self.assertEqual(result["query"], baseline)
            self.assertEqual(result["parameters"], [username, "wrong"])
            self.assertFalse(result["authenticated"])

    def test_multiple_statements_do_not_delete_data(self):
        result = self.login("'; DROP TABLE users; -- ", "wrong", False)
        self.assertEqual(result["status"], "error")
        self.assertTrue(self.login("student", "Studium2026!", True)["authenticated"])

    def test_database_stores_salted_hashes(self):
        with sqlite3.connect(self.database) as connection:
            stored, = connection.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()
        self.assertTrue(stored.startswith("pbkdf2_sha256$260000$"))
        self.assertNotIn("Admin2026!", stored)
        self.assertEqual(verify_password("Admin2026!", stored), 1)
        self.assertEqual(verify_password("wrong", stored), 0)

    def test_http_comparison_executes_both_queries(self):
        status, _, body = self.request("POST", "/api/compare", json.dumps({
            "username": "admin' -- ", "password": "wrong"}))
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result["vulnerable"]["authenticated"])
        self.assertFalse(result["secure"]["authenticated"])

    def test_invalid_http_inputs_are_rejected(self):
        cases = [("{", 400), ("[]", 400), ('{"username": 1, "password": "x"}', 400),
                 ('{"username": "admin"}', 400),
                 (json.dumps({"username": "x" * 201, "password": "x"}), 400),
                 (" " * 4097, 413)]
        for body, expected in cases:
            with self.subTest(body=body[:80]):
                status, _, _ = self.request("POST", "/api/compare", body)
                self.assertEqual(status, expected)
        self.assertEqual(self.request("POST", "/api/compare", "{}", "text/plain")[0], 415)

    def test_static_assets_and_unknown_routes(self):
        for path in ("/", "/styles.css", "/app.js", "/favicon.svg", "/api/health"):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(body)
                self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        for path in ("/missing", "/../app.py", "/data/lab.sqlite3"):
            self.assertEqual(self.request("GET", path)[0], 404)


if __name__ == "__main__":
    unittest.main()
