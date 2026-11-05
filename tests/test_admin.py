import http.client
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path

from app import init_database, make_server


class AdminAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.database = Path(cls.temp.name) / "admin.sqlite3"
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

    def setUp(self):
        with self.server.sessions_lock:
            self.server.sessions.clear()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE users SET display_name = 'Sam Študent', email = 'student@example.test', "
                "study_group = 'INF-1' WHERE username = 'student'"
            )
            self.student_id = connection.execute("SELECT id FROM users WHERE username = 'student'").fetchone()[0]

    def request(self, method, path, payload=None, cookie=None, csrf=None):
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=json.dumps(payload) if payload is not None else None,
                               headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            connection.close()

    def login(self, username="admin", password="Admin2026!", mode="secure", cookie=None):
        status, headers, data = self.request("POST", "/api/login", {
            "username": username, "password": password, "mode": mode,
        }, cookie=cookie)
        self.assertEqual(status, 200)
        return data, headers["Set-Cookie"].split(";", 1)[0]

    def changed_profile(self):
        return {"display_name": "Zmenené meno", "email": "zmenene@example.test", "study_group": "INF-9"}

    def test_anonymous_requests_cannot_read_or_edit_users(self):
        for method, path, body in (
            ("GET", "/api/admin/users", None),
            ("PATCH", f"/api/admin/users/{self.student_id}", self.changed_profile()),
            ("POST", "/api/admin/reset", {}),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path, body)[0], 401)
        self.assertEqual(self.request("GET", "/api/admin/users", cookie="katedra_session=forged")[0], 401)

    def test_student_cannot_read_or_modify_other_users(self):
        login, cookie = self.login("student", "Studium2026!")
        self.assertTrue(login["authenticated"])
        self.assertEqual(login["user"]["email"], "student@example.test")
        for method, path, body in (
            ("GET", "/api/admin/users", None),
            ("PATCH", f"/api/admin/users/{self.student_id}", self.changed_profile()),
            ("POST", "/api/admin/reset", {}),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path, body, cookie, login["csrf_token"])[0], 403)

    def test_injection_creates_real_admin_session_only_in_vulnerable_mode(self):
        login, cookie = self.login("admin' -- ", "wrong", "vulnerable")
        self.assertTrue(login["authenticated"])
        self.assertEqual(login["user"]["role"], "administrátor")
        status, _, result = self.request("GET", "/api/admin/users", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(result["users"]), 8)
        self.assertTrue(all("password_hash" not in user for user in result["users"]))
        self.assertTrue(all("email" in user and "study_group" in user for user in result["users"]))
        denied, _ = self.login("admin' -- ", "wrong", "secure", cookie)
        self.assertFalse(denied["authenticated"])
        self.assertEqual(self.request("GET", "/api/admin/users", cookie=cookie)[0], 401)

    def test_secure_admin_with_correct_password_can_manage_users(self):
        login, cookie = self.login()
        self.assertTrue(login["authenticated"])
        self.assertEqual(self.request("GET", "/api/admin/users", cookie=cookie)[0], 200)

    def test_admin_changes_are_persisted_and_survive_initialization(self):
        login, cookie = self.login("admin' -- ", "wrong", "vulnerable")
        payload = self.changed_profile()
        status, _, result = self.request("PATCH", f"/api/admin/users/{self.student_id}",
                                         payload, cookie, login["csrf_token"])
        self.assertEqual(status, 200)
        for key, value in payload.items():
            self.assertEqual(result["user"][key], value)
        init_database(self.database)
        _, _, result = self.request("GET", "/api/admin/users", cookie=cookie)
        changed = next(user for user in result["users"] if user["id"] == self.student_id)
        for key, value in payload.items():
            self.assertEqual(changed[key], value)

    def test_csrf_required_for_update_reset_and_logout(self):
        login, cookie = self.login()
        for method, path, body in (
            ("PATCH", f"/api/admin/users/{self.student_id}", self.changed_profile()),
            ("POST", "/api/admin/reset", {}),
            ("POST", "/api/logout", {}),
        ):
            for token in (None, "wrong"):
                with self.subTest(path=path, token=token):
                    self.assertEqual(self.request(method, path, body, cookie, token)[0], 403)
        self.assertEqual(self.request("GET", "/api/admin/users", cookie=cookie)[0], 200)

    def test_logout_invalidates_session_and_cookie(self):
        login, cookie = self.login()
        status, headers, _ = self.request("POST", "/api/logout", {}, cookie, login["csrf_token"])
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.request("GET", "/api/admin/users", cookie=cookie)[0], 401)
        self.assertFalse(self.request("GET", "/api/session", cookie=cookie)[2]["authenticated"])

    def test_cookie_flags_session_restore_and_expiry(self):
        status, headers, login = self.request("POST", "/api/login", {
            "username": "admin", "password": "Admin2026!", "mode": "secure",
        })
        self.assertEqual(status, 200)
        for flag in ("HttpOnly", "SameSite=Strict", "Max-Age=3600", "Path=/"):
            self.assertIn(flag, headers["Set-Cookie"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        _, _, restored = self.request("GET", "/api/session", cookie=cookie)
        self.assertEqual(restored["user"]["username"], "admin")
        self.assertEqual(restored["mode"], "secure")
        self.assertEqual(restored["csrf_token"], login["csrf_token"])
        token = cookie.split("=", 1)[1]
        with self.server.sessions_lock:
            self.server.sessions[token]["expires"] = time.monotonic() - 1
        self.assertEqual(self.request("GET", "/api/admin/users", cookie=cookie)[0], 401)

    def test_invalid_updates_do_not_change_permissions_or_data(self):
        login, cookie = self.login()
        for changes in (
            {"role": "administrátor"}, {"display_name": " "}, {"email": "invalid"},
            {"study_group": "x" * 31}, {"display_name": 42}, {"password_hash": "x"},
        ):
            payload = self.changed_profile() | changes
            with self.subTest(changes=changes):
                self.assertEqual(self.request("PATCH", f"/api/admin/users/{self.student_id}",
                                               payload, cookie, login["csrf_token"])[0], 400)
        self.assertEqual(self.request("PATCH", "/api/admin/users/999999", self.changed_profile(),
                                      cookie, login["csrf_token"])[0], 404)
        _, _, result = self.request("GET", "/api/admin/users", cookie=cookie)
        student = next(user for user in result["users"] if user["id"] == self.student_id)
        self.assertEqual(student["display_name"], "Sam Študent")
        self.assertEqual(student["role"], "študent")

    def test_edit_values_are_data_not_sql(self):
        login, cookie = self.login()
        payload = self.changed_profile() | {"display_name": "X'; DROP TABLE users; --"}
        self.assertEqual(self.request("PATCH", f"/api/admin/users/{self.student_id}",
                                      payload, cookie, login["csrf_token"])[0], 200)
        _, _, result = self.request("GET", "/api/admin/users", cookie=cookie)
        student = next(user for user in result["users"] if user["id"] == self.student_id)
        self.assertEqual(student["display_name"], payload["display_name"])

    def test_reset_restores_profiles_without_changing_accounts(self):
        login, cookie = self.login()
        self.request("PATCH", f"/api/admin/users/{self.student_id}", self.changed_profile(),
                     cookie, login["csrf_token"])
        status, _, data = self.request("POST", "/api/admin/reset", {}, cookie, login["csrf_token"])
        self.assertEqual(status, 200)
        student = next(user for user in data["users"] if user["id"] == self.student_id)
        self.assertEqual(student["display_name"], "Sam Študent")
        self.assertEqual(student["email"], "student@example.test")
        self.assertEqual(student["study_group"], "INF-1")
        self.assertTrue(self.login("student", "Studium2026!")[0]["authenticated"])

    def test_comparison_endpoint_does_not_create_session(self):
        _, headers, result = self.request("POST", "/api/compare", {
            "username": "admin' -- ", "password": "wrong",
        })
        self.assertTrue(result["vulnerable"]["authenticated"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertFalse(self.request("GET", "/api/session")[2]["authenticated"])

    def test_unknown_login_mode_is_rejected(self):
        self.assertEqual(self.request("POST", "/api/login", {
            "username": "admin", "password": "Admin2026!", "mode": "unknown",
        })[0], 400)

    def test_existing_database_is_migrated_without_overwriting_account(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.sqlite3"
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
                                   "password_hash TEXT, display_name TEXT, role TEXT)")
                connection.execute("INSERT INTO users VALUES (1, 'admin', 'preserved-hash', "
                                   "'Pôvodný administrátor', 'administrátor')")
            init_database(path)
            with closing(sqlite3.connect(path)) as connection:
                row = connection.execute("SELECT password_hash, display_name, email, study_group "
                                         "FROM users WHERE username='admin'").fetchone()
            self.assertEqual(row, ("preserved-hash", "Pôvodný administrátor", "admin@example.test", "Katedra"))


if __name__ == "__main__":
    unittest.main()
