"""Lokálne laboratórium SQL Injection. Spustenie: python app.py."""

import argparse
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from functools import partial
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "data" / "lab.sqlite3"
ITERATIONS = 260_000
SESSION_SECONDS = 3600
SESSION_COOKIE = "katedra_session"
USER_FIELDS = "id, username, display_name, role, email, study_group"
ACCOUNTS = (
    ("admin", "Admin2026!", "Alex Administrátor", "administrátor", "admin@example.test", "Katedra"),
    ("student", "Studium2026!", "Sam Študent", "študent", "student@example.test", "INF-1"),
    ("o'connor", "Apostrof2026!", "Robin O’Connor", "študent", "robin.oconnor@example.test", "INF-2"),
    ("mnovak", "Studium2026!", "Martin Novák", "študent", "martin.novak@example.test", "INF-1"),
    ("pkovacova", "Studium2026!", "Petra Kováčová", "študent", "petra.kovacova@example.test", "INF-2"),
    ("lhorvath", "Studium2026!", "Lukáš Horváth", "študent", "lukas.horvath@example.test", "INF-1"),
    ("eszabo", "Studium2026!", "Eva Szabóová", "študent", "eva.szaboova@example.test", "INF-3"),
    ("tbalaz", "Studium2026!", "Tomáš Baláž", "študent", "tomas.balaz@example.test", "INF-3"),
)


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest.hex()}"


def verify_password(password, stored):
    if not isinstance(password, str) or not isinstance(stored, str):
        return 0
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return 0
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), int(iterations)
        ).hex()
        return int(hmac.compare_digest(actual, expected))
    except (ValueError, TypeError):
        return 0


def init_database(path=DATABASE):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript((ROOT / "schema.sql").read_text(encoding="utf-8"))
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        for column in ("email", "study_group"):
            if column not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        connection.executemany(
            "INSERT OR IGNORE INTO users "
            "(username, password_hash, display_name, role, email, study_group) VALUES (?, ?, ?, ?, ?, ?)",
            [(name, hash_password(password), label, role, email, group)
             for name, password, label, role, email, group in ACCOUNTS],
        )
        if "email" not in columns or "study_group" not in columns:
            for name, _, _, _, email, group in ACCOUNTS:
                for column, value in (("email", email), ("study_group", group)):
                    if column not in columns:
                        connection.execute(f"UPDATE users SET {column} = ? WHERE username = ?", (value, name))


def authenticate(username, password, *, secure, database=DATABASE):
    """Obe vetvy vykonajú skutočný SQL dotaz nad rovnakými dátami."""
    prefix = "SELECT id, username, display_name, role\nFROM users\n"
    if secure:
        # OPRAVA: používateľské dáta sa odovzdajú oddelene od SQL príkazu.
        query = prefix + "WHERE username = ?\n  AND verify_password(?, password_hash) = 1\nLIMIT 1;"
        parameters = (username, password)
    else:
        # ZÁMERNE ZRANITEĽNÉ: vstup sa stane súčasťou SQL syntaxe.
        query = prefix + (
            f"WHERE username = '{username}' "
            f"AND verify_password('{password}', password_hash) = 1\nLIMIT 1;"
        )
        parameters = ()

    # Read-only pripojenie chráni opakovateľnosť lokálneho cvičenia.
    uri = Path(database).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        connection.create_function("verify_password", 2, verify_password)
        try:
            row = connection.execute(query, parameters).fetchone()
        except sqlite3.Error as error:
            return {"status": "error", "authenticated": False, "user": None,
                    "query": query, "parameters": list(parameters), "error": str(error)}

    return {"status": "success" if row else "denied", "authenticated": bool(row),
            "user": dict(row) if row else None, "query": query,
            "parameters": list(parameters), "error": None}


class LabHandler(BaseHTTPRequestHandler):
    server_version = "SQLLab/1.0"
    static_files = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    }

    def __init__(self, *args, database=DATABASE, **kwargs):
        self.database = database
        super().__init__(*args, **kwargs)

    def send_content(self, status, content, content_type, cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; "
                         "script-src 'self'; style-src 'self'; img-src 'self'; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                         "form-action 'self'")
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, payload, cookie=None):
        self.send_content(status, json.dumps(payload, ensure_ascii=False).encode(),
                          "application/json; charset=utf-8", cookie)

    def cookie_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        item = cookie.get(SESSION_COOKIE)
        return item.value if item else None

    def session(self):
        token = self.cookie_token()
        with self.server.sessions_lock:
            session = self.server.sessions.get(token)
            if session is None:
                return None
            if session["expires"] <= time.monotonic():
                self.server.sessions.pop(token, None)
                return None
            session = dict(session)
        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            user = connection.execute(f"SELECT {USER_FIELDS} FROM users WHERE id = ?",
                                      (session["user_id"],)).fetchone()
        if user is None:
            self.invalidate_session()
            return None
        session["user"] = dict(user)
        return session

    def invalidate_session(self):
        with self.server.sessions_lock:
            self.server.sessions.pop(self.cookie_token(), None)

    @staticmethod
    def session_cookie(token="", max_age=0):
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"

    def require_session(self, *, admin=False, csrf=False):
        session = self.session()
        if session is None:
            self.send_json(401, {"error": "Najprv sa prihláste."})
        elif admin and session["user"]["role"] != "administrátor":
            self.send_json(403, {"error": "Prístup je povolený iba administrátorovi."})
        elif csrf and not hmac.compare_digest(
                self.headers.get("X-CSRF-Token", "").encode(), session["csrf_token"].encode()):
            self.send_json(403, {"error": "Neplatný token požiadavky. Obnovte stránku."})
        else:
            return session
        return None

    def list_users(self):
        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(f"SELECT {USER_FIELDS} FROM users ORDER BY id")]

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route == "/api/health":
            self.send_json(200, {"status": "ok"})
        elif route == "/api/session":
            session = self.session()
            self.send_json(200, {"authenticated": bool(session),
                                 "user": session["user"] if session else None,
                                 "mode": session["mode"] if session else None,
                                 "csrf_token": session["csrf_token"] if session else None})
        elif route == "/api/admin/users":
            if self.require_session(admin=True):
                self.send_json(200, {"users": self.list_users()})
        elif route in self.static_files:
            filename, content_type = self.static_files[route]
            self.send_content(200, (ROOT / "static" / filename).read_bytes(), content_type)
        else:
            self.send_json(404, {"error": "Stránka neexistuje."})

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Očakáva sa application/json."})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Neplatná dĺžka požiadavky."})
            return None
        if not 0 < length <= 4096:
            self.send_json(413, {"error": "Požiadavka musí mať 1 až 4096 bajtov."})
            return None
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {"error": "Neplatný JSON."})
            return None
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Očakáva sa JSON objekt."})
            return None
        return payload

    def do_POST(self):
        if self.path == "/api/logout":
            if self.session() is not None and not self.require_session(csrf=True):
                return
            self.invalidate_session()
            self.send_json(200, {"ok": True}, self.session_cookie())
            return
        if self.path == "/api/admin/reset":
            if not self.require_session(admin=True, csrf=True):
                return
            with closing(sqlite3.connect(self.database)) as connection, connection:
                connection.executemany(
                    "UPDATE users SET display_name = ?, email = ?, study_group = ? WHERE username = ?",
                    [(label, email, group, name) for name, _, label, _, email, group in ACCOUNTS],
                )
            self.send_json(200, {"users": self.list_users()})
            return
        if self.path not in ("/api/login", "/api/compare"):
            self.send_json(404, {"error": "Endpoint neexistuje."})
            return
        payload = self.read_json()
        if payload is None:
            return
        username, password = payload.get("username"), payload.get("password")
        if not all(isinstance(value, str) and len(value) <= 200
                   for value in (username, password)):
            self.send_json(400, {"error": "Meno a heslo musia byť texty do 200 znakov."})
            return
        if self.path == "/api/compare":
            self.send_json(200, {
                "vulnerable": authenticate(username, password, secure=False, database=self.database),
                "secure": authenticate(username, password, secure=True, database=self.database),
            })
            return
        mode = payload.get("mode")
        if mode not in ("vulnerable", "secure"):
            self.send_json(400, {"error": "Neplatná verzia aplikácie."})
            return
        self.invalidate_session()
        result = authenticate(username, password, secure=mode == "secure", database=self.database)
        result.update({"mode": mode, "csrf_token": None})
        cookie = self.session_cookie()
        if result["authenticated"]:
            with closing(sqlite3.connect(self.database)) as connection:
                connection.row_factory = sqlite3.Row
                user = connection.execute(f"SELECT {USER_FIELDS} FROM users WHERE id = ?",
                                          (result["user"]["id"],)).fetchone()
            if user:
                result["user"] = dict(user)
                token = secrets.token_urlsafe(32)
                csrf_token = secrets.token_urlsafe(32)
                now = time.monotonic()
                with self.server.sessions_lock:
                    self.server.sessions = {key: value for key, value in self.server.sessions.items()
                                            if value["expires"] > now}
                    self.server.sessions[token] = {
                        "user_id": user["id"], "mode": mode, "csrf_token": csrf_token,
                        "expires": now + SESSION_SECONDS,
                    }
                result["csrf_token"] = csrf_token
                cookie = self.session_cookie(token, SESSION_SECONDS)
            else:
                result.update({"authenticated": False, "status": "denied", "user": None})
        self.send_json(200, result, cookie)

    def do_PATCH(self):
        match = re.fullmatch(r"/api/admin/users/([1-9][0-9]{0,9})", self.path)
        if match is None:
            self.send_json(404, {"error": "Endpoint neexistuje."})
            return
        if not self.require_session(admin=True, csrf=True):
            return
        payload = self.read_json()
        if payload is None:
            return
        fields = {"display_name", "email", "study_group"}
        if set(payload) != fields or not all(isinstance(payload[key], str) for key in fields):
            self.send_json(400, {"error": "Vyplňte meno, e-mail a skupinu."})
            return
        name, email, group = (payload[key].strip() for key in ("display_name", "email", "study_group"))
        if not 1 <= len(name) <= 100 or len(email) > 150 or len(group) > 30:
            self.send_json(400, {"error": "Meno: 1–100 znakov, e-mail: najviac 150, skupina: najviac 30."})
            return
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self.send_json(400, {"error": "Zadajte platný e-mail."})
            return
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(
                "UPDATE users SET display_name = ?, email = ?, study_group = ? WHERE id = ?",
                (name, email, group, int(match[1])),
            )
            if cursor.rowcount == 0:
                self.send_json(404, {"error": "Používateľ neexistuje."})
                return
            user = connection.execute(f"SELECT {USER_FIELDS} FROM users WHERE id = ?",
                                      (int(match[1]),)).fetchone()
        self.send_json(200, {"user": dict(user)})


def make_server(port=8000, database=DATABASE):
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(LabHandler, database=database))
    server.sessions = {}
    server.sessions_lock = threading.Lock()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000, help="Lokálny port (predvolene 8000)")
    args = parser.parse_args()
    init_database()
    try:
        server = make_server(args.port)
    except OSError as error:
        parser.exit(1, f"Server sa nepodarilo spustiť: {error}\nSkúste --port 8001.\n")
    print(f"SQL Injection Lab: http://127.0.0.1:{server.server_port}", flush=True)
    print("Ukončenie: Ctrl+C. Používajú sa iba lokálne, fiktívne účty.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer bol ukončený.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
