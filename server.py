#!/usr/bin/env python3
"""
HeyJournal — Zero-Knowledge Encrypted Journal Server
Lightweight Python 3 stdlib + SQLite (WAL) API & Static Server.
Runs identically on macOS and Linux/Coolify Docker with zero external dependencies.
"""
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", "8080"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "journal.db")
BACKUP_DIR = os.path.join(BASE_DIR, "data", "backups")
BACKUP_RETENTION_DAYS = max(1, int(os.environ.get("BACKUP_RETENTION_DAYS", "14")))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
QUIZZES_DIR = os.path.join(BASE_DIR, "quizzes")

SESSION_COOKIE_NAME = "hj_session"
SESSION_TTL_DAYS = max(1, int(os.environ.get("SESSION_TTL_DAYS", "14")))
SERVER_AUTH_ITERATIONS = 100_000
MIN_CLIENT_KDF_ITERATIONS = 50_000
MAX_CLIENT_KDF_ITERATIONS = 1_000_000
MAX_BODY_BYTES = 4 * 1024 * 1024  # 4 MB max request body
MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024

DB_LOCK = threading.RLock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS = {}
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get("AUTH_RATE_LIMIT", "30"))

USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$")
UUID_RE = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@contextlib.contextmanager
def _connect_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with DB_LOCK:
        with _connect_db() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS app_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    display_username TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    kdf_salt TEXT NOT NULL,
                    kdf_iterations INTEGER NOT NULL DEFAULT 150000,
                    auth_salt TEXT NOT NULL,
                    auth_hash TEXT NOT NULL,
                    wrapped_dek TEXT NOT NULL,
                    vault_meta TEXT NOT NULL DEFAULT '',
                    vault_meta_updated_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS entries (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_entries_user_updated
                    ON entries(user_id, updated_at DESC);

                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON sessions(user_id);
                """
            )

            # Ensure server challenge secret exists (for constant-appearance nonexistent-user challenges)
            row = conn.execute(
                "SELECT value FROM app_config WHERE key = 'challenge_secret'"
            ).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO app_config (key, value) VALUES ('challenge_secret', ?)",
                    (secrets.token_hex(32),),
                )

            row_signups = conn.execute(
                "SELECT value FROM app_config WHERE key = 'allow_signups'"
            ).fetchone()
            if not row_signups:
                env_default = os.environ.get("ALLOW_SIGNUPS", "1").strip().lower()
                val = "0" if env_default in ("0", "false", "no", "off") else "1"
                conn.execute(
                    "INSERT INTO app_config (key, value) VALUES ('allow_signups', ?)",
                    (val,),
                )


def _get_config(conn, key, default=""):
    row = conn.execute("SELECT value FROM app_config WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def _set_config(conn, key, value):
    conn.execute(
        "INSERT INTO app_config (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def _hash_token(raw_token):
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _derive_server_auth_hash(client_auth_key_b64, auth_salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256",
        client_auth_key_b64.encode("utf-8"),
        bytes.fromhex(auth_salt_hex),
        SERVER_AUTH_ITERATIONS,
    ).hex()


def _fake_challenge_salt(conn, username):
    secret_hex = _get_config(conn, "challenge_secret", "00" * 32)
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        username.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).digest()[:16]
    import base64
    return base64.b64encode(digest).decode("ascii")


def _validate_encrypted_blob(raw_str, allow_empty=False):
    if raw_str == "" and allow_empty:
        return ""
    if not isinstance(raw_str, str):
        return None
    if len(raw_str.encode("utf-8")) > MAX_CIPHERTEXT_BYTES:
        return None
    try:
        parsed = json.loads(raw_str)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if parsed.get("v") != 1 or parsed.get("alg") != "A256GCM":
        return None
    iv = parsed.get("iv")
    ct = parsed.get("ct")
    if not isinstance(iv, str) or not isinstance(ct, str) or not iv or not ct:
        return None
    return raw_str


def _sanitize_theme_id(raw_id, fallback="metro"):
    if not isinstance(raw_id, str):
        return fallback
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "", raw_id.strip())
    return cleaned or fallback


def discover_themes():
    """
    Auto-discovers drop-in themes from `public/themes/<theme-id>/theme.json`.
    Matches FamilyCoordination's exact theme contract.
    """
    themes_dir = os.path.join(PUBLIC_DIR, "themes")
    found = []
    if not os.path.isdir(themes_dir):
        return found

    for folder in sorted(os.listdir(themes_dir)):
        if folder.startswith(("_", ".")):
            continue
        folder_path = os.path.join(themes_dir, folder)
        if not os.path.isdir(folder_path):
            continue
        manifest_path = os.path.join(folder_path, "theme.json")
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            if not isinstance(manifest, dict):
                continue
            theme_id = _sanitize_theme_id(manifest.get("id") or folder, "")
            if not theme_id:
                continue
            rel_css = str(manifest.get("stylesheet") or "theme.css").strip().lstrip("/")
            if not rel_css or ".." in rel_css.split("/"):
                continue
            css_full_path = os.path.realpath(os.path.join(folder_path, rel_css))
            real_folder_path = os.path.realpath(folder_path)
            if not css_full_path.startswith(real_folder_path + os.sep):
                continue
            if not os.path.isfile(css_full_path):
                continue

            modes = manifest.get("modes")
            if not isinstance(modes, list):
                modes = ["dark", "light"]
            modes = [m for m in modes if m in ("dark", "light")] or ["dark", "light"]
            default_mode = manifest.get("defaultMode")
            if default_mode not in modes:
                default_mode = modes[0]

            found.append(
                {
                    "id": theme_id,
                    "name": str(manifest.get("name") or theme_id),
                    "description": str(manifest.get("description") or ""),
                    "author": str(manifest.get("author") or ""),
                    "order": int(manifest.get("order", 100)),
                    "modes": modes,
                    "defaultMode": default_mode,
                    "defaultAccent": str(manifest.get("defaultAccent") or "#00ABA9"),
                    "accents": manifest.get("accents") if isinstance(manifest.get("accents"), list) else [],
                    "extensionAccents": manifest.get("extensionAccents")
                    if isinstance(manifest.get("extensionAccents"), dict)
                    else {},
                    "metaThemeColor": manifest.get("metaThemeColor")
                    if isinstance(manifest.get("metaThemeColor"), dict)
                    else {},
                    "preview": manifest.get("preview") if isinstance(manifest.get("preview"), dict) else {},
                    "stylesheetUrl": f"/themes/{folder}/{rel_css}",
                }
            )
        except Exception:
            continue

    found.sort(key=lambda t: (t.get("order", 100), t.get("name", "").lower()))
    return found


def discover_quizzes():
    """
    Auto-discovers standardized clinical/self-report quizzes from `quizzes/*.json`.
    One quiz per file; files starting with `_` or `.` are ignored.
    """
    found = []
    if not os.path.isdir(QUIZZES_DIR):
        return found

    for fname in sorted(os.listdir(QUIZZES_DIR)):
        if fname.startswith(("_", ".")) or not fname.endswith(".json"):
            continue
        full_path = os.path.join(QUIZZES_DIR, fname)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path, "r", encoding="utf-8") as fh:
                quiz = json.load(fh)
            if not isinstance(quiz, dict):
                continue
            qid = str(quiz.get("id") or os.path.splitext(fname)[0]).strip()
            if not qid or not re.match(r"^[a-zA-Z0-9_-]+$", qid):
                continue
            questions = quiz.get("questions")
            scoring = quiz.get("scoring")
            if not isinstance(questions, list) or len(questions) == 0:
                continue
            if not isinstance(scoring, dict):
                continue
            quiz["id"] = qid
            quiz["fileName"] = fname
            found.append(quiz)
        except Exception:
            continue

    found.sort(key=lambda q: (str(q.get("category") or "").lower(), str(q.get("name") or "").lower()))
    return found


def perform_sqlite_backup(tag=None):
    """
    Creates an online atomic SQLite backup in `data/backups/`.
    Because all user content in SQLite is client-side AES-256-GCM encrypted,
    every backup file is automatically zero-knowledge encrypted at rest.
    """
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = tag or datetime.now().strftime("%Y-%m-%d")
    backup_name = f"journal-backup-{stamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    tmp_path = backup_path + ".tmp"

    with DB_LOCK:
        with _connect_db() as src_conn:
            dst_conn = sqlite3.connect(tmp_path)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        os.replace(tmp_path, backup_path)

    prune_old_backups()
    return backup_name


def prune_old_backups():
    if not os.path.isdir(BACKUP_DIR):
        return
    files = sorted(
        f for f in os.listdir(BACKUP_DIR)
        if f.startswith("journal-backup-") and f.endswith(".db")
    )
    excess = len(files) - BACKUP_RETENTION_DAYS
    if excess > 0:
        for old_name in files[:excess]:
            try:
                os.remove(os.path.join(BACKUP_DIR, old_name))
            except OSError:
                pass


def list_backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    result = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not (fname.startswith("journal-backup-") and fname.endswith(".db")):
            continue
        fpath = os.path.join(BACKUP_DIR, fname)
        try:
            st = os.stat(fpath)
            result.append(
                {
                    "name": fname,
                    "sizeBytes": st.st_size,
                    "modifiedAt": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            )
        except OSError:
            continue
    return result


def _backup_scheduler_loop(stop_event):
    """Runs daily at 3:00 AM local time (respecting TZ env var)."""
    while not stop_event.is_set():
        now = datetime.now()
        next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        wait_seconds = max(1.0, (next_run - now).total_seconds())
        if stop_event.wait(timeout=wait_seconds):
            break
        try:
            perform_sqlite_backup()
        except Exception as exc:
            sys.stderr.write(f"[HeyJournal] Nightly backup failed: {exc}\n")


def _check_rate_limit(client_ip):
    now = time.monotonic()
    with RATE_LOCK:
        bucket = RATE_BUCKETS.get(client_ip, [])
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        bucket = [t for t in bucket if t > cutoff]
        if len(bucket) >= RATE_LIMIT_MAX_ATTEMPTS:
            RATE_BUCKETS[client_ip] = bucket
            return False
        bucket.append(now)
        RATE_BUCKETS[client_ip] = bucket
        return True


def _serialize_user_row(row):
    return {
        "id": row["id"],
        "username": row["display_username"],
        "isAdmin": bool(row["is_admin"]),
        "kdfSalt": row["kdf_salt"],
        "kdfIterations": int(row["kdf_iterations"]),
        "wrappedDek": row["wrapped_dek"],
        "createdAt": row["created_at"],
    }


class JournalRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def log_message(self, format_str, *args):
        if os.environ.get("QUIET_LOGS") == "1":
            return
        super().log_message(format_str, *args)

    def _is_https_request(self):
        xfp = (self.headers.get("X-Forwarded-Proto") or "").lower()
        return xfp == "https"

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def _send_security_headers(self, is_api=False):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        if is_api:
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")

    def end_headers(self):
        path = urlparse(self.path).path if hasattr(self, "path") else ""
        is_api = path.startswith("/api/")
        self._send_security_headers(is_api=is_api)
        if not is_api and path.endswith((".html", "/sw.js", "/manifest.json")):
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def _send_json(self, status_code, payload, extra_headers=None):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return None, "Invalid Content-Length header"
        if length < 0 or length > MAX_BODY_BYTES:
            return None, "Request body exceeds maximum size"
        if length == 0:
            return {}, None
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return None, "Invalid JSON payload"
        if not isinstance(data, dict):
            return None, "JSON payload must be an object"
        return data, None

    def _check_csrf_origin(self):
        host = (self.headers.get("Host") or "").lower().strip()
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlparse(origin)
            origin_host = (parsed.netloc or "").lower().strip()
            if host and origin_host and origin_host != host:
                return False
        referer = self.headers.get("Referer")
        if not origin and referer:
            parsed = urlparse(referer)
            ref_host = (parsed.netloc or "").lower().strip()
            if host and ref_host and ref_host != host:
                return False
        return True

    def _build_session_cookie(self, token, max_age=None):
        parts = [
            f"{SESSION_COOKIE_NAME}={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
        ]
        if max_age is not None:
            parts.append(f"Max-Age={int(max_age)}")
        if self._is_https_request():
            parts.append("Secure")
        return "; ".join(parts)

    def _get_session_token(self):
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel and morsel.value else None

    def _authenticate(self, conn):
        raw_token = self._get_session_token()
        if not raw_token:
            return None
        token_hash = _hash_token(raw_token)
        row = conn.execute(
            """
            SELECT u.*, s.expires_at AS session_expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None
        if row["session_expires_at"] < utc_now_iso():
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            return None
        return row

    def _create_session(self, conn, user_id):
        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=SESSION_TTL_DAYS)
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (
                token_hash,
                user_id,
                now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                expires.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ),
        )
        # Opportunistic cleanup of expired sessions
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (utc_now_iso(),))
        return raw_token

    # ------------------------------------------------------------------
    # HTTP Method Dispatch
    # ------------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json(200, {"ok": True, "service": "heyjournal"})
            return
        if path == "/api/themes":
            self._send_json(200, {"themes": discover_themes()})
            return
        if path == "/api/quizzes":
            self._send_json(200, {"quizzes": discover_quizzes()})
            return
        if path == "/api/auth/status":
            self._handle_auth_status()
            return
        if path == "/api/vault":
            self._handle_get_vault()
            return
        if path == "/api/admin/users":
            self._handle_admin_list_users()
            return
        if path.startswith("/api/"):
            self._send_json(404, {"error": "API endpoint not found"})
            return

        # Static file serving (SPA root fallback to index.html for clean paths)
        if path == "/" or path == "":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        if not self._check_csrf_origin():
            self._send_json(403, {"error": "Cross-origin request blocked"})
            return

        path = urlparse(self.path).path
        if path == "/api/auth/challenge":
            self._handle_auth_challenge()
            return
        if path == "/api/auth/register":
            self._handle_auth_register()
            return
        if path == "/api/auth/login":
            self._handle_auth_login()
            return
        if path == "/api/auth/logout":
            self._handle_auth_logout()
            return
        if path == "/api/auth/change-password":
            self._handle_change_password()
            return
        if path == "/api/entries":
            self._handle_create_entry()
            return
        if path == "/api/admin/backup":
            self._handle_admin_backup()
            return
        self._send_json(404, {"error": "API endpoint not found"})

    def do_PUT(self):
        if not self._check_csrf_origin():
            self._send_json(403, {"error": "Cross-origin request blocked"})
            return

        path = urlparse(self.path).path
        if path == "/api/vault/meta":
            self._handle_update_vault_meta()
            return
        if path == "/api/admin/settings":
            self._handle_admin_update_settings()
            return
        if path.startswith("/api/entries/"):
            entry_id = path[len("/api/entries/"):].strip("/")
            self._handle_update_entry(entry_id)
            return
        self._send_json(404, {"error": "API endpoint not found"})

    def do_DELETE(self):
        if not self._check_csrf_origin():
            self._send_json(403, {"error": "Cross-origin request blocked"})
            return

        path = urlparse(self.path).path
        if path.startswith("/api/entries/"):
            entry_id = path[len("/api/entries/"):].strip("/")
            self._handle_delete_entry(entry_id)
            return
        if path.startswith("/api/admin/users/"):
            target_id = path[len("/api/admin/users/"):].strip("/")
            self._handle_admin_delete_user(target_id)
            return
        self._send_json(404, {"error": "API endpoint not found"})

    # ------------------------------------------------------------------
    # Auth Handlers
    # ------------------------------------------------------------------
    def _handle_auth_status(self):
        with DB_LOCK:
            with _connect_db() as conn:
                user_count = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
                allow_signups = _get_config(conn, "allow_signups", "1") == "1" or user_count == 0
                user = self._authenticate(conn)
                if not user:
                    self._send_json(
                        200,
                        {
                            "authenticated": False,
                            "userCount": user_count,
                            "allowSignups": allow_signups,
                            "user": None,
                        },
                    )
                    return
                self._send_json(
                    200,
                    {
                        "authenticated": True,
                        "userCount": user_count,
                        "allowSignups": allow_signups,
                        "user": _serialize_user_row(user),
                    },
                )

    def _handle_auth_challenge(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment and try again."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        username = str(body.get("username") or "").strip()
        if not username:
            self._send_json(400, {"error": "Username is required"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                row = conn.execute(
                    "SELECT kdf_salt, kdf_iterations FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()
                if row:
                    self._send_json(
                        200,
                        {
                            "kdfSalt": row["kdf_salt"],
                            "kdfIterations": int(row["kdf_iterations"]),
                        },
                    )
                else:
                    self._send_json(
                        200,
                        {
                            "kdfSalt": _fake_challenge_salt(conn, username),
                            "kdfIterations": 150_000,
                        },
                    )

    def _handle_auth_register(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment and try again."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        username = str(body.get("username") or "").strip()
        auth_key = str(body.get("authKey") or "").strip()
        kdf_salt = str(body.get("kdfSalt") or "").strip()
        try:
            kdf_iterations = int(body.get("kdfIterations", 150_000))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid KDF iterations"})
            return
        wrapped_dek = _validate_encrypted_blob(body.get("wrappedDek"), allow_empty=False)
        vault_meta = _validate_encrypted_blob(body.get("vaultMeta", ""), allow_empty=True)

        if not USERNAME_RE.match(username):
            self._send_json(
                400,
                {
                    "error": "Username must be 2–32 characters (letters, numbers, ., _, -) and start with a letter or number."
                },
            )
            return
        if len(auth_key) < 32 or len(auth_key) > 256:
            self._send_json(400, {"error": "Invalid auth key"})
            return
        if len(kdf_salt) < 16 or len(kdf_salt) > 128:
            self._send_json(400, {"error": "Invalid KDF salt"})
            return
        if not (MIN_CLIENT_KDF_ITERATIONS <= kdf_iterations <= MAX_CLIENT_KDF_ITERATIONS):
            self._send_json(400, {"error": "KDF iterations out of safe bounds"})
            return
        if wrapped_dek is None:
            self._send_json(400, {"error": "Invalid wrapped vault key"})
            return
        if vault_meta is None:
            self._send_json(400, {"error": "Invalid encrypted vault metadata"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                user_count = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
                allow_signups = _get_config(conn, "allow_signups", "1") == "1"
                if user_count > 0 and not allow_signups:
                    self._send_json(403, {"error": "New registrations are currently disabled by the admin."})
                    return

                existing = conn.execute(
                    "SELECT id FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()
                if existing:
                    self._send_json(409, {"error": "That username is already taken."})
                    return

                user_id = str(uuid.uuid4())
                is_admin = 1 if user_count == 0 else 0
                auth_salt = secrets.token_hex(16)
                auth_hash = _derive_server_auth_hash(auth_key, auth_salt)
                now_iso = utc_now_iso()

                conn.execute(
                    """
                    INSERT INTO users (
                        id, username, display_username, is_admin,
                        kdf_salt, kdf_iterations, auth_salt, auth_hash,
                        wrapped_dek, vault_meta, vault_meta_updated_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        username.lower(),
                        username,
                        is_admin,
                        kdf_salt,
                        kdf_iterations,
                        auth_salt,
                        auth_hash,
                        wrapped_dek,
                        vault_meta,
                        now_iso if vault_meta else "",
                        now_iso,
                    ),
                )

                raw_token = self._create_session(conn, user_id)
                user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                cookie_header = self._build_session_cookie(raw_token, max_age=SESSION_TTL_DAYS * 86400)

        self._send_json(
            201,
            {
                "user": _serialize_user_row(user_row),
                "vaultMeta": user_row["vault_meta"],
                "vaultMetaUpdatedAt": user_row["vault_meta_updated_at"],
            },
            extra_headers=[("Set-Cookie", cookie_header)],
        )

    def _handle_auth_login(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many login attempts. Please wait a moment and try again."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        username = str(body.get("username") or "").strip()
        auth_key = str(body.get("authKey") or "").strip()
        if not username or not auth_key:
            self._send_json(400, {"error": "Username and password are required"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                user_row = conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()
                if not user_row:
                    # Burn equivalent PBKDF2 time to resist timing side-channels
                    _derive_server_auth_hash(auth_key, "00" * 16)
                    self._send_json(401, {"error": "Invalid username or password"})
                    return

                candidate_hash = _derive_server_auth_hash(auth_key, user_row["auth_salt"])
                if not hmac.compare_digest(candidate_hash, user_row["auth_hash"]):
                    self._send_json(401, {"error": "Invalid username or password"})
                    return

                raw_token = self._create_session(conn, user_row["id"])
                cookie_header = self._build_session_cookie(raw_token, max_age=SESSION_TTL_DAYS * 86400)

        self._send_json(
            200,
            {
                "user": _serialize_user_row(user_row),
                "vaultMeta": user_row["vault_meta"],
                "vaultMetaUpdatedAt": user_row["vault_meta_updated_at"],
            },
            extra_headers=[("Set-Cookie", cookie_header)],
        )

    def _handle_auth_logout(self):
        raw_token = self._get_session_token()
        if raw_token:
            token_hash = _hash_token(raw_token)
            with DB_LOCK:
                with _connect_db() as conn:
                    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        clear_cookie = self._build_session_cookie("", max_age=0)
        self._send_json(200, {"ok": True}, extra_headers=[("Set-Cookie", clear_cookie)])

    def _handle_change_password(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        current_auth_key = str(body.get("currentAuthKey") or "").strip()
        new_auth_key = str(body.get("newAuthKey") or "").strip()
        new_kdf_salt = str(body.get("newKdfSalt") or "").strip()
        try:
            new_kdf_iterations = int(body.get("newKdfIterations", 150_000))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid KDF iterations"})
            return
        new_wrapped_dek = _validate_encrypted_blob(body.get("newWrappedDek"), allow_empty=False)

        if not current_auth_key or len(new_auth_key) < 32 or len(new_kdf_salt) < 16 or new_wrapped_dek is None:
            self._send_json(400, {"error": "Invalid password update payload"})
            return
        if not (MIN_CLIENT_KDF_ITERATIONS <= new_kdf_iterations <= MAX_CLIENT_KDF_ITERATIONS):
            self._send_json(400, {"error": "KDF iterations out of safe bounds"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return

                candidate_hash = _derive_server_auth_hash(current_auth_key, user["auth_salt"])
                if not hmac.compare_digest(candidate_hash, user["auth_hash"]):
                    self._send_json(403, {"error": "Current password is incorrect"})
                    return

                new_auth_salt = secrets.token_hex(16)
                new_auth_hash = _derive_server_auth_hash(new_auth_key, new_auth_salt)

                conn.execute(
                    """
                    UPDATE users
                    SET kdf_salt = ?, kdf_iterations = ?, auth_salt = ?, auth_hash = ?, wrapped_dek = ?
                    WHERE id = ?
                    """,
                    (
                        new_kdf_salt,
                        new_kdf_iterations,
                        new_auth_salt,
                        new_auth_hash,
                        new_wrapped_dek,
                        user["id"],
                    ),
                )
                # Rotate all sessions for security
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
                raw_token = self._create_session(conn, user["id"])
                updated_user = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
                cookie_header = self._build_session_cookie(raw_token, max_age=SESSION_TTL_DAYS * 86400)

        self._send_json(
            200,
            {"ok": True, "user": _serialize_user_row(updated_user)},
            extra_headers=[("Set-Cookie", cookie_header)],
        )

    # ------------------------------------------------------------------
    # Encrypted Vault & Entries Handlers
    # ------------------------------------------------------------------
    def _handle_get_vault(self):
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                rows = conn.execute(
                    """
                    SELECT id, ciphertext, created_at, updated_at
                    FROM entries
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    """,
                    (user["id"],),
                ).fetchall()
                entries = [
                    {
                        "id": r["id"],
                        "ciphertext": r["ciphertext"],
                        "createdAt": r["created_at"],
                        "updatedAt": r["updated_at"],
                    }
                    for r in rows
                ]
                self._send_json(
                    200,
                    {
                        "user": _serialize_user_row(user),
                        "vaultMeta": user["vault_meta"],
                        "vaultMetaUpdatedAt": user["vault_meta_updated_at"],
                        "entries": entries,
                    },
                )

    def _handle_update_vault_meta(self):
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        vault_meta = _validate_encrypted_blob(body.get("vaultMeta"), allow_empty=False)
        if vault_meta is None:
            self._send_json(400, {"error": "Invalid encrypted vault metadata"})
            return
        expected_updated_at = body.get("expectedUpdatedAt")

        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                current_ts = user["vault_meta_updated_at"] or ""
                if (
                    isinstance(expected_updated_at, str)
                    and current_ts
                    and expected_updated_at != current_ts
                ):
                    self._send_json(
                        409,
                        {
                            "error": "Settings were updated on another device.",
                            "vaultMeta": user["vault_meta"],
                            "vaultMetaUpdatedAt": current_ts,
                        },
                    )
                    return
                now_iso = utc_now_iso()
                conn.execute(
                    "UPDATE users SET vault_meta = ?, vault_meta_updated_at = ? WHERE id = ?",
                    (vault_meta, now_iso, user["id"]),
                )
        self._send_json(200, {"ok": True, "vaultMetaUpdatedAt": now_iso})

    def _handle_create_entry(self):
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        ciphertext = _validate_encrypted_blob(body.get("ciphertext"), allow_empty=False)
        if ciphertext is None:
            self._send_json(400, {"error": "Invalid encrypted entry payload"})
            return
        entry_id = str(body.get("id") or "").strip() or str(uuid.uuid4())
        if not UUID_RE.match(entry_id):
            self._send_json(400, {"error": "Invalid entry id"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                existing = conn.execute(
                    "SELECT id FROM entries WHERE id = ?",
                    (entry_id,),
                ).fetchone()
                if existing:
                    self._send_json(409, {"error": "Entry with this id already exists"})
                    return
                now_iso = utc_now_iso()
                conn.execute(
                    "INSERT INTO entries (id, user_id, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (entry_id, user["id"], ciphertext, now_iso, now_iso),
                )

        self._send_json(
            201,
            {
                "entry": {
                    "id": entry_id,
                    "ciphertext": ciphertext,
                    "createdAt": now_iso,
                    "updatedAt": now_iso,
                }
            },
        )

    def _handle_update_entry(self, entry_id):
        if not UUID_RE.match(entry_id):
            self._send_json(400, {"error": "Invalid entry id"})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        ciphertext = _validate_encrypted_blob(body.get("ciphertext"), allow_empty=False)
        if ciphertext is None:
            self._send_json(400, {"error": "Invalid encrypted entry payload"})
            return
        expected_updated_at = body.get("expectedUpdatedAt")

        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                row = conn.execute(
                    "SELECT id, ciphertext, created_at, updated_at FROM entries WHERE id = ? AND user_id = ?",
                    (entry_id, user["id"]),
                ).fetchone()
                if not row:
                    self._send_json(404, {"error": "Entry not found"})
                    return
                if (
                    isinstance(expected_updated_at, str)
                    and expected_updated_at
                    and expected_updated_at != row["updated_at"]
                ):
                    self._send_json(
                        409,
                        {
                            "error": "Entry was modified on another device.",
                            "entry": {
                                "id": row["id"],
                                "ciphertext": row["ciphertext"],
                                "createdAt": row["created_at"],
                                "updatedAt": row["updated_at"],
                            },
                        },
                    )
                    return
                now_iso = utc_now_iso()
                conn.execute(
                    "UPDATE entries SET ciphertext = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                    (ciphertext, now_iso, entry_id, user["id"]),
                )
                created_at = row["created_at"]

        self._send_json(
            200,
            {
                "entry": {
                    "id": entry_id,
                    "ciphertext": ciphertext,
                    "createdAt": created_at,
                    "updatedAt": now_iso,
                }
            },
        )

    def _handle_delete_entry(self, entry_id):
        if not UUID_RE.match(entry_id):
            self._send_json(400, {"error": "Invalid entry id"})
            return
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                cur = conn.execute(
                    "DELETE FROM entries WHERE id = ? AND user_id = ?",
                    (entry_id, user["id"]),
                )
                if cur.rowcount == 0:
                    self._send_json(404, {"error": "Entry not found"})
                    return
        self._send_json(200, {"ok": True, "deletedId": entry_id})

    # ------------------------------------------------------------------
    # Admin Handlers (First User Only — Zero Access to User Data)
    # ------------------------------------------------------------------
    def _handle_admin_list_users(self):
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                if not user["is_admin"]:
                    self._send_json(403, {"error": "Admin privileges required"})
                    return
                rows = conn.execute(
                    """
                    SELECT u.id, u.display_username, u.is_admin, u.created_at,
                           COUNT(e.id) AS entry_count
                    FROM users u
                    LEFT JOIN entries e ON e.user_id = u.id
                    GROUP BY u.id
                    ORDER BY u.created_at ASC
                    """
                ).fetchall()
                allow_signups = _get_config(conn, "allow_signups", "1") == "1"
                users = [
                    {
                        "id": r["id"],
                        "username": r["display_username"],
                        "isAdmin": bool(r["is_admin"]),
                        "createdAt": r["created_at"],
                        "entryCount": int(r["entry_count"]),
                    }
                    for r in rows
                ]
        self._send_json(
            200,
            {
                "allowSignups": allow_signups,
                "users": users,
                "backups": list_backups(),
            },
        )

    def _handle_admin_delete_user(self, target_id):
        if not UUID_RE.match(target_id):
            self._send_json(400, {"error": "Invalid user id"})
            return
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                if not user["is_admin"]:
                    self._send_json(403, {"error": "Admin privileges required"})
                    return
                if target_id == user["id"]:
                    self._send_json(400, {"error": "You cannot delete your own admin account."})
                    return
                cur = conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
                if cur.rowcount == 0:
                    self._send_json(404, {"error": "Account not found"})
                    return
        self._send_json(200, {"ok": True, "deletedUserId": target_id})

    def _handle_admin_update_settings(self):
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        allow_signups = body.get("allowSignups")
        if not isinstance(allow_signups, bool):
            self._send_json(400, {"error": "allowSignups must be a boolean"})
            return
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                if not user["is_admin"]:
                    self._send_json(403, {"error": "Admin privileges required"})
                    return
                _set_config(conn, "allow_signups", "1" if allow_signups else "0")
        self._send_json(200, {"ok": True, "allowSignups": allow_signups})

    def _handle_admin_backup(self):
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                if not user["is_admin"]:
                    self._send_json(403, {"error": "Admin privileges required"})
                    return
        stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        backup_name = perform_sqlite_backup(tag=stamp)
        self._send_json(200, {"ok": True, "backupName": backup_name, "backups": list_backups()})


def run_server():
    init_db()
    stop_event = threading.Event()
    backup_thread = threading.Thread(
        target=_backup_scheduler_loop,
        args=(stop_event,),
        name="heyjournal-nightly-backup",
        daemon=True,
    )
    backup_thread.start()

    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), JournalRequestHandler)

    def _shutdown(signum, frame):
        stop_event.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(f"HeyJournal listening on http://0.0.0.0:{PORT}", flush=True)
    try:
        httpd.serve_forever()
    finally:
        stop_event.set()
        httpd.server_close()


if __name__ == "__main__":
    run_server()
