#!/usr/bin/env python3
"""
HeyJournal — Zero-Knowledge Encrypted Journal Server
Lightweight Python 3 stdlib + SQLite (WAL) API & Static Server.
Runs identically on macOS and Linux/Coolify Docker with zero external dependencies.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
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
DEFAULT_CLIENT_KDF_ITERATIONS = 600_000  # OWASP 2023 PBKDF2-HMAC-SHA256 target for new/updated passwords
RECOVERY_KDF_ITERATIONS = 150_000  # High-entropy 160-bit random recovery key KDF iterations
MIN_CLIENT_KDF_ITERATIONS = 50_000
MAX_CLIENT_KDF_ITERATIONS = 1_000_000
MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 MB max request body (supports batched encrypted JSON imports)
MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024
MAX_BATCH_IMPORT_ENTRIES = 500
TRUST_PROXY_MODE = os.environ.get("TRUST_PROXY", "auto").strip().lower()

DB_LOCK = threading.RLock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS = {}
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_ATTEMPTS = max(1, int(os.environ.get("AUTH_RATE_LIMIT", "30")))
_LAST_RATE_PRUNE = 0.0

USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$")
UUID_RE = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")
SAFE_FOLDER_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
NIGHTLY_BACKUP_RE = re.compile(r"^journal-backup-\d{4}-\d{2}-\d{2}\.db$")
BACKUP_FILE_RE = re.compile(r"^journal-backup-\d{4}-\d{2}-\d{2}(?:-\d{6})?\.db$")


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
                    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
                    auth_salt TEXT NOT NULL,
                    auth_hash TEXT NOT NULL,
                    wrapped_dek TEXT NOT NULL,
                    vault_meta TEXT NOT NULL DEFAULT '',
                    vault_meta_updated_at TEXT NOT NULL DEFAULT '',
                    recovery_kdf_salt TEXT NOT NULL DEFAULT '',
                    recovery_kdf_iterations INTEGER NOT NULL DEFAULT 0,
                    recovery_auth_salt TEXT NOT NULL DEFAULT '',
                    recovery_auth_hash TEXT NOT NULL DEFAULT '',
                    recovery_wrapped_dek TEXT NOT NULL DEFAULT '',
                    recovery_created_at TEXT NOT NULL DEFAULT '',
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
                    id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_entries_user_updated
                    ON entries(user_id, updated_at DESC);

                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON sessions(user_id);
                """
            )

            # Migrate older SQLite databases whose `entries` table used a global single-column PK (`id`)
            # instead of composite `(user_id, id)` — prevents cross-user ID collisions & ID existence leaks.
            entry_pk_cols = [
                row["name"]
                for row in conn.execute("PRAGMA table_info(entries)").fetchall()
                if row["pk"] > 0
            ]
            if entry_pk_cols == ["id"]:
                conn.executescript(
                    """
                    CREATE TABLE entries_v2 (
                        id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        ciphertext TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (user_id, id),
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                    INSERT INTO entries_v2 (id, user_id, ciphertext, created_at, updated_at)
                        SELECT id, user_id, ciphertext, created_at, updated_at FROM entries;
                    DROP TABLE entries;
                    ALTER TABLE entries_v2 RENAME TO entries;
                    CREATE INDEX IF NOT EXISTS idx_entries_user_updated
                        ON entries(user_id, updated_at DESC);
                    """
                )

            # Migrate older SQLite databases lacking optional recovery-key columns
            existing_cols = {
                row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
            }
            migrations = [
                ("recovery_kdf_salt", "TEXT NOT NULL DEFAULT ''"),
                ("recovery_kdf_iterations", "INTEGER NOT NULL DEFAULT 0"),
                ("recovery_auth_salt", "TEXT NOT NULL DEFAULT ''"),
                ("recovery_auth_hash", "TEXT NOT NULL DEFAULT ''"),
                ("recovery_wrapped_dek", "TEXT NOT NULL DEFAULT ''"),
                ("recovery_created_at", "TEXT NOT NULL DEFAULT ''"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

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
    return base64.b64encode(digest).decode("ascii")


def _validate_encrypted_blob(raw_str, allow_empty=False):
    """Validates the client-side AES-256-GCM wire envelope without decrypting."""
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
    try:
        iv_bytes = base64.b64decode(iv.encode("ascii"), validate=True)
        ct_bytes = base64.b64decode(ct.encode("ascii"), validate=True)
    except Exception:
        return None
    if len(iv_bytes) != 12 or len(ct_bytes) < 16:
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
        if folder.startswith(("_", ".")) or not SAFE_FOLDER_RE.match(folder):
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

            try:
                order_val = int(manifest.get("order", 100))
            except (TypeError, ValueError):
                order_val = 100

            found.append(
                {
                    "id": theme_id,
                    "name": str(manifest.get("name") or theme_id),
                    "description": str(manifest.get("description") or ""),
                    "author": str(manifest.get("author") or ""),
                    "order": order_val,
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
        except Exception as exc:
            sys.stderr.write(f"[HeyJournal] Skipping invalid theme '{folder}': {exc}\n")
            continue

    found.sort(key=lambda t: (t.get("order", 100), t.get("name", "").lower()))
    return found


def discover_quizzes():
    """
    Auto-discovers standardized clinical/self-report quizzes from `quizzes/*.json`.
    One quiz per file; files starting with `_` or `.` are ignored.
    """
    found = []
    seen_ids = set()
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
            if qid in seen_ids:
                sys.stderr.write(f"[HeyJournal] Skipping duplicate quiz id '{qid}' in '{fname}'\n")
                continue
            questions = quiz.get("questions")
            scoring = quiz.get("scoring")
            if not isinstance(questions, list) or len(questions) == 0:
                continue
            if not isinstance(scoring, dict):
                continue
            seen_ids.add(qid)
            quiz["id"] = qid
            quiz["fileName"] = fname
            found.append(quiz)
        except Exception as exc:
            sys.stderr.write(f"[HeyJournal] Skipping invalid quiz '{fname}': {exc}\n")
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
    tmp_path = f"{backup_path}.{os.getpid()}.{threading.get_ident()}.tmp"

    with DB_LOCK:
        try:
            with _connect_db() as src_conn:
                dst_conn = sqlite3.connect(tmp_path)
                try:
                    src_conn.backup(dst_conn)
                finally:
                    dst_conn.close()
            os.replace(tmp_path, backup_path)
        except Exception:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            raise
        prune_old_backups()

    return backup_name


def prune_old_backups():
    """Retains up to BACKUP_RETENTION_DAYS nightly backups and equally many manual snapshots."""
    if not os.path.isdir(BACKUP_DIR):
        return
    all_files = sorted(
        f for f in os.listdir(BACKUP_DIR)
        if f.startswith("journal-backup-") and f.endswith(".db")
    )
    nightly = [f for f in all_files if NIGHTLY_BACKUP_RE.match(f)]
    manual = [f for f in all_files if not NIGHTLY_BACKUP_RE.match(f)]
    for bucket in (nightly, manual):
        excess = len(bucket) - BACKUP_RETENTION_DAYS
        if excess > 0:
            for old_name in bucket[:excess]:
                try:
                    os.remove(os.path.join(BACKUP_DIR, old_name))
                except OSError:
                    pass


def list_backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    result = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not BACKUP_FILE_RE.match(fname):
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
    last_backup_day = None
    while not stop_event.is_set():
        now = datetime.now()
        next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if next_run <= now or last_backup_day == now.date():
            next_run += timedelta(days=1)
        wait_seconds = max(1.0, (next_run - now).total_seconds())
        if stop_event.wait(timeout=wait_seconds):
            break
        if datetime.now() < next_run:
            continue
        try:
            perform_sqlite_backup()
            last_backup_day = datetime.now().date()
        except Exception as exc:
            sys.stderr.write(f"[HeyJournal] Nightly backup failed: {exc}\n")


def _check_rate_limit(client_ip):
    global _LAST_RATE_PRUNE
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with RATE_LOCK:
        # Periodically evict stale IPs so RATE_BUCKETS stays bounded on long-lived servers
        if now - _LAST_RATE_PRUNE > RATE_LIMIT_WINDOW_SECONDS or len(RATE_BUCKETS) > 1000:
            stale = [ip for ip, times in RATE_BUCKETS.items() if not times or times[-1] <= cutoff]
            for ip in stale:
                del RATE_BUCKETS[ip]
            _LAST_RATE_PRUNE = now

        bucket = [t for t in RATE_BUCKETS.get(client_ip, []) if t > cutoff]
        if len(bucket) >= RATE_LIMIT_MAX_ATTEMPTS:
            RATE_BUCKETS[client_ip] = bucket
            return False
        bucket.append(now)
        RATE_BUCKETS[client_ip] = bucket
        return True


_TRUSTED_PROXY_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # Tailscale / CGNAT
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _is_private_proxy_hop(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in _TRUSTED_PROXY_NETWORKS)
    except ValueError:
        return False


def _is_trusted_proxy_ip(peer_ip):
    """Returns True if forwarded proxy headers from `peer_ip` should be honored."""
    if TRUST_PROXY_MODE in ("1", "true", "yes", "on"):
        return True
    if TRUST_PROXY_MODE in ("0", "false", "no", "off"):
        return False
    # Default "auto": trust local/LAN/Docker/Tailscale reverse proxies only
    return _is_private_proxy_hop(peer_ip)


def _serialize_user_row(row):
    return {
        "id": row["id"],
        "username": row["display_username"],
        "isAdmin": bool(row["is_admin"]),
        "kdfSalt": row["kdf_salt"],
        "kdfIterations": int(row["kdf_iterations"]),
        "wrappedDek": row["wrapped_dek"],
        "hasRecoveryKey": bool(row["recovery_wrapped_dek"]),
        "recoveryCreatedAt": row["recovery_created_at"] or "",
        "createdAt": row["created_at"],
    }


class JournalRequestHandler(SimpleHTTPRequestHandler):
    timeout = 30

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def log_message(self, format_str, *args):
        if os.environ.get("QUIET_LOGS") == "1":
            return
        super().log_message(format_str, *args)

    def _peer_ip(self):
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def _is_https_request(self):
        if not _is_trusted_proxy_ip(self._peer_ip()):
            return False
        xfp = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        return xfp == "https"

    def _client_ip(self):
        peer = self._peer_ip()
        if _is_trusted_proxy_ip(peer):
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                valid_ips = []
                for part in xff.split(","):
                    candidate = part.strip()
                    if not candidate:
                        continue
                    try:
                        ipaddress.ip_address(candidate)
                        valid_ips.append(candidate)
                    except ValueError:
                        continue
                # Walk right-to-left to resist client-supplied spoofed prefixes
                for candidate in reversed(valid_ips):
                    if not _is_private_proxy_hop(candidate):
                        return candidate
                if valid_ips:
                    return valid_ips[0]
        return peer

    def list_directory(self, path):
        # Never expose directory listings of `public/` or `public/themes/`
        self.send_error(404, "Not found")
        return None

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
        if len(raw) != length:
            return None, "Incomplete request body"
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
        if origin is not None:
            parsed = urlparse(origin.strip())
            origin_host = (parsed.netloc or "").lower().strip()
            # Reject `Origin: null`, non-http(s) schemes, or any mismatched host
            if parsed.scheme not in ("http", "https") or not origin_host:
                return False
            if host and origin_host != host:
                return False
            return True
        referer = self.headers.get("Referer")
        if referer is not None:
            parsed = urlparse(referer.strip())
            ref_host = (parsed.netloc or "").lower().strip()
            if parsed.scheme not in ("http", "https") or not ref_host:
                return False
            if host and ref_host != host:
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
    def _dispatch_api(self, fn):
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            sys.stderr.write(f"[HeyJournal] Unhandled API error on {self.command} {self.path}: {exc}\n")
            try:
                self._send_json(500, {"error": "Internal server error"})
            except Exception:
                pass

    def _has_dotfile_segment(self, path):
        return any(seg.startswith(".") for seg in path.split("/") if seg)

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            body = json.dumps({"ok": True, "service": "heyjournal"}, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        if path.startswith("/api/"):
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self._has_dotfile_segment(path):
            self.send_error(404, "Not found")
            return
        if path == "/" or path == "":
            self.path = "/index.html"
        super().do_HEAD()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json(200, {"ok": True, "service": "heyjournal"})
            return
        if path == "/api/themes":
            self._dispatch_api(lambda: self._send_json(200, {"themes": discover_themes()}))
            return
        if path == "/api/quizzes":
            self._dispatch_api(lambda: self._send_json(200, {"quizzes": discover_quizzes()}))
            return
        if path == "/api/auth/status":
            self._dispatch_api(self._handle_auth_status)
            return
        if path == "/api/vault":
            self._dispatch_api(self._handle_get_vault)
            return
        if path == "/api/admin/users":
            self._dispatch_api(self._handle_admin_list_users)
            return
        if path.startswith("/api/admin/backups/"):
            fname = path[len("/api/admin/backups/"):].strip("/")
            self._dispatch_api(lambda: self._handle_admin_download_backup(fname))
            return
        if path.startswith("/api/"):
            self._send_json(404, {"error": "API endpoint not found"})
            return

        if self._has_dotfile_segment(path):
            self.send_error(404, "Not found")
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
        routes = {
            "/api/auth/challenge": self._handle_auth_challenge,
            "/api/auth/register": self._handle_auth_register,
            "/api/auth/login": self._handle_auth_login,
            "/api/auth/logout": self._handle_auth_logout,
            "/api/auth/change-password": self._handle_change_password,
            "/api/auth/recovery-key": self._handle_set_recovery_key,
            "/api/auth/recovery-challenge": self._handle_recovery_challenge,
            "/api/auth/recovery-verify": self._handle_recovery_verify,
            "/api/auth/recover": self._handle_recover_password,
            "/api/entries": self._handle_create_entry,
            "/api/entries/batch": self._handle_batch_import_entries,
            "/api/admin/backup": self._handle_admin_backup,
        }
        handler = routes.get(path)
        if handler:
            self._dispatch_api(handler)
            return
        self._send_json(404, {"error": "API endpoint not found"})

    def do_PUT(self):
        if not self._check_csrf_origin():
            self._send_json(403, {"error": "Cross-origin request blocked"})
            return

        path = urlparse(self.path).path
        if path == "/api/vault/meta":
            self._dispatch_api(self._handle_update_vault_meta)
            return
        if path == "/api/admin/settings":
            self._dispatch_api(self._handle_admin_update_settings)
            return
        if path.startswith("/api/admin/users/") and path.endswith("/role"):
            target_id = path[len("/api/admin/users/"):-len("/role")].strip("/")
            self._dispatch_api(lambda: self._handle_admin_update_user_role(target_id))
            return
        if path.startswith("/api/entries/"):
            entry_id = path[len("/api/entries/"):].strip("/")
            self._dispatch_api(lambda: self._handle_update_entry(entry_id))
            return
        self._send_json(404, {"error": "API endpoint not found"})

    def do_DELETE(self):
        if not self._check_csrf_origin():
            self._send_json(403, {"error": "Cross-origin request blocked"})
            return

        path = urlparse(self.path).path
        if path == "/api/auth/recovery-key":
            self._dispatch_api(self._handle_delete_recovery_key)
            return
        if path == "/api/auth/account":
            self._dispatch_api(self._handle_delete_own_account)
            return
        if path.startswith("/api/entries/"):
            entry_id = path[len("/api/entries/"):].strip("/")
            self._dispatch_api(lambda: self._handle_delete_entry(entry_id))
            return
        if path.startswith("/api/admin/users/"):
            target_id = path[len("/api/admin/users/"):].strip("/")
            self._dispatch_api(lambda: self._handle_admin_delete_user(target_id))
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
        if not username or len(username) > 128:
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
                            "kdfIterations": DEFAULT_CLIENT_KDF_ITERATIONS,
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
            kdf_iterations = int(body.get("kdfIterations", DEFAULT_CLIENT_KDF_ITERATIONS))
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

        # Compute server-side PBKDF2 outside DB_LOCK so logins/saves stay unblocked
        auth_salt = secrets.token_hex(16)
        auth_hash = _derive_server_auth_hash(auth_key, auth_salt)

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
                now_iso = utc_now_iso()

                try:
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
                except sqlite3.IntegrityError:
                    self._send_json(409, {"error": "That username is already taken."})
                    return

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
        if not username or len(username) > 128 or not auth_key or len(auth_key) > 256:
            self._send_json(400, {"error": "Username and password are required"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()
                user_row = dict(row) if row else None

        # Run PBKDF2 outside DB_LOCK; burn equivalent time on missing user to resist timing leaks
        if not user_row:
            _derive_server_auth_hash(auth_key, "00" * 16)
            self._send_json(401, {"error": "Invalid username or password"})
            return

        candidate_hash = _derive_server_auth_hash(auth_key, user_row["auth_salt"])
        if not hmac.compare_digest(candidate_hash, user_row["auth_hash"]):
            self._send_json(401, {"error": "Invalid username or password"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                # Re-verify user still exists before issuing session
                fresh = conn.execute("SELECT * FROM users WHERE id = ?", (user_row["id"],)).fetchone()
                if not fresh or not hmac.compare_digest(candidate_hash, fresh["auth_hash"]):
                    self._send_json(401, {"error": "Invalid username or password"})
                    return
                raw_token = self._create_session(conn, fresh["id"])
                cookie_header = self._build_session_cookie(raw_token, max_age=SESSION_TTL_DAYS * 86400)
                user_row = dict(fresh)

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
            new_kdf_iterations = int(body.get("newKdfIterations", DEFAULT_CLIENT_KDF_ITERATIONS))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid KDF iterations"})
            return
        new_wrapped_dek = _validate_encrypted_blob(body.get("newWrappedDek"), allow_empty=False)

        if (
            not current_auth_key
            or len(current_auth_key) > 256
            or len(new_auth_key) < 32
            or len(new_auth_key) > 256
            or len(new_kdf_salt) < 16
            or len(new_kdf_salt) > 128
            or new_wrapped_dek is None
        ):
            self._send_json(400, {"error": "Invalid password update payload"})
            return
        if not (MIN_CLIENT_KDF_ITERATIONS <= new_kdf_iterations <= MAX_CLIENT_KDF_ITERATIONS):
            self._send_json(400, {"error": "KDF iterations out of safe bounds"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                user_row = self._authenticate(conn)
                if not user_row:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                user = dict(user_row)

        # Compute both PBKDF2 hashes outside DB_LOCK to avoid blocking other requests
        candidate_hash = _derive_server_auth_hash(current_auth_key, user["auth_salt"])
        if not hmac.compare_digest(candidate_hash, user["auth_hash"]):
            self._send_json(403, {"error": "Current password is incorrect"})
            return

        new_auth_salt = secrets.token_hex(16)
        new_auth_hash = _derive_server_auth_hash(new_auth_key, new_auth_salt)

        with DB_LOCK:
            with _connect_db() as conn:
                # Guard against concurrent password change or revoked session
                fresh = self._authenticate(conn)
                if not fresh or fresh["id"] != user["id"] or not hmac.compare_digest(candidate_hash, fresh["auth_hash"]):
                    self._send_json(401, {"error": "Session expired or password changed concurrently"})
                    return

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
                updated_user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone())
                cookie_header = self._build_session_cookie(raw_token, max_age=SESSION_TTL_DAYS * 86400)

        self._send_json(
            200,
            {"ok": True, "user": _serialize_user_row(updated_user)},
            extra_headers=[("Set-Cookie", cookie_header)],
        )

    # ------------------------------------------------------------------
    # Zero-Knowledge Emergency Recovery Key & Self-Service Account Delete
    # ------------------------------------------------------------------
    def _handle_set_recovery_key(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        rec_auth_key = str(body.get("recoveryAuthKey") or "").strip()
        rec_kdf_salt = str(body.get("recoveryKdfSalt") or "").strip()
        try:
            rec_kdf_iterations = int(body.get("recoveryKdfIterations", RECOVERY_KDF_ITERATIONS))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid recovery KDF iterations"})
            return
        rec_wrapped_dek = _validate_encrypted_blob(body.get("recoveryWrappedDek"), allow_empty=False)

        if (
            len(rec_auth_key) < 32
            or len(rec_auth_key) > 256
            or len(rec_kdf_salt) < 16
            or len(rec_kdf_salt) > 128
            or rec_wrapped_dek is None
        ):
            self._send_json(400, {"error": "Invalid recovery key payload"})
            return
        if not (MIN_CLIENT_KDF_ITERATIONS <= rec_kdf_iterations <= MAX_CLIENT_KDF_ITERATIONS):
            self._send_json(400, {"error": "Recovery KDF iterations out of safe bounds"})
            return

        # Compute server-side PBKDF2 hash outside DB_LOCK
        rec_auth_salt = secrets.token_hex(16)
        rec_auth_hash = _derive_server_auth_hash(rec_auth_key, rec_auth_salt)
        now_iso = utc_now_iso()

        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                conn.execute(
                    """
                    UPDATE users
                    SET recovery_kdf_salt = ?, recovery_kdf_iterations = ?,
                        recovery_auth_salt = ?, recovery_auth_hash = ?,
                        recovery_wrapped_dek = ?, recovery_created_at = ?
                    WHERE id = ?
                    """,
                    (
                        rec_kdf_salt,
                        rec_kdf_iterations,
                        rec_auth_salt,
                        rec_auth_hash,
                        rec_wrapped_dek,
                        now_iso,
                        user["id"],
                    ),
                )
                updated_user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone())

        self._send_json(200, {"ok": True, "user": _serialize_user_row(updated_user)})

    def _handle_delete_recovery_key(self):
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                conn.execute(
                    """
                    UPDATE users
                    SET recovery_kdf_salt = '', recovery_kdf_iterations = 0,
                        recovery_auth_salt = '', recovery_auth_hash = '',
                        recovery_wrapped_dek = '', recovery_created_at = ''
                    WHERE id = ?
                    """,
                    (user["id"],),
                )
                updated_user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone())

        self._send_json(200, {"ok": True, "user": _serialize_user_row(updated_user)})

    def _handle_recovery_challenge(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment and try again."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        username = str(body.get("username") or "").strip()
        if not username or len(username) > 128:
            self._send_json(400, {"error": "Username is required"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                row = conn.execute(
                    "SELECT recovery_kdf_salt, recovery_kdf_iterations, recovery_wrapped_dek FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()
                if row and row["recovery_wrapped_dek"] and row["recovery_kdf_salt"]:
                    self._send_json(
                        200,
                        {
                            "recoveryKdfSalt": row["recovery_kdf_salt"],
                            "recoveryKdfIterations": int(row["recovery_kdf_iterations"]),
                        },
                    )
                else:
                    # Constant-appearance salt prevents user/recovery-status enumeration
                    self._send_json(
                        200,
                        {
                            "recoveryKdfSalt": _fake_challenge_salt(conn, "recovery:" + username),
                            "recoveryKdfIterations": RECOVERY_KDF_ITERATIONS,
                        },
                    )

    def _handle_recovery_verify(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment and try again."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        username = str(body.get("username") or "").strip()
        rec_auth_key = str(body.get("recoveryAuthKey") or "").strip()
        if not username or len(username) > 128 or not rec_auth_key or len(rec_auth_key) > 256:
            self._send_json(400, {"error": "Username and recovery key are required"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                row = conn.execute(
                    "SELECT recovery_auth_salt, recovery_auth_hash, recovery_wrapped_dek FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()
                user_rec = dict(row) if row else None

        if not user_rec or not user_rec["recovery_auth_hash"] or not user_rec["recovery_wrapped_dek"]:
            _derive_server_auth_hash(rec_auth_key, "00" * 16)
            self._send_json(401, {"error": "Invalid username or recovery key"})
            return

        candidate_hash = _derive_server_auth_hash(rec_auth_key, user_rec["recovery_auth_salt"])
        if not hmac.compare_digest(candidate_hash, user_rec["recovery_auth_hash"]):
            self._send_json(401, {"error": "Invalid username or recovery key"})
            return

        self._send_json(200, {"ok": True, "recoveryWrappedDek": user_rec["recovery_wrapped_dek"]})

    def _handle_recover_password(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment and try again."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return

        username = str(body.get("username") or "").strip()
        rec_auth_key = str(body.get("recoveryAuthKey") or "").strip()
        new_auth_key = str(body.get("newAuthKey") or "").strip()
        new_kdf_salt = str(body.get("newKdfSalt") or "").strip()
        try:
            new_kdf_iterations = int(body.get("newKdfIterations", DEFAULT_CLIENT_KDF_ITERATIONS))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid KDF iterations"})
            return
        new_wrapped_dek = _validate_encrypted_blob(body.get("newWrappedDek"), allow_empty=False)

        if (
            not username
            or len(username) > 128
            or not rec_auth_key
            or len(rec_auth_key) > 256
            or len(new_auth_key) < 32
            or len(new_auth_key) > 256
            or len(new_kdf_salt) < 16
            or len(new_kdf_salt) > 128
            or new_wrapped_dek is None
        ):
            self._send_json(400, {"error": "Invalid recovery payload"})
            return
        if not (MIN_CLIENT_KDF_ITERATIONS <= new_kdf_iterations <= MAX_CLIENT_KDF_ITERATIONS):
            self._send_json(400, {"error": "KDF iterations out of safe bounds"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                row = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone()
                user = dict(row) if row else None

        if not user or not user["recovery_auth_hash"] or not user["recovery_wrapped_dek"]:
            _derive_server_auth_hash(rec_auth_key, "00" * 16)
            self._send_json(401, {"error": "Invalid username or recovery key"})
            return

        candidate_hash = _derive_server_auth_hash(rec_auth_key, user["recovery_auth_salt"])
        if not hmac.compare_digest(candidate_hash, user["recovery_auth_hash"]):
            self._send_json(401, {"error": "Invalid username or recovery key"})
            return

        new_auth_salt = secrets.token_hex(16)
        new_auth_hash = _derive_server_auth_hash(new_auth_key, new_auth_salt)

        with DB_LOCK:
            with _connect_db() as conn:
                fresh = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
                if not fresh or not hmac.compare_digest(candidate_hash, fresh["recovery_auth_hash"]):
                    self._send_json(401, {"error": "Recovery key changed concurrently"})
                    return
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
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
                raw_token = self._create_session(conn, user["id"])
                updated_user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone())
                cookie_header = self._build_session_cookie(raw_token, max_age=SESSION_TTL_DAYS * 86400)

        self._send_json(
            200,
            {
                "ok": True,
                "user": _serialize_user_row(updated_user),
                "vaultMeta": updated_user["vault_meta"],
                "vaultMetaUpdatedAt": updated_user["vault_meta_updated_at"],
            },
            extra_headers=[("Set-Cookie", cookie_header)],
        )

    def _handle_delete_own_account(self):
        if not _check_rate_limit(self._client_ip()):
            self._send_json(429, {"error": "Too many attempts. Please wait a moment."})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        current_auth_key = str(body.get("currentAuthKey") or "").strip()
        if not current_auth_key or len(current_auth_key) > 256:
            self._send_json(400, {"error": "Current password confirmation is required"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                row = self._authenticate(conn)
                if not row:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                user = dict(row)

        candidate_hash = _derive_server_auth_hash(current_auth_key, user["auth_salt"])
        if not hmac.compare_digest(candidate_hash, user["auth_hash"]):
            self._send_json(403, {"error": "Current password is incorrect"})
            return

        with DB_LOCK:
            with _connect_db() as conn:
                fresh = self._authenticate(conn)
                if not fresh or fresh["id"] != user["id"]:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                if fresh["is_admin"]:
                    admin_count = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1").fetchone()["cnt"]
                    if admin_count <= 1:
                        self._send_json(
                            400,
                            {
                                "error": "You are the only admin on this server. Promote another admin first or manage accounts from the server CLI."
                            },
                        )
                        return
                conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))

        clear_cookie = self._build_session_cookie("", max_age=0)
        self._send_json(200, {"ok": True}, extra_headers=[("Set-Cookie", clear_cookie)])

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
                    "SELECT id FROM entries WHERE id = ? AND user_id = ?",
                    (entry_id, user["id"]),
                ).fetchone()
                if existing:
                    self._send_json(409, {"error": "Entry with this id already exists"})
                    return
                now_iso = utc_now_iso()
                try:
                    conn.execute(
                        "INSERT INTO entries (id, user_id, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (entry_id, user["id"], ciphertext, now_iso, now_iso),
                    )
                except sqlite3.IntegrityError:
                    self._send_json(409, {"error": "Entry with this id already exists"})
                    return

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

    def _handle_batch_import_entries(self):
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        items = body.get("entries")
        if not isinstance(items, list) or len(items) == 0:
            self._send_json(400, {"error": "entries must be a non-empty array"})
            return
        if len(items) > MAX_BATCH_IMPORT_ENTRIES:
            self._send_json(400, {"error": f"Batch size exceeds maximum of {MAX_BATCH_IMPORT_ENTRIES} entries"})
            return

        validated = []
        seen_ids = set()
        for item in items:
            if not isinstance(item, dict):
                self._send_json(400, {"error": "Each entry must be an object"})
                return
            eid = str(item.get("id") or "").strip() or str(uuid.uuid4())
            if not UUID_RE.match(eid):
                self._send_json(400, {"error": "Invalid entry id in import batch"})
                return
            ct = _validate_encrypted_blob(item.get("ciphertext"), allow_empty=False)
            if ct is None:
                self._send_json(400, {"error": "Invalid encrypted entry payload in import batch"})
                return
            if eid in seen_ids:
                continue
            seen_ids.add(eid)
            validated.append((eid, ct))

        imported = []
        skipped_count = 0
        now_iso = utc_now_iso()

        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                for eid, ct in validated:
                    existing = conn.execute(
                        "SELECT id FROM entries WHERE id = ? AND user_id = ?",
                        (eid, user["id"]),
                    ).fetchone()
                    if existing:
                        skipped_count += 1
                        continue
                    conn.execute(
                        "INSERT INTO entries (id, user_id, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (eid, user["id"], ct, now_iso, now_iso),
                    )
                    imported.append(
                        {
                            "id": eid,
                            "ciphertext": ct,
                            "createdAt": now_iso,
                            "updatedAt": now_iso,
                        }
                    )

        self._send_json(
            201,
            {
                "ok": True,
                "imported": imported,
                "importedCount": len(imported),
                "skippedCount": skipped_count,
            },
        )

    # ------------------------------------------------------------------
    # Admin Handlers (Zero Access to User Data)
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

    def _handle_admin_update_user_role(self, target_id):
        if not UUID_RE.match(target_id):
            self._send_json(400, {"error": "Invalid user id"})
            return
        body, err = self._read_json_body()
        if err:
            self._send_json(400, {"error": err})
            return
        is_admin = body.get("isAdmin")
        if not isinstance(is_admin, bool):
            self._send_json(400, {"error": "isAdmin must be a boolean"})
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
                target = conn.execute("SELECT id, is_admin FROM users WHERE id = ?", (target_id,)).fetchone()
                if not target:
                    self._send_json(404, {"error": "Account not found"})
                    return
                if target["is_admin"] and not is_admin:
                    admin_count = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1").fetchone()["cnt"]
                    if admin_count <= 1:
                        self._send_json(400, {"error": "Cannot remove admin role from the only admin."})
                        return
                conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if is_admin else 0, target_id))

        self._send_json(200, {"ok": True, "userId": target_id, "isAdmin": is_admin})

    def _handle_admin_download_backup(self, filename):
        with DB_LOCK:
            with _connect_db() as conn:
                user = self._authenticate(conn)
                if not user:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                if not user["is_admin"]:
                    self._send_json(403, {"error": "Admin privileges required"})
                    return

        if not BACKUP_FILE_RE.match(filename):
            self._send_json(400, {"error": "Invalid backup filename"})
            return
        real_dir = os.path.realpath(BACKUP_DIR)
        target_path = os.path.realpath(os.path.join(BACKUP_DIR, filename))
        if not target_path.startswith(real_dir + os.sep) or not os.path.isfile(target_path):
            self._send_json(404, {"error": "Backup file not found"})
            return

        with open(target_path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(size))
            self.end_headers()
            shutil.copyfileobj(fh, self.wfile)


def cli_list_users():
    init_db()
    with DB_LOCK:
        with _connect_db() as conn:
            rows = conn.execute(
                """
                SELECT u.display_username, u.is_admin, u.created_at,
                       CASE WHEN u.recovery_wrapped_dek != '' THEN 1 ELSE 0 END AS has_recovery,
                       COUNT(e.id) AS entry_count
                FROM users u
                LEFT JOIN entries e ON e.user_id = u.id
                GROUP BY u.id
                ORDER BY u.created_at ASC
                """
            ).fetchall()
    if not rows:
        print("No registered users.")
        return 0
    for r in rows:
        role = "admin" if r["is_admin"] else "user"
        rec = "recovery-key" if r["has_recovery"] else "no-recovery-key"
        print(f"{r['display_username']}\trole={role}\tentries={r['entry_count']}\t{rec}\tjoined={r['created_at']}")
    return 0


def cli_promote_admin(username):
    init_db()
    with DB_LOCK:
        with _connect_db() as conn:
            row = conn.execute(
                "SELECT id, display_username, is_admin FROM users WHERE username = ?",
                (username.strip().lower(),),
            ).fetchone()
            if not row:
                sys.stderr.write(f"Error: user '{username}' not found.\n")
                return 1
            conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (row["id"],))
            print(f"Promoted '{row['display_username']}' to admin.")
    return 0


def cli_delete_user(username):
    init_db()
    with DB_LOCK:
        with _connect_db() as conn:
            row = conn.execute(
                "SELECT id, display_username FROM users WHERE username = ?",
                (username.strip().lower(),),
            ).fetchone()
            if not row:
                sys.stderr.write(f"Error: user '{username}' not found.\n")
                return 1
            conn.execute("DELETE FROM users WHERE id = ?", (row["id"],))
            print(f"Deleted user '{row['display_username']}' and all associated encrypted entries.")
    return 0


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
    httpd.daemon_threads = True

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


def main():
    parser = argparse.ArgumentParser(description="HeyJournal zero-knowledge encrypted journal server")
    parser.add_argument("--list-users", action="store_true", help="List registered accounts (no plaintext access)")
    parser.add_argument("--promote-admin", metavar="USERNAME", help="Grant admin privileges to an existing account")
    parser.add_argument("--delete-user", metavar="USERNAME", help="Permanently delete an account and its entries")
    args = parser.parse_args()

    if args.list_users:
        sys.exit(cli_list_users())
    if args.promote_admin:
        sys.exit(cli_promote_admin(args.promote_admin))
    if args.delete_user:
        sys.exit(cli_delete_user(args.delete_user))
    run_server()


if __name__ == "__main__":
    main()
