"""
HeyJournal — Backend Server, Zero-Knowledge Auth, Multi-User Isolation & Admin Test Suite
Zero external dependencies (Python standard library unittest).
"""
import base64
import io
import json
import os
import tempfile
import unittest

import server


class MockHandler(server.JournalRequestHandler):
    """In-memory socket-free mock of JournalRequestHandler."""

    def __init__(self, raw_request_bytes):
        self.directory = server.PUBLIC_DIR
        self.rfile = io.BytesIO(raw_request_bytes)
        self.wfile = io.BytesIO()
        self.client_address = ("127.0.0.1", 54321)
        self.server = None
        self.close_connection = True
        self.handle_one_request()


def execute_request(method, path, headers=None, body=b"", cookie=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    elif isinstance(body, dict):
        body = json.dumps(body).encode("utf-8")

    req_headers = {"Host": "localhost:8080"}
    if headers:
        req_headers.update(headers)
    if cookie:
        req_headers["Cookie"] = cookie
    if body and "Content-Length" not in req_headers:
        req_headers["Content-Length"] = str(len(body))
    if body and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"

    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in req_headers.items():
        lines.append(f"{k}: {v}")
    raw_req = "\r\n".join(lines).encode("utf-8") + b"\r\n\r\n" + body

    handler = MockHandler(raw_req)
    raw_resp = handler.wfile.getvalue()
    header_part, _, resp_body = raw_resp.partition(b"\r\n\r\n")
    hdr_lines = header_part.split(b"\r\n")
    status_line = hdr_lines[0].decode("latin1") if hdr_lines else ""
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 500

    resp_headers = {}
    set_cookies = []
    for line in hdr_lines[1:]:
        if b":" in line:
            hk, hv = line.split(b":", 1)
            key = hk.decode("latin1").strip().lower()
            val = hv.decode("latin1").strip()
            if key == "set-cookie":
                set_cookies.append(val)
            resp_headers[key] = val

    parsed = None
    if resp_body:
        try:
            parsed = json.loads(resp_body.decode("utf-8"))
        except Exception:
            parsed = None

    return status_code, resp_headers, set_cookies, resp_body, parsed


def extract_session_cookie(set_cookies):
    for sc in set_cookies:
        part = sc.split(";", 1)[0].strip()
        if part.startswith(f"{server.SESSION_COOKIE_NAME}="):
            return part
    return None


def make_fake_blob(tag="test"):
    return json.dumps(
        {
            "v": 1,
            "alg": "A256GCM",
            "iv": base64.b64encode(b"123456789012").decode("ascii"),
            "ct": base64.b64encode(f"ciphertext-{tag}".encode("utf-8")).decode("ascii"),
        }
    )


def register_user(username, auth_key_seed="A"):
    auth_key = base64.b64encode((auth_key_seed * 32).encode("utf-8")).decode("ascii")
    kdf_salt = base64.b64encode(b"0123456789abcdef").decode("ascii")
    return execute_request(
        "POST",
        "/api/auth/register",
        body={
            "username": username,
            "authKey": auth_key,
            "kdfSalt": kdf_salt,
            "kdfIterations": 150000,
            "wrappedDek": make_fake_blob("dek-" + username),
            "vaultMeta": make_fake_blob("meta-" + username),
        },
    ), auth_key


class BaseServerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.orig_db = server.DB_PATH
        self.orig_backup = server.BACKUP_DIR
        self.orig_rate = server.RATE_LIMIT_MAX_ATTEMPTS
        server.DB_PATH = os.path.join(self.temp_dir.name, "journal.db")
        server.BACKUP_DIR = os.path.join(self.temp_dir.name, "backups")
        server.RATE_LIMIT_MAX_ATTEMPTS = 1000
        with server.RATE_LOCK:
            server.RATE_BUCKETS.clear()
        server.init_db()

    def tearDown(self):
        server.DB_PATH = self.orig_db
        server.BACKUP_DIR = self.orig_backup
        server.RATE_LIMIT_MAX_ATTEMPTS = self.orig_rate
        self.temp_dir.cleanup()


class TestDiscoveryAndSecurityHeaders(BaseServerTestCase):
    def test_health_and_security_headers(self):
        status, hdrs, _, _, data = execute_request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
        self.assertEqual(hdrs.get("x-frame-options"), "DENY")
        self.assertIn("script-src 'self'", hdrs.get("content-security-policy", ""))
        self.assertNotIn("unsafe-inline", hdrs.get("content-security-policy", "").split("script-src")[1].split(";")[0])
        self.assertIn("no-store", hdrs.get("cache-control", ""))

    def test_discovers_all_20_themes_and_13_quizzes(self):
        st_t, _, _, _, data_t = execute_request("GET", "/api/themes")
        self.assertEqual(st_t, 200)
        theme_ids = {t["id"] for t in data_t["themes"]}
        self.assertGreaterEqual(len(theme_ids), 20)
        self.assertIn("metro", theme_ids)
        self.assertIn("lcars", theme_ids)
        self.assertIn("eink", theme_ids)

        st_q, _, _, _, data_q = execute_request("GET", "/api/quizzes")
        self.assertEqual(st_q, 200)
        quiz_ids = {q["id"] for q in data_q["quizzes"]}
        self.assertGreaterEqual(len(quiz_ids), 13)
        for required in ("phq-9", "gad-7", "oci-r", "whodas-2-12", "pss-10", "dass-21", "who-5", "isi", "ess", "pcl-5", "asrs-v1-1", "audit", "mdq"):
            self.assertIn(required, quiz_ids)

    def test_csrf_cross_origin_blocked(self):
        status, _, _, _, data = execute_request(
            "POST",
            "/api/auth/logout",
            headers={"Origin": "https://evil.example.com"},
        )
        self.assertEqual(status, 403)
        self.assertIn("Cross-origin", data["error"])


class TestAuthVaultAndMultiUserIsolation(BaseServerTestCase):
    def test_first_user_is_admin_and_second_user_is_standard(self):
        (st1, _, sc1, _, d1), _ = register_user("josh", "J")
        self.assertEqual(st1, 201)
        self.assertTrue(d1["user"]["isAdmin"])
        self.assertIsNotNone(extract_session_cookie(sc1))

        (st2, _, sc2, _, d2), _ = register_user("alex", "A")
        self.assertEqual(st2, 201)
        self.assertFalse(d2["user"]["isAdmin"])
        self.assertIsNotNone(extract_session_cookie(sc2))

    def test_challenge_does_not_leak_nonexistent_users(self):
        register_user("josh", "J")
        st_real, _, _, _, d_real = execute_request("POST", "/api/auth/challenge", body={"username": "josh"})
        st_fake1, _, _, _, d_fake1 = execute_request("POST", "/api/auth/challenge", body={"username": "nobody_here"})
        st_fake2, _, _, _, d_fake2 = execute_request("POST", "/api/auth/challenge", body={"username": "nobody_here"})
        self.assertEqual(st_real, 200)
        self.assertEqual(st_fake1, 200)
        self.assertEqual(d_fake1["kdfSalt"], d_fake2["kdfSalt"])
        self.assertEqual(d_fake1["kdfIterations"], 150000)

    def test_encrypted_entry_crud_optimistic_concurrency_and_isolation(self):
        (_, _, sc1, _, _), _ = register_user("alice", "A")
        (_, _, sc2, _, _), _ = register_user("bob", "B")
        cookie_alice = extract_session_cookie(sc1)
        cookie_bob = extract_session_cookie(sc2)

        # Reject unencrypted / malformed ciphertext
        st_bad, _, _, _, _ = execute_request(
            "POST", "/api/entries", cookie=cookie_alice, body={"ciphertext": "plaintext secret!"}
        )
        self.assertEqual(st_bad, 400)

        # Create valid encrypted entry as Alice
        st_c, _, _, _, d_c = execute_request(
            "POST",
            "/api/entries",
            cookie=cookie_alice,
            body={"id": "entry-11111111", "ciphertext": make_fake_blob("entry1")},
        )
        self.assertEqual(st_c, 201)
        ts1 = d_c["entry"]["updatedAt"]

        # Bob cannot read, update, or delete Alice's entry
        st_vb, _, _, _, d_vb = execute_request("GET", "/api/vault", cookie=cookie_bob)
        self.assertEqual(st_vb, 200)
        self.assertEqual(len(d_vb["entries"]), 0)

        st_ub, _, _, _, _ = execute_request(
            "PUT",
            "/api/entries/entry-11111111",
            cookie=cookie_bob,
            body={"ciphertext": make_fake_blob("tamper")},
        )
        self.assertEqual(st_ub, 404)

        st_db, _, _, _, _ = execute_request("DELETE", "/api/entries/entry-11111111", cookie=cookie_bob)
        self.assertEqual(st_db, 404)

        # Alice updates entry cleanly, then stale expectedUpdatedAt returns 409
        st_u1, _, _, _, d_u1 = execute_request(
            "PUT",
            "/api/entries/entry-11111111",
            cookie=cookie_alice,
            body={"ciphertext": make_fake_blob("entry1-v2"), "expectedUpdatedAt": ts1},
        )
        self.assertEqual(st_u1, 200)
        self.assertNotEqual(d_u1["entry"]["updatedAt"], ts1)

        st_conflict, _, _, _, _ = execute_request(
            "PUT",
            "/api/entries/entry-11111111",
            cookie=cookie_alice,
            body={"ciphertext": make_fake_blob("entry1-stale"), "expectedUpdatedAt": ts1},
        )
        self.assertEqual(st_conflict, 409)

        # Delete works for Alice
        st_del, _, _, _, _ = execute_request("DELETE", "/api/entries/entry-11111111", cookie=cookie_alice)
        self.assertEqual(st_del, 200)

    def test_password_change_rotates_session_and_rejects_old_auth_key(self):
        (_, _, sc1, _, _), old_auth_key = register_user("josh", "O")
        old_cookie = extract_session_cookie(sc1)
        new_auth_key = base64.b64encode((b"N" * 32)).decode("ascii")
        new_salt = base64.b64encode(b"fedcba9876543210").decode("ascii")

        st_cp, _, sc_new, _, _ = execute_request(
            "POST",
            "/api/auth/change-password",
            cookie=old_cookie,
            body={
                "currentAuthKey": old_auth_key,
                "newAuthKey": new_auth_key,
                "newKdfSalt": new_salt,
                "newKdfIterations": 150000,
                "newWrappedDek": make_fake_blob("rewrapped-dek"),
            },
        )
        self.assertEqual(st_cp, 200)
        new_cookie = extract_session_cookie(sc_new)
        self.assertIsNotNone(new_cookie)
        self.assertNotEqual(old_cookie, new_cookie)

        # Old session cookie is revoked
        st_old_sess, _, _, _, _ = execute_request("GET", "/api/vault", cookie=old_cookie)
        self.assertEqual(st_old_sess, 401)

        # Old authKey cannot log in; new authKey succeeds
        st_old_login, _, _, _, _ = execute_request(
            "POST", "/api/auth/login", body={"username": "josh", "authKey": old_auth_key}
        )
        self.assertEqual(st_old_login, 401)

        st_new_login, _, _, _, _ = execute_request(
            "POST", "/api/auth/login", body={"username": "josh", "authKey": new_auth_key}
        )
        self.assertEqual(st_new_login, 200)


class TestAdminAccountManagementAndBackups(BaseServerTestCase):
    def test_admin_can_list_and_delete_other_users_without_seeing_data(self):
        (_, _, sc_admin, _, d_admin), _ = register_user("adminuser", "A")
        (_, _, sc_member, _, d_member), _ = register_user("memberuser", "M")
        cookie_admin = extract_session_cookie(sc_admin)
        cookie_member = extract_session_cookie(sc_member)

        # Member creates an encrypted entry
        execute_request(
            "POST",
            "/api/entries",
            cookie=cookie_member,
            body={"id": "member-entry-1", "ciphertext": make_fake_blob("private")},
        )

        # Member cannot call admin API
        st_forbid, _, _, _, _ = execute_request("GET", "/api/admin/users", cookie=cookie_member)
        self.assertEqual(st_forbid, 403)

        # Admin sees user list & entry count, NEVER ciphertext/vaultMeta/wrappedDek
        st_list, _, _, _, d_list = execute_request("GET", "/api/admin/users", cookie=cookie_admin)
        self.assertEqual(st_list, 200)
        self.assertEqual(len(d_list["users"]), 2)
        for u in d_list["users"]:
            self.assertNotIn("ciphertext", u)
            self.assertNotIn("vaultMeta", u)
            self.assertNotIn("wrappedDek", u)
        member_summary = [u for u in d_list["users"] if u["username"] == "memberuser"][0]
        self.assertEqual(member_summary["entryCount"], 1)

        # Admin cannot delete self
        st_self_del, _, _, _, _ = execute_request(
            "DELETE", f"/api/admin/users/{d_admin['user']['id']}", cookie=cookie_admin
        )
        self.assertEqual(st_self_del, 400)

        # Admin deletes member; entries cascade-deleted
        st_del, _, _, _, _ = execute_request(
            "DELETE", f"/api/admin/users/{d_member['user']['id']}", cookie=cookie_admin
        )
        self.assertEqual(st_del, 200)

        # Member session is invalidated
        st_after, _, _, _, _ = execute_request("GET", "/api/vault", cookie=cookie_member)
        self.assertEqual(st_after, 401)

        # Admin disables signups -> new registration blocked with 403
        st_set, _, _, _, _ = execute_request(
            "PUT", "/api/admin/settings", cookie=cookie_admin, body={"allowSignups": False}
        )
        self.assertEqual(st_set, 200)
        (st_blocked, _, _, _, _), _ = register_user("newperson", "X")
        self.assertEqual(st_blocked, 403)

        # Admin triggers online encrypted SQLite backup
        st_bk, _, _, _, d_bk = execute_request("POST", "/api/admin/backup", cookie=cookie_admin)
        self.assertEqual(st_bk, 200)
        self.assertTrue(os.path.isfile(os.path.join(server.BACKUP_DIR, d_bk["backupName"])))

    def test_all_20_theme_stylesheets_serve_200_and_db_contains_no_plaintext(self):
        # Verify every discovered theme's stylesheet is actually servable via HTTP
        st_t, _, _, _, data_t = execute_request("GET", "/api/themes")
        self.assertEqual(st_t, 200)
        for theme in data_t["themes"]:
            st_css, hdrs, _, body, _ = execute_request("GET", theme["stylesheetUrl"])
            self.assertEqual(st_css, 200, f"Theme stylesheet failed to serve: {theme['stylesheetUrl']}")
            self.assertGreater(len(body), 50)

        # Verify zero-knowledge property on raw SQLite bytes
        (_, _, sc, _, _), _ = register_user("privacycheck", "P")
        cookie = extract_session_cookie(sc)
        secret_blob = make_fake_blob("opaque-only")
        execute_request(
            "POST",
            "/api/entries",
            cookie=cookie,
            body={"id": "entry-zk-check", "ciphertext": secret_blob},
        )
        with open(server.DB_PATH, "rb") as fh:
            raw_db = fh.read()
        self.assertNotIn(b"P" * 32, raw_db, "Raw client authKey must never be stored in SQLite")
        self.assertIn(b"A256GCM", raw_db)


if __name__ == "__main__":
    unittest.main()
