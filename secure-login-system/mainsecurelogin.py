# secure_login_system.py
# CLI login app + OIDC dev provider (RS256 + JWKS + rotation) + SCIM 2.0 (Users & Groups)

import os, json, time, uuid, base64, struct, hashlib, hmac, logging, threading, pathlib, sqlite3
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timedelta, UTC

import bcrypt, jwt, pyotp, msvcrt, requests
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from typing import List, Dict  # add if not already present
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from typing import cast

# ========================= Helpers / Env / Logging =========================

_BASE32_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")

def normalize_base32(secret: str) -> str:
    if secret is None: raise ValueError("Empty TOTP secret")
    s = ''.join(str(secret).split()).upper()
    s += "=" * ((8 - (len(s) % 8)) % 8)
    if any(ch not in _BASE32_OK for ch in s): raise ValueError("TOTP secret contains invalid characters")
    return s

def now_utc() -> datetime: return datetime.now(UTC)

LOG_PATH = "security_log.jsonl"
_audit_logger = logging.getLogger("audit")
_audit_logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_handler)

def _ship_splunk_async(rec: dict):
    if SPLUNK_ENABLE and SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN:
        threading.Thread(target=_post_splunk, args=(rec,), daemon=True).start()

def audit(event: str, user: Optional[str] = None, outcome: Optional[str] = None, **extra):
    rec = {"ts": now_utc().isoformat(), "event": event, "user": user, "outcome": outcome,
           "app": "secure-login-system", "corr_id": extra.pop("corr_id", str(uuid.uuid4())), **extra}
    _audit_logger.info(json.dumps(rec, ensure_ascii=False))
    _ship_splunk_async(rec)

load_dotenv()
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
SPLUNK_ENABLE = os.getenv("SPLUNK_ENABLE", "false").lower() in {"1", "true", "yes", "on"}
SPLUNK_VERIFY_TLS = os.getenv("SPLUNK_VERIFY_TLS", "true").lower() in {"1", "true", "yes", "on"}

def _post_splunk(payload: dict):
    try:
        if not (SPLUNK_ENABLE and SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN): return
        requests.post(SPLUNK_HEC_URL,
                      headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
                      data=json.dumps({"event": payload}, ensure_ascii=False),
                      timeout=4.0, verify=SPLUNK_VERIFY_TLS)
    except Exception:
        pass

CLIENT_IP = os.getenv("CLIENT_IP", "UNKNOWN")
CLIENT_COUNTRY = os.getenv("CLIENT_COUNTRY", "UNKNOWN")

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_SIGNUP_KEY = os.getenv("ADMIN_SIGNUP_KEY")
if not JWT_SECRET:
    raise EnvironmentError("Missing JWT_SECRET in .env")

# =============================== Database ================================

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password BLOB,
    role TEXT DEFAULT 'user',
    failed_attempts INTEGER DEFAULT 0,
    locked INTEGER DEFAULT 0,
    totp_secret TEXT
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT, action TEXT, timestamp TEXT
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS user_prefs (
    username TEXT PRIMARY KEY,
    last_register_choice TEXT CHECK(last_register_choice IN ('user','admin')) NOT NULL DEFAULT 'user'
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
    username TEXT NOT NULL, ts INTEGER NOT NULL
)''')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_user_ts ON rate_limits(username, ts)')

cursor.execute('''CREATE TABLE IF NOT EXISTS mfa_events (
    username TEXT NOT NULL, ts INTEGER NOT NULL,
    kind TEXT CHECK(kind IN ('prompt','fail','success')) NOT NULL
)''')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_mfa_events_user_ts ON mfa_events(username, ts)')

cursor.execute('''CREATE TABLE IF NOT EXISTS failed_login_events (
    username TEXT NOT NULL, ts INTEGER NOT NULL
)''')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_failed_login_events_user_ts ON failed_login_events(username, ts)')

cursor.execute('''CREATE TABLE IF NOT EXISTS user_last_login (
    username TEXT PRIMARY KEY, last_country TEXT, last_ts INTEGER
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS issued_tokens (
    jti TEXT PRIMARY KEY, username TEXT NOT NULL, iat INTEGER NOT NULL,
    exp INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
)''')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_issued_tokens_user ON issued_tokens(username)')

# SCIM groups + membership
cursor.execute('''CREATE TABLE IF NOT EXISTS scim_groups (
    id TEXT PRIMARY KEY, displayName TEXT NOT NULL
)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id TEXT NOT NULL, user_id INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
)''')
conn.commit()

# ====================== Rate Limit / Detections (CLI) =====================

RATE_LIMIT = 5
RATE_WINDOW = 60
MFA_FATIGUE_WINDOW = 600
MFA_FATIGUE_PROMPTS = 5
MFA_FATIGUE_FAILS = 3
BRUTE_FORCE_WINDOW = 600
BRUTE_FORCE_FAILS = 10
IMPOSSIBLE_TRAVEL_MIN_DELTA = 7200

def _now_epoch() -> int: return int(time.time())
def _epoch_now() -> int: return int(time.time())

def _prune_old_attempts(username: str):
    cutoff = _now_epoch() - RATE_WINDOW
    cursor.execute("DELETE FROM rate_limits WHERE username=? AND ts < ?", (username, cutoff)); conn.commit()

def _count_recent_attempts(username: str) -> int:
    cutoff = _now_epoch() - RATE_WINDOW
    cursor.execute("SELECT COUNT(*) FROM rate_limits WHERE username=? AND ts >= ?", (username, cutoff))
    r = cursor.fetchone(); return int(r[0] if r and r[0] else 0)

def _earliest_attempt_ts(username: str) -> Optional[int]:
    cutoff = _now_epoch() - RATE_WINDOW
    cursor.execute("SELECT MIN(ts) FROM rate_limits WHERE username=? AND ts >= ?", (username, cutoff))
    r = cursor.fetchone(); return int(r[0]) if r and r[0] else None

def record_attempt(username: str):
    cursor.execute("INSERT INTO rate_limits (username, ts) VALUES (?, ?)", (username, _now_epoch())); conn.commit()

def clear_attempts(username: str):
    cursor.execute("DELETE FROM rate_limits WHERE username=?", (username,)); conn.commit()

def too_many_attempts(username: str) -> tuple[bool, int]:
    _prune_old_attempts(username)
    if (c := _count_recent_attempts(username)) >= RATE_LIMIT:
        first_ts = _earliest_attempt_ts(username)
        if first_ts is None: return True, RATE_WINDOW
        return True, max(1, (first_ts + RATE_WINDOW) - _now_epoch())
    return False, 0

def _window_count(table: str, username: str, window_s: int) -> int:
    cutoff = _epoch_now() - window_s
    cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE username=? AND ts>=?", (username, cutoff))
    r = cursor.fetchone(); return int(r[0] if r and r[0] else 0)

def record_mfa_event(username: str, kind: str):
    cursor.execute("INSERT INTO mfa_events(username, ts, kind) VALUES (?, ?, ?)", (username, _epoch_now(), kind)); conn.commit()

def record_failed_login(username: str):
    cursor.execute("INSERT INTO failed_login_events(username, ts) VALUES (?, ?)", (username, _epoch_now())); conn.commit()

def set_last_login(username: str, country: str):
    cursor.execute("""INSERT INTO user_last_login(username, last_country, last_ts)
                      VALUES (?, ?, ?)
                      ON CONFLICT(username) DO UPDATE SET last_country=excluded.last_country, last_ts=excluded.last_ts""",
                   (username, country, _epoch_now())); conn.commit()

def get_last_login(username: str) -> tuple[str, Optional[int]]:
    cursor.execute("SELECT last_country, last_ts FROM user_last_login WHERE username=?", (username,))
    r = cursor.fetchone()
    return (r[0] or "UNKNOWN", int(r[1]) if r and r[1] is not None else None) if r else ("UNKNOWN", None)

def check_mfa_fatigue(username: str):
    prompts = _window_count("mfa_events", username, MFA_FATIGUE_WINDOW)
    cutoff = _epoch_now() - MFA_FATIGUE_WINDOW
    cursor.execute("SELECT COUNT(*) FROM mfa_events WHERE username=? AND ts>=? AND kind='fail'", (username, cutoff))
    fails = int(cursor.fetchone()[0])
    if prompts >= MFA_FATIGUE_PROMPTS and fails >= MFA_FATIGUE_FAILS:
        audit("detect_mfa_fatigue", user=username, outcome="suspect", prompts=prompts, fails=fails, window_s=MFA_FATIGUE_WINDOW)

def check_brute_force(username: str, locked_now: bool = False):
    if locked_now or _window_count("failed_login_events", username, BRUTE_FORCE_WINDOW) >= BRUTE_FORCE_FAILS:
        audit("detect_bruteforce", user=username, outcome="suspect", locked=locked_now)

def check_impossible_travel(username: str, new_country: str):
    prev_country, prev_ts = get_last_login(username)
    if prev_country == "UNKNOWN" or new_country == "UNKNOWN" or prev_ts is None: return
    if new_country != prev_country and (_epoch_now() - prev_ts) < IMPOSSIBLE_TRAVEL_MIN_DELTA:
        audit("detect_impossible_travel", user=username, outcome="suspect",
              from_country=prev_country, to_country=new_country, delta_s=_epoch_now()-prev_ts,
              threshold_s=IMPOSSIBLE_TRAVEL_MIN_DELTA)

def flag_privilege_escalation(actor: str, target: str):
    audit("detect_priv_escalation", user=target, outcome="suspect", actor=actor)

# ========================== CLI Token Helpers (HS256) ==========================

def store_token_record(jti: str, username: str, iat: int, exp: int):
    cursor.execute("INSERT OR REPLACE INTO issued_tokens (jti, username, iat, exp, revoked) VALUES (?, ?, ?, ?, 0)",
                   (jti, username, iat, exp)); conn.commit()

def revoke_token_by_jti(jti: str, acting_admin: Optional[str] = None):
    cursor.execute("UPDATE issued_tokens SET revoked=1 WHERE jti=?", (jti,)); conn.commit()
    if cursor.rowcount: print(f"Revoked token {jti}"); audit("revoke_token", outcome="success", jti=jti, actor=acting_admin)
    else: print("No matching token."); audit("revoke_token", outcome="fail", reason="no_match", jti=jti, actor=acting_admin)

def revoke_tokens_for_user(username: str, acting_admin: Optional[str] = None):
    cursor.execute("UPDATE issued_tokens SET revoked=1 WHERE username=? AND revoked=0", (username,)); conn.commit()
    print(f"Revoked {cursor.rowcount or 0} token(s) for {username}")
    audit("revoke_tokens", user=username, outcome="success", count=cursor.rowcount or 0, actor=acting_admin)

def list_tokens_for_user(username: str):
    cursor.execute("SELECT jti, iat, exp, revoked FROM issued_tokens WHERE username=? ORDER BY exp DESC", (username,))
    rows = cursor.fetchall()
    if not rows: print("No tokens for user."); return
    for jti, iat, exp, revoked in rows: print(f"JTI={jti} issued={iat} exp={exp} revoked={revoked}")

def issue_jwt(username: str, role: Optional[str]) -> Tuple[str, str]:
    """
    CLI tokens: HS256 using JWT_SECRET (separate from OIDC RS256 tokens).
    """
    # Runtime guard (in case .env is missing or not loaded yet)
    if not JWT_SECRET:
        raise EnvironmentError("Missing JWT_SECRET in .env (needed for HS256 CLI tokens)")

    iat_epoch = int(now_utc().timestamp())
    exp_epoch = iat_epoch + 30 * 60  # 30 minutes
    jti = str(uuid.uuid4())

    payload = {
        "sub": username,
        "role": (role or "user"),
        "iat": iat_epoch,
        "exp": exp_epoch,
        "jti": jti,
    }

    # cast() tells the type checker this is definitely a str
    token = jwt.encode(payload, cast(str, JWT_SECRET), algorithm="HS256")

    # track for revocation / audit
    store_token_record(jti, username, iat_epoch, exp_epoch)
    audit("token_issued", user=username, outcome="success", jti=jti, exp=exp_epoch)

    return token, jti

# ================================ Prefs & Helpers ================================

def get_last_register_choice(email: Optional[str]) -> str:
    cursor.execute("SELECT last_register_choice FROM user_prefs WHERE username=?", ((email or "").strip(),))
    r = cursor.fetchone(); return r[0] if r and r[0] else "user"

def set_last_register_choice(email: Optional[str], choice: str):
    email = (email or "").strip()
    if not email or choice not in ("user", "admin"): return
    cursor.execute("""INSERT INTO user_prefs (username, last_register_choice) VALUES (?, ?)
                      ON CONFLICT(username) DO UPDATE SET last_register_choice=excluded.last_register_choice""",
                   (email, choice)); conn.commit()

def has_admin() -> bool:
    cursor.execute("SELECT 1 FROM users WHERE LOWER(role)='admin' LIMIT 1"); return cursor.fetchone() is not None

def input_with_asterisks(prompt: str='Password: ') -> str:
    print(prompt, end='', flush=True); pw = ''
    while True:
        ch = msvcrt.getch()
        if ch in {b'\r', b'\n'}: print(); break
        elif ch == b'\x08' and pw: pw = pw[:-1]; print('\b \b', end='', flush=True)
        elif ch == b'\x03': raise KeyboardInterrupt
        else:
            try: pw += ch.decode('utf-8', errors='ignore'); print('*', end='', flush=True)
            except Exception: pass
    return pw

def hash_password(password: str) -> bytes: return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
def check_password(password: str, hashed: bytes) -> bool: return bcrypt.checkpw(password.encode(), hashed)

def log_action(username: str, action: str):
    cursor.execute("INSERT INTO audit_log (username, action, timestamp) VALUES (?, ?, ?)",
                   ((username or "").strip(), action, now_utc().isoformat())); conn.commit()

def show_totp_instructions(username: str, totp_secret: str, is_admin: bool=False):
    print("\nRegistration successful." + (" (ADMIN)" if is_admin else ""))
    print("Set up Microsoft Authenticator (manual entry):")
    print(" - Account name (email):", username)
    print(" - Issuer: SecureLoginApp")
    print(" - Secret key:", totp_secret)
    print(" - Type: Time-based (TOTP), 6 digits, 30s")
    uri = pyotp.TOTP(totp_secret, digits=6, interval=30).provisioning_uri(name=username, issuer_name="SecureLoginApp")
    print("\notpauth URI:\n", uri)

def _base32_decode(s: str) -> bytes:
    s = ''.join(s.split()).upper(); s += '=' * ((-len(s)) % 8); return base64.b32decode(s, casefold=True)

def rfc6238_totp(secret_b32: str, for_time: int, step: int=30, digits: int=6) -> str:
    key = _base32_decode(secret_b32); counter = int(for_time // step); msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest(); o = h[-1] & 0x0F
    code_int = ((h[o] & 0x7f)<<24) | ((h[o+1] & 0xff)<<16) | ((h[o+2] & 0xff)<<8) | (h[o+3] & 0xff)
    return str(code_int % (10 ** digits)).zfill(digits)

# ============================== Registration / Login (CLI) ==============================

def register(role_choice: str="user", pre_username: Optional[str]=None):
    username = (pre_username or "").strip() or input("Choose a username (email): ").strip()
    password = input_with_asterisks("Choose a password: ")
    if not username or not password: print("Username and password are required."); return

    if role_choice == "admin":
        if not has_admin(): print("[INFO] No admin exists yet; creating the first admin.")
        else:
            if not ADMIN_SIGNUP_KEY: print("Admin creation blocked: ADMIN_SIGNUP_KEY not set in .env"); return
            if input("Enter ADMIN_SIGNUP_KEY: ").strip() != ADMIN_SIGNUP_KEY: print("Incorrect ADMIN_SIGNUP_KEY."); return

    hashed = hash_password(password); totp_secret = pyotp.random_base32()
    try:
        cursor.execute("INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)",
                       (username, hashed, role_choice, totp_secret)); conn.commit()
        set_last_register_choice(username, role_choice); show_totp_instructions(username, totp_secret, is_admin=(role_choice=="admin"))
        log_action(username, f"Registration as {role_choice}"); audit("register", user=username, outcome="success", role=role_choice)
    except sqlite3.IntegrityError:
        print("Username already taken."); audit("register", user=username, outcome="fail", reason="username_taken")

def login():
    username = input("Username: ").strip(); password = input_with_asterisks("Password: ")
    blocked, retry_after = too_many_attempts(username)
    if blocked: print(f"Too many attempts. Try again in ~{retry_after}s."); audit("rate_limit", user=username, outcome="blocked"); return
    record_attempt(username); audit("login_attempt", user=username, outcome="pending", ip=CLIENT_IP, country=CLIENT_COUNTRY)

    cursor.execute("SELECT password, role, failed_attempts, locked, totp_secret FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row: print("Invalid username or password."); audit("login_attempt", user=username, outcome="fail", reason="no_such_user"); record_failed_login(username); check_brute_force(username, False); return

    hashed_password, role, failed_attempts, locked, totp_secret = row
    if locked: print("Account is locked. Contact admin."); audit("lockout", user=username, outcome="blocked"); return
    if not check_password(password, hashed_password):
        failed_attempts = int(failed_attempts or 0) + 1; audit("login_attempt", user=username, outcome="fail", reason="bad_password", failed_attempts=failed_attempts)
        record_failed_login(username)
        if failed_attempts >= 3:
            cursor.execute("UPDATE users SET failed_attempts=?, locked=1 WHERE username=?", (failed_attempts, username)); conn.commit()
            print("Account locked after 3 failed attempts."); log_action(username, "Account locked due to failed logins"); audit("lockout", user=username, outcome="blocked", reason="too_many_failures"); check_brute_force(username, True)
        else:
            cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempts, username)); conn.commit()
            print("Invalid password."); log_action(username, "Failed login"); check_brute_force(username, False)
        return

    cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,)); conn.commit()
    if not totp_secret: print("2FA not set up. Contact admin."); audit("mfa_challenge", user=username, outcome="fail", reason="no_totp_secret"); log_action(username, "Failed 2FA (missing)"); return

    try: norm_secret = normalize_base32(totp_secret)
    except Exception as e: print(f"2FA configuration error: {e}"); audit("mfa_challenge", user=username, outcome="fail", reason="bad_secret"); log_action(username, "Failed 2FA (bad secret)"); return

    seconds_remaining = 30 - (int(time.time()) % 30); print(f"\nThe current 6-digit code will expire in {seconds_remaining} seconds.")
    record_mfa_event(username, "prompt"); check_mfa_fatigue(username)

    entered_code = ''.join(ch for ch in input("Enter the 6-digit code from Microsoft Authenticator: ") if ch.isdigit())
    if len(entered_code) != 6: print("Invalid 2FA code format."); audit("mfa_challenge", user=username, outcome="fail", reason="format"); log_action(username, "Failed 2FA (format)"); record_mfa_event(username, "fail"); check_mfa_fatigue(username); return

    totp = pyotp.TOTP(norm_secret, digits=6, interval=30, digest=hashlib.sha1)
    ok = totp.verify(entered_code, valid_window=1)
    if not ok:
        now = int(time.time()); base = (now // 30) * 30
        for off in (-60, -30, 0, 30, 60):
            if totp.at(base + off) == entered_code: ok = True; break
    if not ok: print("\nInvalid 2FA code."); audit("mfa_challenge", user=username, outcome="fail", reason="invalid_code"); log_action(username, "Failed 2FA"); record_mfa_event(username, "fail"); check_mfa_fatigue(username); return

    clear_attempts(username); record_mfa_event(username, "success"); check_mfa_fatigue(username)
    check_impossible_travel(username, CLIENT_COUNTRY); set_last_login(username, CLIENT_COUNTRY)
    audit("mfa_challenge", user=username, outcome="success"); token, jti = issue_jwt(username, role)
    print(f"\nLogin successful. Token: {token}"); log_action(username, "Successful login")
    audit("login_success", user=username, outcome="success", role=(role or "user"), jti=jti)
    admin_menu(username) if (role or "").strip().lower() == 'admin' else user_menu(username)

# ================================ Menus ================================

def reset_2fa(u: Optional[str], acting_admin: Optional[str]=None):
    u = (u or "").strip()
    if not u: print("Invalid username."); audit("reset_2fa", user=u, outcome="fail", reason="invalid_input", actor=acting_admin); return
    cursor.execute("SELECT username FROM users WHERE username=?", (u,)); row = cursor.fetchone()
    if not row: print("User not found."); audit("reset_2fa", user=u, outcome="fail", reason="user_not_found", actor=acting_admin); return
    new_secret = pyotp.random_base32()
    cursor.execute("UPDATE users SET totp_secret=? WHERE username=?", (new_secret, u)); conn.commit()
    print("\n2FA reset. Re-enroll using secret:", new_secret)
    audit("reset_2fa", user=u, outcome="success", actor=acting_admin)

def lock_user(u: Optional[str], acting_admin: Optional[str]=None, reason: str="manual_lock"):
    u = (u or "").strip()
    if not u: print("Invalid username."); audit("admin_lock", user=u, outcome="fail", reason="invalid_input", actor=acting_admin); return
    cursor.execute("UPDATE users SET locked=1 WHERE username=?", (u,)); conn.commit()
    if cursor.rowcount: print(f"Locked account for {u}"); audit("admin_lock", user=u, outcome="success", actor=acting_admin, reason=reason)
    else: print("No matching user."); audit("admin_lock", user=u, outcome="fail", reason="no_match", actor=acting_admin)

def promote_to_admin(u: Optional[str], acting_admin: Optional[str]=None):
    u = (u or "").strip()
    if not u: print("Invalid username."); audit("promote_to_admin", user=u, outcome="fail", reason="invalid_input", actor=acting_admin); return
    cursor.execute("UPDATE users SET role='admin' WHERE username=?", (u,)); conn.commit()
    print(f"{u} is now an admin."); audit("promote_to_admin", user=u, outcome="success", actor=acting_admin)
    flag_privilege_escalation(acting_admin or u, target=u)

def delete_user(u: Optional[str], acting_admin: Optional[str]=None):
    u = (u or "").strip()
    if not u: print("Invalid username."); audit("delete_user", user=u, outcome="fail", reason="invalid_input", actor=acting_admin); return
    cursor.execute("DELETE FROM users WHERE username=?", (u,)); conn.commit()
    if cursor.rowcount:
        print(f"Deleted {u}"); audit("delete_user", user=u, outcome="success", actor=acting_admin)
        cursor.execute("DELETE FROM issued_tokens WHERE username=?", (u,)); conn.commit()
    else: print("No matching user."); audit("delete_user", user=u, outcome="fail", reason="no_match", actor=acting_admin)

def rename_user(old_email: Optional[str], new_email: Optional[str], acting_admin: Optional[str]=None):
    old_email = (old_email or "").strip(); new_email = (new_email or "").strip()
    if not old_email or not new_email: print("Invalid email(s)."); audit("rename_user", user=old_email, outcome="fail", reason="invalid_input", actor=acting_admin, new_user=new_email); return
    try:
        cursor.execute("UPDATE users SET username=? WHERE username=?", (new_email, old_email)); conn.commit()
        if cursor.rowcount:
            print(f"Renamed {old_email} -> {new_email}"); audit("rename_user", user=old_email, outcome="success", actor=acting_admin, new_user=new_email)
            cursor.execute("UPDATE issued_tokens SET username=? WHERE username=?", (new_email, old_email)); conn.commit()
        else: print("No matching user."); audit("rename_user", user=old_email, outcome="fail", reason="no_match", actor=acting_admin, new_user=new_email)
    except sqlite3.IntegrityError:
        print("That new email is already in use."); audit("rename_user", user=old_email, outcome="fail", reason="email_in_use", actor=acting_admin, new_user=new_email)

def reset_password(u: Optional[str], new_pw: str, acting_admin: Optional[str]=None):
    u = (u or "").strip()
    if not u: print("Invalid username."); audit("reset_password", user=u, outcome="fail", reason="invalid_input", actor=acting_admin); return
    cursor.execute("UPDATE users SET password=? WHERE username=?", (hash_password(new_pw), u)); conn.commit()
    if cursor.rowcount: print(f"Password reset for {u}"); audit("reset_password", user=u, outcome="success", actor=acting_admin)
    else: print("No matching user."); audit("reset_password", user=u, outcome="fail", reason="no_match", actor=acting_admin)

def incident_secure_user(u: Optional[str], acting_admin: Optional[str]=None):
    u = (u or "").strip()
    if not u: print("Invalid username."); audit("incident_secure_user", user=u, outcome="fail", reason="invalid_input", actor=acting_admin); return
    print("\n[Playbook] Securing account...")
    lock_user(u, acting_admin=acting_admin, reason="incident_response")
    reset_2fa(u, acting_admin=acting_admin)
    revoke_tokens_for_user(u, acting_admin=acting_admin)
    audit("incident_secure_user", user=u, outcome="success", actor=acting_admin)

def admin_menu(admin_username: str):
    admin_username = (admin_username or "").strip()
    while True:
        print("\nAdmin Menu")
        print("1. View users\n2. Reset failed attempts\n3. Unlock user\n4. View audit log\n5. Reset user's 2FA\n6. Logout\n7. Promote user to admin\n8. Delete user\n9. Rename user\n10. Reset user password\n11. Lock user\n12. Revoke ALL tokens\n13. Revoke ONE token by JTI\n14. Incident Secure User\n15. List tokens")
        choice = input("Enter choice: ").strip()
        if choice == '1':
            cursor.execute("SELECT username, role, failed_attempts, locked FROM users ORDER BY id")
            for row in cursor.fetchall(): print(row)
        elif choice == '2':
            u = input("Username: ").strip(); 
            if not u: print("Invalid username."); continue
            cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (u,)); conn.commit(); print(f"Failed attempts reset for {u}")
        elif choice == '3':
            u = input("Username: ").strip(); 
            if not u: print("Invalid username."); continue
            cursor.execute("UPDATE users SET locked=0 WHERE username=?", (u,)); conn.commit(); print(f"Account unlocked for {u}")
        elif choice == '4':
            cursor.execute("SELECT username, action, timestamp FROM audit_log ORDER BY timestamp DESC")
            for row in cursor.fetchall(): print(row)
        elif choice == '5': reset_2fa(input("Username: ").strip(), acting_admin=admin_username)
        elif choice == '6': print("Logging out..."); break
        elif choice == '7': promote_to_admin(input("User to promote: ").strip(), acting_admin=admin_username)
        elif choice == '8':
            target = input("User to DELETE: ").strip(); confirm = input(f"Type DELETE {target} to confirm: ").strip()
            delete_user(target, acting_admin=admin_username) if confirm == f"DELETE {target}" else print("Aborted.")
        elif choice == '9': rename_user(input("Current email: ").strip(), input("New email: ").strip(), acting_admin=admin_username)
        elif choice == '10':
            u = input("Username: ").strip(); 
            if not u: print("Invalid username."); continue
            reset_password(u, input_with_asterisks("New password: "), acting_admin=admin_username)
        elif choice == '11': lock_user(input("Username to LOCK: ").strip(), acting_admin=admin_username, reason=(input("Reason (optional): ").strip() or "manual_lock"))
        elif choice == '12': revoke_tokens_for_user(input("Username: ").strip(), acting_admin=admin_username)
        elif choice == '13': revoke_token_by_jti(input("Token JTI: ").strip(), acting_admin=admin_username)
        elif choice == '14': incident_secure_user(input("Username: ").strip(), acting_admin=admin_username)
        elif choice == '15': list_tokens_for_user(input("Username: ").strip())
        else: print("Invalid choice.")

def user_menu(username: str):
    while True:
        print("\nUser Menu\n1. View profile\n2. Logout")
        choice = input("Enter choice: ").strip()
        if choice == '1': print(f"Logged in as: {username}")
        elif choice == '2': print("Logging out..."); break
        else: print("Invalid choice.")

def main():
    while True:
        print("\nSecure Login System\n1. Register\n2. Login\n3. Admin Menu (direct access)\n4. Exit")
        choice = input("Choose an option: ").strip()
        if choice == '1':
            pre_email = input("\nEnter the email you want to register: ").strip()
            default_choice = get_last_register_choice(pre_email); default_text = "User" if default_choice == "user" else "Admin"
            while True:
                print("\nRegister Menu\n1. Register as User\n2. Register as Admin\n3. Back")
                sel = input(f"Choose an option [default: {default_text}]: ").strip() or ('1' if default_choice=='user' else '2')
                if sel == '1': set_last_register_choice(pre_email, "user"); register("user", pre_username=pre_email); break
                if sel == '2': set_last_register_choice(pre_email, "admin"); register("admin", pre_username=pre_email); break
                if sel == '3': break
                print("Invalid choice.")
        elif choice == '2': login()
        elif choice == '3':
            email = input("Enter admin username (email): ").strip()
            if not email: print("Invalid username."); continue
            cursor.execute("SELECT username FROM users WHERE username=? AND LOWER(role)='admin'", (email,))
            row = cursor.fetchone()
            if row and row[0]: admin_menu(row[0])
            else: print("That user is not an admin.")
        elif choice == '4': print("Goodbye."); break
        else: print("Invalid choice.")

# ======================== JWKS / RSA KeyStore (for OIDC) ========================

def _b64url_int(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    s = base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
    return s or "AA"

class RSAKeyStore:
    def __init__(self, keys_dir: str="keys", rotate_days: int=60):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        self.rsa = rsa
        self.serialization = serialization
        self.dir = pathlib.Path(keys_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.dir / "metadata.json"
        self.rotate_days = rotate_days
        self._meta = {"current_kid": None, "keys": {}}

        if self.meta_path.exists():
            try:
                self._meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        if not self._meta.get("current_kid"):
            self._create_and_set_current()

    def _save_meta(self):
        self.meta_path.write_text(json.dumps(self._meta, indent=2), encoding="utf-8")

    def _pem_paths(self, kid: str):
        return self.dir / f"{kid}_priv.pem", self.dir / f"{kid}_pub.pem"

    def _create_and_set_current(self) -> str:
        key = self.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = key.public_key()

        pub_der = pub.public_bytes(
            encoding=self.serialization.Encoding.DER,
            format=self.serialization.PublicFormat.SubjectPublicKeyInfo
        )
        kid = hashlib.sha256(pub_der).hexdigest()[:16]

        priv_pem, pub_pem = self._pem_paths(kid)
        priv_pem.write_bytes(
            key.private_bytes(
                encoding=self.serialization.Encoding.PEM,
                format=self.serialization.PrivateFormat.PKCS8,
                encryption_algorithm=self.serialization.NoEncryption(),
            )
        )
        pub_pem.write_bytes(
            pub.public_bytes(
                encoding=self.serialization.Encoding.PEM,
                format=self.serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        self._meta["current_kid"] = kid
        self._meta["keys"][kid] = {"created": now_utc().isoformat()}
        self._save_meta()
        return kid

    def current_kid(self) -> str:
        return self._meta["current_kid"]

    def get_private_key_pem(self, kid: str) -> bytes:
        priv, _ = self._pem_paths(kid)
        return priv.read_bytes()

    def get_private_key_obj(self, kid: str) -> RSAPrivateKey:
        key = self.serialization.load_pem_private_key(
            self.get_private_key_pem(kid),
            password=None,
        )
        assert isinstance(key, RSAPrivateKey), "Loaded private key is not RSA"
        return key

    def get_public_key_pem(self, kid: str) -> bytes:
        _, pub = self._pem_paths(kid)
        return pub.read_bytes()

    def get_public_key_obj(self, kid: str) -> RSAPublicKey:
        key = self.serialization.load_pem_public_key(self.get_public_key_pem(kid))
        assert isinstance(key, RSAPublicKey), "Loaded public key is not RSA"
        return key

    def rotate_if_needed(self):
        current = self._meta["current_kid"]
        if not current:
            self._create_and_set_current()
            return
        created_iso = self._meta["keys"].get(current, {}).get("created")
        if not created_iso:
            return
        if (now_utc() - datetime.fromisoformat(created_iso)).days >= self.rotate_days:
            self._create_and_set_current()

    def jwks(self) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for kid in self._meta.get("keys", {}):
            pub = self.get_public_key_obj(kid)
            nums = pub.public_numbers()
            out.append({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": kid,
                "n": _b64url_int(nums.n),
                "e": _b64url_int(nums.e),
            })
        return out

# ========================== OIDC dev server + SCIM 2.0 ==========================

def run_oidc_server():
    from flask import Flask, request, redirect, jsonify, make_response, render_template_string, abort

    # OIDC config
    OIDC_ISSUER        = os.getenv("OIDC_ISSUER", "http://localhost:8000")
    OIDC_CLIENT_ID     = os.getenv("OIDC_CLIENT_ID", "demo-client")
    OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "demo-secret")
    OIDC_REDIRECT_URI  = os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/callback")
    ACCESS_TOKEN_TTL   = int(os.getenv("ACCESS_TOKEN_TTL", "900"))
    ID_TOKEN_TTL       = int(os.getenv("ID_TOKEN_TTL", "900"))
    AUTH_CODE_TTL      = int(os.getenv("AUTH_CODE_TTL", "300"))
    ALLOWED_SCOPES     = {"openid", "profile", "email"}
    KEYS_DIR           = os.getenv("OIDC_KEYS_DIR", "keys")
    ROTATE_DAYS        = int(os.getenv("OIDC_ROTATE_DAYS", "60"))

    # SCIM config
    SCIM_BEARER_TOKEN  = os.getenv("SCIM_BEARER_TOKEN", "change-me-super-secret")

    _auth_codes: Dict[str, Dict[str, Any]] = {}
    _access_tokens: Dict[str, Dict[str, Any]] = {}
    ks = RSAKeyStore(keys_dir=KEYS_DIR, rotate_days=ROTATE_DAYS); ks.rotate_if_needed()

    def _db_get_user(username: str):
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor()
            cur.execute("SELECT id, username, password, role, locked, totp_secret FROM users WHERE username=?", (username,))
            r = cur.fetchone()
            return {"id": r[0], "username": r[1], "password": r[2], "role": r[3], "locked": r[4], "totp_secret": r[5]} if r else None

    def _user_claims(user):
        return {"sub": str(user["id"]), "preferred_username": user["username"],
                "name": user["username"], "email": user["username"] if "@" in user["username"] else None,
                "role": user["role"]}

    def _sign_jwt_rs256(payload: dict, ttl_seconds: int, aud: Optional[str]=None) -> Tuple[str, str, datetime]:
        now = datetime.now(UTC); exp = now + timedelta(seconds=ttl_seconds)
        to_sign = {"iss": OIDC_ISSUER, "iat": int(now.timestamp()), "exp": int(exp.timestamp()), **payload}
        if aud: to_sign["aud"] = aud
        kid = ks.current_kid()
        priv_key: RSAPrivateKey = ks.get_private_key_obj(kid)

        token = jwt.encode(
            to_sign,
            priv_key,
            algorithm="RS256",
            headers={"kid": kid, "alg": "RS256", "typ": "JWT"})
        return token, kid, exp

    def _make_access_token(sub: str, scope: str) -> str:
        jti = str(uuid.uuid4()); token, kid, exp = _sign_jwt_rs256({"sub": sub, "scope": scope, "jti": jti, "typ": "at+jwt"}, ACCESS_TOKEN_TTL, aud=OIDC_CLIENT_ID)
        _access_tokens[jti] = {"sub": sub, "scope": scope, "exp": exp, "kid": kid}; return token

    def _make_id_token(sub: str, nonce: Optional[str], extra: dict) -> str:
        claims = {"sub": sub, "auth_time": int(time.time())}; 
        if nonce: claims["nonce"] = nonce
        claims.update({k: v for k, v in extra.items() if v is not None})
        token, _, _ = _sign_jwt_rs256(claims, ID_TOKEN_TTL, aud=OIDC_CLIENT_ID); return token

    def _parse_bearer() -> Optional[str]:
        h = request.headers.get("Authorization", ""); return h[7:].strip() if h.startswith("Bearer ") else None

    def _decode_with_kid(token: str, audience: str):
        try:
            hdr = jwt.get_unverified_header(token); kid = hdr.get("kid"); 
            if not kid: return None
            pub_pem = ks.get_public_key_pem(kid)
            return jwt.decode(token, pub_pem, algorithms=["RS256"], audience=audience, options={"require": ["exp", "iss"]})
        except Exception:
            return None

    # ---------- OIDC routes ----------
    app = Flask(__name__)

    @app.get("/.well-known/openid-configuration")
    def discovery():
        return jsonify({
            "issuer": OIDC_ISSUER,
            "authorization_endpoint": f"{OIDC_ISSUER}/authorize",
            "token_endpoint": f"{OIDC_ISSUER}/token",
            "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
            "jwks_uri": f"{OIDC_ISSUER}/jwks.json",
            "response_types_supported": ["code"],
            "scopes_supported": list(ALLOWED_SCOPES),
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub", "name", "preferred_username", "email", "role"],
        })

    @app.get("/jwks.json")
    def jwks(): ks.rotate_if_needed(); return jsonify({"keys": ks.jwks()})

    _LOGIN_PAGE = """
    <!doctype html><title>Sign in</title><h2>Sign in</h2>
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="{{client_id}}">
      <input type="hidden" name="redirect_uri" value="{{redirect_uri}}">
      <input type="hidden" name="state" value="{{state}}">
      <input type="hidden" name="scope" value="{{scope}}">
      <input type="hidden" name="response_type" value="{{response_type}}">
      <input type="hidden" name="nonce" value="{{nonce}}">
      <div><label>Username <input name="username" required></label></div>
      <div><label>Password <input name="password" type="password" required></label></div>
      <div><label>TOTP Code <input name="totp" pattern="\\d{6}" placeholder="6-digit" required></label></div>
      <button type="submit">Continue</button>
    </form>"""

    def _validate_authz_args(args):
        client_id = args.get("client_id"); redirect_uri = args.get("redirect_uri")
        response_type = args.get("response_type", "code"); scope = args.get("scope", "openid")
        state = args.get("state", ""); nonce = args.get("nonce", "")
        if client_id != OIDC_CLIENT_ID: abort(400, description="invalid client_id")
        if redirect_uri != OIDC_REDIRECT_URI: abort(400, description="invalid redirect_uri")
        if response_type != "code": abort(400, description="unsupported response_type")
        scopes = set(scope.split())
        if "openid" not in scopes or not scopes.issubset(ALLOWED_SCOPES): abort(400, description="invalid/unsupported scope")
        return client_id, redirect_uri, " ".join(scopes), state, nonce

    def _client_ok(req):
        cid = req.form.get("client_id"); csec = req.form.get("client_secret")
        if cid and csec: return cid == OIDC_CLIENT_ID and csec == OIDC_CLIENT_SECRET
        auth = req.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                raw = base64.b64decode(auth[6:]).decode("utf-8"); cid2, csec2 = raw.split(":", 1)
                return cid2 == OIDC_CLIENT_ID and csec2 == OIDC_CLIENT_SECRET
            except Exception: return False
        return False

    @app.route("/authorize", methods=["GET","POST"])
    def authorize():
        if request.method == "GET":
            cid, ru, scope, state, nonce = _validate_authz_args(request.args)
            audit("oidc_authorize", user=None, outcome="pending", client_id=cid, scope=scope)
            return render_template_string(_LOGIN_PAGE, client_id=cid, redirect_uri=ru, state=state, scope=scope, response_type="code", nonce=nonce)
        cid, ru, scope, state, nonce = _validate_authz_args(request.form)
        username = (request.form.get("username") or "").strip(); password = request.form.get("password") or ""; totp_in = (request.form.get("totp") or "").strip()
        user = _db_get_user(username)
        if not user or user["locked"]: audit("oidc_auth", user=username, outcome="fail", reason="no_user_or_locked"); return make_response("Invalid credentials", 401)
        try:
            if not bcrypt.checkpw(password.encode("utf-8"), user["password"]): audit("oidc_auth", user=username, outcome="fail", reason="bad_password"); return make_response("Invalid credentials", 401)
        except Exception: audit("oidc_auth", user=username, outcome="fail", reason="bcrypt_error"); return make_response("Invalid credentials", 401)
        if not user["totp_secret"]: audit("oidc_mfa", user=username, outcome="fail", reason="no_totp_secret"); return make_response("2FA not configured", 401)
        try: norm = normalize_base32(user["totp_secret"])
        except Exception: audit("oidc_mfa", user=username, outcome="fail", reason="totp_bad_secret"); return make_response("2FA error", 401)
        totp = pyotp.TOTP(norm, digits=6, interval=30, digest=hashlib.sha1); ok = totp.verify(totp_in, valid_window=1)
        if not ok:
            now = int(time.time()); base = (now // 30) * 30
            for off in (-60, -30, 0, 30, 60):
                if totp.at(base + off) == totp_in: ok = True; break
        if not ok: audit("oidc_mfa", user=username, outcome="fail", reason="invalid_code"); return make_response("Invalid 2FA code", 401)
        code = uuid.uuid4().hex
        _auth_codes[code] = {"client_id": cid, "redirect_uri": ru, "scope": scope, "sub": str(user["id"]), "nonce": nonce, "exp": time.time() + AUTH_CODE_TTL}
        audit("oidc_authorize", user=username, outcome="success", client_id=cid)
        sep = '&' if "?" in (ru or "") else "?"; return redirect(f"{ru}{sep}code={code}&state={state}", code=302)

    @app.post("/token")
    def token():
        if not _client_ok(request): return jsonify({"error": "invalid_client"}), 401
        if request.form.get("grant_type") != "authorization_code": return jsonify({"error": "unsupported_grant_type"}), 400
        code = request.form.get("code"); ru = request.form.get("redirect_uri")
        if not code or code not in _auth_codes: return jsonify({"error": "invalid_grant"}), 400
        entry = _auth_codes.pop(code)
        if entry["exp"] < time.time(): return jsonify({"error": "invalid_grant", "error_description": "code expired"}), 400
        if ru != entry["redirect_uri"]: return jsonify({"error": "invalid_grant"}), 400
        sub, scope, nonce = entry["sub"], entry["scope"], entry["nonce"]
        access_token = _make_access_token(sub, scope); id_token = _make_id_token(sub, nonce, extra={})
        audit("oidc_token", user=sub, outcome="success", scope=scope)
        return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL, "id_token": id_token, "scope": scope})

    @app.get("/userinfo")
    def userinfo():
        bearer = _parse_bearer()
        if not bearer: return jsonify({"error": "invalid_request"}), 401
        data = _decode_with_kid(bearer, audience=OIDC_CLIENT_ID)
        if not data: return jsonify({"error": "invalid_token"}), 401
        sub = data.get("sub")
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("SELECT id, username, role FROM users WHERE id = ?", (sub,))
            r = cur.fetchone()
            if not r: return jsonify({"error": "invalid_token"}), 401
            user = {"id": r[0], "username": r[1], "role": r[2]}
        return jsonify({k: v for k, v in _user_claims(user).items() if v is not None})

    @app.get("/callback")
    def oidc_callback():
        code = request.args.get("code"); state = request.args.get("state")
        if not code: return make_response("Missing code", 400)
        try:
            token_resp = requests.post(f"{OIDC_ISSUER}/token",
                                       data={"grant_type":"authorization_code","code":code,"redirect_uri":OIDC_REDIRECT_URI,
                                             "client_id":OIDC_CLIENT_ID,"client_secret":OIDC_CLIENT_SECRET},
                                       timeout=5)
        except Exception as e:
            return make_response(f"Token request failed: {e}", 500)
        if token_resp.status_code != 200:
            return make_response(f"Token exchange failed ({token_resp.status_code}): {token_resp.text}", 400)
        tokens = token_resp.json()
        return f"""<h2>OIDC Callback</h2><p><b>state:</b> {state}</p>
                   <h3>Tokens</h3><pre style="white-space:pre-wrap">{json.dumps(tokens, indent=2)}</pre>
                   <h3>Try /userinfo</h3><pre>curl -H "Authorization: Bearer {tokens.get('access_token','')}" {OIDC_ISSUER}/userinfo</pre>"""

    # ---------- SCIM helpers ----------
    def _scim_auth_ok() -> bool:
        tok = _parse_bearer()
        return bool(tok) and (tok == SCIM_BEARER_TOKEN)

    def _scim_user_to_dict(row) -> Dict[str, Any]:
        uid, username, role, locked = row
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": str(uid),
            "userName": username,
            "active": (locked == 0),
            "name": {"formatted": username},
            "emails": [{"value": username, "primary": True}] if "@" in username else [],
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": role or "user"},
            "meta": {"resourceType": "User"}
        }

    def _scim_group_to_dict(gid: str, display: str) -> Dict[str, Any]:
        # load members
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor()
            cur.execute("SELECT user_id FROM scim_group_members WHERE group_id=?", (gid,))
            members = [{"value": str(uid)} for (uid,) in cur.fetchall()]
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": gid, "displayName": display, "members": members,
            "meta": {"resourceType": "Group"}
        }

    # ---------- SCIM discovery endpoints ----------
    @app.get("/scim/v2/ServiceProviderConfig")
    def scim_spc():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        return jsonify({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type":"oauthbearertoken","name":"OAuth Bearer Token","description":"Send Authorization: Bearer <token>"}]
        })

    @app.get("/scim/v2/ResourceTypes")
    def scim_resources():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        return jsonify([
            {"id":"User","name":"User","endpoint":"/scim/v2/Users","schema":"urn:ietf:params:scim:schemas:core:2.0:User"},
            {"id":"Group","name":"Group","endpoint":"/scim/v2/Groups","schema":"urn:ietf:params:scim:schemas:core:2.0:Group"},
        ])

    @app.get("/scim/v2/Schemas")
    def scim_schemas():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        return jsonify([
            {"id":"urn:ietf:params:scim:schemas:core:2.0:User","name":"User"},
            {"id":"urn:ietf:params:scim:schemas:core:2.0:Group","name":"Group"},
            {"id":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","name":"EnterpriseUser"}
        ])

    # ---------- SCIM Users ----------
    @app.get("/scim/v2/Users")
    def scim_users_query():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        start = int(request.args.get("startIndex", "1")); count = int(request.args.get("count", "100"))
        flt = request.args.get("filter", "")
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor()
            if flt.startswith('userName eq "'):
                val = flt[len('userName eq "'):-1]
                cur.execute("SELECT id, username, role, locked FROM users WHERE username=?", (val,))
            else:
                cur.execute("SELECT id, username, role, locked FROM users ORDER BY id")
            rows = cur.fetchall()
        resources = [_scim_user_to_dict(r) for r in rows]
        total = len(resources)
        slice_ = resources[max(0, start-1):max(0, start-1)+count]
        return jsonify({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                        "totalResults": total, "startIndex": start, "itemsPerPage": len(slice_), "Resources": slice_})

    @app.post("/scim/v2/Users")
    def scim_user_create():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        data = request.get_json(force=True)
        username = (data.get("userName") or "").strip()
        if not username: return jsonify({"detail":"userName required"}), 400
        password = bcrypt.gensalt().decode("utf-8")  # random placeholder
        hashed = hash_password(password)
        try:
            with sqlite3.connect('database.db') as _c:
                cur = _c.cursor()
                cur.execute("INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, 'user', ?)",
                            (username, hashed, pyotp.random_base32()))
                _c.commit()
                cur.execute("SELECT id, username, role, locked FROM users WHERE username=?", (username,))
                row = cur.fetchone()
        except sqlite3.IntegrityError:
            return jsonify({"status":409,"detail":"User already exists"}), 409
        return jsonify(_scim_user_to_dict(row)), 201

    @app.get("/scim/v2/Users/<uid>")
    def scim_user_get(uid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("SELECT id, username, role, locked FROM users WHERE id=?", (uid,))
            r = cur.fetchone()
        if not r: return jsonify({"status":404,"detail":"Not found"}), 404
        return jsonify(_scim_user_to_dict(r))

    @app.put("/scim/v2/Users/<uid>")
    def scim_user_replace(uid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        data = request.get_json(force=True); username = (data.get("userName") or "").strip()
        if not username: return jsonify({"detail":"userName required"}), 400
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("UPDATE users SET username=? WHERE id=?", (username, uid)); _c.commit()
            cur.execute("SELECT id, username, role, locked FROM users WHERE id=?", (uid,)); r = cur.fetchone()
        if not r: return jsonify({"status":404,"detail":"Not found"}), 404
        return jsonify(_scim_user_to_dict(r))

    @app.patch("/scim/v2/Users/<uid>")
    def scim_user_patch(uid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        body = request.get_json(force=True) or {}
        ops = body.get("Operations", [])
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor()
            for op in ops:
                if op.get("op", "").lower() == "replace":
                    path = (op.get("path") or "").lower()
                    value = op.get("value")
                    if path == "active":
                        active = bool(value)
                        cur.execute("UPDATE users SET locked=? WHERE id=?", (0 if active else 1, uid))
            _c.commit()
            cur.execute("SELECT id, username, role, locked FROM users WHERE id=?", (uid,))
            r = cur.fetchone()
        if not r: return jsonify({"status":404,"detail":"Not found"}), 404
        return jsonify(_scim_user_to_dict(r))

    @app.delete("/scim/v2/Users/<uid>")
    def scim_user_delete(uid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("DELETE FROM users WHERE id=?", (uid,)); _c.commit()
        return "", 204

    # ---------- SCIM Groups ----------
    @app.get("/scim/v2/Groups")
    def scim_groups_query():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        start = int(request.args.get("startIndex", "1")); count = int(request.args.get("count", "100"))
        flt = request.args.get("filter", "")
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor()
            if flt.startswith('displayName eq "'):
                val = flt[len('displayName eq "'):-1]
                cur.execute("SELECT id, displayName FROM scim_groups WHERE displayName=?", (val,))
            else:
                cur.execute("SELECT id, displayName FROM scim_groups ORDER BY displayName")
            groups = cur.fetchall()
        resources = [_scim_group_to_dict(gid, dn) for gid, dn in groups]
        total = len(resources); slice_ = resources[max(0,start-1):max(0,start-1)+count]
        return jsonify({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                        "totalResults": total, "startIndex": start, "itemsPerPage": len(slice_), "Resources": slice_})

    @app.post("/scim/v2/Groups")
    def scim_group_create():
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        data = request.get_json(force=True); dn = (data.get("displayName") or "").strip()
        if not dn: return jsonify({"detail":"displayName required"}), 400
        gid = uuid.uuid4().hex
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("INSERT INTO scim_groups (id, displayName) VALUES (?, ?)", (gid, dn)); _c.commit()
        return jsonify(_scim_group_to_dict(gid, dn)), 201

    @app.get("/scim/v2/Groups/<gid>")
    def scim_group_get(gid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("SELECT id, displayName FROM scim_groups WHERE id=?", (gid,)); r = cur.fetchone()
        if not r: return jsonify({"status":404,"detail":"Not found"}), 404
        return jsonify(_scim_group_to_dict(r[0], r[1]))

    @app.put("/scim/v2/Groups/<gid>")
    def scim_group_replace(gid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        data = request.get_json(force=True); dn = (data.get("displayName") or "").strip()
        if not dn: return jsonify({"detail":"displayName required"}), 400
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("UPDATE scim_groups SET displayName=? WHERE id=?", (dn, gid)); _c.commit()
        return jsonify(_scim_group_to_dict(gid, dn))

    @app.patch("/scim/v2/Groups/<gid>")
    def scim_group_patch(gid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        body = request.get_json(force=True) or {}; ops = body.get("Operations", [])
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor()
            for op in ops:
                opn = op.get("op","").lower()
                if opn == "add":
                    for m in op.get("value", {}).get("members", []):
                        uid = int(m.get("value"))
                        cur.execute("INSERT OR IGNORE INTO scim_group_members (group_id, user_id) VALUES (?, ?)", (gid, uid))
                elif opn == "remove":
                    path = (op.get("path") or "")
                    if path.startswith("members[value eq "):
                        uid = path[len("members[value eq "):].strip('"] ')
                        cur.execute("DELETE FROM scim_group_members WHERE group_id=? AND user_id=?", (gid, int(uid)))
                elif opn == "replace":
                    dn = (op.get("value", {}).get("displayName") or "").strip()
                    if dn: cur.execute("UPDATE scim_groups SET displayName=? WHERE id=?", (dn, gid))
            _c.commit()
            cur.execute("SELECT displayName FROM scim_groups WHERE id=?", (gid,)); r = cur.fetchone()
            if not r: return jsonify({"status":404,"detail":"Not found"}), 404
            dn = r[0]
        return jsonify(_scim_group_to_dict(gid, dn))

    @app.delete("/scim/v2/Groups/<gid>")
    def scim_group_delete(gid):
        if not _scim_auth_ok(): return jsonify({"detail":"unauthorized"}), 401
        with sqlite3.connect('database.db') as _c:
            cur = _c.cursor(); cur.execute("DELETE FROM scim_groups WHERE id=?", (gid,)); cur.execute("DELETE FROM scim_group_members WHERE group_id=?", (gid,)); _c.commit()
        return "", 204

    # --------- console hints + run ----------
    base = OIDC_ISSUER
    print("[OIDC] Issuer:", base)
    print("[OIDC] Client ID:", OIDC_CLIENT_ID)
    print("[OIDC] RedirectURI:", OIDC_REDIRECT_URI)
    print("[OIDC] JWKS URI:", f"{base}/jwks.json")
    print("[OIDC] Endpoints:")
    print(f"  {base}/.well-known/openid-configuration\n  {base}/authorize\n  {base}/token\n  {base}/userinfo\n  {base}/jwks.json")
    print("[SCIM] Base: /scim/v2  (auth: Bearer <SCIM_BEARER_TOKEN>)")
    app.run(host="127.0.0.1", port=8000, debug=True)

# ============================== Entrypoint ==============================

def _env_truthy(name: str, default: str="0") -> bool:
    return str(os.getenv(name, default)).strip().lower() in {"1","true","yes","on"}

if __name__ == "__main__":
    load_dotenv()
    if _env_truthy("ENABLE_OIDC"): run_oidc_server()
    else: main()
