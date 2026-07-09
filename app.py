#!/usr/bin/env python3
"""AI Proxy Gateway — Smart model-level proxy with automatic key rotation."""

import os, re, json, sqlite3, secrets, time, uuid, hashlib, threading, hmac as _hmac
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import unquote
import httpx
from curl_cffi import requests as curl_requests

app = Flask(__name__)

# ── Stable SECRET_KEY (critical for multi-worker gunicorn) ──
# If not provided via env, derive a stable key from AUTH_PASSWORD_HASH
# so all workers share the same key across restarts.
_DEFAULT_SECRET = os.environ.get("SECRET_KEY", "") or hashlib.sha256(
    (os.environ.get("AUTH_PASSWORD_HASH", "") + os.environ.get("AUTH_PASSWORD", "fallback-secret-key-v542")).encode()
).hexdigest()
app.secret_key = _DEFAULT_SECRET

# ── Production security settings ──
# Use SECURE cookies only when behind HTTPS reverse proxy (Traefik handles TLS)
# Check both FLASK_ENV and X-Forwarded-Proto header at runtime
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 min
# Don't set SESSION_COOKIE_SECURE here — set it dynamically in before_request
# based on whether the request came over HTTPS (via Traefik X-Forwarded-Proto)

# ── Jinja context processor: inject CSRF token into all templates ──
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

# ═══════════════════════════════════════════════════════════════════════════
# SECURITY LAYER — Fernet cookie encryption + API key minting + validation
# (Adapted from zlexdev/claude-webapi gateway/features/auth/)
# ═══════════════════════════════════════════════════════════════════════════

COOKIE_ENCRYPTION_KEY = os.environ.get("COOKIE_ENCRYPTION_KEY", "")
_fernet = None

def _get_fernet():
    """Lazily init Fernet cipher for at-rest cookie encryption."""
    global _fernet
    if _fernet is not None or not COOKIE_ENCRYPTION_KEY:
        return _fernet
    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(COOKIE_ENCRYPTION_KEY.encode())
    except Exception:
        _fernet = None
    return _fernet

def encrypt_cookies(cookies_dict):
    """Seal a cookie dict into a Fernet token string. Returns dict if no key."""
    f = _get_fernet()
    if f is None:
        return json.dumps(cookies_dict)  # legacy plaintext fallback
    raw = json.dumps(cookies_dict, separators=(",", ":")).encode()
    return f.encrypt(raw).decode()

def decrypt_cookies(token):
    """Unseal a Fernet token → dict. Handles legacy plaintext JSON too."""
    f = _get_fernet()
    if f is None:
        # No key configured — data is plaintext JSON
        try:
            return {str(k): str(v) for k, v in json.loads(token).items()}
        except (json.JSONDecodeError, TypeError):
            return {}
    try:
        from cryptography.fernet import InvalidToken
        try:
            raw = f.decrypt(token.encode())
        except InvalidToken:
            # Try legacy plaintext
            try:
                return {str(k): str(v) for k, v in json.loads(token).items()}
            except (json.JSONDecodeError, TypeError):
                return {}
        data = json.loads(raw.decode())
        return {str(k): str(v) for k, v in data.items()}
    except Exception:
        return {}

# ── API Key Minting ──
KEY_PREFIX = "sk-aic-"

def generate_api_key():
    """Return (plaintext, sha256_hex). Persist only the hash."""
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hash_api_key(raw)

def hash_api_key(raw):
    return hashlib.sha256(raw.encode()).hexdigest()

def verify_api_key(raw, stored_hash):
    return _hmac.compare_digest(hash_api_key(raw), stored_hash)

# ── Cookie Name Validation ──
_COOKIE_NAME_RE = re.compile(r'^[\w\-\.]+$')
_COOKIE_UNSAFE_RE = re.compile(r'[\x00-\x1f\x7f]')
_XSRF_NAMES = ("XSRF-TOKEN", "xsrf_token")

def extract_xsrf_token(cookies_dict):
    """Extract XSRF token from a cookies dict."""
    for name in _XSRF_NAMES:
        if name in cookies_dict:
            return unquote(cookies_dict[name])
    return None

def build_auth_headers(cookies_dict):
    """Build Cookie + x-xsrf-token headers from a cookies dict."""
    headers = {}
    if cookies_dict:
        headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
    xsrf = extract_xsrf_token(cookies_dict)
    if xsrf:
        headers["x-xsrf-token"] = xsrf
    return headers

def validate_cookie_name(name):
    """Check cookie name is valid (safe charset, no control chars)."""
    if not name or not _COOKIE_NAME_RE.match(name):
        return False
    return True

# ── Auth ──────────────────────────────────────────────────────────────────
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "mahmoud")
AUTH_PASSWORD_HASH = generate_password_hash(os.environ.get("AUTH_PASSWORD", "Mmm12011305"))
PROXY_API_KEY_HASH = os.environ.get("PROXY_API_KEY_HASH", "")  # SHA256 hash of the real key

# ── IPRoyal Proxy Config ─────────────────────────────────────────────────
# IPRoyal residential proxies — no KYC, rotating, sticky via dashboard setting
# Format: http://USER:PASS@geo.iproyal.com:12321
PROXY_ENABLED = os.environ.get("PROXY_ENABLED", "false").lower() == "true"
PROXY_USER   = os.environ.get("PROXY_USER", "7MbCthZqPB0y1E1T")
PROXY_PASS   = os.environ.get("PROXY_PASS", "sTj24Oqhz2RPrIM8")
PROXY_HOST   = os.environ.get("PROXY_HOST", "geo.iproyal.com")
PROXY_PORT   = os.environ.get("PROXY_PORT", "12321")

def get_proxy_url(session_id=None):
    """Build IPRoyal proxy URL.
    IPRoyal sticky sessions are dashboard-controlled — same credentials = same IP when enabled.
    Session ID is reserved for future use (IPRoyal may support URL-based sessions)."""
    if not PROXY_ENABLED:
        return None
    return f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"

# ── Database ──────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/data/cookies.db")


def get_current_proxy_ip():
    """Get the current IP being used through the proxy.
    Returns (ip, country) or (None, None)."""
    try:
        proxy_url = get_proxy_url()
        if proxy_url:
            from curl_cffi import requests as cr
            r = cr.get("https://api.ipify.org", proxy=proxy_url, impersonate="chrome131", timeout=10)
            ip = r.text.strip()
            # Try to get country
            try:
                r2 = cr.get(f"https://ipapi.co/{ip}/country/", proxy=proxy_url, impersonate="chrome131", timeout=10)
                country = r2.text.strip() if r2.status_code == 200 else ""
            except:
                country = ""
        else:
            import httpx
            r = httpx.get("https://api.ipify.org", timeout=5)
            ip = r.text.strip()
            try:
                r2 = httpx.get(f"https://ipapi.co/{ip}/country/", timeout=5)
                country = r2.text.strip() if r2.status_code == 200 else ""
            except:
                country = ""
        return ip, country
    except:
        return None, None

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS cookie_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT, platform TEXT NOT NULL, filename TEXT,
        raw_content TEXT NOT NULL, cookie_count INTEGER DEFAULT 0, uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        proxy_session_id TEXT, proxy_enabled INTEGER DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, platform TEXT NOT NULL,
        domain TEXT NOT NULL, flag TEXT, path TEXT DEFAULT '/', secure TEXT DEFAULT 'FALSE',
        expiration TEXT, name TEXT NOT NULL, value TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES cookie_files(id) ON DELETE CASCADE)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS api_providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
        base_url TEXT, api_docs_url TEXT, free_models TEXT, description TEXT,
        provider_type TEXT DEFAULT 'free', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT, provider_id INTEGER NOT NULL,
        label TEXT, key_value TEXT NOT NULL, is_active INTEGER DEFAULT 1,
        dead INTEGER DEFAULT 0, usage_count INTEGER DEFAULT 0, error_count INTEGER DEFAULT 0,
        last_used_at TIMESTAMP, last_error_at TIMESTAMP, last_error_msg TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (provider_id) REFERENCES api_providers(id) ON DELETE CASCADE)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS proxy_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, model_slug TEXT NOT NULL, provider_slug TEXT,
        key_id INTEGER, status TEXT, latency_ms INTEGER,
        error_msg TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_provider ON api_keys(provider_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_proxy_requests_model ON proxy_requests(model_slug)")

    # ── Migration: add columns if they don't exist ──
    for col, col_type in [("proxy_session_id", "TEXT"), ("proxy_enabled", "INTEGER DEFAULT 0")]:
        try: conn.execute(f"ALTER TABLE cookie_files ADD COLUMN {col} {col_type}")
        except: pass
    for col, col_type in [("dead", "INTEGER DEFAULT 0"), ("error_count", "INTEGER DEFAULT 0"),
                           ("last_error_at", "TIMESTAMP"), ("last_error_msg", "TEXT")]:
        try: conn.execute(f"ALTER TABLE api_keys ADD COLUMN {col} {col_type}")
        except: pass
    for col, col_type in [("suspended", "INTEGER DEFAULT 0")]:
        try: conn.execute(f"ALTER TABLE api_keys ADD COLUMN {col} {col_type}")
        except: pass
    for col, col_type in [("credits_dollar", "TEXT"), ("credits_initial", "TEXT"), ("models_count", "INTEGER")]:
        try: conn.execute(f"ALTER TABLE key_account_info ADD COLUMN {col} {col_type}")
        except: pass
    for col, col_type in [("provider_type", "TEXT DEFAULT 'free'")]:
        try: conn.execute(f"ALTER TABLE api_providers ADD COLUMN {col} {col_type}")
        except: pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_dead ON api_keys(dead)")
    for col, col_type in [("proxy_ip", "TEXT"), ("proxy_country", "TEXT")]:
        try: conn.execute(f"ALTER TABLE proxy_requests ADD COLUMN {col} {col_type}")
        except: pass

    # ── Custom Endpoints table ──
    # Virtual API endpoints with forced system prompts and parameter overrides.
    # Each endpoint has a unique slug that becomes its URL: /v1/{slug}/chat/completions
    conn.execute("""CREATE TABLE IF NOT EXISTS custom_endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        description TEXT,
        model_slug TEXT NOT NULL,
        system_prompt TEXT,
        temperature REAL,
        max_tokens INTEGER,
        top_p REAL,
        is_active INTEGER DEFAULT 1,
        is_public INTEGER DEFAULT 0,
        usage_count INTEGER DEFAULT 0,
        last_used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_custom_endpoints_slug ON custom_endpoints(slug)")

    # ── Key account metadata table ──
    # Stores account info (name, plan, credits, rate limits) fetched from provider APIs.
    # Populated automatically when a Fireworks key is added, and on-demand via UI button.
    conn.execute("""CREATE TABLE IF NOT EXISTS key_account_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id INTEGER NOT NULL UNIQUE,
        provider_slug TEXT NOT NULL,
        account_name TEXT,
        account_email TEXT,
        account_status TEXT,
        plan_type TEXT,
        credits_remaining TEXT,
        credits_total TEXT,
        rate_limit_prompt INTEGER,
        rate_limit_generated INTEGER,
        rate_limit_remaining_prompt INTEGER,
        rate_limit_remaining_generated INTEGER,
        models_available TEXT,
        billing_url TEXT,
        suspension_reason TEXT,
        raw_response TEXT,
        last_fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_key_account_info_key ON key_account_info(key_id)")

    # ── Seed providers ──
    providers = [
        ("nvidia", "NVIDIA NIM", "https://integrate.api.nvidia.com/v1", "free",
         '["nvidia/llama-3.3-nemotron-super-49b-v1","nvidia/llama-3.1-nemotron-70b-instruct","qwen/qwen2.5-32b-instruct","deepseek-ai/deepseek-r1","mistralai/mistral-nemo-minitrait-8b-16k"]',
         "1000 free credits/month. OpenAI-compatible. Keys start with 'nvapi-'."),
        ("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", "free",
         '["google/gemini-2.0-flash-exp:free","deepseek/deepseek-r1:free","meta-llama/llama-3.3-70b-instruct:free","qwen/qwen-2.5-32b-instruct:free","google/gemma-3-27b-it:free","mistralai/mistral-7b-instruct:free"]',
         "Free tier models (:free suffix). OpenAI-compatible. Keys start with 'sk-or-v1-'."),
        ("google", "Google AI Studio", "https://generativelanguage.googleapis.com/v1beta", "free",
         '["gemini-2.0-flash","gemini-2.5-flash","gemini-2.5-pro","gemini-2.0-flash-lite"]',
         "Free tier: 15 RPM (5 RPM for Pro). OpenAI-compatible. Keys start with 'AIza'."),
        ("fireworks", "Fireworks AI", "https://api.fireworks.ai/inference/v1", "prepaid",
         '["accounts/fireworks/models/glm-5p2","accounts/fireworks/models/kimi-k2p7-code","accounts/fireworks/models/qwen3p7-plus","accounts/fireworks/models/deepseek-v4-pro"]',
         "$6 per account. When depleted → permanently dead. OpenAI-compatible."),
        ("openai", "OpenAI", "https://api.openai.com/v1", "paid",
         '["gpt-4o","gpt-4o-mini","gpt-4-turbo","o1-pro","o3-mini"]',
         "Paid API keys. Keys start with 'sk-', 'sk-proj-', or 'sk-svcacct-'."),
        ("claude", "Claude (Anthropic)", "https://api.anthropic.com/v1", "cookie",
         '["claude-sonnet-4-20250514","claude-3-5-sonnet-20241022"]',
         "Cookie-based access or API keys. Keys start with 'sk-ant-'."),
    ]

    active_slugs = {p[0] for p in providers}
    for slug, name, base_url, ptype, models, desc in providers:
        conn.execute("""INSERT OR IGNORE INTO api_providers (slug, name, base_url, provider_type, free_models, description)
            VALUES (?, ?, ?, ?, ?, ?)""", (slug, name, base_url, ptype, models, desc))
        conn.execute("""UPDATE api_providers SET name=?, base_url=?, provider_type=?, free_models=?, description=?
            WHERE slug=?""", (name, base_url, ptype, models, desc, slug))
    existing = conn.execute("SELECT slug FROM api_providers").fetchall()
    for row in existing:
        if row["slug"] not in active_slugs:
            conn.execute("DELETE FROM api_providers WHERE slug = ?", (row["slug"],))
    conn.commit()
    conn.close()

init_db()

# ── Ensure tables exist in forked gunicorn workers ──
@app.before_request
def _ensure_db_tables():
    """Re-run init_db on first request in each worker to handle gunicorn fork."""
    # Dynamic SESSION_COOKIE_SECURE based on actual request protocol
    fwd_proto = request.headers.get("X-Forwarded-Proto", "")
    if fwd_proto == "https" or request.url.startswith("https://"):
        app.config["SESSION_COOKIE_SECURE"] = True
    else:
        app.config["SESSION_COOKIE_SECURE"] = False
    if not getattr(app, '_db_initialized', False):
        try:
            init_db()
            app._db_initialized = True
        except Exception as e:
            app.logger.error(f"[init_db] Error in before_request: {e}")

# ── Auth decorator ───────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        # ── Session timeout (30 min inactivity) ──
        last_activity = session.get("_last_activity")
        if last_activity:
            import time as _t
            if _t.time() - float(last_activity) > 1800:
                session.clear()
                flash("⏰ Session expired — please login again", "warning")
                return redirect(url_for("login_page"))
        session["_last_activity"] = str(time.time())
        return f(*args, **kwargs)
    return decorated

# ── CSRF Protection ──────────────────────────────────────────────────────
def generate_csrf_token():
    """Generate and store a CSRF token in the session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf_token(token):
    """Validate a CSRF token against the session token."""
    if not token or not session.get("_csrf_token"):
        return False
    return _hmac.compare_digest(str(token), str(session["_csrf_token"]))

def csrf_protect(f):
    """Decorator for CSRF protection on POST/PUT/DELETE routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE"):
            token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
            if not validate_csrf_token(token):
                app.logger.warning(f"[csrf] Blocked request to {request.path} from {request.remote_addr}")
                if request.path.startswith("/api/"):
                    return jsonify({"error": "CSRF token missing or invalid"}), 403
                flash("❌ Security token expired — please try again", "danger")
                return redirect(request.referrer or url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

# ── Login Rate Limiter ───────────────────────────────────────────────────
_login_attempts = {}  # {ip: [(timestamp, ...)]}
_login_lock = threading.Lock()

def check_login_rate_limit(ip):
    """Allow max 5 login attempts per IP per 10 minutes. Returns (allowed, remaining, wait_s)."""
    now = time.time()
    with _login_lock:
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        # Remove attempts older than 600s
        _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < 600]
        if len(_login_attempts[ip]) >= 5:
            wait = int(600 - (now - _login_attempts[ip][0]))
            return False, 0, max(wait, 1)
        _login_attempts[ip].append(now)
        remaining = 5 - len(_login_attempts[ip])
        return True, remaining, 0

# ═══════════════════════════════════════════════════════════════════════════
# MODEL REGISTRY — maps model slugs to providers
# ═══════════════════════════════════════════════════════════════════════════

MODELS = {
    # ───────────────────────────────────────────────────────────────────────
    # Claude (cookie-based — special handling, no API key needed)
    # ───────────────────────────────────────────────────────────────────────
    "claude-sonnet-4-6": {
        "provider": "claude", "real_model": "claude-sonnet-4-6",
        "desc": "Claude Sonnet 4 — 200K context, cookie-based", "style": "direct", "tokens": 200000,
        "developer": "Anthropic", "display_name": "Claude Sonnet 4",
        "max_output": 8192, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": True, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "$3.00", "out": "$15.00"},
    },
    # ───────────────────────────────────────────────────────────────────────
    # NVIDIA NIM API (integrate.api.nvidia.com) — 1000 free credits/month
    # ───────────────────────────────────────────────────────────────────────
    "nvidia-nemotron-70b": {
        "provider": "nvidia", "real_model": "nvidia/llama-3.3-nemotron-super-49b-v1",
        "desc": "Nemotron Super 49B — NVIDIA-tuned Llama, 128K ctx, optimized for instruction-following", "style": "direct", "tokens": 131072,
        "developer": "NVIDIA", "display_name": "Nemotron Super 49B",
        "max_output": 131072, "params": "49B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "nvidia-llama-3.3-70b": {
        "provider": "nvidia", "real_model": "nvidia/llama-3.3-nemotron-super-49b-v1",
        "desc": "Llama 3.3 70B via NVIDIA NIM — fast, reliable, 128K ctx", "style": "direct", "tokens": 131072,
        "developer": "Meta × NVIDIA", "display_name": "Llama 3.3 70B (NIM)",
        "max_output": 131072, "params": "70B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "nvidia-qwen-32b": {
        "provider": "nvidia", "real_model": "qwen/qwen2.5-32b-instruct",
        "desc": "Qwen 2.5 32B Instruct — strong code+reasoning, 128K ctx, NVIDIA-hosted", "style": "direct", "tokens": 131072,
        "developer": "Alibaba × NVIDIA", "display_name": "Qwen 2.5 32B (NIM)",
        "max_output": 131072, "params": "32B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "nvidia-deepseek-r1": {
        "provider": "nvidia", "real_model": "deepseek-ai/deepseek-r1",
        "desc": "DeepSeek R1 — deep reasoning, 128K ctx, interleaved thinking", "style": "reasoning", "tokens": 131072,
        "developer": "DeepSeek × NVIDIA", "display_name": "DeepSeek R1 (NIM)",
        "max_output": 131072, "params": "671B MoE",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "nvidia-mistral-nemo": {
        "provider": "nvidia", "real_model": "mistralai/mistral-nemo-minitrait-8b-16k",
        "desc": "Mistral NeMo 12B — multilingual, 128K ctx, NVIDIA-hosted", "style": "direct", "tokens": 131072,
        "developer": "Mistral × NVIDIA", "display_name": "Mistral NeMo (NIM)",
        "max_output": 131072, "params": "12B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    # ───────────────────────────────────────────────────────────────────────
    # OpenRouter (openrouter.ai) — Free tier models (:free suffix)
    # ───────────────────────────────────────────────────────────────────────
    "or-gemini-flash": {
        "provider": "openrouter", "real_model": "google/gemini-2.0-flash-exp:free",
        "desc": "Gemini 2.0 Flash — fast multimodal, 1M ctx, via OpenRouter free", "style": "direct", "tokens": 1048576,
        "developer": "Google", "display_name": "Gemini 2.0 Flash (OR)",
        "max_output": 8192, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": True, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "or-deepseek-r1": {
        "provider": "openrouter", "real_model": "deepseek/deepseek-r1:free",
        "desc": "DeepSeek R1 — full 671B reasoning model, free via OpenRouter", "style": "reasoning", "tokens": 65536,
        "developer": "DeepSeek", "display_name": "DeepSeek R1 (OR Free)",
        "max_output": 65536, "params": "671B MoE",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "or-llama-3.3-70b": {
        "provider": "openrouter", "real_model": "meta-llama/llama-3.3-70b-instruct:free",
        "desc": "Llama 3.3 70B Instruct — open-weight flagship, 128K ctx, free via OR", "style": "direct", "tokens": 131072,
        "developer": "Meta", "display_name": "Llama 3.3 70B (OR Free)",
        "max_output": 131072, "params": "70B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "or-qwen-32b": {
        "provider": "openrouter", "real_model": "qwen/qwen-2.5-32b-instruct:free",
        "desc": "Qwen 2.5 32B — code+math+reasoning, 128K ctx, free via OpenRouter", "style": "direct", "tokens": 131072,
        "developer": "Alibaba / Qwen", "display_name": "Qwen 2.5 32B (OR Free)",
        "max_output": 131072, "params": "32B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "or-gemma-3-27b": {
        "provider": "openrouter", "real_model": "google/gemma-3-27b-it:free",
        "desc": "Gemma 3 27B — Google's open model, 96K ctx, multimodal, free via OR", "style": "direct", "tokens": 96320,
        "developer": "Google", "display_name": "Gemma 3 27B (OR Free)",
        "max_output": 96320, "params": "27B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": True, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "or-mistral-7b": {
        "provider": "openrouter", "real_model": "mistralai/mistral-7b-instruct:free",
        "desc": "Mistral 7B — lightweight, fast, 32K ctx, free via OpenRouter", "style": "direct", "tokens": 32768,
        "developer": "Mistral AI", "display_name": "Mistral 7B (OR Free)",
        "max_output": 32768, "params": "7B",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    # ───────────────────────────────────────────────────────────────────────
    # Google AI Studio (generativelanguage.googleapis.com) — Free tier
    # ───────────────────────────────────────────────────────────────────────
    "gemini-2.0-flash": {
        "provider": "google", "real_model": "gemini-2.0-flash",
        "desc": "Gemini 2.0 Flash — fast, multimodal, 1M ctx, free tier 15 RPM", "style": "direct", "tokens": 1048576,
        "developer": "Google", "display_name": "Gemini 2.0 Flash",
        "max_output": 8192, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": True, "web_search": True, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "gemini-2.5-flash": {
        "provider": "google", "real_model": "gemini-2.5-flash",
        "desc": "Gemini 2.5 Flash — next-gen, adaptive thinking, 1M ctx, free 15 RPM", "style": "reasoning", "tokens": 1048576,
        "developer": "Google", "display_name": "Gemini 2.5 Flash",
        "max_output": 8192, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": True, "web_search": True, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "gemini-2.5-pro": {
        "provider": "google", "real_model": "gemini-2.5-pro",
        "desc": "Gemini 2.5 Pro — frontier reasoning+vision, 2M ctx, free tier 5 RPM", "style": "reasoning", "tokens": 2097152,
        "developer": "Google", "display_name": "Gemini 2.5 Pro",
        "max_output": 8192, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": True, "web_search": True, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    "gemini-flash-lite": {
        "provider": "google", "real_model": "gemini-2.0-flash-lite",
        "desc": "Gemini 2.0 Flash-Lite — ultra-fast, cheapest, 1M ctx, free 30 RPM", "style": "direct", "tokens": 1048576,
        "developer": "Google", "display_name": "Gemini 2.0 Flash-Lite",
        "max_output": 8192, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": True, "web_search": True, "json": True, "stream": True},
        "pricing": {"in": "Free", "out": "Free"},
    },
    # ───────────────────────────────────────────────────────────────────────
    # Fireworks AI (api.fireworks.ai) — prepaid ($6 per account)
    # ───────────────────────────────────────────────────────────────────────
    "glm-5p2": {
        "provider": "fireworks", "real_model": "accounts/fireworks/models/glm-5p2",
        "desc": "GLM 5.2 — Opus-level reasoning, 131K ctx, interleaved thinking", "style": "reasoning", "tokens": 131072,
        "developer": "Zhipu AI / Z.AI", "display_name": "GLM 5.2",
        "max_output": 131072, "params": "Undisclosed (MoE)",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "$1.40", "out": "$4.40", "cached_in": "$0.14"},
    },
    "kimi-k2p7-code": {
        "provider": "fireworks", "real_model": "accounts/fireworks/models/kimi-k2p7-code",
        "desc": "Kimi K2.7 Code — agentic coding specialist, 32K ctx", "style": "direct", "tokens": 32768,
        "developer": "Moonshot AI / Kimi", "display_name": "Kimi K2.7 Code",
        "max_output": 32768, "params": "~1T MoE",
        "capabilities": {"text": True, "code": True, "thinking": False, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "$0.95", "out": "$4.00", "cached_in": "$0.19"},
    },
    "qwen3p7-plus": {
        "provider": "fireworks", "real_model": "accounts/fireworks/models/qwen3p7-plus",
        "desc": "Qwen 3.7 Plus — affordable reasoning model, 131K ctx", "style": "reasoning", "tokens": 131072,
        "developer": "Alibaba / Qwen", "display_name": "Qwen 3.7 Plus",
        "max_output": 131072, "params": "Undisclosed",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "$0.40", "out": "$1.60", "cached_in": "$0.08"},
    },
    "deepseek-v4-pro": {
        "provider": "fireworks", "real_model": "accounts/fireworks/models/deepseek-v4-pro",
        "desc": "DeepSeek V4 Pro — deep reasoning, 131K ctx, interleaved thinking", "style": "reasoning", "tokens": 131072,
        "developer": "DeepSeek", "display_name": "DeepSeek V4 Pro",
        "max_output": 131072, "params": "Undisclosed (MoE)",
        "capabilities": {"text": True, "code": True, "thinking": True, "tools": True, "vision": False, "web_search": False, "json": True, "stream": True},
        "pricing": {"in": "$1.74", "out": "$3.48", "cached_in": "$0.145"},
    },
}

# ── Provider base URLs ──────────────────────────────────────────────────────
PROVIDER_BASE_URLS = {
    "claude":    "https://claude.ai",
    "nvidia":    "https://integrate.api.nvidia.com/v1",
    "openrouter":"https://openrouter.ai/api/v1",
    "google":    "https://generativelanguage.googleapis.com/v1beta",
    "fireworks": "https://api.fireworks.ai/inference/v1",
}

# ── Auto-detect provider from API key format ────────────────────────────────
def detect_provider_from_key(api_key):
    """Automatically detect which provider an API key belongs to based on its format/prefix.
    
    Returns dict {id, slug, name} from the database, or None if unrecognized.
    Supports: NVIDIA NIM, OpenRouter, Google AI Studio, Fireworks, OpenAI, Anthropic (Claude).
    
    Key patterns (based on research 2025-07):
    - NVIDIA NIM:    nvapi-[A-Za-z0-9]{64,}         (~70-90 chars)
    - OpenRouter:    sk-or-v1-[A-Za-z0-9]{40,}      (~50-60 chars)
    - Google AI:     AIza[A-Za-z0-9_-]{35}          (exactly 39 chars, starts with AIza)
    - Anthropic:     sk-ant-[a-z0-9]{4}-[A-Za-z0-9]{60,}  (~70-80 chars)
    - OpenAI:        sk-(-[a-z]+)?-[A-Za-z0-9]{32,} (sk-, sk-proj-, sk-svcacct-, 48-56+ chars)
    - Fireworks:     [A-Za-z0-9]{32,64}             (no prefix, hex-like, 40+ chars)
    """
    k = api_key.strip()
    kl = k.lower()
    klen = len(k)
    
    if klen < 10:  # Too short to be valid
        return None
    
    # 1. NVIDIA NIM keys: nvapi- prefix (70-90 chars)
    if kl.startswith("nvapi-") and klen >= 70:
        slug = "nvidia"
    
    # 2. OpenRouter keys: sk-or-v1- or sk-or- prefix (50-60 chars)
    elif kl.startswith("sk-or-v1-") or kl.startswith("sk-or-"):
        slug = "openrouter"
    
    # 3. Google AI Studio keys: AIza prefix (exactly 39 chars)
    elif k.startswith("AIza") and klen == 39:
        slug = "google"
    
    # 4. Anthropic/Claude keys: sk-ant- prefix (70-80 chars, with mid-hyphen)
    elif kl.startswith("sk-ant-") and klen >= 70:
        slug = "claude"
    
    # 5. OpenAI keys: sk-, sk-proj-, sk-svcacct- (not sk-or/sk-ant)
    elif (kl.startswith("sk-proj-") or kl.startswith("sk-svcacct-") or 
          (kl.startswith("sk-") and not kl.startswith("sk-or") and not kl.startswith("sk-ant") and klen >= 48)):
        slug = "openai"
    
    # 6. Fireworks keys: fw_ prefix (typically 25 chars)
    elif kl.startswith("fw_") and klen >= 20:
        slug = "fireworks"
    
    # 7. Google AI Studio fallback (AIza + 35+ chars)
    elif k.startswith("AIza") and klen >= 35:
        slug = "google"
    
    else:
        return None
    
    conn = get_db()
    row = conn.execute("SELECT id, slug, name FROM api_providers WHERE slug=?", (slug,)).fetchone()
    conn.close()
    if row:
        return {"id": row["id"], "slug": row["slug"], "name": row["name"]}
    return None

# ── Cookie parser ───────────────────────────────────────────────────────
def detect_platform_from_content(raw): 
    return "claude" if ("claude.ai" in raw.lower() or "anthropic" in raw.lower()) else "unknown"
def parse_netscape_cookies(raw):
    cookies = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = line.split("\t")
        if len(parts) < 7: continue
        cookies.append({"domain": parts[0], "flag": parts[1], "path": parts[2], "secure": parts[3], "expiration": parts[4], "name": parts[5], "value": parts[6]})
    return cookies

# ═══════════════════════════════════════════════════════════════════════════
# SMART KEY ROTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def get_provider_keys(provider_slug):
    """Get active, non-dead, non-suspended keys for a provider, ordered by usage_count."""
    conn = get_db()
    rows = conn.execute("""
        SELECT k.*, p.base_url, p.provider_type
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = ? AND k.is_active = 1 AND k.dead = 0 AND k.suspended = 0
        ORDER BY k.usage_count ASC, k.created_at ASC
    """, (provider_slug,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_key_dead(key_id, reason=""):
    """Permanently mark a key as dead (for prepaid providers like Fireworks)."""
    conn = get_db()
    conn.execute("UPDATE api_keys SET dead=1, is_active=0, last_error_msg=?, last_error_at=CURRENT_TIMESTAMP WHERE id=?", (reason, key_id))
    conn.commit()
    conn.close()

def mark_key_suspended(key_id, reason=""):
    """Mark a key as suspended (temporary — admin can reactivate). Differs from dead."""
    conn = get_db()
    conn.execute("UPDATE api_keys SET suspended=1, is_active=0, last_error_msg=?, last_error_at=CURRENT_TIMESTAMP WHERE id=?", (reason, key_id))
    conn.commit()
    conn.close()

def mark_key_rate_limited(key_id, reason=""):
    """Temporarily bump usage so key rotates to the back."""
    conn = get_db()
    conn.execute("UPDATE api_keys SET usage_count=usage_count+100, error_count=error_count+1, last_error_msg=?, last_error_at=CURRENT_TIMESTAMP WHERE id=?", (reason, key_id))
    conn.commit()
    conn.close()

def mark_key_error(key_id, reason=""):
    """Increment error count, may disable if too many errors."""
    conn = get_db()
    key = conn.execute("SELECT error_count FROM api_keys WHERE id=?", (key_id,)).fetchone()
    errs = key["error_count"] + 1 if key else 1
    if errs >= 10:
        conn.execute("UPDATE api_keys SET is_active=0, last_error_msg=? WHERE id=?", (reason, key_id))
    else:
        conn.execute("UPDATE api_keys SET error_count=?, last_error_msg=?, last_error_at=CURRENT_TIMESTAMP WHERE id=?", (errs, reason, key_id))
    conn.commit()
    conn.close()

def record_proxy_request(model_slug, provider_slug, key_id, status, latency_ms, error_msg=None, proxy_ip=None, proxy_country=None):
    conn = get_db()
    conn.execute("INSERT INTO proxy_requests (model_slug, provider_slug, key_id, status, latency_ms, error_msg, proxy_ip, proxy_country) VALUES (?,?,?,?,?,?,?,?)",
                 (model_slug, provider_slug, key_id, status, latency_ms, error_msg, proxy_ip, proxy_country))
    conn.commit()
    conn.close()

def bump_key_usage(key_id):
    conn = get_db()
    conn.execute("UPDATE api_keys SET usage_count=usage_count+1, last_used_at=CURRENT_TIMESTAMP WHERE id=?", (key_id,))
    conn.commit()
    conn.close()

# ═══════════════════════════════════════════════════════════════════════════
# ACCOUNT INFO FETCHER — Fireworks AI
# ═══════════════════════════════════════════════════════════════════════════

def fetch_fireworks_account_info(api_key):
    """Fetch comprehensive account info for a Fireworks AI key.
    
    Makes a minimal chat completion to extract rate-limit headers,
    fetches available models, parses error messages for account details,
    and calculates promotional credit remaining ($6 initial).
    
    Returns dict with 18+ fields: account_name, account_status, plan_type,
    credits_dollar, rate_limits, models_available, suspension_reason, etc.
    """
    import json as _json
    import urllib.request, urllib.error, re
    
    result = {
        "provider_slug": "fireworks",
        "account_name": None,
        "account_email": None,
        "account_status": "unknown",
        "plan_type": None,
        "credits_remaining": None,
        "credits_total": None,
        "credits_dollar": None,
        "credits_initial": None,
        "rate_limit_prompt": None,
        "rate_limit_generated": None,
        "rate_limit_remaining_prompt": None,
        "rate_limit_remaining_generated": None,
        "models_available": None,
        "models_count": None,
        "billing_url": "https://fireworks.ai/account/billing",
        "suspension_reason": None,
        "raw_response": None,
    }
    
    # Fireworks $6 promotional credit ≈ 7.2M prompt tokens
    FW_CREDITS_DOLLAR_INITIAL = 6.00
    FW_CREDITS_TOKEN_LIMIT = 7200000

    base_url = "https://api.fireworks.ai/inference/v1"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # ── Step 1: Make a minimal chat completion to extract rate-limit headers ──
    try:
        payload = _json.dumps({
            "model": "accounts/fireworks/models/glm-5p2",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
            "temperature": 0,
        }).encode()
        
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_headers = dict(resp.headers)
                body = _json.loads(resp.read().decode())

                result["account_status"] = "active"
                result["plan_type"] = "promotional"  # $6 free credit tier
                
                # Extract rate limit headers
                prompt_limit = int(resp_headers.get("x-ratelimit-limit-tokens-prompt", 0))
                prompt_remaining = int(resp_headers.get("x-ratelimit-remaining-tokens-prompt", 0))
                gen_limit = int(resp_headers.get("x-ratelimit-limit-tokens-generated", 0))
                gen_remaining = int(resp_headers.get("x-ratelimit-remaining-tokens-generated", 0))
                
                result["rate_limit_prompt"] = prompt_limit or FW_CREDITS_TOKEN_LIMIT
                result["rate_limit_remaining_prompt"] = prompt_remaining if prompt_remaining else prompt_limit - 13 if prompt_limit else None
                result["rate_limit_generated"] = gen_limit or None
                result["rate_limit_remaining_generated"] = gen_remaining or None
                
                # Calculate credit in dollars
                if prompt_limit and prompt_limit >= FW_CREDITS_TOKEN_LIMIT * 0.8:  # ~7M = promotional tier
                    prompt_rem = prompt_remaining if prompt_remaining else (prompt_limit - 13)
                    dollar_remaining = round((prompt_rem / FW_CREDITS_TOKEN_LIMIT) * FW_CREDITS_DOLLAR_INITIAL, 2)
                    result["credits_remaining"] = f"{prompt_rem:,}"
                    result["credits_total"] = f"{prompt_limit:,}"
                    result["credits_dollar"] = f"${dollar_remaining:.2f}"
                    result["credits_initial"] = f"${FW_CREDITS_DOLLAR_INITIAL:.2f}"
                else:
                    result["credits_remaining"] = str(prompt_limit)
                    result["credits_total"] = str(prompt_limit)
                    result["credits_dollar"] = None

                # Save raw key headers
                result["raw_response"] = _json.dumps({
                    "status": "ok",
                    "headers": {k: v for k, v in resp_headers.items()
                                if any(p in k.lower() for p in ("x-ratelimit", "fireworks"))}
                })
                
                # Extract account name from usage/model field if available
                model_name = body.get("model", "")
                usage = body.get("usage", {})
                result["_model_used"] = model_name
                result["_usage_details"] = _json.dumps(usage) if usage else None

        except urllib.error.HTTPError as e:
            body_text = e.read().decode()
            resp_headers = dict(e.headers) if hasattr(e, 'headers') else {}
            result["raw_response"] = body_text[:2000]
            
            code = e.code
            msg = ""
            try:
                err = _json.loads(body_text)
                msg = err.get("error", {}).get("message", "")
            except:
                msg = body_text[:500]

            if code in (403, 422, 412):
                # Account suspended
                result["account_status"] = "suspended"
                result["suspension_reason"] = msg
                result["plan_type"] = "promotional"
                
                # Extract account name: "Account X is suspended..."
                name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
                if name_match:
                    result["account_name"] = name_match.group(1)
                
                # Extract email if present in message
                email_match = re.search(r'([\w.+-]+@[\w-]+\.[\w.]+)', msg)
                if email_match:
                    result["account_email"] = email_match.group(1)
                    
                # Extract credits/dollar info from suspension message
                dollar_match = re.search(r'\$([\d.]+)', msg)
                if dollar_match:
                    result["credits_initial"] = f"${FW_CREDITS_DOLLAR_INITIAL:.2f}"
                    result["credits_dollar"] = "$0.00"
                    result["credits_remaining"] = "0"
                    result["credits_total"] = str(FW_CREDITS_TOKEN_LIMIT)
                    
            elif code == 401:
                result["account_status"] = "invalid_key"
                result["suspension_reason"] = "Authentication failed — invalid API key"
            elif code == 429:
                result["account_status"] = "rate_limited"
                result["suspension_reason"] = "Rate limit exceeded — try again later"
            else:
                result["account_status"] = "error"
                result["suspension_reason"] = f"HTTP {code}: {msg[:300]}"

    except urllib.error.URLError as e:
        result["account_status"] = "network_error"
        result["suspension_reason"] = f"Network error: {str(e.reason)[:300]}" if hasattr(e, 'reason') else str(e)[:300]
    except Exception as e:
        result["account_status"] = "fetch_failed"
        result["suspension_reason"] = f"{type(e).__name__}: {str(e)[:400]}"

    # ── Step 2: Fetch available models (works even for some suspended accounts) ──
    try:
        req2 = urllib.request.Request(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        with urllib.request.urlopen(req2, timeout=10) as resp:
            models_data = _json.loads(resp.read().decode())
            model_ids = [m.get("id", "") for m in models_data.get("data", [])]
            result["models_available"] = _json.dumps(model_ids[:50])
            result["models_count"] = len(model_ids)
            
            # Try to extract org/owner info from first model
            if model_ids and not result.get("account_name"):
                first_model = models_data.get("data", [{}])[0] if models_data.get("data") else {}
                owned_by = first_model.get("owned_by", "")
                if owned_by and not owned_by.startswith("accounts/"):
                    result["account_name"] = owned_by
    except urllib.error.HTTPError as e:
        # 412 for suspended accounts — still try to parse body
        if e.code == 412 and result["account_status"] != "suspended":
            try:
                err = _json.loads(e.read().decode())
                msg = err.get("error", {}).get("message", "")
                if "suspended" in msg.lower():
                    result["account_status"] = "suspended"
                    result["suspension_reason"] = msg
                    name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
                    if name_match:
                        result["account_name"] = name_match.group(1)
            except:
                pass
    except:
        pass

    # ── Step 3: Post-processing ──
    if result["account_status"] == "active":
        if not result["account_name"]:
            # Try to get account name from models endpoint's owned_by
            try:
                models_list = _json.loads(result["models_available"]) if result["models_available"] else []
                if models_list:
                    result["account_name"] = models_list[0].split("/")[1] if "/" in models_list[0] else None
            except:
                pass

    # Ensure credits_dollar = "$0.00" for suspended accounts
    if result["account_status"] == "suspended" and not result.get("credits_dollar"):
        result["credits_remaining"] = "0"
        result["credits_total"] = str(FW_CREDITS_TOKEN_LIMIT)
        result["credits_dollar"] = "$0.00"
        result["credits_initial"] = f"${FW_CREDITS_DOLLAR_INITIAL:.2f}"

    return result


def save_account_info(key_id, info):
    """Save or update account info for a key in the database."""
    conn = get_db()
    conn.execute("""INSERT OR REPLACE INTO key_account_info
        (key_id, provider_slug, account_name, account_email, account_status, plan_type,
         credits_remaining, credits_total, credits_dollar, credits_initial,
         rate_limit_prompt, rate_limit_generated,
         rate_limit_remaining_prompt, rate_limit_remaining_generated,
         models_available, models_count, billing_url, suspension_reason, raw_response, last_fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (key_id, info.get("provider_slug"), info.get("account_name"),
         info.get("account_email"),
         info.get("account_status"), info.get("plan_type"),
         info.get("credits_remaining"), info.get("credits_total"),
         info.get("credits_dollar"), info.get("credits_initial"),
         info.get("rate_limit_prompt"), info.get("rate_limit_generated"),
         info.get("rate_limit_remaining_prompt"), info.get("rate_limit_remaining_generated"),
         info.get("models_available"), info.get("models_count"), info.get("billing_url"),
         info.get("suspension_reason"), info.get("raw_response")))
    conn.commit()
    conn.close()


def fetch_and_store_account_info(key_id, api_key, provider_slug="fireworks"):
    """Fetch account info and store in DB. Returns the info dict.
    Also updates the api_keys table: if account is suspended, mark key accordingly."""
    if provider_slug != "fireworks":
        return {"error": f"Account info fetching not supported for provider: {provider_slug}"}

    info = fetch_fireworks_account_info(api_key)
    save_account_info(key_id, info)

    # Auto-mark key as suspended if account status is suspended
    if info.get("account_status") == "suspended":
        conn = get_db()
        conn.execute("UPDATE api_keys SET suspended=1, is_active=0, last_error_msg=? WHERE id=?", 
                     (f"Account suspended: {info.get('suspension_reason', '')[:200]}", key_id))
        conn.commit()
        conn.close()
        app.logger.info(f"[account-info] Key #{key_id} auto-marked SUSPENDED — {info.get('suspension_reason', '')[:100]}")
    elif info.get("account_status") == "active":
        # If key was previously suspended but now active, unsuspend it
        conn = get_db()
        key = conn.execute("SELECT suspended FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if key and key["suspended"]:
            conn.execute("UPDATE api_keys SET suspended=0, is_active=1, last_error_msg=NULL WHERE id=?", (key_id,))
            conn.commit()
            app.logger.info(f"[account-info] Key #{key_id} auto-UNSUSPENDED — account now active")
        conn.close()

    return info

# ═══════════════════════════════════════════════════════════════════════════
# PROXY ENGINE — try keys in rotation until one works
# ═══════════════════════════════════════════════════════════════════════════

def proxy_to_provider(provider_slug, real_model, model_slug):
    """Forward the incoming request to the actual provider, trying keys in rotation."""
    
    # ── Claude: special cookie-based handling ──
    if provider_slug == "claude":
        return proxy_to_claude(real_model, model_slug)
    
    # ── Standard API key providers ──
    keys = get_provider_keys(provider_slug)
    if not keys:
        return jsonify({"error": f"No active keys for provider '{provider_slug}'", "model": model_slug}), 503
    body = request.get_data()
    incoming_headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length', 'authorization', 'accept-encoding')}
    
    tried_keys = []
    
    for key_info in keys:
        key_id = key_info["id"]
        base_url = key_info["base_url"]
        key_val = key_info["key_value"]
        provider_type = key_info.get("provider_type", "free")
        
        start = time.time()
        error_msg = None
        
        try:
            # All current providers (NVIDIA, OpenRouter, Google, Fireworks) use OpenAI-compatible /v1/chat/completions
            url = f"{base_url}/chat/completions"
            payload = inject_model_into_body(body, real_model, provider_slug)
            
            is_streaming = False
            try:
                body_data = json.loads(payload)
                is_streaming = body_data.get("stream", False)
            except: pass
            
            headers = {"Authorization": f"Bearer {key_val}", "Content-Type": "application/json",
                       "Accept": "text/event-stream" if is_streaming else "application/json"}
            for h, v in incoming_headers.items():
                try: headers[h] = v
                except: pass
            
            # Use httpx with optional proxy (API keys don't need per-account proxy)
            proxy = get_proxy_url()  # Rotating proxy, no session ID for API keys
            with httpx.Client(proxy=proxy, timeout=120.0, verify=False) as client:
                resp = client.post(url, content=payload, headers=headers)

            latency = int((time.time() - start) * 1000)

            # ── Check response status BEFORE recording success ──
            # If status >= 400, handle error and try next key
            if resp.status_code >= 400:
                code = resp.status_code
                try: body_err = resp.text[:500]
                except: body_err = ""
                body_err_lower = body_err.lower()

                # ── Determine error type and handle accordingly ──
                # 412 = Account suspended (Fireworks-specific — could be temporary billing)
                # 402 = Payment required / depleted
                # "suspended" = temporarily suspended — admin can reactivate
                # "insufficient" / "quota" / "spending limit" / "failure to pay" = permanent
                # 429 = Rate limited (temporary)
                # 401/403 = Auth error (permanent for prepaid, temp for free)

                is_suspended = (
                    "suspended" in body_err_lower
                    and "insufficient" not in body_err_lower
                    and "quota" not in body_err_lower
                    and "spending" not in body_err_lower
                )

                is_permanent = (
                    code == 402 or
                    "insufficient" in body_err_lower or
                    "quota" in body_err_lower or
                    "spending limit" in body_err_lower or
                    "failure to pay" in body_err_lower or
                    "billing" in body_err_lower and "limit" in body_err_lower
                )

                if is_suspended:
                    # Temporary suspension — key can be reactivated by admin
                    mark_key_suspended(key_id, f"{code} Account suspended: {body_err[:200]}")
                    error_msg = "SUSPENDED"
                    app.logger.warning(f"[proxy] Key #{key_id} ({provider_slug}) marked SUSPENDED — {code}: {body_err[:100]}")
                elif is_permanent:
                    # Permanent death — account depleted, won't recover
                    mark_key_dead(key_id, f"{code} Account suspended/depleted: {body_err[:200]}")
                    error_msg = "ACCOUNT_SUSPENDED"
                    app.logger.warning(f"[proxy] Key #{key_id} ({provider_slug}) marked DEAD — {code}: {body_err[:100]}")
                elif code == 429:
                    # Temporary rate limit — rotate to back
                    mark_key_rate_limited(key_id, f"429: {body_err[:200]}")
                    error_msg = "RATE_LIMITED"
                elif code in (401, 403):
                    if provider_type == "prepaid" or provider_slug == "fireworks":
                        mark_key_dead(key_id, f"{code} Auth failed: {body_err[:200]}")
                        error_msg = "DEAD_AUTH"
                    else:
                        mark_key_error(key_id, f"{code}: {body_err[:200]}")
                        error_msg = "AUTH_ERROR"
                else:
                    mark_key_error(key_id, f"{code}: {body_err[:200]}")
                    error_msg = f"HTTP_{code}"

                record_proxy_request(model_slug, provider_slug, key_id, "error", latency, error_msg)
                tried_keys.append({"key_id": key_id, "error": error_msg, "code": code})
                continue  # ← Try next key!

            # ── Success — record and return ──
            bump_key_usage(key_id)
            record_proxy_request(model_slug, provider_slug, key_id, "ok", latency)

            if is_streaming:
                def generate():
                    for chunk in resp.iter_bytes(8192):
                        yield chunk
                return Response(stream_with_context(generate()), status=resp.status_code, headers={
                    "Content-Type": resp.headers.get("Content-Type", "text/event-stream"),
                    "X-Proxy-Provider": provider_slug, "X-Proxy-Key": str(key_id),
                    "X-Proxy-Latency": str(latency), "X-Proxy-Model": real_model,
                })
            else:
                # ── Post-process non-streaming responses ──
                resp_body = resp.content
                # Strip reasoning/thinking prefix for reasoning-style models
                model_entry = MODELS.get(model_slug, {})
                if model_entry.get("style") == "reasoning":
                    resp_body = strip_reasoning_prefix(resp_body, model_slug)

                return resp_body, resp.status_code, {
                    "Content-Type": resp.headers.get("Content-Type", "application/json"),
                    "X-Proxy-Provider": provider_slug, "X-Proxy-Key": str(key_id),
                    "X-Proxy-Latency": str(latency),
                }
        
        except httpx.HTTPStatusError as e:
            latency = int((time.time() - start) * 1000)
            code = e.response.status_code
            body_err = e.response.text[:500]
            # ── Same logic as above — differentiate suspended vs dead ──
            body_err_lower = body_err.lower()
            is_suspended = (
                "suspended" in body_err_lower
                and "insufficient" not in body_err_lower
                and "quota" not in body_err_lower
                and "spending" not in body_err_lower
            )
            is_permanent = (
                code == 402 or
                "insufficient" in body_err_lower or "quota" in body_err_lower or
                "spending limit" in body_err_lower or
                "failure to pay" in body_err_lower
            )
            if is_suspended:
                mark_key_suspended(key_id, f"{code} Account suspended: {body_err[:200]}")
                error_msg = "SUSPENDED"
            elif is_permanent:
                mark_key_dead(key_id, f"{code} Account suspended/depleted: {body_err[:200]}")
                error_msg = "ACCOUNT_SUSPENDED"
            elif code == 429:
                mark_key_rate_limited(key_id, f"429: {body_err[:200]}")
                error_msg = "RATE_LIMITED"
            elif code in (401, 403):
                if provider_type == "prepaid" or provider_slug == "fireworks":
                    mark_key_dead(key_id, f"{code} Auth failed: {body_err[:200]}")
                    error_msg = "DEAD_AUTH"
                else:
                    mark_key_error(key_id, f"{code}: {body_err[:200]}")
                    error_msg = "AUTH_ERROR"
            else:
                mark_key_error(key_id, f"{code}: {body_err[:200]}")
                error_msg = f"HTTP_{code}"
            record_proxy_request(model_slug, provider_slug, key_id, "error", latency, error_msg)
            tried_keys.append({"key_id": key_id, "error": error_msg, "code": code})
            continue
        
        except Exception as e:
            latency = int((time.time() - start) * 1000)
            error_msg = str(e)[:200]
            mark_key_error(key_id, error_msg)
            record_proxy_request(model_slug, provider_slug, key_id, "error", latency, error_msg)
            tried_keys.append({"key_id": key_id, "error": error_msg})
            continue
    
    # All keys failed — try cross-provider fallback before giving up
    app.logger.warning(f"[proxy] All {len(tried_keys)} keys failed for {provider_slug}/{model_slug}: {tried_keys}")
    
    # ── Cross-Provider Fallback ──
    # If this provider has a fallback chain, try the next provider automatically
    fallback_chain = PROVIDER_FALLBACK_CHAIN.get(provider_slug, [])
    for fb_provider, fb_model, fb_label in fallback_chain:
        fb_keys = get_provider_keys(fb_provider)
        if not fb_keys:
            continue
        
        app.logger.info(f"[proxy] Cross-provider fallback: {provider_slug}/{model_slug} → {fb_provider}/{fb_model} ({fb_label})")
        
        # Build a modified request with the fallback model
        try:
            body_data = json.loads(body)
            body_data["model"] = MODELS.get(fb_model, {}).get("real_model", fb_model)
            fb_body = json.dumps(body_data).encode()
        except:
            fb_body = body  # If we can't modify, just forward as-is
        
        for fb_key in fb_keys:
            fb_key_id = fb_key["id"]
            fb_base_url = fb_key["base_url"]
            fb_key_val = fb_key["key_value"]
            
            fb_start = time.time()
            try:
                fb_url = f"{fb_base_url}/chat/completions"
                
                fb_payload = inject_model_into_body(fb_body, MODELS.get(fb_model, {}).get("real_model", fb_model), fb_provider)
                fb_headers = {"Authorization": f"Bearer {fb_key_val}", "Content-Type": "application/json"}
                
                proxy = get_proxy_url()
                with httpx.Client(proxy=proxy, timeout=120.0, verify=False) as client:
                    fb_resp = client.post(fb_url, content=fb_payload, headers=fb_headers)
                
                fb_latency = int((time.time() - fb_start) * 1000)
                
                if fb_resp.status_code < 400:
                    bump_key_usage(fb_key_id)
                    record_proxy_request(fb_model, fb_provider, fb_key_id, "ok", fb_latency)
                    app.logger.info(f"[proxy] Fallback SUCCESS: {fb_provider}/{fb_model} via key #{fb_key_id}")
                    
                    # Add fallback notice in headers
                    if is_streaming:
                        def fb_generate():
                            for chunk in fb_resp.iter_bytes(8192):
                                yield chunk
                        return Response(stream_with_context(fb_generate()), status=fb_resp.status_code, headers={
                            "Content-Type": fb_resp.headers.get("Content-Type", "text/event-stream"),
                            "X-Proxy-Provider": fb_provider, "X-Proxy-Key": str(fb_key_id),
                            "X-Proxy-Latency": str(fb_latency), "X-Proxy-Model": fb_model,
                            "X-Proxy-Fallback": f"{provider_slug}->{fb_provider}",
                            "X-Proxy-Fallback-Reason": "Primary provider exhausted",
                        })
                    else:
                        # ── Post-process fallback non-streaming responses ──
                        fb_body = fb_resp.content
                        fb_model_entry = MODELS.get(fb_model, {})
                        if fb_model_entry.get("style") == "reasoning":
                            fb_body = strip_reasoning_prefix(fb_body, fb_model)

                        return fb_body, fb_resp.status_code, {
                            "Content-Type": fb_resp.headers.get("Content-Type", "application/json"),
                            "X-Proxy-Provider": fb_provider, "X-Proxy-Key": str(fb_key_id),
                            "X-Proxy-Latency": str(fb_latency),
                            "X-Proxy-Fallback": f"{provider_slug}->{fb_provider}",
                            "X-Proxy-Fallback-Reason": "Primary provider exhausted",
                        }
                else:
                    # Fallback key also failed — continue to next
                    fb_code = fb_resp.status_code
                    try: fb_err = fb_resp.text[:200]
                    except: fb_err = ""
                    if fb_code == 429:
                        mark_key_rate_limited(fb_key_id, f"429: {fb_err}")
                    elif fb_code in (401, 403, 412, 402):
                        mark_key_dead(fb_key_id, f"{fb_code}: {fb_err}")
                    else:
                        mark_key_error(fb_key_id, f"{fb_code}: {fb_err}")
                    record_proxy_request(fb_model, fb_provider, fb_key_id, "error", fb_latency, f"HTTP_{fb_code}")
                    continue
            except Exception as fb_e:
                app.logger.warning(f"[proxy] Fallback key #{fb_key_id} error: {str(fb_e)[:100]}")
                continue
    
    # All keys AND all fallbacks failed — return user-friendly error
    is_stream = False
    try:
        is_stream = json.loads(body).get("stream", False)
    except: pass
    
    return format_error_response(
        "ALL_KEYS_EXHAUSTED", model_slug, provider_slug,
        tried_count=len(tried_keys),
        retry_after_ms=5000,
        is_streaming=is_stream,
    )

# ═══════════════════════════════════════════════════════════════════════════
# PRODUCTION RESILIENCE LAYER — Mid-stream failover, cross-provider fallback,
# user-friendly error formatting, SSE error events
# ═══════════════════════════════════════════════════════════════════════════

import random as _random

# ── Cross-Provider Fallback Chain ──
# When ALL keys for a provider are exhausted, try a similar model from another provider.
# This gives the user a seamless experience even when an entire provider goes down.
PROVIDER_FALLBACK_CHAIN = {
    "fireworks": [
        ("nvidia",    "nvidia-llama-3.3-70b", "Llama 3.3 70B (NVIDIA NIM fallback)"),
        ("openrouter","or-llama-3.3-70b",     "Llama 3.3 70B (OpenRouter fallback)"),
    ],
    "nvidia": [
        ("openrouter","or-llama-3.3-70b",     "Llama 3.3 70B (OpenRouter fallback)"),
        ("fireworks", "glm-5p2",              "GLM-5.2 (Fireworks fallback)"),
    ],
    "openrouter": [
        ("nvidia",    "nvidia-llama-3.3-70b", "Llama 3.3 70B (NVIDIA NIM fallback)"),
        ("google",    "gemini-2.0-flash",     "Gemini 2.0 Flash (Google fallback)"),
    ],
    "google": [
        ("openrouter","or-gemini-flash",      "Gemini 2.0 Flash (OpenRouter fallback)"),
        ("nvidia",    "nvidia-llama-3.3-70b", "Llama 3.3 70B (NVIDIA NIM fallback)"),
    ],
    # Claude has no direct API fallback, but GLM is the closest reasoning model
    "claude": [
        ("fireworks", "glm-5p2",              "GLM-5.2 Reasoning (Fireworks fallback for Claude)"),
        ("google",    "gemini-2.5-pro",       "Gemini 2.5 Pro (Google fallback for Claude)"),
    ],
}

# ── User-Friendly Error Formatter ──
def format_error_response(error_type, model_slug, provider_slug=None, detail=None,
                          tried_count=0, retry_after_ms=5000, is_streaming=False):
    """Format a user-friendly error response that explains what happened.
    
    Returns either a JSON response (non-streaming) or an SSE event (streaming).
    The error message is written in plain language that a developer can understand
    and act on — not raw internal error codes.
    """
    error_messages = {
        "RATE_LIMITED": {
            "title": "Rate Limit Reached",
            "message": "The AI provider is temporarily limiting requests from this key. "
                       "The system automatically rotated to another key, but all available "
                       "keys for this provider are currently cooling down.",
            "suggestion": f"Wait {retry_after_ms // 1000}s and retry, or try a different model.",
        },
        "ALL_KEYS_EXHAUSTED": {
            "title": "All Provider Keys Exhausted",
            "message": f"All {tried_count} API key(s) for '{provider_slug}' are currently "
                       "unavailable (rate-limited, suspended, or dead). "
                       "The system attempted cross-provider fallback but no suitable "
                       "alternative was found.",
            "suggestion": "Try again in a few minutes, or use a different model from another provider.",
        },
        "CLAUDE_ALL_SESSIONS_BUSY": {
            "title": "All Claude Sessions Busy",
            "message": f"All {tried_count} Claude cookie sessions are currently in cooldown "
                       "or expired. Claude.ai enforces per-account rate limits.",
            "suggestion": f"Wait {retry_after_ms // 1000}s for cooldown to expire, "
                          "or upload fresh Claude cookies at /upload.",
        },
        "TIMEOUT": {
            "title": "Request Timeout",
            "message": f"The request to '{provider_slug}' timed out after exceeding the "
                       "maximum allowed response time. This can happen with complex reasoning "
                       "models that take longer to generate responses.",
            "suggestion": "Try simplifying your prompt, reducing max_tokens, or using a faster model.",
        },
        "CLOUDFLARE_CHALLENGE": {
            "title": "Cloudflare Protection Triggered",
            "message": "Claude.ai's Cloudflare protection blocked the request. "
                       "This usually happens when the residential proxy IP is flagged.",
            "suggestion": "The system will auto-retry with a different proxy. "
                          "If this persists, refresh the Claude cookies.",
        },
        "PROXY_ERROR": {
            "title": "Proxy Connection Error",
            "message": "The residential proxy failed to connect to the AI provider.",
            "suggestion": "The system auto-blacklisted the failing proxy and will use a different one.",
        },
        "INTERNAL_ERROR": {
            "title": "Internal Server Error",
            "message": f"An unexpected error occurred while processing your request: {detail}",
            "suggestion": "Please retry. If the problem persists, check server logs.",
        },
        "MODEL_NOT_FOUND": {
            "title": "Model Not Found",
            "message": f"The model '{model_slug}' is not in the available models list.",
            "suggestion": "Check /v1/models for the list of available models.",
        },
        "INVALID_REQUEST": {
            "title": "Invalid Request",
            "message": f"The request was malformed: {detail}",
            "suggestion": "Check the API documentation at /docs for the correct format.",
        },
    }
    
    info = error_messages.get(error_type, {
        "title": "Service Error",
        "message": detail or f"An error occurred: {error_type}",
        "suggestion": "Please retry.",
    })
    
    error_body = {
        "error": {
            "type": error_type.lower(),
            "title": info["title"],
            "message": info["message"],
            "suggestion": info["suggestion"],
            "model": model_slug,
            "provider": provider_slug,
            "retry_after_ms": retry_after_ms,
        },
        # Keep backward compatibility with OpenAI error format
        "error_code": error_type,
    }
    
    if is_streaming:
        # Return as SSE event so streaming clients receive it gracefully
        sse_data = json.dumps({"error": error_body["error"]})
        return f"data: {sse_data}\n\ndata: [DONE]\n\n", 200, {"Content-Type": "text/event-stream"}
    else:
        return jsonify(error_body), 503 if error_type != "MODEL_NOT_FOUND" and error_type != "INVALID_REQUEST" else 400


# ── Mid-Stream Partial Response Capture ──
def _capture_stream_partial(resp, max_chunks=500):
    """Capture partial content from a streaming response before it breaks.
    
    Works with both httpx responses (iter_lines) and curl_cffi responses (.text).
    Returns (partial_text, chunk_count) — the text accumulated so far.
    Used for mid-stream failover: if the stream breaks, we can send a
    continuation request to the next key with the partial text as context.
    """
    partial_text = ""
    chunk_count = 0
    
    # Method 1: Try httpx-style iter_lines (for API providers)
    if hasattr(resp, 'iter_lines'):
        try:
            for line in resp.iter_lines():
                if line:
                    chunk_count += 1
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            data = json.loads(line[6:])
                            delta = data.get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                partial_text += content
                        except (json.JSONDecodeError, IndexError, KeyError):
                            pass
                    if chunk_count >= max_chunks:
                        break
        except Exception:
            pass
    
    # Method 2: Try .text attribute (curl_cffi — already downloaded)
    # For Claude SSE, parse the full text for text_delta events
    elif hasattr(resp, 'text'):
        try:
            raw = resp.text
            if raw and "data:" in raw:
                for line in raw.split("\n"):
                    if line.startswith("data: ") and line.strip() != "data: [DONE]":
                        chunk_count += 1
                        try:
                            data = json.loads(line[6:])
                            # Claude SSE format: {"type":"completion","completion":"..."}
                            # or OpenAI format: {"choices":[{"delta":{"content":"..."}}]}
                            if "completion" in data:
                                partial_text += data.get("completion", "")
                            elif "choices" in data:
                                partial_text += data["choices"][0].get("delta", {}).get("content", "")
                        except (json.JSONDecodeError, IndexError, KeyError):
                            pass
            elif raw:
                # Not SSE — just use the text directly
                partial_text = raw
                chunk_count = 1
        except Exception:
            pass
    
    return partial_text, chunk_count


# ── Build Continuation Messages ──
def _build_continuation_messages(original_messages, partial_text):
    """Build a messages array for a continuation request.
    
    When a stream breaks mid-response, we:
    1. Keep the original user messages
    2. Add the partial assistant response as an 'assistant' message
    3. Add a 'user' message asking to continue from where it left off
    
    This makes the next key/provider continue seamlessly.
    """
    if not partial_text.strip():
        return original_messages, None
    
    continuation_messages = list(original_messages)
    continuation_messages.append({"role": "assistant", "content": partial_text})
    continuation_messages.append({
        "role": "user",
        "content": "Continue your response from exactly where you left off. "
                   "Do not repeat what you already said. Just continue naturally."
    })
    return continuation_messages, partial_text


# ── Seamless Stream Stitcher ──
def _stitch_stream(first_generator, second_generator, first_partial_text):
    """Stitch two SSE streams together seamlessly.
    
    The first stream produced partial_text before breaking.
    The second stream continues from where the first left off.
    We yield both as a single continuous SSE stream to the client.
    """
    # Yield the first generator's output (already captured as text)
    if first_partial_text:
        # Send the partial text as SSE chunks
        # Split into word-level chunks for smooth streaming
        words = first_partial_text.split()
        for i, word in enumerate(words):
            chunk_data = {
                "choices": [{"index": 0, "delta": {"content": word + (" " if i < len(words) - 1 else "")}, "finish_reason": None}]
            }
            yield f"data: {json.dumps(chunk_data)}\n\n"
    
    # Yield the second generator's output
    if second_generator:
        yield from second_generator

# ── Retry with exponential backoff + jitter ──
RETRY_MAX_ATTEMPTS = 3
RETRY_BASE_DELAY = 1.0      # seconds
RETRY_MAX_DELAY = 30.0      # cap
RETRY_RETRYABLE_STATUS = {429, 502, 503, 504, 529}

def compute_retry_delay(attempt, retry_after_header=None):
    """Exponential backoff with jitter. Respects Retry-After header if given."""
    if retry_after_header is not None:
        try:
            return min(float(retry_after_header), RETRY_MAX_DELAY)
        except (ValueError, TypeError):
            pass
    delay = min(RETRY_BASE_DELAY * (2 ** attempt), RETRY_MAX_DELAY)
    jitter = _random.uniform(0, delay * 0.1)
    return delay + jitter

def is_retryable_status(code):
    """Check if an HTTP status code is worth retrying."""
    return code in RETRY_RETRYABLE_STATUS

def retry_with_backoff(func, max_attempts=RETRY_MAX_ATTEMPTS, retryable_check=None):
    """Decorator: retry a function with exponential backoff.
    
    Args:
        func: callable that returns (result, status_code, retry_after_header)
        max_attempts: max retry attempts
        retryable_check: optional callable(status_code) -> bool
    Returns:
        Last result from func, or raises after exhausting attempts.
    """
    check = retryable_check or is_retryable_status
    result = None
    for attempt in range(max_attempts):
        result, status, retry_after = func()
        if status is None or not check(status):
            return result
        if attempt < max_attempts - 1:
            delay = compute_retry_delay(attempt, retry_after)
            time.sleep(delay)
    return result

# ── Rate limiter (token bucket per client IP) ──
_rate_limiter_lock = threading.Lock()
_rate_limiter_buckets = {}  # ip → {tokens, last_refill}
RATE_LIMIT_CAPACITY = 60    # max requests per minute
RATE_LIMIT_REFILL_RATE = 1.0  # tokens per second

def check_rate_limit(client_ip=None):
    """Token bucket rate limiter. Returns (allowed, remaining, reset_in_seconds).
    
    Uses in-memory buckets per client IP. Resets on restart.
    """
    if not client_ip:
        client_ip = request.remote_addr or "unknown"
    
    now = time.time()
    with _rate_limiter_lock:
        bucket = _rate_limiter_buckets.get(client_ip)
        if bucket is None:
            bucket = {"tokens": RATE_LIMIT_CAPACITY, "last_refill": now}
            _rate_limiter_buckets[client_ip] = bucket
        
        # Refill tokens based on elapsed time
        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(RATE_LIMIT_CAPACITY, bucket["tokens"] + elapsed * RATE_LIMIT_REFILL_RATE)
        bucket["last_refill"] = now
        
        if bucket["tokens"] >= 1.0:
            bucket["tokens"] -= 1.0
            return True, int(bucket["tokens"]), int(RATE_LIMIT_CAPACITY - bucket["tokens"]) // max(1, int(RATE_LIMIT_REFILL_RATE))
        else:
            retry_after = int((1.0 - bucket["tokens"]) / RATE_LIMIT_REFILL_RATE) + 1
            return False, 0, retry_after

# ── Proxy Blacklist (in-memory, auto-expiring) ──
_proxy_blacklist_lock = threading.Lock()
_proxy_blacklist = {}  # proxy_url → {fail_count, blacklisted_until, last_failure}

PROXY_MAX_FAILURES = 3
PROXY_BLACKLIST_DURATION = 300  # 5 minutes

def report_proxy_failure(proxy_url, reason=""):
    """Report a proxy failure. Auto-blacklists after MAX_FAILURES."""
    if not proxy_url:
        return
    with _proxy_blacklist_lock:
        entry = _proxy_blacklist.get(proxy_url, {"fail_count": 0, "blacklisted_until": 0, "last_failure": ""})
        entry["fail_count"] += 1
        entry["last_failure"] = reason[:200]
        if entry["fail_count"] >= PROXY_MAX_FAILURES:
            entry["blacklisted_until"] = time.time() + PROXY_BLACKLIST_DURATION
        _proxy_blacklist[proxy_url] = entry

def report_proxy_success(proxy_url):
    """Reset failure count on successful proxy use."""
    if not proxy_url:
        return
    with _proxy_blacklist_lock:
        if proxy_url in _proxy_blacklist:
            _proxy_blacklist[proxy_url] = {"fail_count": 0, "blacklisted_until": 0, "last_failure": ""}

def is_proxy_blacklisted(proxy_url):
    """Check if a proxy is currently blacklisted."""
    if not proxy_url:
        return False
    with _proxy_blacklist_lock:
        entry = _proxy_blacklist.get(proxy_url)
        if not entry:
            return False
        if entry.get("blacklisted_until", 0) > time.time():
            return True
        # Blacklist expired — reset
        if entry.get("blacklisted_until", 0) > 0 and entry["blacklisted_until"] <= time.time():
            entry["fail_count"] = 0
            entry["blacklisted_until"] = 0
        return False

def get_proxy_blacklist_status():
    """Get current blacklist status for dashboard display."""
    with _proxy_blacklist_lock:
        now = time.time()
        return [
            {
                "proxy": url,
                "fail_count": e["fail_count"],
                "blacklisted": e.get("blacklisted_until", 0) > now,
                "remaining_seconds": max(0, int(e.get("blacklisted_until", 0) - now)),
                "last_failure": e.get("last_failure", ""),
            }
            for url, e in _proxy_blacklist.items()
            if e["fail_count"] > 0
        ]


# ═══════════════════════════════════════════════════════════════════════════
# CLAUDE PROXY — Smart Token Rotation & State Management
# ═══════════════════════════════════════════════════════════════════════════

# ── Account Tiers ──
# Free tier has lower rate limits; Pro/Max have higher.
# Inferred from cookie content (presence of 'lastActiveOrg' with specific patterns).
ACCOUNT_TIERS = {"free": 0, "pro": 1, "max": 2}

# ── Availability States ──
# parked: temporarily rate-limited (auto-recovers after cooldown)
# quarantined: dead/expired session (needs manual intervention)
STATE_ACTIVE = "active"
STATE_PARKED = "parked"
STATE_QUARANTINED = "quarantined"

# In-memory state for Claude cookie sessions (survives between requests, lost on restart)
_claude_token_lock = threading.RLock()
_claude_token_state = {}  # cookie_file_id → {usage, cooldown_until, dead, last_error, tier, availability, affinity_pin}

COOLDOWN_SECONDS = 300  # 5 minutes cooldown after rate limit

# ── Affinity Tracker ──
# Pins a conversation thread to a specific cookie so follow-up messages
# use the same account (avoids context loss across turns).
_affinity_lock = threading.RLock()
_affinity_map = {}  # conversation_key → cookie_file_id

def _affinity_key(messages):
    """Generate a stable affinity key from the first user message.
    This lets multi-turn conversations reuse the same cookie."""
    for m in messages:
        if m.get("role") == "user":
            content = str(m.get("content", ""))
            # Use first 200 chars as a fingerprint
            return hashlib.sha256(content[:200].encode()).hexdigest()[:16]
    return None

def _get_affinity_pin(key):
    """Get the cookie_file_id pinned to this conversation key, if any."""
    if not key:
        return None
    with _affinity_lock:
        pinned_id = _affinity_map.get(key)
        if pinned_id is None:
            return None
        # Check if pinned token is still usable
        state = _get_token_state(pinned_id)
        if state["dead"] or state["availability"] == STATE_QUARANTINED:
            # Pinned token died — remove affinity
            _affinity_map.pop(key, None)
            return None
        if state["cooldown_until"] > time.time():
            # Pinned token is cooling down — remove affinity temporarily
            return None
        return pinned_id

def _set_affinity_pin(key, cookie_file_id):
    """Pin a conversation key to a cookie_file_id."""
    if not key:
        return
    with _affinity_lock:
        _affinity_map[key] = cookie_file_id
        # Keep map bounded — evict oldest if > 200 entries
        if len(_affinity_map) > 200:
            oldest_key = next(iter(_affinity_map))
            _affinity_map.pop(oldest_key, None)

def _infer_tier(cookie_set):
    """Infer account tier from cookie content. Default: free.
    Pro/Max accounts typically have different cookie patterns."""
    raw = cookie_set.get("raw_content", "")
    # Heuristic: Pro accounts often have 'cf_clearance' with longer values
    # and specific org patterns. This is a best-effort inference.
    if "maxPlan" in raw or "max_plan" in raw:
        return "max"
    if "proPlan" in raw or "pro_plan" in raw:
        return "pro"
    return "free"

def _get_token_state(cookie_id):
    """Get or create state entry for a cookie token."""
    with _claude_token_lock:
        if cookie_id not in _claude_token_state:
            _claude_token_state[cookie_id] = {
                "usage": 0,
                "cooldown_until": 0,
                "dead": False,
                "last_error": None,
                "tier": "free",
                "availability": STATE_ACTIVE,
                "affinity_pin": None,
            }
        return _claude_token_state[cookie_id]

def _mark_token_used(cookie_id):
    with _claude_token_lock:
        state = _get_token_state(cookie_id)
        state["usage"] += 1
        state["availability"] = STATE_ACTIVE
        state["cooldown_until"] = 0

def _mark_token_cooldown(cookie_id, reason=""):
    with _claude_token_lock:
        state = _get_token_state(cookie_id)
        state["cooldown_until"] = time.time() + COOLDOWN_SECONDS
        state["last_error"] = reason
        state["availability"] = STATE_PARKED

def _mark_token_dead(cookie_id, reason=""):
    with _claude_token_lock:
        state = _get_token_state(cookie_id)
        state["dead"] = True
        state["last_error"] = reason
        state["availability"] = STATE_QUARANTINED
    # Also persist to DB
    try:
        conn = get_db()
        conn.execute("UPDATE cookie_files SET raw_content = 'DEAD:' || raw_content WHERE id = ?", (cookie_id,))
        conn.commit()
        conn.close()
    except:
        pass

def _get_available_tokens(cookie_sets, affinity_pin_id=None, min_tier="free"):
    """Filter and sort cookie sets with affinity + tier awareness.
    
    Args:
        cookie_sets: list of cookie set dicts from DB
        affinity_pin_id: if set, this cookie_id is tried first (conversation affinity)
        min_tier: minimum account tier required ('free', 'pro', 'max')
    
    Sorting priority:
        1. Affinity-pinned token (if still usable)
        2. Active tokens sorted by tier (higher first) then usage (least first)
    """
    now = time.time()
    min_tier_val = ACCOUNT_TIERS.get(min_tier, 0)
    available = []
    pinned_cs = None
    
    with _claude_token_lock:
        for cs in cookie_sets:
            state = _get_token_state(cs["id"])
            
            # Infer tier if not yet set
            if state.get("tier", "free") == "free" and cs.get("raw_content"):
                inferred = _infer_tier(cs)
                if inferred != "free":
                    state["tier"] = inferred
            
            tier_val = ACCOUNT_TIERS.get(state.get("tier", "free"), 0)
            
            if state["dead"] or state["availability"] == STATE_QUARANTINED:
                continue
            if state["cooldown_until"] > now:
                continue
            if tier_val < min_tier_val:
                continue
            
            # Check if this is the affinity-pinned token
            if affinity_pin_id and cs["id"] == affinity_pin_id:
                pinned_cs = cs
                continue
            
            available.append((tier_val, state["usage"], cs))
    
    # Sort: higher tier first, then least-used
    available.sort(key=lambda x: (-x[0], x[1]))
    
    result = []
    if pinned_cs:
        result.append(pinned_cs)  # Affinity-pinned token goes first
    result.extend([cs for _, _, cs in available])
    return result

def get_claude_cookie_sets():
    """Get all Claude cookie files from DB, excluding dead ones. Includes proxy info."""
    conn = get_db()
    rows = conn.execute("""
        SELECT id, raw_content, filename, uploaded_at, proxy_session_id, proxy_enabled FROM cookie_files
        WHERE platform = 'claude' AND raw_content NOT LIKE 'DEAD:%'
        ORDER BY uploaded_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def extract_claude_cookies(cookie_file):
    """Extract ALL cookies from a Netscape cookie file for Claude API.
    
    We send ALL cookies to maximize Cloudflare acceptance — 
    including cf_clearance, __cf_bm, __ssid, _cfuvid, etc.
    Validates cookie names (safe charset) and auto-extracts XSRF token.
    """
    raw = cookie_file["raw_content"]
    cookies = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        name = parts[5]
        value = parts[6]
        if not validate_cookie_name(name):
            continue
        cookies.append({"name": name, "value": value})
    return cookies

def cookies_to_dict(cookies_list):
    """Convert [{name,value},...] list → {name: value} dict."""
    return {c["name"]: c["value"] for c in cookies_list}

def cookies_to_header(cookies_list):
    """Convert [{name,value},...] list → 'name=value; name2=value2' header."""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies_list)

def transform_claude_stream(sse_text, conv_uuid, real_model):
    """Transform Anthropic SSE stream chunks → OpenAI-compatible SSE stream.
    
    Handles both old format (completion field) and new format (content_block_delta
    with text_delta) used when tools/web search are enabled.
    Filters out tool_use/tool_result blocks — only text reaches the client.
    Transforms <antArtifact> XML → standard Markdown code blocks (with buffering
    for artifacts that span multiple SSE events).
    
    Input (Claude/Anthropic):
        Old: data: {"completion":"Hello","stop_reason":null}
        New: data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}
    
    Output (OpenAI):
        data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello"}}]}
    """
    import time as _time
    
    chunk_id = f"chatcmpl-{conv_uuid[:8]}"
    created = int(_time.time())
    
    # ── Phase 1: Extract all text and stop_reason from SSE events ──
    all_text_parts = []
    stop_reason = None
    
    for line in sse_text.split("\n"):
        if not line.startswith("data: "):
            continue
        try:
            obj = json.loads(line[6:])
        except (json.JSONDecodeError, ValueError):
            continue
        
        # Old format: direct completion field
        if obj.get("completion"):
            all_text_parts.append(obj["completion"])
        # New format: content_block_delta with text_delta
        if obj.get("type") == "content_block_delta":
            delta = obj.get("delta", {})
            if delta.get("type") == "text_delta":
                all_text_parts.append(delta.get("text", ""))
        # Stop reason
        if obj.get("stop_reason"):
            stop_reason = obj["stop_reason"]
        if obj.get("type") == "message_delta":
            if obj.get("delta", {}).get("stop_reason"):
                stop_reason = obj["delta"]["stop_reason"]
    
    full_text = "".join(all_text_parts)
    
    # ── Phase 2: Transform artifacts + filter tool XML on full text ──
    # Doing this on the full text handles artifacts that span multiple chunks
    full_text = transform_ant_artifacts(full_text)
    full_text = filter_tool_artifacts(full_text)
    
    # ── Phase 3: Re-emit as streaming chunks ──
    finish_reason = map_stop_reason(stop_reason) if stop_reason else None
    
    # Split into reasonable chunks for streaming feel (by lines, keeping newlines)
    lines = full_text.split("\n")
    for i, line in enumerate(lines):
        chunk_text = line + ("\n" if i < len(lines) - 1 else "")
        if not chunk_text:
            continue
        
        openai_chunk = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": real_model,
            "choices": [{
                "index": 0,
                "delta": {"content": chunk_text},
                "finish_reason": None,
            }],
        }
        yield f"data: {json.dumps(openai_chunk, ensure_ascii=False)}\n\n".encode()
    
    # Final chunk with finish_reason
    final_chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": real_model,
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": finish_reason or "stop",
        }],
    }
    yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def _extract_content_text(content):
    """Extract text from content that may be a string or a list of content blocks
    (multimodal support: text parts, image URLs, etc.)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(block.get("text", ""))
                elif block.get("type") == "image_url":
                    # Describe image presence (Claude.ai web doesn't accept image URLs in prompt text)
                    url = block.get("image_url", {}).get("url", "") if isinstance(block.get("image_url"), dict) else str(block.get("image_url", ""))
                    if url:
                        parts.append(f"[Image: {url[:100]}]")
                elif block.get("type") == "tool_call":
                    # Tool call from assistant — render as function call
                    fn = block.get("function", {})
                    name = fn.get("name", "unknown")
                    args = fn.get("arguments", "{}")
                    parts.append(f"[Tool call: {name}({args})]")
                elif block.get("type") == "tool_result":
                    # Tool result — render as function result
                    result = block.get("content", "")
                    if isinstance(result, list):
                        result = " ".join(r.get("text", "") if isinstance(r, dict) else str(r) for r in result)
                    parts.append(f"[Tool result: {result}]")
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


def build_natural_prompt(messages, tools=None, tool_choice=None):
    """Convert OpenAI-format API messages into a natural conversation prompt
    for Claude.ai's web interface.

    This middleware replaces the old Mistral-based humanization. It:
    - Converts system prompts into natural context notes (not <system> tags)
    - Preserves full multi-turn context (user + assistant messages)
    - Handles multimodal content (text blocks, image URLs, tool calls/results)
    - Renders tool history (assistant tool_calls + tool role messages)
    - Injects custom tool definitions when tools are provided (Path B emulation)
    - Removes API artifacts that could trigger Claude's anti-automation heuristics
    - Keeps the exact meaning and intent of every message
    - Adds natural conversational framing

    Args:
        messages: OpenAI-format messages array
        tools: optional list of OpenAI function definitions
        tool_choice: optional "none", "required", or {"function": {"name": "..."}}

    Returns: (prompt_text, was_transformed)
    """
    if not messages:
        return "", False

    # Separate system messages from conversation
    system_parts = []
    conv_parts = []
    for m in messages:
        role = m.get("role", "user")
        content = _extract_content_text(m.get("content", ""))
        if role == "system":
            system_parts.append(content)
        elif role == "user":
            conv_parts.append(("user", content))
        elif role == "assistant":
            # Check for tool_calls in assistant message
            tool_calls = m.get("tool_calls")
            if tool_calls:
                tool_text = []
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    name = fn.get("name", "unknown")
                    args = fn.get("arguments", "{}")
                    tool_text.append(f"[I called {name} with arguments: {args}]")
                conv_parts.append(("assistant", content + "\n" + "\n".join(tool_text) if content else "\n".join(tool_text)))
            else:
                conv_parts.append(("assistant", content))
        elif role == "tool":
            # Tool result message — render as function result
            tool_call_id = m.get("tool_call_id", "")
            conv_parts.append(("tool", f"[Tool result for {tool_call_id}]: {content}"))
        else:
            conv_parts.append((role, content))

    prompt_pieces = []

    # ── System prompt → natural context note ──
    if system_parts:
        system_text = "\n".join(system_parts).strip()
        if system_text:
            prompt_pieces.append(system_text)

    # ── Custom tool definitions (Path B emulation) ──
    # When the client sends OpenAI function definitions, we inject them as
    # a natural preamble so Claude knows what tools are available and how
    # to call them using <function_calls> XML format.
    if tools and tool_choice != "none":
        tool_preamble = _render_tools_preamble(tools, tool_choice)
        if tool_preamble:
            prompt_pieces.append(tool_preamble)

    # ── Conversation turns → natural dialogue ──
    for role, content in conv_parts:
        if role == "user":
            prompt_pieces.append(f"Human: {content}")
        elif role == "assistant":
            prompt_pieces.append(f"Assistant: {content}")
        elif role == "tool":
            prompt_pieces.append(f"Tool: {content}")
        else:
            prompt_pieces.append(f"{role.capitalize()}: {content}")

    prompt_text = "\n\n".join(prompt_pieces)

    # ── Artifact format instruction ──
    artifact_instruction = (
        "\n\n---\n"
        "Output format note: When writing code, UI components, HTML, SVG, or any "
        "file content, use standard Markdown code blocks (```html, ```tsx, ```python, "
        "```csv, etc.) with the appropriate language label. Do NOT use <antArtifact> "
        "XML tags or <antThinking> tags — output everything as standard Markdown."
    )
    prompt_text = prompt_text + artifact_instruction

    # Transformation happened if we had system messages, multi-turn, or tools
    was_transformed = len(system_parts) > 0 or len(conv_parts) > 2 or bool(tools)

    return prompt_text, was_transformed


# ── Tool Preamble Rendering (Path B emulation) ──
# Adapted from zlexdev/claude-webapi tool_protocol.py

def _render_tools_preamble(tools, tool_choice=None):
    """Render OpenAI function definitions as a natural preamble for Claude.
    
    Tells Claude what tools are available, their parameters, and how to call
    them using <function_calls><invoke name="..."> XML format.
    """
    lines = ["You have access to the following tools. Use them when appropriate."]
    lines.append("")
    
    for tool in tools:
        if tool.get("type") == "function":
            fn = tool.get("function", {})
        else:
            fn = tool
        name = fn.get("name", "unknown")
        desc = fn.get("description", "")
        params = fn.get("parameters", {})
        
        lines.append(f"## Tool: {name}")
        if desc:
            lines.append(f"Description: {desc}")
        if params and isinstance(params, dict):
            props = params.get("properties", {})
            required = params.get("required", [])
            if props:
                lines.append("Parameters:")
                for pname, pinfo in props.items():
                    ptype = pinfo.get("type", "string")
                    pdesc = pinfo.get("description", "")
                    req = " (required)" if pname in required else ""
                    lines.append(f"  - {pname} ({ptype}){req}: {pdesc}")
        lines.append("")
    
    # How to call tools
    lines.append("To call a tool, use this exact format:")
    lines.append('<function_calls>')
    lines.append('<invoke name="tool_name">')
    lines.append('<parameter name="param_name">value</parameter>')
    lines.append('</invoke>')
    lines.append('</function_calls>')
    lines.append("")
    
    # tool_choice handling
    if tool_choice == "required":
        lines.append("You MUST call at least one tool in your response.")
    elif isinstance(tool_choice, dict) and "function" in tool_choice:
        fn_name = tool_choice["function"].get("name", "")
        if fn_name:
            lines.append(f"You MUST call the tool '{fn_name}' in your response.")
    else:
        lines.append("Call a tool only when it would help answer the user's request. "
                      "If no tool is needed, respond normally without any tool calls.")
    
    return "\n".join(lines)


def parse_tool_calls_from_response(text):
    """Extract tool calls from Claude's response text.
    
    Parses <function_calls><invoke name="..."> XML and returns a list of
    OpenAI-format tool_calls. Tolerant of JSON fences and bare JSON too.
    
    Returns: list of {"id": ..., "type": "function", "function": {"name": ..., "arguments": ...}}
    """
    tool_calls = []
    
    # Pattern 1: <function_calls><invoke name="...">...</invoke></function_calls>
    invoke_pattern = re.compile(
        r'<(?:antml:)?function_calls>\s*'
        r'<(?:antml:)?invoke\s+name="([^"]+)"[^>]*>(.*?)</(?:antml:)?invoke>\s*'
        r'(?:</(?:antml:)?function_calls>)?',
        re.DOTALL
    )
    
    param_pattern = re.compile(
        r'<(?:antml:)?parameter\s+name="([^"]+)"[^>]*>(.*?)</(?:antml:)?parameter>',
        re.DOTALL
    )
    
    for m in invoke_pattern.finditer(text):
        name = m.group(1)
        params_text = m.group(2)
        
        # Extract parameters
        args = {}
        for pm in param_pattern.finditer(params_text):
            pname = pm.group(1)
            pval = pm.group(2).strip()
            args[pname] = pval
        
        tool_calls.append({
            "id": f"call_{secrets.token_hex(12)}",
            "type": "function",
            "function": {
                "name": name,
                "arguments": json.dumps(args),
            }
        })
    
    # Pattern 2: ```json with tool call format (tolerant)
    if not tool_calls:
        json_fences = re.findall(r'```json\s*\n(.*?)\n```', text, re.DOTALL)
        for jf in json_fences:
            try:
                parsed = json.loads(jf)
                if isinstance(parsed, dict) and "name" in parsed and "arguments" in parsed:
                    tool_calls.append({
                        "id": f"call_{secrets.token_hex(12)}",
                        "type": "function",
                        "function": {
                            "name": parsed["name"],
                            "arguments": json.dumps(parsed["arguments"]) if isinstance(parsed["arguments"], dict) else str(parsed["arguments"]),
                        }
                    })
            except (json.JSONDecodeError, TypeError):
                continue
    
    return tool_calls


# ═══════════════════════════════════════════════════════════════════════════
# TOOL ARTIFACT FILTERING — strips Claude's internal tool/function call XML
# ═══════════════════════════════════════════════════════════════════════════

# Regex patterns for Claude's tool call XML artifacts.
# Claude.ai's web interface has tools (web search, MCP, etc.) enabled in its
# system prompt. When the model decides to use a tool, it emits XML tags like
# <function_calls><invoke name="..."> as plain text. Since our gateway doesn't
# execute tools, these would leak to the API consumer as raw text.
_TOOL_PATTERNS = [
    re.compile(r'<function_calls>.*?</function_calls>', re.DOTALL),
    re.compile(r'<function_calls>.*', re.DOTALL),            # unclosed (stream stopped)
    re.compile(r'<antml:function_calls>.*?</antml:function_calls>', re.DOTALL),
    re.compile(r'<antml:function_calls>.*', re.DOTALL),
    re.compile(r'<invoke\s+name="[^"]*">.*?</invoke>', re.DOTALL),
    re.compile(r'<invoke\s+name="[^"]*">.*', re.DOTALL),     # unclosed
    re.compile(r'<antml:invoke\s+name="[^"]*">.*?</antml:invoke>', re.DOTALL),
    re.compile(r'<web_search>.*?</web_search>', re.DOTALL | re.IGNORECASE),  # our injected format
    re.compile(r'<web_search>.*', re.DOTALL | re.IGNORECASE),  # unclosed
    re.compile(r'</?(?:function_calls|invoke|function_results|parameter|result|web_search)\b[^>]*>', re.IGNORECASE),
    re.compile(r'</?antml:(?:function_calls|invoke|function_results|parameter|result)\b[^>]*>', re.IGNORECASE),
]

def filter_tool_artifacts(text):
    """Remove Claude's internal tool/function call XML from response text.

    Strips <function_calls>, <invoke>, <function_results>, and antml: variants.
    Cleans up excessive whitespace left by removed blocks.
    """
    for pattern in _TOOL_PATTERNS:
        text = pattern.sub('', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.rstrip()

def contains_tool_artifacts(text):
    """Check if response text contains tool/function call artifacts."""
    return bool(re.search(
        r'<(?:function_calls|invoke\b|function_results|antml:function_calls|antml:invoke|web_search)',
        text, re.IGNORECASE
    ))

# ═══════════════════════════════════════════════════════════════════════════
# ARTIFACT TRANSFORMATION — converts Claude.ai's <antArtifact> XML blocks
# into standard Markdown code blocks that any frontend can parse.
# Also strips <antThinking> blocks (Claude's internal reasoning).
# ═══════════════════════════════════════════════════════════════════════════

# Map Claude.ai artifact types → markdown code block languages
_ARTIFACT_TYPE_MAP = {
    "text/html": "html",
    "application/vnd.ant.react": "tsx",
    "text/react": "tsx",
    "text/python": "python",
    "text/javascript": "javascript",
    "text/typescript": "typescript",
    "text/markdown": "markdown",
    "image/svg+xml": "svg",
    "text/csv": "csv",
    "text/css": "css",
    "application/json": "json",
    "text/xml": "xml",
    "text/yaml": "yaml",
    "text/sql": "sql",
    "text/sh": "bash",
    "text/bash": "bash",
    "text/plain": "text",
}

_ARTIFACT_ATTRS_RE = re.compile(
    r'(?P<attr>\w+)\s*=\s*"(?P<val>[^"]*)"'
)

_ANT_ARTIFACT_BLOCK_RE = re.compile(
    r'<antArtifact(?P<attrs>[^>]*)>(?P<content>.*?)</antArtifact>',
    re.DOTALL | re.IGNORECASE,
)
_ANT_ARTIFACT_UNCLOSED_RE = re.compile(
    r'<antArtifact(?P<attrs>[^>]*)>(?P<content>.*)',
    re.DOTALL | re.IGNORECASE,
)
_ANT_THINKING_RE = re.compile(
    r'<antThinking>.*?</antThinking>', re.DOTALL | re.IGNORECASE
)
_ANT_THINKING_UNCLOSED_RE = re.compile(
    r'<antThinking>.*', re.DOTALL | re.IGNORECASE
)
_ANT_ARTIFACT_TAG_RE = re.compile(
    r'</?antArtifact[^>]*>', re.IGNORECASE
)


def _extract_artifact_lang(attrs_text):
    """Parse attributes string and determine the markdown language."""
    lang = "text"
    has_lang = False
    has_type = False
    type_val = ""
    for m in _ARTIFACT_ATTRS_RE.finditer(attrs_text):
        key = m.group("attr").lower()
        val = m.group("val")
        if key == "language":
            lang = val
            has_lang = True
        elif key == "type":
            type_val = val
            has_type = True
    if has_lang:
        return lang
    if has_type:
        return _ARTIFACT_TYPE_MAP.get(type_val, type_val.replace("text/", "") if type_val.startswith("text/") else "text")
    return "text"


def transform_ant_artifacts(text):
    """Convert <antArtifact> XML blocks → standard Markdown code blocks.

    Also strips <antThinking> reasoning blocks (not meant for the user).
    Safe to run on any text — only touches antArtifact/antThinking tags,
    never affects legitimate HTML/SVG/code the user asked for.
    """
    # 1. Strip <antThinking> blocks (complete and unclosed)
    text = _ANT_THINKING_RE.sub("", text)
    text = _ANT_THINKING_UNCLOSED_RE.sub("", text)

    # 2. Transform complete <antArtifact>...</antArtifact> blocks
    def _replace_block(m):
        lang = _extract_artifact_lang(m.group("attrs"))
        content = m.group("content").strip("\n")
        # If content already starts with ``` we don't double-wrap
        if content.startswith("```"):
            return content
        return f"```{lang}\n{content}\n```"

    text = _ANT_ARTIFACT_BLOCK_RE.sub(_replace_block, text)

    # 3. Handle unclosed <antArtifact> (stream was cut off)
    def _replace_unclosed(m):
        content = m.group("content").strip("\n")
        if content.startswith("```"):
            return content
        return f"```\n{content}\n```"

    text = _ANT_ARTIFACT_UNCLOSED_RE.sub(_replace_unclosed, text)

    # 4. Clean up any orphaned antArtifact tags (self-closing, malformed)
    text = _ANT_ARTIFACT_TAG_RE.sub("", text)

    # 5. Normalize whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def map_stop_reason(stop_reason):
    """Map Anthropic stop_reason to OpenAI finish_reason."""
    if not stop_reason:
        return "stop"
    stop_lower = str(stop_reason).lower()
    if stop_lower in ("stop_sequence", "stop", "end_turn"):
        return "stop"
    if "max_token" in stop_lower or "length" in stop_lower:
        return "length"
    if "tool_use" in stop_lower:
        return "tool_calls"
    return "stop"

def _parse_claude_sse(sse_text):
    """Parse Anthropic SSE response text → (full_completion, stop_reason).
    
    Handles both the old format (completion field) and the new format
    (content_block_delta with text_delta) used when tools are enabled.
    """
    completion_parts = []
    stop_reason = None
    for line in sse_text.split("\n"):
        if not line.startswith("data: "):
            continue
        try:
            obj = json.loads(line[6:])
        except (json.JSONDecodeError, ValueError):
            continue
        # Old format: direct completion field
        if obj.get("completion"):
            completion_parts.append(obj["completion"])
        # New format: content_block_delta with text_delta
        if obj.get("type") == "content_block_delta":
            delta = obj.get("delta", {})
            if delta.get("type") == "text_delta":
                completion_parts.append(delta.get("text", ""))
        # Stop reason from message_delta or message_stop
        if obj.get("stop_reason"):
            stop_reason = obj["stop_reason"]
        if obj.get("type") == "message_delta":
            if obj.get("delta", {}).get("stop_reason"):
                stop_reason = obj["delta"]["stop_reason"]
    return "".join(completion_parts), stop_reason

# ═══════════════════════════════════════════════════════════════════════════
# PROXY-SIDE WEB SEARCH — Claude free-tier accounts don't have native web_search.
# We intercept Claude's tool-use attempts, execute the search ourselves,
# and inject results back so Claude can continue its response.
# ═══════════════════════════════════════════════════════════════════════════

import urllib.parse

def proxy_web_search(query, max_results=5):
    """Execute a web search using DuckDuckGo HTML endpoint (no API key needed).
    Returns list of {title, url, snippet} dicts.
    """
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        resp = curl_requests.get(url, headers=headers, impersonate="chrome131", timeout=15, verify=False)
        if resp.status_code != 200:
            return []
        results = []
        # Parse DuckDuckGo HTML results
        text = resp.text
        # Extract result blocks
        blocks = re.findall(r'<div class="result results_links results_links_deep web-result "[^>]*>(.*?)</div>\s*</div>', text, re.DOTALL)
        if not blocks:
            blocks = re.findall(r'<div class="result[^"]*"[^>]*>(.*?)</div>\s*</div>', text, re.DOTALL)
        for block in blocks[:max_results]:
            title_m = re.search(r'<a[^>]*class="result__a"[^>]*>(.*?)</a>', block, re.DOTALL)
            url_m = re.search(r'<a[^>]*class="result__a"[^>]*href="([^"]*)"', block)
            snippet_m = re.search(r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', block, re.DOTALL)
            if title_m and url_m:
                title = re.sub(r'<[^>]+>', '', title_m.group(1)).strip()
                raw_url = url_m.group(1)
                # DuckDuckGo wraps URLs — extract actual URL
                url_match = re.search(r'uddg=([^&]+)', raw_url)
                actual_url = urllib.parse.unquote(url_match.group(1)) if url_match else raw_url
                snippet = ""
                if snippet_m:
                    snippet = re.sub(r'<[^>]+>', '', snippet_m.group(1)).strip()
                results.append({"title": title, "url": actual_url, "snippet": snippet})
        return results
    except Exception as e:
        app.logger.error(f"[web_search] error: {e}")
        return []

def proxy_web_fetch(url):
    """Fetch URL content as plain text (truncated to ~4000 chars for prompt injection).
    Uses Jina Reader API (r.jina.ai) which returns clean markdown from any URL.
    """
    try:
        jina_url = f"https://r.jina.ai/{url}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/plain",
        }
        resp = curl_requests.get(jina_url, headers=headers, impersonate="chrome131", timeout=20, verify=False)
        if resp.status_code == 200:
            text = resp.text[:4000]
            return text
        return f"[Failed to fetch: HTTP {resp.status_code}]"
    except Exception as e:
        return f"[Fetch error: {str(e)}]"

def format_search_results(results):
    """Format search results as a natural text block for Claude to read."""
    if not results:
        return "[No search results found]"
    lines = ["Here are the web search results:"]
    for i, r in enumerate(results, 1):
        lines.append(f"\n{i}. {r['title']}")
        lines.append(f"   URL: {r['url']}")
        if r['snippet']:
            lines.append(f"   {r['snippet']}")
    return "\n".join(lines)

def detect_search_request(text):
    """Detect if Claude is trying to use web search.
    Checks for both <web_search>query</web_search> format (our injected instruction)
    and <function_calls><invoke name="web_search"> format (Claude's native tool calls).
    Returns (search_query, cleaned_text) or (None, text).
    """
    # Pattern 1: <web_search>query</web_search> — our injected format
    m = re.search(r'<web_search>(.*?)</web_search>', text, re.DOTALL | re.IGNORECASE)
    if m:
        query = m.group(1).strip()
        cleaned = re.sub(r'<web_search>.*?</web_search>', '', text, flags=re.DOTALL | re.IGNORECASE)
        return query, cleaned.strip()
    
    # Pattern 2: Unclosed <web_search>query (stream was cut)
    m = re.search(r'<web_search>(.*?)$', text, re.DOTALL | re.IGNORECASE)
    if m:
        query = m.group(1).strip()
        cleaned = re.sub(r'<web_search>.*', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remove trailing incomplete tags
        cleaned = re.sub(r'</?web_search>?$', '', cleaned).strip()
        if query:
            return query, cleaned
    
    # Pattern 3: <function_calls> with web_search (Claude's native format)
    patterns = [
        r'<function_calls>\s*<invoke\s+name="web_search"[^>]*>.*?<parameter\s+name="query"[^>]*>(.*?)</parameter>',
        r'<function_calls>\s*<invoke\s+name="web_search"[^>]*>.*?<parameter\s+name="query">(.*?)</parameter>',
        r'<antml:function_calls>\s*<antml:invoke\s+name="web_search"[^>]*>.*?<antml:parameter\s+name="query"[^>]*>(.*?)</antml:parameter>',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.DOTALL)
        if m:
            query = m.group(1).strip()
            cleaned = re.sub(r'<function_calls>.*?</function_calls>', '', text, flags=re.DOTALL)
            cleaned = re.sub(r'<function_calls>.*', '', cleaned, flags=re.DOTALL)
            cleaned = re.sub(r'<antml:function_calls>.*?</antml:function_calls>', '', cleaned, flags=re.DOTALL)
            cleaned = re.sub(r'<antml:function_calls>.*', '', cleaned, flags=re.DOTALL)
            return query, cleaned.strip()
    
    return None, text


def _cleanup_claude_conversation(org_uuid, conv_uuid, cookie_header, proxy_url):
    """Delete a conversation from Claude.ai to prevent accumulation."""
    try:
        cleanup_headers = {
            "Cookie": cookie_header,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Origin": "https://claude.ai",
        }
        cleanup_kwargs = {"impersonate": "chrome131", "timeout": 30, "verify": False}
        if proxy_url:
            cleanup_kwargs["proxy"] = proxy_url
        curl_requests.delete(
            f"https://claude.ai/api/organizations/{org_uuid}/chat_conversations/{conv_uuid}",
            headers=cleanup_headers, **cleanup_kwargs,
        )
    except Exception:
        pass


# ── Conversation Title Generation ──
# Generates a concise title for the conversation via Claude's title endpoint.
# This makes the conversation history more readable in Claude.ai's UI.

def _generate_conversation_title(org_uuid, conv_uuid, cookie_header, proxy_url):
    """Ask Claude.ai to generate a title for the conversation."""
    try:
        headers = {
            "Cookie": cookie_header,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Origin": "https://claude.ai",
        }
        kwargs = {"impersonate": "chrome131", "timeout": 15, "verify": False}
        if proxy_url:
            kwargs["proxy"] = proxy_url
        resp = curl_requests.post(
            f"https://claude.ai/api/organizations/{org_uuid}/chat_conversations/{conv_uuid}/title",
            json={},
            headers=headers,
            **kwargs,
        )
        if resp.status_code == 200:
            title_data = resp.json()
            return title_data.get("title", "")
    except Exception:
        pass
    return None


# ── Conversation Cache (in-memory, TTL-based) ──
# Caches conversation list/get responses to reduce API calls to Claude.ai.
_conv_cache_lock = threading.Lock()
_conv_cache = {}  # cache_key → {data, expires_at}
CONV_CACHE_TTL = 300  # 5 minutes

def _cache_get(key):
    """Get a cached conversation response. Returns None if expired."""
    with _conv_cache_lock:
        entry = _conv_cache.get(key)
        if entry and entry["expires_at"] > time.time():
            return entry["data"]
        if entry:
            _conv_cache.pop(key, None)
        return None

def _cache_set(key, data, ttl=CONV_CACHE_TTL):
    """Store a conversation response in cache."""
    with _conv_cache_lock:
        _conv_cache[key] = {"data": data, "expires_at": time.time() + ttl}
        # Evict expired entries periodically
        if len(_conv_cache) > 100:
            now = time.time()
            expired = [k for k, v in _conv_cache.items() if v["expires_at"] <= now]
            for k in expired:
                _conv_cache.pop(k, None)


def proxy_to_claude(real_model, model_slug):
    """Forward request to Claude.ai web API using stored browser cookies.
    
    Smart rotation features:
    - Least-Used first (distributes load evenly)
    - Cooldown timer after 429 (5 min, auto-recovery)
    - Dead token detection on 401/403 (permanent removal)
    - Seamless failover: retries next token on failure within same request
    - Thread-safe with RLock for concurrent requests
    """
    cookie_sets = get_claude_cookie_sets()
    if not cookie_sets:
        return jsonify({"error": "No Claude cookie files stored. Upload at /upload", "model": model_slug}), 503
    
    body = request.get_data()
    try:
        data = json.loads(body)
        messages = data.get("messages", [])
        is_streaming = data.get("stream", False)
        request_tools = data.get("tools", [])
        tool_choice = data.get("tool_choice", None)
    except:
        return jsonify({"error": "Invalid JSON body"}), 400
    
    if not messages:
        return jsonify({"error": "messages array is required"}), 400
    
    # ── Build natural prompt from OpenAI-format messages ──
    # build_natural_prompt replaces the old Mistral humanization:
    # - Converts system prompts to natural context (not <system> tags)
    # - Preserves full multi-turn context (user + assistant messages)
    # - Handles multimodal content (text blocks, image URLs)
    # - Injects custom tool definitions (Path B emulation)
    # - No external API call — pure local transformation
    try:
        prompt_text, was_transformed = build_natural_prompt(messages, tools=request_tools, tool_choice=tool_choice)
    except Exception as e:
        app.logger.error(f"[claude] build_natural_prompt error: {e}")
        return jsonify({"error": "Prompt construction failed", "detail": str(e)}), 500

    if not prompt_text.strip():
        return jsonify({"error": "Empty prompt — no user content found"}), 400

    last_role = messages[-1].get("role") if messages else None
    if last_role != "user":
        return jsonify({"error": "Bad Request", "message": "Claude requires the last message to be from 'user'.", "last_role": last_role}), 400
    
    # ── Conversation affinity: pin multi-turn conversations to same cookie ──
    affinity_key = _affinity_key(messages)
    pinned_id = _get_affinity_pin(affinity_key) if affinity_key else None
    
    # ── Cache lookup: return cached response for identical prompts ──
    cache_key = f"claude:{affinity_key or 'nopin'}:{hashlib.sha256(prompt_text.encode()).hexdigest()[:16]}"
    cached = _cache_get(cache_key)
    if cached and not is_streaming:
        app.logger.info(f"[claude] cache hit for key {cache_key[:40]}")
        cached["cached"] = True
        return jsonify(cached), 200, {
            "X-Proxy-Provider": "claude", "X-Cache-Hit": "true",
            "X-Proxy-Cookie": "cached",
        }
    if pinned_id:
        app.logger.info(f"[claude] affinity: pinned to cookie {pinned_id} for key {affinity_key[:8] if affinity_key else '?'}")
    
    # ── Smart rotation: get available tokens with affinity + tier awareness ──
    available = _get_available_tokens(cookie_sets, affinity_pin_id=pinned_id)
    if not available:
        # Check if ALL are in cooldown
        with _claude_token_lock:
            on_cooldown = sum(1 for cs in cookie_sets if _get_token_state(cs["id"])["cooldown_until"] > time.time())
            dead_count = sum(1 for cs in cookie_sets if _get_token_state(cs["id"])["dead"])
        return jsonify({
            "error": "Service Unavailable",
            "message": "All Claude sessions are busy or expired.",
            "details": f"{len(cookie_sets)} total: {dead_count} dead, {on_cooldown} cooling down",
            "retry_after_ms": COOLDOWN_SECONDS * 1000,
            "model": model_slug,
        }), 503
    
    tried = []
    accumulated_partial = ""  # ← Text accumulated from failed attempts, for continuation
    
    for cookie_set in available:
        cookies = extract_claude_cookies(cookie_set)
        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        
        org_uuid = None
        for c in cookies:
            if c["name"] == "lastActiveOrg":
                org_uuid = c["value"]
                break
        if not org_uuid:
            continue
        
        # ── Determine proxy for this cookie set ──
        proxy_session_id = cookie_set.get("proxy_session_id") or None
        proxy_enabled = cookie_set.get("proxy_enabled") or False
        proxy_url = get_proxy_url(proxy_session_id) if (PROXY_ENABLED and proxy_enabled and proxy_session_id) else get_proxy_url()
        
        # ── Skip blacklisted proxies ──
        if proxy_url and is_proxy_blacklisted(proxy_url):
            app.logger.info(f"[claude] token {cookie_set['id']}: skipping blacklisted proxy")
            tried.append({"token": cookie_set["id"], "action": "SKIP", "reason": "Proxy blacklisted"})
            continue
        
        start = time.time()
        
        def _claude_http_call(prompt_override=None):
            """Inner function: use curl_cffi with Chrome 131 impersonation for Cloudflare bypass.
            
            prompt_override: if set, uses this prompt instead of the default (for retry with anti-tool instructions)
            """
            effective_prompt = prompt_override if prompt_override else prompt_text
            
            # ── Continuation: if we have partial text from a failed attempt, ask Claude to continue ──
            if accumulated_partial:
                effective_prompt = (
                    f"{prompt_text}\n\n"
                    f"---\n\n"
                    f"[A previous attempt to answer this was interrupted. Here is what was generated so far:]\n"
                    f'"{accumulated_partial}"\n\n'
                    f"[Continue the answer from exactly where it left off. Do not repeat the text above. "
                    f"Just continue naturally as if you never stopped.]"
                )
            
            headers = {
                "Cookie": cookie_header,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Origin": "https://claude.ai",
            }
            
            common_kwargs = {
                "impersonate": "chrome131",
                "timeout": 180,
                "verify": False,
            }
            if proxy_url:
                common_kwargs["proxy"] = proxy_url
            
            # Step 1: Create conversation — empty name so Claude auto-names it
            resp1 = curl_requests.post(
                f"https://claude.ai/api/organizations/{org_uuid}/chat_conversations",
                json={
                    "name": "", "prompt": "",
                    "timezone": "Africa/Cairo", "model": real_model,
                    "attachments": [], "files": [], "organization_uuid": org_uuid
                },
                headers=headers,
                **common_kwargs,
            )
            conv_result = resp1.json()
            conv_uuid = conv_result.get("uuid")
            if not conv_uuid:
                raise Exception("No conversation UUID returned")
            
            # Step 2: Send prompt — with native web search tools enabled
            # The tools array with web_search_v0 enables Claude's built-in web search.
            # This is the per-request toggle (conversation settings alone don't work).
            completion_payload = {
                "prompt": effective_prompt,
                "timezone": "Africa/Cairo",
                "locale": "en-US",
                "rendering_mode": "messages",
                "attachments": [],
                "files": [],
                "sync_sources": [],
                "personalized_styles": [],
                "tools": [{"type": "web_search_v0", "name": "web_search"}],
            }
            resp2 = curl_requests.post(
                f"https://claude.ai/api/organizations/{org_uuid}/chat_conversations/{conv_uuid}/completion",
                json=completion_payload,
                headers={**headers, "Accept": "text/event-stream"},
                **common_kwargs,
            )
            return resp1, resp2, conv_uuid
        
        try:
            # ── First attempt ──
            resp1, resp2, conv_uuid = _claude_http_call()
            latency = int((time.time() - start) * 1000)
            
            # Parse the SSE response
            raw_completion, stop_reason = _parse_claude_sse(resp2.text)
            finish = map_stop_reason(stop_reason)
            
            # ── Tool Artifact Handling ──
            # With native web search enabled, Claude uses tool_use/tool_result blocks
            # in the SSE stream. Our _parse_claude_sse already extracts only text_delta
            # (not tool_use content), so raw_completion should be clean text.
            # If any XML tool artifacts leak through, filter them out.
            if contains_tool_artifacts(raw_completion):
                app.logger.info(f"[claude] token {cookie_set['id']}: tool artifacts in response — filtering")
            
            # ── Transform artifacts + filter tool XML ──
            # Step 1: Convert <antArtifact> blocks → standard Markdown code blocks
            transformed_text = transform_ant_artifacts(raw_completion)
            # Step 2: Filter internal tool XML (function_calls, invoke, etc.)
            filtered_text = filter_tool_artifacts(transformed_text).rstrip('\n')
            if not filtered_text and raw_completion:
                # Response was entirely tool XML — use raw as fallback
                filtered_text = raw_completion.rstrip('\n')
            
            full_text = filtered_text
            
            _mark_token_used(cookie_set["id"])
            if proxy_url:
                report_proxy_success(proxy_url)
            # ── Pin this conversation to this cookie for follow-up messages ──
            if affinity_key:
                _set_affinity_pin(affinity_key, cookie_set["id"])
            proxy_ip = "unknown"
            proxy_country = "unknown"
            try:
                proxy_ip = getattr(resp2, "remote_addr", None) or "unknown"
            except Exception:
                pass
            record_proxy_request(model_slug, "claude", cookie_set["id"], "ok", latency,
                               proxy_ip=proxy_ip if proxy_ip != "unknown" else None,
                               proxy_country=proxy_country if proxy_country != "unknown" else None)
            
            if is_streaming:
                # ── Generate title in background (fire-and-forget) ──
                def _bg_title():
                    _generate_conversation_title(org_uuid, conv_uuid, cookie_header, proxy_url)
                    _cleanup_claude_conversation(org_uuid, conv_uuid, cookie_header, proxy_url)
                threading.Thread(target=_bg_title, daemon=True).start()

                def generate():
                    """Transform Anthropic SSE stream → OpenAI-compatible SSE stream with tool artifact filtering."""
                    yield from transform_claude_stream(resp2.text, conv_uuid, real_model)
                return Response(stream_with_context(generate()), status=200, headers={
                    "Content-Type": "text/event-stream", "X-Proxy-Provider": "claude",
                    "X-Proxy-Cookie": str(cookie_set["id"]), "X-Proxy-Latency": str(latency),
                    "X-Proxy-Rotation": f"token {cookie_set['id']} (used {_get_token_state(cookie_set['id'])['usage']}x)",
                    **({"X-Proxy-Continuation": "true"} if accumulated_partial else {}),
                })
            else:
                # ── Generate title then cleanup conversation ──
                title = _generate_conversation_title(org_uuid, conv_uuid, cookie_header, proxy_url)
                _cleanup_claude_conversation(org_uuid, conv_uuid, cookie_header, proxy_url)

                # Token estimation (~4 chars/token for English, ~2 for CJK)
                prompt_chars = len(prompt_text)
                completion_chars = len(full_text)
                est_prompt_tokens = max(1, prompt_chars // 4)
                est_completion_tokens = max(1, completion_chars // 4)
                
                # ── Parse tool calls from response (Path B emulation) ──
                # If custom tools were requested, check if Claude emitted tool calls
                tool_calls_parsed = []
                if request_tools:
                    tool_calls_parsed = parse_tool_calls_from_response(full_text)
                    if tool_calls_parsed:
                        # Strip tool XML from the text content
                        full_text = filter_tool_artifacts(full_text).rstrip('\n')
                        finish = "tool_calls"
                
                response_body = {
                    "id": f"claude-{conv_uuid[:8]}", "object": "chat.completion",
                    "created": int(time.time()), "model": real_model,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": full_text, **({"tool_calls": tool_calls_parsed} if tool_calls_parsed else {})}, "finish_reason": finish}],
                    "usage": {"prompt_tokens": est_prompt_tokens, "completion_tokens": est_completion_tokens, "total_tokens": est_prompt_tokens + est_completion_tokens},
                    **({"title": title} if title else {}),
                }
                # ── Cache the response for repeat requests ──
                cache_key = f"claude:{affinity_key or conv_uuid}:{hashlib.sha256(prompt_text.encode()).hexdigest()[:16]}"
                _cache_set(cache_key, response_body)
                return jsonify(response_body), 200, {
                    "X-Proxy-Provider": "claude", "X-Proxy-Cookie": str(cookie_set["id"]),
                    "X-Proxy-Latency": str(latency),
                    "X-Proxy-IP": proxy_ip or "unknown",
                    "X-Proxy-Country": proxy_country or "unknown",
                    "X-Proxy-Rotation": f"token {cookie_set['id']} (used {_get_token_state(cookie_set['id'])['usage']}x)",
                    **({"X-Proxy-Tool-Calls": str(len(tool_calls_parsed))} if tool_calls_parsed else {}),
                    **({"X-Proxy-Continuation": "true"} if accumulated_partial else {}),
                }
        
        except (httpx.HTTPStatusError, httpx.ProxyError, Exception) as e:
            latency = int((time.time() - start) * 1000)

            # ── Robust error classification ──
            if isinstance(e, httpx.HTTPStatusError):
                code = e.response.status_code
                body_err = e.response.text[:500]
            elif isinstance(e, httpx.ProxyError):
                code = 502
                body_err = f"Proxy error: {str(e)}"
                if proxy_url:
                    report_proxy_failure(proxy_url, body_err)
            elif isinstance(e, httpx.ConnectTimeout):
                code = 504
                body_err = f"Connection timeout: {str(e)}"
            elif isinstance(e, httpx.ReadTimeout):
                code = 504
                body_err = f"Read timeout: {str(e)}"
            elif isinstance(e, ConnectionError):
                code = 503
                body_err = f"Connection error: {str(e)}"
            else:
                # curl_cffi raises its own exceptions — try to extract status
                resp = getattr(e, 'response', None)
                code = getattr(resp, 'status_code', 0) if resp else 0
                body_err = str(e)[:500]
                if resp:
                    try:
                        body_err = resp.text[:500]
                    except Exception:
                        pass

            app.logger.warning(f"[claude] token {cookie_set['id']} error: code={code} err={body_err[:80]}")
            record_proxy_request(model_slug, "claude", cookie_set["id"], "error", latency, body_err[:100])

            # ── Capture partial response for continuation ──
            # If we got ANY text back before the error (e.g. timeout during thinking),
            # accumulate it so the next cookie can continue from where this one stopped.
            try:
                _r2 = locals().get('resp2')
                if _r2 is not None:
                    partial_text, _ = _capture_stream_partial(_r2)
                    if partial_text:
                        accumulated_partial = (accumulated_partial + partial_text).strip()
                        app.logger.info(f"[claude] Captured {len(partial_text)} chars partial text for continuation (total: {len(accumulated_partial)})")
            except Exception:
                pass

            # Check for Cloudflare challenge FIRST (before generic 403 handling)
            if code == 403 and ("challenge" in body_err.lower() or "just a moment" in body_err.lower()):
                # Cloudflare challenge — cooldown, don't kill the token
                _mark_token_cooldown(cookie_set["id"], f"403 CF: {body_err[:100]}")
                tried.append({"token": cookie_set["id"], "action": "COOLDOWN", "reason": "Cloudflare challenge"})
            elif code in (401, 403):
                _mark_token_dead(cookie_set["id"], f"HTTP {code}: {body_err[:200]}")
                tried.append({"token": cookie_set["id"], "action": "DEAD", "reason": f"HTTP {code}"})
            elif code == 429 or "out of" in body_err.lower() or "limit" in body_err.lower() or "exhausted" in body_err.lower():
                _mark_token_cooldown(cookie_set["id"], f"429: {body_err[:200]}")
                tried.append({"token": cookie_set["id"], "action": "COOLDOWN", "reason": "Rate limited"})
            else:
                _mark_token_cooldown(cookie_set["id"], f"HTTP {code}: {body_err[:100]}")
                tried.append({"token": cookie_set["id"], "action": "COOLDOWN", "reason": f"HTTP {code}"})
            continue
    
    # All tokens exhausted in this request — try cross-provider fallback for Claude
    app.logger.warning(f"[claude] All {len(tried)} cookie sessions exhausted for {model_slug}")
    
    # Claude fallback: try GLM-5.2 (closest reasoning model) via Fireworks
    fallback_chain = PROVIDER_FALLBACK_CHAIN.get("claude", [])
    for fb_provider, fb_model, fb_label in fallback_chain:
        fb_keys = get_provider_keys(fb_provider)
        if not fb_keys:
            continue
        
        app.logger.info(f"[claude] Cross-provider fallback: claude → {fb_provider}/{fb_model} ({fb_label})")
        
        # Build a modified request with the fallback model
        try:
            body_data = json.loads(body)
            body_data["model"] = MODELS.get(fb_model, {}).get("real_model", fb_model)
            fb_body = json.dumps(body_data).encode()
        except:
            fb_body = body
        
        for fb_key in fb_keys:
            fb_key_id = fb_key["id"]
            fb_base_url = fb_key["base_url"]
            fb_key_val = fb_key["key_value"]
            
            fb_start = time.time()
            try:
                fb_url = f"{fb_base_url}/chat/completions"
                fb_payload = inject_model_into_body(fb_body, MODELS.get(fb_model, {}).get("real_model", fb_model), fb_provider)
                fb_headers = {"Authorization": f"Bearer {fb_key_val}", "Content-Type": "application/json"}
                
                proxy = get_proxy_url()
                with httpx.Client(proxy=proxy, timeout=120.0, verify=False) as client:
                    fb_resp = client.post(fb_url, content=fb_payload, headers=fb_headers)
                
                fb_latency = int((time.time() - fb_start) * 1000)
                
                if fb_resp.status_code < 400:
                    bump_key_usage(fb_key_id)
                    record_proxy_request(fb_model, fb_provider, fb_key_id, "ok", fb_latency)
                    app.logger.info(f"[claude] Fallback SUCCESS: {fb_provider}/{fb_model}")
                    
                    if is_streaming:
                        def fb_gen():
                            for chunk in fb_resp.iter_bytes(8192):
                                yield chunk
                        return Response(stream_with_context(fb_gen()), status=fb_resp.status_code, headers={
                            "Content-Type": fb_resp.headers.get("Content-Type", "text/event-stream"),
                            "X-Proxy-Provider": fb_provider, "X-Proxy-Key": str(fb_key_id),
                            "X-Proxy-Fallback": f"claude→{fb_provider}",
                            "X-Proxy-Fallback-Reason": "All Claude sessions exhausted",
                        })
                    else:
                        return fb_resp.content, fb_resp.status_code, {
                            "Content-Type": fb_resp.headers.get("Content-Type", "application/json"),
                            "X-Proxy-Provider": fb_provider, "X-Proxy-Key": str(fb_key_id),
                            "X-Proxy-Fallback": f"claude→{fb_provider}",
                            "X-Proxy-Fallback-Reason": "All Claude sessions exhausted",
                        }
                else:
                    fb_code = fb_resp.status_code
                    try: fb_err = fb_resp.text[:200]
                    except: fb_err = ""
                    if fb_code == 429:
                        mark_key_rate_limited(fb_key_id, f"429: {fb_err}")
                    elif fb_code in (401, 403, 412, 402):
                        mark_key_dead(fb_key_id, f"{fb_code}: {fb_err}")
                    continue
            except Exception:
                continue
    
    # All Claude sessions AND all fallbacks failed — return user-friendly error
    return format_error_response(
        "CLAUDE_ALL_SESSIONS_BUSY", model_slug, "claude",
        tried_count=len(tried),
        retry_after_ms=COOLDOWN_SECONDS * 1000,
        is_streaming=is_streaming,
    )


# ═══════════════════════════════════════════════════════════════════════════
# PLAYWRIGHT FALLBACK — when httpx gets Cloudflare challenge
# ═══════════════════════════════════════════════════════════════════════════

def _playwright_fallback(cookie_set, prompt_text, real_model, is_streaming, proxy_session_id):
    """Use a real Chromium browser through the same proxy to bypass Cloudflare Turnstile."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None  # Playwright not installed
    
    pw_proxy = get_playwright_proxy(proxy_session_id)
    if not pw_proxy:
        return None
    
    org_uuid = None
    cookies_list = extract_claude_cookies(cookie_set)
    for c in cookies_list:
        if c["name"] == "lastActiveOrg":
            org_uuid = c["value"]
            break
    if not org_uuid:
        return None
    
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            proxy=pw_proxy,
            args=['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
        )
        context = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )
        # Set cookies from the cookie file
        domain_cookies = []
        for c in cookies_list:
            domain_cookies.append({
                "name": c["name"], "value": c["value"],
                "domain": ".claude.ai", "path": "/"
            })
        context.add_cookies(domain_cookies)
        
        page = context.new_page()
        
        # Navigate to warm up the session (passes Turnstile)
        page.goto("https://claude.ai", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(2000)  # Let Turnstile resolve
        
        # Create conversation via fetch — empty name so Claude auto-names it
        conv_result = page.evaluate("""
            async (orgUuid) => {
                const resp = await fetch(`/api/organizations/${orgUuid}/chat_conversations`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: '', prompt: '', timezone: 'Africa/Cairo', model: '""" + real_model + """', attachments: [], files: [], organization_uuid: orgUuid})
                });
                return await resp.json();
            }
        """, org_uuid)
        
        conv_uuid = conv_result.get("uuid")
        if not conv_uuid:
            browser.close()
            return None
        
        # Send prompt via fetch
        result = page.evaluate("""
            async ({orgUuid, convUuid, prompt}) => {
                const resp = await fetch(`/api/organizations/${orgUuid}/chat_conversations/${convUuid}/completion`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Accept': 'text/event-stream'},
                    body: JSON.stringify({prompt: prompt, timezone: 'Africa/Cairo', attachments: [], files: []})
                });
                return await resp.text();
            }
        """, {"orgUuid": org_uuid, "convUuid": conv_uuid, "prompt": prompt_text})
        
        browser.close()
        
        # Parse SSE response + filter tool artifacts
        full_text, stop_reason = _parse_claude_sse(result)
        full_text = filter_tool_artifacts(full_text).rstrip('\n')
        finish = map_stop_reason(stop_reason)
        
        if full_text:
            return jsonify({
                "id": f"claude-pw-{conv_uuid[:8]}", "object": "chat.completion",
                "created": int(time.time()), "model": real_model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": full_text}, "finish_reason": finish}],
                "usage": {"completion_tokens": len(full_text.split())},
            }), 200, {
                "X-Proxy-Provider": "claude-playwright",
                "X-Proxy-Cookie": str(cookie_set["id"]),
            }
        return None
    
    return None


def inject_model_into_body(body, real_model, provider_slug):
    """Replace or inject the model name in the request body."""
    try:
        data = json.loads(body)
    except:
        return body

    data["model"] = real_model

    return json.dumps(data).encode()


def strip_reasoning_prefix(resp_bytes, model_slug):
    """For reasoning models (style='reasoning'), strip 'Thinking Process:' / chain-of-thought
    prefixes from the response content so the final answer is clean.

    Reasoning models like glm-5p2, qwen3p7-plus, deepseek-v4-pro often prepend:
      'Thinking Process:\\n\\n1.  Analyze...\\n\\n**Final Answer:** Hello!'
    We extract the text after the last 'Final Answer' marker, or strip the numbered
    thinking block if no marker is found.

    Also handles Fireworks' 'reasoning_content' field — when present, the actual
    answer is in 'content' and the thinking is separated in 'reasoning_content'.
    In that case we just need to remove the reasoning_content field and keep content as-is.
    """
    try:
        data = json.loads(resp_bytes)
    except Exception:
        return resp_bytes

    if "choices" not in data:
        return resp_bytes  # Not OpenAI format — leave it

    for choice in data.get("choices", []):
        msg = choice.get("message", {})

        # ── Fireworks reasoning_content handling ──
        # If the API already separated thinking into 'reasoning_content', just drop it
        if "reasoning_content" in msg:
            # The 'content' field already has the clean answer — just remove reasoning_content
            msg.pop("reasoning_content", None)
            continue

        content = msg.get("content", "")
        if not isinstance(content, str) or not content:
            continue

        # Skip if content is already short and clean (no thinking prefix)
        if len(content) < 80 and not re.match(r'^(Thinking Process|1\.\s+\*\*Analyze|Let me|We need|We are asked)', content, re.I):
            continue

        # Pattern 1: Look for "Final Answer:" or "**Final Answer:**" marker
        final_match = re.search(r'(?:\*\*)?Final Answer(?:\*\*)?\s*[:：]?\s*(.+)', content, re.S | re.I)
        if final_match:
            msg["content"] = final_match.group(1).strip()
            continue

        # Pattern 2: Look for a JSON object in the content (for JSON mode requests)
        json_match = re.search(r'(\{[^{}]*\})', content)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                if isinstance(parsed, dict):
                    msg["content"] = json.dumps(parsed)
                    continue
            except:
                pass

        # Pattern 3: Strip numbered thinking block — find the actual answer after the reasoning
        # Look for double-newline after numbered list, then take the rest
        lines = content.split('\n')
        answer_start = None
        for i, line in enumerate(lines):
            # Skip thinking lines (numbered, bold markers, "Analyze", etc.)
            stripped = line.strip()
            if not stripped:
                if answer_start is not None:
                    break
                continue
            if re.match(r'^\d+\.\s', stripped) or stripped.startswith('**') or 'Analyze' in stripped or 'Thinking' in stripped:
                answer_start = i + 1
                continue
            # Found a non-thinking line
            if answer_start is not None:
                msg["content"] = '\n'.join(lines[i:]).strip()
                break

    return json.dumps(data).encode()

# ═══════════════════════════════════════════════════════════════════════════
# PROXY AUTH — check API key on /v1/* if configured
# ═══════════════════════════════════════════════════════════════════════════

def _verify_token_in_db(raw_key):
    """Check if a generated sk-aic- token exists and is active in the DB.
    Returns (is_valid, token_row_or_None)."""
    try:
        conn = get_db()
        conn.execute("""CREATE TABLE IF NOT EXISTS proxy_api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT 'default',
            is_active INTEGER DEFAULT 1,
            usage_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP
        )""")
        key_hash = hash_api_key(raw_key)
        row = conn.execute("SELECT * FROM proxy_api_keys WHERE key_hash=? AND is_active=1", (key_hash,)).fetchone()
        if row:
            conn.execute("UPDATE proxy_api_keys SET usage_count=usage_count+1, last_used_at=CURRENT_TIMESTAMP WHERE id=?", (row["id"],))
            conn.commit()
        conn.close()
        return (row is not None), row
    except Exception:
        return False, None

def check_proxy_auth():
    """If PROXY_API_KEY_HASH is set or proxy_api_keys table has tokens, require Bearer token.
    Checks: 1) legacy env hash, 2) generated tokens in DB.
    Uses constant-time comparison to prevent timing attacks."""
    if not PROXY_API_KEY_HASH:
        # Check if any generated tokens exist in DB — if none, no auth required
        try:
            conn = get_db()
            conn.execute("""CREATE TABLE IF NOT EXISTS proxy_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                label TEXT DEFAULT 'default',
                is_active INTEGER DEFAULT 1,
                usage_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP
            )""")
            count = conn.execute("SELECT COUNT(*) FROM proxy_api_keys WHERE is_active=1").fetchone()[0]
            conn.close()
            if count == 0:
                return None  # No auth configured at all
        except Exception:
            return None

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized — valid API key required", "hint": "Use Authorization: Bearer <key>"}), 401
    raw_key = auth[7:]

    # 1) Check legacy env hash
    if PROXY_API_KEY_HASH and verify_api_key(raw_key, PROXY_API_KEY_HASH):
        return None

    # 2) Check generated tokens in DB
    is_valid, _ = _verify_token_in_db(raw_key)
    if is_valid:
        return None

    return jsonify({"error": "Unauthorized — invalid API key"}), 401

# ═══════════════════════════════════════════════════════════════════════════
# CUSTOM ENDPOINTS — Virtual API endpoints with forced system prompts
# Each endpoint becomes a URL: /v1/{slug}/chat/completions
# The system prompt from the client is REPLACED with the endpoint's configured prompt
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/v1/<endpoint_slug>/chat/completions", methods=["POST"])
def custom_endpoint_proxy(endpoint_slug):
    """Route custom endpoint requests — replaces system prompt and forwards to the configured model.
    
    URL: /v1/{slug}/chat/completions
    
    If the slug matches a custom endpoint:
    1. The system prompt from the client's messages is REMOVED
    2. The endpoint's configured system_prompt is INJECTED at position 0
    3. Temperature, max_tokens, top_p are overridden if set on the endpoint
    4. The request is forwarded to the configured model
    5. Rate limiting, auth, and all resilience features apply normally
    
    Falls through to the legacy model-slug route if no custom endpoint matches.
    """
    # ── Skip if this is a known model slug (handled by legacy route) ──
    if endpoint_slug in MODELS:
        return proxy_chat_legacy(endpoint_slug)
    
    # ── Look up custom endpoint ──
    conn = get_db()
    ep = conn.execute("SELECT * FROM custom_endpoints WHERE slug=?", (endpoint_slug,)).fetchone()
    if not ep:
        conn.close()
        return format_error_response("MODEL_NOT_FOUND", endpoint_slug, detail=f"No custom endpoint or model found with slug '{endpoint_slug}'")
    
    if not ep["is_active"]:
        conn.close()
        return format_error_response("INVALID_REQUEST", endpoint_slug, detail=f"Endpoint '{endpoint_slug}' is paused. Activate it from the dashboard.")
    
    # ── Auth ──
    auth_err = check_proxy_auth()
    if auth_err:
        conn.close()
        return auth_err
    
    # ── Rate limiting ──
    allowed, remaining, retry_after = check_rate_limit()
    if not allowed:
        conn.close()
        return jsonify({"error": "Rate limit exceeded", "message": f"Too many requests. Retry in {retry_after}s.", "retry_after_seconds": retry_after}), 429, {"Retry-After": str(retry_after)}
    
    # ── Parse and modify the request body ──
    body = request.get_data()
    try:
        data = json.loads(body)
    except:
        conn.close()
        return format_error_response("INVALID_REQUEST", "", detail="Invalid JSON body")
    
    model_slug = ep["model_slug"]
    if model_slug not in MODELS:
        conn.close()
        return format_error_response("MODEL_NOT_FOUND", model_slug, detail=f"Endpoint '{endpoint_slug}' is configured with model '{model_slug}' which is no longer available")
    
    # ── Replace system prompt ──
    messages = data.get("messages", [])
    forced_system_prompt = ep["system_prompt"] or ""
    
    # Remove ALL existing system messages from the client
    messages = [m for m in messages if m.get("role") != "system"]
    
    # Inject the endpoint's system prompt at position 0
    if forced_system_prompt.strip():
        messages.insert(0, {"role": "system", "content": forced_system_prompt})
    
    data["messages"] = messages
    data["model"] = model_slug  # Keep the slug for Claude routing
    
    # ── Override parameters if configured ──
    if ep["temperature"] is not None:
        data["temperature"] = ep["temperature"]
    if ep["max_tokens"] is not None:
        data["max_tokens"] = ep["max_tokens"]
    if ep["top_p"] is not None:
        data["top_p"] = ep["top_p"]
    
    # ── Update usage count ──
    conn.execute("UPDATE custom_endpoints SET usage_count=usage_count+1, last_used_at=CURRENT_TIMESTAMP WHERE id=?", (ep["id"],))
    conn.commit()
    conn.close()
    
    # ── Forward to the model via internal dispatch ──
    # We use Flask's test client to re-dispatch the modified request internally.
    # This ensures proxy_to_provider reads the modified body correctly.
    modified_body = json.dumps(data).encode()
    model_info = MODELS[model_slug]
    
    # Use Flask's test client to re-dispatch with auth headers preserved
    with app.test_client() as client:
        headers_dict = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length')}
        internal_resp = client.post(
            "/v1/chat/completions",
            data=modified_body,
            headers=headers_dict,
            content_type="application/json",
        )
    
    # Build response with custom endpoint headers
    resp_headers = dict(internal_resp.headers)
    resp_headers["X-Custom-Endpoint"] = endpoint_slug
    resp_headers["X-Custom-Model"] = model_slug
    resp_headers["X-RateLimit-Remaining"] = str(remaining)
    
    return internal_resp.data, internal_resp.status_code, resp_headers


# ═══════════════════════════════════════════════════════════════════════════
# PROXY ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/v1/chat/completions", methods=["POST"])
def proxy_chat_standard():
    """OpenAI-standard endpoint — reads model from JSON body."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    
    # ── Rate limiting (token bucket per client IP) ──
    allowed, remaining, retry_after = check_rate_limit()
    if not allowed:
        return jsonify({
            "error": "Rate limit exceeded",
            "message": f"Too many requests. Retry in {retry_after}s.",
            "retry_after_seconds": retry_after,
        }), 429, {"X-RateLimit-Limit": str(RATE_LIMIT_CAPACITY), "X-RateLimit-Remaining": "0", "Retry-After": str(retry_after)}
    
    body = request.get_data()
    try:
        data = json.loads(body)
        model_slug = data.get("model", "")
    except:
        return format_error_response("INVALID_REQUEST", "", detail="Invalid JSON body. Send {\"model\":\"...\",\"messages\":[...]}")
    
    if not model_slug or model_slug not in MODELS:
        return format_error_response("MODEL_NOT_FOUND", model_slug or "unknown")
    
    model_info = MODELS[model_slug]
    resp = proxy_to_provider(model_info["provider"], model_info["real_model"], model_slug)
    # Add rate limit headers to successful responses
    if isinstance(resp, tuple) and len(resp) == 3:
        resp_obj, status, headers = resp
        if hasattr(resp_obj, 'headers'):
            resp_obj.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_CAPACITY)
            resp_obj.headers["X-RateLimit-Remaining"] = str(remaining)
        return resp_obj, status, headers
    return resp


@app.route("/v1/health", methods=["GET"])
def proxy_health():
    """Health check endpoint for API consumers. No auth required."""
    conn = get_db()
    claude_count = conn.execute("SELECT COUNT(*) FROM cookie_files WHERE platform='claude' AND raw_content NOT LIKE 'DEAD:%'").fetchone()[0]
    providers = conn.execute("SELECT slug, provider_type FROM api_providers").fetchall()
    active_keys = 0
    for p in providers:
        kc = conn.execute("SELECT COUNT(*) FROM api_keys WHERE provider_id=(SELECT id FROM api_providers WHERE slug=?) AND is_active=1 AND dead=0", (p["slug"],)).fetchone()[0]
        active_keys += kc
    conn.close()
    
    # ── Claude session orchestration status ──
    with _claude_token_lock:
        active = sum(1 for s in _claude_token_state.values() if s["availability"] == STATE_ACTIVE and not s["dead"])
        parked = sum(1 for s in _claude_token_state.values() if s["availability"] == STATE_PARKED)
        quarantined = sum(1 for s in _claude_token_state.values() if s["availability"] == STATE_QUARANTINED)
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models_available": len(MODELS),
        "claude_sessions": claude_count,
        "claude_orchestration": {
            "active": active,
            "parked": parked,
            "quarantined": quarantined,
            "affinity_pins": len(_affinity_map),
        },
        "proxy_blacklist": get_proxy_blacklist_status(),
        "active_api_keys": active_keys,
        "version": "3.0.0",
        "proxy_provider": "IPRoyal" if PROXY_ENABLED else "direct",
    })


@app.after_request
def add_cors_headers(response):
    """Add CORS headers for API endpoints only. Frontend pages are protected."""
    # Only allow CORS on API endpoints (/v1/*) — frontend pages should not be CORS-accessible
    if request.path.startswith("/v1/"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        response.headers["Access-Control-Max-Age"] = "86400"
    # Add rate limit headers so clients can adapt
    response.headers["X-RateLimit-Limit"] = "100"
    response.headers["X-RateLimit-Remaining"] = "99"
    response.headers["X-RateLimit-Reset"] = str(int(time.time() + 60))
    return response


@app.route("/v1/chat/completions", methods=["OPTIONS"])
@app.route("/v1/<path:path>", methods=["OPTIONS"])
def handle_options(path=""):
    """Handle CORS preflight requests."""
    return "", 204

@app.route("/v1/<model_slug>/chat/completions", methods=["POST"])
def proxy_chat_legacy(model_slug):
    """Legacy endpoint — model in URL path. Kept for backward compatibility."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    
    if model_slug not in MODELS:
        return format_error_response("MODEL_NOT_FOUND", model_slug)
    
    model_info = MODELS[model_slug]
    return proxy_to_provider(model_info["provider"], model_info["real_model"], model_slug)

@app.route("/v1/<model_slug>", methods=["GET"])
def proxy_info(model_slug):
    """Get info about a specific model endpoint."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    
    if model_slug not in MODELS:
        return jsonify({"error": f"Unknown model: '{model_slug}'", "available": list(MODELS.keys())}), 404
    m = MODELS[model_slug]
    return jsonify({
        "model": model_slug,
        "provider": m["provider"],
        "real_model": m["real_model"],
        "description": m["desc"],
        "endpoint": f"https://aicookies.elliaa.com/v1/{model_slug}/chat/completions",
        "format": "OpenAI-compatible (POST with messages array)",
        "auth_required": bool(PROXY_API_KEY_HASH),
    })

@app.route("/v1/models", methods=["GET"])
def list_models():
    """List all available proxy models."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    models = []
    for slug, info in MODELS.items():
        conn = get_db()
        key_count = conn.execute("""
            SELECT COUNT(*) FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
            WHERE p.slug = ? AND k.is_active = 1 AND k.dead = 0
        """, (info["provider"],)).fetchone()[0]
        conn.close()
        caps = info.get("capabilities", {})
        pricing = info.get("pricing", {})
        models.append({
            "id": slug,
            "object": "model",
            "provider": info["provider"],
            "description": info["desc"],
            "active_keys": key_count,
            "endpoint": f"/v1/{slug}/chat/completions",
            # ── Extended metadata ──
            "display_name": info.get("display_name", slug),
            "developer": info.get("developer", info["provider"]),
            "context_window": info.get("tokens", 0),
            "max_output_tokens": info.get("max_output", info.get("tokens", 0)),
            "parameters": info.get("params", "Undisclosed"),
            "style": info.get("style", "direct"),
            "capabilities": {
                "text_generation": caps.get("text", False),
                "code_generation": caps.get("code", False),
                "reasoning_thinking": caps.get("thinking", False),
                "tool_function_calling": caps.get("tools", False),
                "vision_image_input": caps.get("vision", False),
                "web_search": caps.get("web_search", False),
                "json_mode": caps.get("json", False),
                "streaming": caps.get("stream", False),
            },
            "pricing": {
                "input_per_million": pricing.get("in", "N/A"),
                "output_per_million": pricing.get("out", "N/A"),
                "cached_input_per_million": pricing.get("cached_in"),
            },
        })
    return jsonify({"object": "list", "data": models})

# ═══════════════════════════════════════════════════════════════════════════
# EXTENDED API ENDPOINTS — Embeddings, FIM, Moderation
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/v1/embeddings", methods=["POST"])
def proxy_embeddings():
    """OpenAI-compatible embeddings endpoint — proxies to Mistral embeddings."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err

    allowed, remaining, retry_after = check_rate_limit()
    if not allowed:
        return jsonify({"error": "Rate limit exceeded", "retry_after_seconds": retry_after}), 429, {"Retry-After": str(retry_after)}

    body = request.get_data()
    try:
        data = json.loads(body)
        model_slug = data.get("model", "nvidia-nv-embed-v1")
    except:
        return jsonify({"error": "Invalid JSON body. Send {\"model\":\"nvidia-nv-embed-v1\",\"input\":[\"text\"]}"}), 400

    # Resolve model — support NVIDIA NV-Embed and Google text-embedding
    EMBED_MODELS = {
        "nvidia-nv-embed-v1": {"provider": "nvidia", "real_model": "nvidia/nv-embed-v1"},
        "nvidia-llama-embed": {"provider": "nvidia", "real_model": "nvidia/llama-3.2-nv-embedqa-1b-v2"},
        "google-text-embedding-004": {"provider": "google", "real_model": "text-embedding-004"},
    }
    if model_slug in EMBED_MODELS:
        emb_info = EMBED_MODELS[model_slug]
        real_model = emb_info["real_model"]
        emb_provider = emb_info["provider"]
    elif "nv-embed" in model_slug.lower() or "nvidia" in model_slug.lower():
        real_model = model_slug
        emb_provider = "nvidia"
    elif "text-embedding" in model_slug.lower():
        real_model = model_slug
        emb_provider = "google"
    else:
        return jsonify({"error": f"Unknown embeddings model: '{model_slug}'", "available": list(EMBED_MODELS.keys())}), 404

    keys = get_provider_keys(emb_provider)
    if not keys:
        return jsonify({"error": f"No active keys for {emb_provider} provider"}), 503

    for key_info in keys:
        key_id = key_info["id"]
        base_url = key_info["base_url"]
        key_val = key_info["key_value"]

        try:
            payload = json.loads(body)
            payload["model"] = real_model
            url = f"{base_url}/embeddings"
            headers = {"Authorization": f"Bearer {key_val}", "Content-Type": "application/json"}

            proxy = get_proxy_url()
            with httpx.Client(proxy=proxy, timeout=60.0, verify=False) as client:
                resp = client.post(url, json=payload, headers=headers)

            if resp.status_code >= 400:
                if resp.status_code == 429:
                    mark_key_rate_limited(key_id, f"429: {resp.text[:200]}")
                elif resp.status_code in (401, 403):
                    mark_key_error(key_id, f"{resp.status_code}: {resp.text[:200]}")
                else:
                    mark_key_error(key_id, f"{resp.status_code}: {resp.text[:200]}")
                continue

            bump_key_usage(key_id)
            record_proxy_request(model_slug, emb_provider, key_id, "ok", int(time.time() * 1000 % 100000))
            return resp.content, resp.status_code, {"Content-Type": "application/json", "X-Proxy-Provider": emb_provider}

        except Exception as e:
            mark_key_error(key_id, str(e)[:200])
            continue

    return jsonify({"error": f"All {emb_provider} keys failed for embeddings"}), 503


@app.route("/v1/fim/completions", methods=["POST"])
def proxy_fim():
    """FIM (Fill-in-the-Middle) endpoint — deprecated.

    Codestral was the only FIM-capable provider and has been removed.
    Use /v1/chat/completions with a code-capable model instead.
    """
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    return jsonify({
        "error": "FIM endpoint deprecated. Mistral Codestral has been removed from the gateway.",
        "alternative": "Use /v1/chat/completions with models like 'nvidia-qwen-32b', 'or-qwen-32b', or 'kimi-k2p7-code' for code completion tasks.",
        "endpoint": "/v1/chat/completions"
    }), 410


@app.route("/v1/moderations", methods=["POST"])
def proxy_moderation():
    """OpenAI-compatible moderation endpoint — deprecated.

    Mistral moderation was the only moderation provider and has been removed.
    Use the chat completions endpoint with a system prompt for content classification.
    """
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    return jsonify({
        "error": "Moderation endpoint deprecated. Mistral moderation has been removed from the gateway.",
        "alternative": "Use /v1/chat/completions with a classification prompt, or use OpenAI's native moderation API.",
        "endpoint": "/v1/chat/completions"
    }), 410


@app.route("/v1/chat/moderations", methods=["POST"])
def proxy_chat_moderation():
    """Conversational moderation endpoint — deprecated."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    return jsonify({
        "error": "Chat moderation endpoint deprecated. Mistral moderation has been removed from the gateway.",
        "alternative": "Use /v1/chat/completions with a moderation/classification system prompt.",
        "endpoint": "/v1/chat/completions"
    }), 410

# ═══════════════════════════════════════════════════════════════════════════
# PAGES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        # ── Login rate limiting ──
        allowed, remaining, wait_s = check_login_rate_limit(request.remote_addr)
        if not allowed:
            flash(f"⏰ Too many login attempts. Please wait {wait_s}s.", "danger")
            return render_template("login.html"), 429
        if request.form.get("username") == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, request.form.get("password", "")):
            session["logged_in"] = True
            session["username"] = AUTH_USERNAME
            session["_last_activity"] = str(time.time())
            # Clear failed attempts on successful login
            with _login_lock:
                _login_attempts.pop(request.remote_addr, None)
            flash("✅ Login successful", "success")
            return redirect(url_for("dashboard"))
        flash(f"❌ Invalid credentials ({remaining} attempts remaining)", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login_page"))

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    cookie_files = conn.execute("SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files ORDER BY uploaded_at DESC").fetchall()
    claude_count = conn.execute("SELECT COUNT(*) FROM cookie_files WHERE platform = 'claude'").fetchone()[0]
    providers = conn.execute("SELECT p.*, COUNT(k.id) as key_count FROM api_providers p LEFT JOIN api_keys k ON k.provider_id = p.id AND k.is_active = 1 AND k.dead = 0 AND k.suspended = 0 GROUP BY p.id ORDER BY p.name").fetchall()
    dead_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE dead = 1").fetchone()[0]
    suspended_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE suspended = 1").fetchone()[0]
    
    # Calculate stats for dashboard
    total_keys = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    active_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE is_active = 1 AND dead = 0 AND suspended = 0").fetchone()[0]
    total_usage = conn.execute("SELECT COALESCE(SUM(usage_count), 0) FROM api_keys").fetchone()[0]
    
    conn.close()
    
    stats = {
        'total': total_keys,
        'active': active_keys,
        'dead': dead_keys,
        'suspended': suspended_keys,
        'usage': total_usage
    }
    
    return render_template("dashboard.html", files=cookie_files, claude_count=claude_count, providers=providers, dead_keys=dead_keys, suspended_keys=suspended_keys, models=MODELS, stats=stats)

@app.route("/dashboard")
@login_required
def dashboard_alias():
    """Alias for / — redirects to main dashboard."""
    return redirect(url_for("dashboard"))

@app.route("/cookies")
@login_required
def cookies_page():
    """Cookie files list page."""
    conn = get_db()
    cookie_files = conn.execute("SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files ORDER BY uploaded_at DESC").fetchall()
    conn.close()
    return render_template("cookies.html", files=cookie_files)

@app.route("/docs")
@login_required
def docs_page():
    return render_template("docs.html", models=MODELS)

@app.route("/docs.md")
@login_required
def docs_md():
    """Generate downloadable markdown documentation."""
    md = []
    md.append("# AI Proxy Gateway — API Documentation\n\n")
    md.append("## Endpoint\n\n```\nPOST https://aicookies.elliaa.com/v1/chat/completions\n```\n\n")
    md.append("## Authentication\n\nAll requests require a Bearer token:\n\n```\nAuthorization: Bearer YOUR_AICOOKIES_API_KEY\n```\n\n")
    md.append("## Available Models\n\n")
    md.append("| Model | Provider | Style |\n|-------|----------|-------|\n")
    for slug, info in sorted(MODELS.items()):
        style = "🧠 Reasoning" if info.get("style") == "reasoning" else "⚡ Direct"
        md.append(f"| `{slug}` | {info['provider']} | {style} |\n")
    md.append(f"\n**Total:** {len(MODELS)} models\n\n")
    md.append("## Response Styles\n\n")
    md.append("### ⚡ Direct Response\nModels that reply immediately — just the answer. **All** NVIDIA non-reasoning, OpenRouter free, Google non-reasoning, and `kimi-k2p7-code`.\n\n")
    md.append("### 🧠 Reasoning Response\nModels that show thinking process before answering: `glm-5p2`, `qwen3p7-plus`, `deepseek-v4-pro`, `nvidia-deepseek-r1`, `gemini-2.5-flash`, `gemini-2.5-pro`, `or-deepseek-r1`.\n**Important:** set `max_tokens ≥ 500` or answer may be cut off.\n\n")
    md.append("## Streaming (SSE)\n\nAdd `\"stream\": true` to the request body for real-time token streaming:\n\n```bash\ncurl -X POST https://aicookies.elliaa.com/v1/chat/completions \\\n  -H \"Authorization: Bearer YOUR_AICOOKIES_API_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"model\":\"gemini-2.0-flash\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Hello!\"}]}'\n```\n\n")
    md.append("## cURL Example\n\n```bash\ncurl -X POST https://aicookies.elliaa.com/v1/chat/completions \\\n  -H \"Authorization: Bearer YOUR_AICOOKIES_API_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"model\":\"nvidia-llama-3.3-70b\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello!\"}]}'\n```\n\n")
    md.append("## Python (OpenAI SDK)\n\n```python\nfrom openai import OpenAI\nclient = OpenAI(base_url=\"https://aicookies.elliaa.com/v1\", api_key=\"YOUR_AICOOKIES_API_KEY\")\nresponse = client.chat.completions.create(model=\"gemini-2.0-flash\", messages=[{\"role\":\"user\",\"content\":\"Hello!\"}])\n```\n\n")
    md.append("## Smart Key Rotation\n\n- 429/402 → rotate to next key (free providers recover; Fireworks 💀 dies)\n- All keys busy → 503 with `retry_after_ms: 5000`\n- Keys ordered by usage count (least-used first)\n- Cross-provider fallback: if all keys for a provider fail, automatically tries a similar model from another provider\n\n")
    md.append(f"*Generated from https://aicookies.elliaa.com/docs*\n")
    return "".join(md), 200, {"Content-Type": "text/markdown; charset=utf-8", "Content-Disposition": "attachment; filename=aicookies-api-docs.md"}

# ── API Key Minting endpoint ────────────────────────────────────────────
@app.route("/generate-key", methods=["GET", "POST"])
@login_required
def generate_key_page():
    """Admin endpoint to mint a new API key. Returns the plaintext key once."""
    if request.method == "POST" or request.args.get("generate"):
        raw_key, key_hash = generate_api_key()
        # Store the hash in the DB (cookie_files table repurposed as generic kv)
        conn = get_db()
        conn.execute("""CREATE TABLE IF NOT EXISTS proxy_api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT 'default',
            is_active INTEGER DEFAULT 1,
            usage_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP
        )""")
        conn.execute("INSERT OR IGNORE INTO proxy_api_keys (key_hash, label) VALUES (?, ?)", (key_hash, request.form.get("label", "default")))
        conn.commit()
        conn.close()
        flash(f"🔑 API Key generated: {raw_key}", "success")
        return render_template("key_generated.html", api_key=raw_key)
    return render_template("key_generated.html", api_key=None)

# ── Token Management UI ────────────────────────────────────────────────
@app.route("/tokens")
@login_required
def tokens_page():
    """Token management dashboard — list all generated API tokens."""
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS proxy_api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_hash TEXT UNIQUE NOT NULL,
        label TEXT DEFAULT 'default',
        is_active INTEGER DEFAULT 1,
        usage_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP
    )""")
    tokens = conn.execute("SELECT * FROM proxy_api_keys ORDER BY created_at DESC").fetchall()
    tokens_list = [dict(t) for t in tokens]  # Convert to dicts
    total_requests = conn.execute("SELECT COALESCE(SUM(usage_count),0) FROM proxy_api_keys").fetchone()[0]
    conn.close()
    return render_template("tokens.html", tokens=tokens_list, total_requests=total_requests)

@app.route("/tokens/create", methods=["POST"])
@login_required
def tokens_create():
    """Create a new API token. Returns JSON for the modal UI."""
    if request.is_json:
        label = (request.json.get("label") or "").strip()
    else:
        label = (request.form.get("label") or "").strip()
    raw_key, key_hash = generate_api_key()
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS proxy_api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_hash TEXT UNIQUE NOT NULL,
        label TEXT DEFAULT 'default',
        is_active INTEGER DEFAULT 1,
        usage_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP
    )""")
    conn.execute("INSERT OR IGNORE INTO proxy_api_keys (key_hash, label) VALUES (?, ?)", (key_hash, label or "default"))
    conn.commit()
    conn.close()
    app.logger.info(f"[tokens] New API key minted with label '{label}'")
    return jsonify({"api_key": raw_key, "label": label or "default"})

@app.route("/tokens/pause/<int:token_id>", methods=["POST"])
@login_required
def tokens_pause(token_id):
    """Pause a token — it stops working immediately but can be reactivated."""
    conn = get_db()
    conn.execute("UPDATE proxy_api_keys SET is_active=0 WHERE id=?", (token_id,))
    conn.commit()
    conn.close()
    flash("⏸ Token paused", "info")
    return redirect(url_for("tokens_page"))

@app.route("/tokens/activate/<int:token_id>", methods=["POST"])
@login_required
def tokens_activate(token_id):
    """Reactivate a paused token."""
    conn = get_db()
    conn.execute("UPDATE proxy_api_keys SET is_active=1 WHERE id=?", (token_id,))
    conn.commit()
    conn.close()
    flash("▶ Token activated", "success")
    return redirect(url_for("tokens_page"))

@app.route("/tokens/revoke/<int:token_id>", methods=["POST"])
@login_required
def tokens_revoke(token_id):
    """Permanently revoke (delete) a token."""
    conn = get_db()
    conn.execute("DELETE FROM proxy_api_keys WHERE id=?", (token_id,))
    conn.commit()
    conn.close()
    flash("🗑 Token revoked permanently", "danger")
    return redirect(url_for("tokens_page"))


# ═══════════════════════════════════════════════════════════════════════════
# CUSTOM ENDPOINTS UI — Create, manage, test virtual API endpoints
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/endpoints")
@login_required
def endpoints_page():
    """Custom endpoints management dashboard."""
    conn = get_db()
    endpoints = conn.execute("SELECT * FROM custom_endpoints ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("endpoints.html", endpoints=endpoints, models=MODELS)


@app.route("/endpoints/create", methods=["POST"])
@login_required
def endpoints_create():
    """Create a new custom endpoint."""
    slug = request.form.get("slug", "").strip().lower()
    label = request.form.get("label", "").strip()
    description = request.form.get("description", "").strip()
    model_slug = request.form.get("model_slug", "").strip()
    system_prompt = request.form.get("system_prompt", "").strip()
    temperature = request.form.get("temperature", "").strip()
    max_tokens = request.form.get("max_tokens", "").strip()
    top_p = request.form.get("top_p", "").strip()
    is_public = 1 if request.form.get("is_public") else 0
    
    # ── Validation ──
    if not slug or not label or not model_slug:
        flash("⚠ Slug, label, and model are required", "danger")
        return redirect(url_for("endpoints_page"))
    
    # Slug must be URL-safe and not collide with existing models
    import re as _re
    if not _re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', slug):
        flash("⚠ Slug must be lowercase letters, numbers, and hyphens only", "danger")
        return redirect(url_for("endpoints_page"))
    
    if slug in MODELS:
        flash(f"⚠ Slug '{slug}' conflicts with an existing model name", "danger")
        return redirect(url_for("endpoints_page"))
    
    if model_slug not in MODELS:
        flash(f"⚠ Model '{model_slug}' not found", "danger")
        return redirect(url_for("endpoints_page"))
    
    # Parse optional numeric fields
    temp_val = float(temperature) if temperature else None
    max_tok = int(max_tokens) if max_tokens else None
    top_p_val = float(top_p) if top_p else None
    
    conn = get_db()
    try:
        conn.execute("""INSERT INTO custom_endpoints 
            (slug, label, description, model_slug, system_prompt, temperature, max_tokens, top_p, is_active, is_public)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
            (slug, label, description, model_slug, system_prompt, temp_val, max_tok, top_p_val, is_public))
        conn.commit()
        flash(f"✅ Endpoint created: /v1/{slug}/chat/completions", "success")
    except sqlite3.IntegrityError:
        flash(f"⚠ Slug '{slug}' already exists", "danger")
    finally:
        conn.close()
    return redirect(url_for("endpoints_page"))


@app.route("/endpoints/toggle/<int:ep_id>", methods=["POST"])
@login_required
def endpoints_toggle(ep_id):
    """Activate/pause a custom endpoint."""
    conn = get_db()
    ep = conn.execute("SELECT slug, is_active FROM custom_endpoints WHERE id=?", (ep_id,)).fetchone()
    if ep:
        new_state = 0 if ep["is_active"] else 1
        conn.execute("UPDATE custom_endpoints SET is_active=? WHERE id=?", (new_state, ep_id))
        conn.commit()
        flash(f"{'▶ Activated' if new_state else '⏸ Paused'} endpoint /v1/{ep['slug']}/chat/completions", "info")
    conn.close()
    return redirect(url_for("endpoints_page"))


@app.route("/endpoints/delete/<int:ep_id>", methods=["POST"])
@login_required
def endpoints_delete(ep_id):
    """Delete a custom endpoint."""
    conn = get_db()
    ep = conn.execute("SELECT slug FROM custom_endpoints WHERE id=?", (ep_id,)).fetchone()
    if ep:
        conn.execute("DELETE FROM custom_endpoints WHERE id=?", (ep_id,))
        conn.commit()
        flash(f"🗑 Deleted endpoint /v1/{ep['slug']}/chat/completions", "danger")
    conn.close()
    return redirect(url_for("endpoints_page"))


@app.route("/endpoints/test/<int:ep_id>", methods=["POST"])
@login_required
def endpoints_test(ep_id):
    """Test a custom endpoint from the dashboard."""
    conn = get_db()
    ep = conn.execute("SELECT * FROM custom_endpoints WHERE id=?", (ep_id,)).fetchone()
    if not ep:
        conn.close()
        return jsonify({"error": "Endpoint not found"}), 404
    
    test_message = request.form.get("test_message", "Hello, who are you?")
    model_slug = ep["model_slug"]
    
    if model_slug not in MODELS:
        conn.close()
        return jsonify({"error": f"Model '{model_slug}' not available"}), 400
    
    # Build test request
    messages = []
    if ep["system_prompt"]:
        messages.append({"role": "system", "content": ep["system_prompt"]})
    messages.append({"role": "user", "content": test_message})
    
    test_body = json.dumps({
        "model": model_slug,
        "messages": messages,
        "max_tokens": ep["max_tokens"] or 256,
        "temperature": ep["temperature"] or 0.7,
        "top_p": ep["top_p"] or 1.0,
    }).encode()
    
    conn.close()
    
    # Use test client to dispatch internally — pass a valid proxy API key
    # The test runs in a logged-in admin session, so we inject the admin key
    admin_key = os.environ.get("ADMIN_TEST_KEY", "")
    test_headers = {"Content-Type": "application/json"}
    if admin_key:
        test_headers["Authorization"] = f"Bearer {admin_key}"
    
    with app.test_client() as client:
        resp = client.post("/v1/chat/completions", data=test_body, headers=test_headers)
    
    try:
        resp_data = json.loads(resp.data)
        if "choices" in resp_data:
            content = resp_data["choices"][0]["message"]["content"]
            return jsonify({"response": content, "model": resp_data.get("model", model_slug), "status": "success"})
        else:
            return jsonify({"error": resp_data.get("error", "Unknown error"), "status": "error"}), resp.status_code
    except:
        return jsonify({"error": "Failed to parse response", "raw": resp.data.decode()[:500]}), 500


# ── Cookie routes ───────────────────────────────────────────────────────
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_page():
    if request.method == "POST":
        file = request.files.get("cookie_file")
        if not file or file.filename == "": 
            flash("❌ No file selected", "danger")
            return redirect(url_for("upload_page"))
        raw = file.read().decode("utf-8", errors="replace")
        if not raw.strip():
            flash("❌ File is empty", "danger")
            return redirect(url_for("upload_page"))
        platform = detect_platform_from_content(raw)
        cookies = parse_netscape_cookies(raw)
        if not cookies:
            flash("⚠️ No valid cookies found", "warning")
            return redirect(url_for("upload_page"))
        conn = get_db()
        cursor = conn.execute("INSERT INTO cookie_files (platform, filename, raw_content, cookie_count) VALUES (?,?,?,?)",
                              (platform, file.filename, raw, len(cookies)))
        fid = cursor.lastrowid
        for c in cookies:
            conn.execute("INSERT INTO cookies (file_id, platform, domain, flag, path, secure, expiration, name, value) VALUES (?,?,?,?,?,?,?,?,?)",
                         (fid, platform, c["domain"], c["flag"], c["path"], c["secure"], c["expiration"], c["name"], c["value"]))
        conn.commit(); conn.close()
        flash(f"✅ Uploaded {len(cookies)} cookies for {platform.upper()}", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")

@app.route("/cookies/<int:file_id>")
@login_required
def view_cookies(file_id):
    conn = get_db()
    f = conn.execute("SELECT * FROM cookie_files WHERE id=?", (file_id,)).fetchone()
    if not f: conn.close(); flash("❌ Not found", "danger"); return redirect(url_for("dashboard"))
    cookies = conn.execute("SELECT * FROM cookies WHERE file_id=? ORDER BY domain, name", (file_id,)).fetchall()
    conn.close()
    return render_template("cookie_detail.html", file=f, cookies=cookies)

@app.route("/delete-cookie/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    conn = get_db()
    conn.execute("DELETE FROM cookie_files WHERE id=?", (file_id,)); conn.commit(); conn.close()
    flash("🗑️ Deleted", "info")
    return redirect(url_for("dashboard"))

# ── Keys routes ──────────────────────────────────────────────────────────
@app.route("/keys", methods=["GET", "POST"])
@login_required
def keys_page():
    conn = get_db()
    if request.method == "POST":
        try:
            key_val = request.form.get("key_value", "").strip()
            if not key_val:
                flash("❌ API key is required", "danger")
                conn.close()
                return redirect(url_for("keys_page"))

            # ── Auto-detect provider from key prefix/format ──
            detected_provider = detect_provider_from_key(key_val)
            if not detected_provider:
                flash("❌ Could not identify provider from key format. Please check the key.", "danger")
                conn.close()
                return redirect(url_for("keys_page"))

            pid = detected_provider["id"]
            prov_slug = detected_provider["slug"]
            prov_name = detected_provider["name"]
            label = request.form.get("label", "").strip()
            if not label:
                label = f"{prov_name} key"

            conn.execute("INSERT INTO api_keys (provider_id, label, key_value) VALUES (?,?,?)", (int(pid), label, key_val))
            new_key_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
            flash(f"✅ Key added → detected as <b>{prov_name}</b>", "success")
            # Auto-fetch account info for Fireworks keys
            if prov_slug == "fireworks":
                conn.close()  # close before fetch (fetch opens its own conn)
                try:
                    info = fetch_and_store_account_info(new_key_id, key_val, "fireworks")
                    status = info.get("account_status", "unknown")
                    name = info.get("account_name", "")
                    if status == "active":
                        flash(f"✅ Account info fetched: {name or 'active'} — rate limit: {info.get('rate_limit_prompt', 'N/A')} prompt tokens", "info")
                    elif status == "suspended":
                        flash(f"⚠️ Account suspended: {name or 'unknown'} — {info.get('suspension_reason', '')[:100]}", "warning")
                    else:
                        flash(f"ℹ️ Account status: {status}", "info")
                except Exception as e:
                    flash(f"ℹ️ Key added, but account info fetch failed: {str(e)[:100]}", "info")
            else:
                conn.close()
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error: {str(e)[:100]}", "danger")
        finally:
            conn.close()
        return redirect(url_for("keys_page"))
    
    providers = conn.execute("SELECT * FROM api_providers ORDER BY name").fetchall()
    keys = conn.execute("""SELECT k.id, k.provider_id, k.label, k.key_value, k.is_active, k.dead, 
        k.usage_count, k.error_count, k.last_used_at, k.last_error_at, k.last_error_msg, k.created_at, k.suspended,
        p.name as provider_name, p.slug as provider_slug, p.provider_type,
        CASE p.slug
            WHEN 'anthropic' THEN '🤖'
            WHEN 'openai' THEN '🧠'
            WHEN 'google' THEN '🔵'
            WHEN 'mistral' THEN '🌪️'
            WHEN 'fireworks' THEN '🎆'
            WHEN 'groq' THEN '⚡'
            WHEN 'perplexity' THEN '🔍'
            WHEN 'cohere' THEN '🧩'
            WHEN 'nvidia' THEN '💚'
            WHEN 'openrouter' THEN '🔀'
            ELSE '🔑'
        END as provider_icon
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.suspended = 0
        ORDER BY p.name, k.dead ASC, k.created_at DESC""").fetchall()
    
    # Convert sqlite3.Row objects to dicts for template access
    keys_list = [dict(k) for k in keys]
    
    providers_parsed = []
    for p in providers:
        pd = dict(p)
        # Add icon to provider
        pd["icon"] = {
            'anthropic': '🤖', 'openai': '🧠', 'google': '🔵', 'mistral': '🌪️',
            'fireworks': '🎆', 'groq': '⚡', 'perplexity': '🔍', 'cohere': '🧩',
            'nvidia': '💚', 'openrouter': '🔀'
        }.get(pd.get('slug', ''), '🔑')
        try: pd["free_models_parsed"] = json.loads(p["free_models"]) if p["free_models"] else []
        except: pd["free_models_parsed"] = []
        providers_parsed.append(pd)
    conn.close()
    
    # Calculate stats
    active_count = sum(1 for k in keys_list if k['is_active'] and not k['dead'])
    dead_count = sum(1 for k in keys_list if k['dead'])
    
    return render_template("keys.html", 
        providers=providers_parsed, 
        keys=keys_list,
        active_count=active_count,
        dead_count=dead_count,
        total_keys=len(keys_list),
        current_provider='all')

@app.route("/delete-key/<int:key_id>", methods=["POST"])
@login_required
def delete_key(key_id):
    conn = get_db(); conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,)); conn.commit(); conn.close()
    flash("🗑️ Deleted", "info")
    return redirect(url_for("keys_page"))

# ── Suspended Keys Page ──────────────────────────────────────────────────
@app.route("/keys/suspended")
@login_required
def suspended_keys_page():
    """View suspended keys (temporarily deactivated, admin can reactivate)."""
    conn = get_db()
    keys = conn.execute("""SELECT k.id, k.provider_id, k.label, k.key_value, k.is_active, k.dead, 
        k.usage_count, k.error_count, k.last_used_at, k.last_error_at, k.last_error_msg, k.created_at, k.suspended,
        p.name as provider_name, p.slug as provider_slug, p.provider_type,
        CASE p.slug
            WHEN 'anthropic' THEN '🤖'
            WHEN 'openai' THEN '🧠'
            WHEN 'google' THEN '🔵'
            WHEN 'mistral' THEN '🌪️'
            WHEN 'fireworks' THEN '🎆'
            WHEN 'groq' THEN '⚡'
            WHEN 'perplexity' THEN '🔍'
            WHEN 'cohere' THEN '🧩'
            WHEN 'nvidia' THEN '💚'
            WHEN 'openrouter' THEN '🔀'
            ELSE '🔑'
        END as provider_icon
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.suspended = 1
        ORDER BY p.name, k.last_error_at DESC""").fetchall()

    # Convert to dicts for template
    keys_list = [dict(k) for k in keys]

    # Also get cached account info for each suspended key
    key_ids = [k["id"] for k in keys_list]
    account_infos = {}
    if key_ids:
        placeholders = ",".join("?" * len(key_ids))
        accts = conn.execute(
            f"SELECT * FROM key_account_info WHERE key_id IN ({placeholders})",
            key_ids
        ).fetchall()
        for a in accts:
            account_infos[a["key_id"]] = dict(a)
    conn.close()

    suspended_count = len(keys_list)
    return render_template("suspended.html", suspended_keys=keys_list, suspended_count=suspended_count,
                          account_infos=account_infos)

# ── Reactivate suspended key ────────────────────────────────────────────
@app.route("/keys/suspended/reactivate/<int:key_id>", methods=["POST"])
@login_required
def reactivate_suspended_key(key_id):
    """Test a suspended key against the provider API. If it responds OK,
    unsuspend it and return it to the active pool."""
    conn = get_db()
    key = conn.execute("""SELECT k.*, p.base_url, p.slug as provider_slug
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.id=? AND k.suspended=1""", (key_id,)).fetchone()
    if not key:
        conn.close()
        flash("❌ Key not found or not suspended", "danger")
        return redirect(url_for("suspended_keys_page"))

    key = dict(key)
    try:
        url = f"{key['base_url']}/models"
        headers = {"Authorization": f"Bearer {key['key_value']}"}
        with httpx.Client(timeout=10.0, verify=False) as c:
            r = c.get(url, headers=headers)

        if r.status_code == 200:
            # Key is working again — unsuspend
            conn.execute("""UPDATE api_keys SET suspended=0, is_active=1, error_count=0,
                last_error_msg=NULL WHERE id=?""", (key_id,))
            conn.commit()
            flash("✅ Key reactivated successfully — account is active again", "success")
            app.logger.info(f"[reactivate] Key #{key_id} manually reactivated by admin")
            
            # Also refresh account info
            try:
                info = fetch_and_store_account_info(key_id, key["key_value"], key.get("provider_slug", "fireworks"))
            except:
                pass
        else:
            # Still suspended or dead
            flash(f"❌ Key still not working (HTTP {r.status_code}). Account may still be suspended.", "danger")
    except Exception as e:
        flash(f"❌ Connection error: {str(e)[:150]}", "danger")
    finally:
        conn.close()

    return redirect(url_for("suspended_keys_page"))

# ── Reactivate ALL suspended keys ───────────────────────────────────────
@app.route("/keys/suspended/reactivate-all", methods=["POST"])
@login_required
def reactivate_all_suspended_keys():
    """Test all suspended keys. Unsuspend those that respond OK."""
    conn = get_db()
    suspended = conn.execute("""SELECT k.id, k.key_value, p.base_url, p.slug as provider_slug
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.suspended = 1""").fetchall()
    conn.close()

    reactivated = 0
    failed = 0
    for k in suspended:
        k = dict(k)
        try:
            url = f"{k['base_url']}/models"
            headers = {"Authorization": f"Bearer {k['key_value']}"}
            with httpx.Client(timeout=10.0, verify=False) as c:
                r = c.get(url, headers=headers)

            if r.status_code == 200:
                conn2 = get_db()
                conn2.execute("""UPDATE api_keys SET suspended=0, is_active=1, error_count=0,
                    last_error_msg=NULL WHERE id=?""", (k["id"],))
                conn2.commit()
                conn2.close()
                reactivated += 1
                app.logger.info(f"[reactivate-all] Key #{k['id']} reactivated")
            else:
                failed += 1
        except Exception:
            failed += 1

    if reactivated:
        flash(f"✅ Reactivated {reactivated} key(s) — {failed} still suspended", "success")
    else:
        flash(f"⚠️ No keys could be reactivated — {failed} keys still suspended", "warning")

    return redirect(url_for("suspended_keys_page"))

@app.route("/toggle-key/<int:key_id>", methods=["POST"])
@login_required
def toggle_key(key_id):
    conn = get_db()
    key = conn.execute("SELECT is_active FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if key:
        conn.execute("UPDATE api_keys SET is_active=? WHERE id=?", (0 if key["is_active"] else 1, key_id))
        conn.commit()
    conn.close()
    return redirect(url_for("keys_page"))

# ── API: Account info ─────────────────────────────────────────────────────
@app.route("/api/account-info/<int:key_id>")
@login_required
def api_account_info(key_id):
    """Fetch (or return cached) account info for a specific key."""
    conn = get_db()
    key = conn.execute("""SELECT k.*, p.slug as provider_slug
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.id=?""", (key_id,)).fetchone()
    if not key:
        conn.close()
        return jsonify({"error": "Key not found"}), 404

    # Check if we have cached data
    cached = conn.execute("SELECT * FROM key_account_info WHERE key_id=?", (key_id,)).fetchone()
    conn.close()

    if cached:
        return jsonify({"status": "cached", "data": dict(cached)})

    # No cached data — fetch fresh
    if key["provider_slug"] == "fireworks":
        try:
            info = fetch_and_store_account_info(key_id, key["key_value"], "fireworks")
            return jsonify({"status": "fresh", "data": info})
        except Exception as e:
            return jsonify({"error": str(e)[:200]}), 500

    return jsonify({"error": f"Account info not supported for {key['provider_slug']}"}), 400


@app.route("/api/account-info/<int:key_id>/refresh", methods=["POST"])
@login_required
def api_account_info_refresh(key_id):
    """Force-refresh account info for a specific key."""
    conn = get_db()
    key = conn.execute("""SELECT k.*, p.slug as provider_slug
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.id=?""", (key_id,)).fetchone()
    conn.close()
    if not key:
        return jsonify({"error": "Key not found"}), 404

    if key["provider_slug"] == "fireworks":
        try:
            info = fetch_and_store_account_info(key_id, key["key_value"], "fireworks")
            return jsonify({"status": "refreshed", "data": info})
        except Exception as e:
            return jsonify({"error": str(e)[:200]}), 500

    return jsonify({"error": f"Account info not supported for {key['provider_slug']}"}), 400


@app.route("/api/account-info/bulk-fetch", methods=["POST"])
@login_required
def api_account_info_bulk():
    """Fetch account info for ALL Fireworks keys at once."""
    conn = get_db()
    keys = conn.execute("""SELECT k.id, k.key_value, k.dead, k.is_active
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = 'fireworks'""").fetchall()
    conn.close()

    results = []
    for k in keys:
        try:
            info = fetch_and_store_account_info(k["id"], k["key_value"], "fireworks")
            results.append({
                "key_id": k["id"],
                "status": info.get("account_status"),
                "account_name": info.get("account_name"),
                "rate_limit_prompt": info.get("rate_limit_prompt"),
            })
        except Exception as e:
            results.append({"key_id": k["id"], "status": "error", "error": str(e)[:100]})

    return jsonify({"status": "ok", "fetched": len(results), "results": results})

# ── API: keys ───────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(force=True, silent=True) or {}
    if d.get("username") == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, d.get("password", "")):
        session["logged_in"] = True
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/cookies", methods=["GET"])
@login_required
def api_list_cookies():
    conn = get_db(); p = request.args.get("platform")
    q = "SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files" + (" WHERE platform=?" if p else "") + " ORDER BY uploaded_at DESC"
    rows = conn.execute(q, (p,) if p else ()).fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/cookies/raw/<int:file_id>")
@login_required
def api_get_raw(file_id):
    conn = get_db(); f = conn.execute("SELECT * FROM cookie_files WHERE id=?", (file_id,)).fetchone(); conn.close()
    if not f: return jsonify({"error": "Not found"}), 404
    return f["raw_content"], 200, {"Content-Type": "text/plain"}

@app.route("/api/cookies/latest")
@login_required
def api_latest():
    conn = get_db()
    f = conn.execute("SELECT * FROM cookie_files WHERE platform=? ORDER BY uploaded_at DESC LIMIT 1", (request.args.get("platform", "claude"),)).fetchone()
    conn.close()
    if not f: return jsonify({"error": "No cookies"}), 404
    return jsonify(dict(f))

@app.route("/api/keys", methods=["GET", "POST"])
@login_required
def api_keys():
    conn = get_db()
    if request.method == "POST":
        d = request.get_json(force=True, silent=True) or {}
        prov = conn.execute("SELECT id FROM api_providers WHERE slug=?", (d.get("provider"),)).fetchone()
        if not prov: conn.close(); return jsonify({"error": "Unknown provider"}), 404
        conn.execute("INSERT INTO api_keys (provider_id, label, key_value) VALUES (?,?,?)", (prov["id"], d.get("label",""), d["key"]))
        conn.commit(); conn.close()
        return jsonify({"status": "ok"}), 201
    
    prov = request.args.get("provider")
    rows = conn.execute("""SELECT k.*, p.name as provider_name, p.slug as provider_slug, p.base_url, p.provider_type
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE k.is_active=1 AND k.dead=0 AND k.suspended=0""" + (" AND p.slug=?" if prov else "") + " ORDER BY k.usage_count ASC",
        (prov,) if prov else ()).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys/next/<provider>")
@login_required
def api_next_key(provider):
    conn = get_db()
    key = conn.execute("""SELECT k.*, p.base_url, p.provider_type FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug=? AND k.is_active=1 AND k.dead=0 AND k.suspended=0 ORDER BY k.usage_count ASC, k.created_at ASC LIMIT 1""", (provider,)).fetchone()
    if key:
        conn.execute("UPDATE api_keys SET usage_count=usage_count+1, last_used_at=CURRENT_TIMESTAMP WHERE id=?", (key["id"],))
        conn.commit()
    conn.close()
    if not key: return jsonify({"error": f"No active key for {provider}"}), 404
    return jsonify(dict(key))

@app.route("/api/keys/mark-rate-limited/<int:key_id>", methods=["POST"])
@login_required
def api_mark_rl(key_id): mark_key_rate_limited(key_id, "manual"); return jsonify({"status": "ok"})

@app.route("/api/keys/revive", methods=["POST"])
@login_required
def api_revive_keys():
    """Manually trigger revive of dead keys. Returns count revived."""
    count = revive_dead_keys()
    return jsonify({"status": "ok", "revived": count})

@app.route("/api/keys/revive/<int:key_id>", methods=["POST"])
@login_required
def api_revive_single(key_id):
    """Manually revive a single dead key — useful after billing resolved."""
    conn = get_db()
    key = conn.execute("SELECT k.*, p.base_url, p.slug FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE k.id=?", (key_id,)).fetchone()
    if not key:
        conn.close()
        return jsonify({"error": "Key not found"}), 404
    key = dict(key)
    try:
        url = f"{key['base_url']}/models"
        headers = {"Authorization": f"Bearer {key['key_value']}"}
        with httpx.Client(timeout=10.0, verify=False) as c:
            r = c.get(url, headers=headers)
        if r.status_code == 200:
            conn.execute("UPDATE api_keys SET dead=0, is_active=1, error_count=0, last_error_msg=NULL WHERE id=?", (key_id,))
            conn.commit()
            conn.close()
            app.logger.info(f"[revive] Key #{key_id} manually revived by admin")
            return jsonify({"status": "ok", "revived": True})
        else:
            conn.close()
            return jsonify({"status": "ok", "revived": False, "http_code": r.status_code})
    except Exception as e:
        conn.close()
        return jsonify({"status": "ok", "revived": False, "error": str(e)[:200]})

@app.route("/api/keys/reset-usage/<provider>", methods=["POST"])
@login_required
def api_reset_usage(provider):
    conn = get_db(); conn.execute("UPDATE api_keys SET usage_count=0 WHERE provider_id=(SELECT id FROM api_providers WHERE slug=?)", (provider,)); conn.commit(); conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/providers")
@login_required
def api_list_providers():
    conn = get_db()
    rows = conn.execute("""SELECT p.*, COUNT(k.id) as key_count FROM api_providers p LEFT JOIN api_keys k ON k.provider_id=p.id AND k.is_active=1 AND k.dead=0 AND k.suspended=0 GROUP BY p.id ORDER BY p.name""").fetchall()
    conn.close()
    result = []
    for p in rows:
        d = dict(p); d["free_models"] = json.loads(p["free_models"]) if p["free_models"] else []; result.append(d)
    return jsonify(result)

@app.route("/api/models")
@login_required
def api_models():
    conn = get_db()
    result = []
    for slug, info in MODELS.items():
        kc = conn.execute("SELECT COUNT(*) FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE p.slug=? AND k.is_active=1 AND k.dead=0 AND k.suspended=0", (info["provider"],)).fetchone()[0]
        dead = conn.execute("SELECT COUNT(*) FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE p.slug=? AND k.dead=1", (info["provider"],)).fetchone()[0]
        suspended = conn.execute("SELECT COUNT(*) FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE p.slug=? AND k.suspended=1", (info["provider"],)).fetchone()[0]
        result.append({"slug": slug, "provider": info["provider"], "real_model": info["real_model"], "desc": info["desc"], "active_keys": kc, "dead_keys": dead, "suspended_keys": suspended, "endpoint": f"/v1/{slug}/chat/completions"})
    conn.close()
    return jsonify(result)

@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM proxy_requests").fetchone()[0]
    ok = conn.execute("SELECT COUNT(*) FROM proxy_requests WHERE status='ok'").fetchone()[0]
    recent = conn.execute("SELECT * FROM proxy_requests ORDER BY created_at DESC LIMIT 20").fetchall()
    dead_keys = conn.execute("SELECT k.*, p.name as provider_name FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE k.dead=1").fetchall()
    suspended_keys = conn.execute("SELECT k.*, p.name as provider_name FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE k.suspended=1").fetchall()
    conn.close()
    
    # Include Claude token state
    claude_state = {}
    with _claude_token_lock:
        for cid, state in _claude_token_state.items():
            claude_state[str(cid)] = {
                "usage": state["usage"],
                "cooldown_until": state["cooldown_until"],
                "cooldown_remaining_s": max(0, int(state["cooldown_until"] - time.time())),
                "dead": state["dead"],
                "last_error": state["last_error"],
            }
    
    return jsonify({
        "total_requests": total, "successful": ok,
        "recent": [dict(r) for r in recent],
        "dead_keys": [dict(d) for d in dead_keys],
        "suspended_keys": [dict(d) for d in suspended_keys],
        "claude_tokens": claude_state,
    })

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL ERROR HANDLERS — catch unhandled exceptions and return clean JSON
# ═══════════════════════════════════════════════════════════════════════════

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "message": str(e)}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found", "message": "The requested endpoint does not exist"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed", "message": "This endpoint does not support the requested method"}), 405

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too Many Requests", "message": "Rate limit exceeded. Please retry later.", "retry_after_ms": 5000}), 429

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"[gateway] 500 error: {e}")
    return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500

@app.errorhandler(502)
def bad_gateway(e):
    return jsonify({"error": "Bad Gateway", "message": "Upstream provider error"}), 502

@app.errorhandler(503)
def service_unavailable(e):
    return jsonify({"error": "Service Unavailable", "message": "All provider sessions are busy or expired"}), 503

@app.errorhandler(504)
def gateway_timeout(e):
    return jsonify({"error": "Gateway Timeout", "message": "Provider did not respond in time"}), 504

@app.errorhandler(Exception)
def unhandled_exception(e):
    """Catch-all for any unhandled exception — prevents Flask from returning HTML."""
    app.logger.error(f"[gateway] Unhandled exception: {type(e).__name__}: {e}")
    if isinstance(e, httpx.HTTPStatusError):
        return jsonify({"error": "Upstream HTTP Error", "message": str(e)[:200]}), 502
    return jsonify({"error": "Internal Server Error", "message": str(e)[:200], "type": type(e).__name__}), 500

# ── Key Revival (manual only — triggered by admin from UI) ────────────────
_revive_lock = threading.Lock()

def revive_dead_keys():
    """Check if 'dead' keys can be revived. Sends a lightweight /models request
    to each dead key. If it returns 200, the account has been reactivated and
    the key is restored. Called ONLY manually by admin — no auto-revive."""
    with _revive_lock:
        conn = get_db()
        dead = conn.execute("""
            SELECT k.id, k.key_value, k.last_error_msg, p.base_url, p.slug
            FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
            WHERE k.dead = 1
        """).fetchall()
        if not dead:
            conn.close()
            return 0
        revived = 0
        for k in dead:
            k = dict(k)
            try:
                url = f"{k['base_url']}/models"
                headers = {"Authorization": f"Bearer {k['key_value']}"}
                with httpx.Client(timeout=10.0, verify=False) as c:
                    r = c.get(url, headers=headers)
                if r.status_code == 200:
                    conn.execute(
                        "UPDATE api_keys SET dead=0, is_active=1, error_count=0, "
                        "last_error_msg=NULL WHERE id=?",
                        (k["id"],),
                    )
                    conn.commit()
                    revived += 1
                    app.logger.info(f"[revive] Key #{k['id']} ({k['slug']}) revived — account reactivated")
            except Exception:
                pass  # Still dead, skip
        conn.close()
        if revived:
            app.logger.info(f"[revive] Revived {revived}/{len(dead)} dead keys (manual trigger)")
        return revived

# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
