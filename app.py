#!/usr/bin/env python3
"""AI Proxy Gateway — Smart model-level proxy with automatic key rotation."""

import os, re, json, sqlite3, secrets, time, uuid, hashlib, threading
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
import httpx
from curl_cffi import requests as curl_requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
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
    for col, col_type in [("provider_type", "TEXT DEFAULT 'free'")]:
        try: conn.execute(f"ALTER TABLE api_providers ADD COLUMN {col} {col_type}")
        except: pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_dead ON api_keys(dead)")
    for col, col_type in [("proxy_ip", "TEXT"), ("proxy_country", "TEXT")]:
        try: conn.execute(f"ALTER TABLE proxy_requests ADD COLUMN {col} {col_type}")
        except: pass

    # ── Seed providers ──
    providers = [
        ("mistral", "Mistral AI", "https://api.mistral.ai/v1", "free",
         '["mistral-small-latest","mistral-medium-latest","open-mistral-nemo","codestral-latest","ministral-8b-latest"]',
         "Free tier: 1 req/sec, 1M tokens/month."),
        ("cohere", "Cohere", "https://api.cohere.com/v2", "free",
         '["command-a-03-2025","command-r7b-12-2024","command-r-plus-08-2024"]',
         "Free trial: 1000 req/month. Uses /v2/chat endpoint."),
        ("sambanova", "SambaNova", "https://api.sambanova.ai/v1", "free",
         '["Meta-Llama-3.3-70B-Instruct"]',
         "Free tier: generous rate limits. OpenAI-compatible."),
        ("fireworks", "Fireworks AI", "https://api.fireworks.ai/inference/v1", "prepaid",
         '["accounts/fireworks/models/glm-5p2","accounts/fireworks/models/kimi-k2p7-code","accounts/fireworks/models/qwen3p7-plus","accounts/fireworks/models/deepseek-v4-pro"]',
         "$6 per account. When depleted → permanently dead."),
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

# ── Auth decorator ───────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════════════════════════
# MODEL REGISTRY — maps model slugs to providers
# ═══════════════════════════════════════════════════════════════════════════

MODELS = {
    # Claude (cookie-based — special handling)
    "claude-sonnet-4-6":  {"provider": "claude",  "real_model": "claude-sonnet-4-6",  "desc": "Claude Sonnet 4 — 200K context", "style": "direct", "tokens": 200000},
    # Mistral
    "mistral-small":     {"provider": "mistral", "real_model": "mistral-small-latest",     "desc": "Mistral Small — fast, efficient", "tokens": 32000},
    "mistral-medium":    {"provider": "mistral", "real_model": "mistral-medium-latest",    "desc": "Mistral Medium — balanced", "tokens": 32000},
    "mistral-nemo":      {"provider": "mistral", "real_model": "open-mistral-nemo",        "desc": "Open Mistral Nemo — 12B", "tokens": 128000},
    "codestral":         {"provider": "mistral", "real_model": "codestral-latest",         "desc": "Codestral — code generation", "tokens": 256000},
    "ministral-8b":      {"provider": "mistral", "real_model": "ministral-8b-latest",      "desc": "Ministral 8B — lightweight", "tokens": 128000},
    # Cohere
    "command-a":         {"provider": "cohere",  "real_model": "command-a-03-2025",        "desc": "Command A — latest flagship", "tokens": 256000},
    "command-r7b":       {"provider": "cohere",  "real_model": "command-r7b-12-2024",      "desc": "Command R7B — fast & capable", "tokens": 128000},
    "command-r-plus":    {"provider": "cohere",  "real_model": "command-r-plus-08-2024",   "desc": "Command R+ — most powerful", "tokens": 128000},
    # SambaNova
    "llama-3.3-70b":     {"provider": "sambanova", "real_model": "Meta-Llama-3.3-70B-Instruct",          "desc": "Llama 3.3 70B — powerful", "style": "direct", "tokens": 131072},
    # Fireworks
    "glm-5p2":           {"provider": "fireworks", "real_model": "accounts/fireworks/models/glm-5p2",          "desc": "GLM 5P2 — general reasoning", "style": "reasoning", "tokens": 131072},
    "kimi-k2p7-code":    {"provider": "fireworks", "real_model": "accounts/fireworks/models/kimi-k2p7-code",   "desc": "Kimi K2.7 — code generation", "style": "direct", "tokens": 32768},
    "qwen3p7-plus":      {"provider": "fireworks", "real_model": "accounts/fireworks/models/qwen3p7-plus",     "desc": "Qwen 3.7 Plus — multimodal reasoning", "style": "reasoning", "tokens": 4000},
    "deepseek-v4-pro":   {"provider": "fireworks", "real_model": "accounts/fireworks/models/deepseek-v4-pro",  "desc": "DeepSeek V4 Pro — deep reasoning", "style": "reasoning", "tokens": 131072},
}

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
    """Get active, non-dead keys for a provider, ordered by usage_count."""
    conn = get_db()
    rows = conn.execute("""
        SELECT k.*, p.base_url, p.provider_type
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = ? AND k.is_active = 1 AND k.dead = 0
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
            if provider_slug == "cohere":
                url = f"{base_url}/chat"
                payload = inject_model_into_body(body, real_model, provider_slug)
            else:
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
                return resp.content, resp.status_code, {
                    "Content-Type": resp.headers.get("Content-Type", "application/json"),
                    "X-Proxy-Provider": provider_slug, "X-Proxy-Key": str(key_id),
                    "X-Proxy-Latency": str(latency),
                }
        
        except httpx.HTTPStatusError as e:
            latency = int((time.time() - start) * 1000)
            code = e.response.status_code
            body_err = e.response.text[:500]
            
            if code == 402 or "insufficient" in body_err.lower() or "quota" in body_err.lower():
                if provider_type == "prepaid" or provider_slug == "fireworks":
                    mark_key_dead(key_id, f"402 Depleted: {body_err[:200]}")
                    error_msg = "DEPLETED"
                else:
                    mark_key_rate_limited(key_id, f"402: {body_err[:200]}")
                    error_msg = "RATE_LIMITED_402"
            elif code == 429:
                mark_key_rate_limited(key_id, f"429: {body_err[:200]}")
                error_msg = "RATE_LIMITED"
            elif code in (401, 403):
                if provider_type == "prepaid":
                    mark_key_dead(key_id, f"{code}: {body_err[:200]}")
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
    
    # All keys failed — return clean error without exposing provider internals
    return jsonify({
        "error": "Service Unavailable",
        "message": "All providers are currently busy. Please try again in a moment.",
        "model": model_slug,
        "retry_after_ms": 5000,
    }), 503

# ═══════════════════════════════════════════════════════════════════════════
# CLAUDE PROXY — Smart Token Rotation & State Management
# ═══════════════════════════════════════════════════════════════════════════

# In-memory state for Claude cookie sessions (survives between requests, lost on restart)
_claude_token_lock = threading.RLock()
_claude_token_state = {}  # cookie_file_id → {usage, cooldown_until, dead, last_error}

COOLDOWN_SECONDS = 300  # 5 minutes cooldown after rate limit

def _get_token_state(cookie_id):
    """Get or create state entry for a cookie token."""
    with _claude_token_lock:
        if cookie_id not in _claude_token_state:
            _claude_token_state[cookie_id] = {
                "usage": 0,
                "cooldown_until": 0,
                "dead": False,
                "last_error": None,
            }
        return _claude_token_state[cookie_id]

def _mark_token_used(cookie_id):
    with _claude_token_lock:
        state = _get_token_state(cookie_id)
        state["usage"] += 1

def _mark_token_cooldown(cookie_id, reason=""):
    with _claude_token_lock:
        state = _get_token_state(cookie_id)
        state["cooldown_until"] = time.time() + COOLDOWN_SECONDS
        state["last_error"] = reason

def _mark_token_dead(cookie_id, reason=""):
    with _claude_token_lock:
        state = _get_token_state(cookie_id)
        state["dead"] = True
        state["last_error"] = reason
    # Also persist to DB
    try:
        conn = get_db()
        conn.execute("UPDATE cookie_files SET raw_content = 'DEAD:' || raw_content WHERE id = ?", (cookie_id,))
        conn.commit()
        conn.close()
    except:
        pass

def _get_available_tokens(cookie_sets):
    """Filter and sort cookie sets: skip dead, skip cooldown, sort by usage (least first)."""
    now = time.time()
    available = []
    with _claude_token_lock:
        for cs in cookie_sets:
            state = _get_token_state(cs["id"])
            if state["dead"]:
                continue
            if state["cooldown_until"] > now:
                continue
            available.append((state["usage"], cs))
    available.sort(key=lambda x: x[0])  # Least-used first
    return [cs for _, cs in available]

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
        cookies.append({"name": parts[5], "value": parts[6]})
    return cookies

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


def build_natural_prompt(messages):
    """Convert OpenAI-format API messages into a natural conversation prompt
    for Claude.ai's web interface.

    This middleware replaces the old Mistral-based humanization. It:
    - Converts system prompts into natural context notes (not <system> tags)
    - Preserves full multi-turn context (user + assistant messages)
    - Removes API artifacts that could trigger Claude's anti-automation heuristics
    - Keeps the exact meaning and intent of every message
    - Adds natural conversational framing

    Returns: (prompt_text, was_transformed)
    """
    if not messages:
        return "", False

    # Separate system messages from conversation
    system_parts = []
    conv_parts = []
    for m in messages:
        role = m.get("role", "user")
        content = str(m.get("content", ""))
        if role == "system":
            system_parts.append(content)
        elif role == "user":
            conv_parts.append(("user", content))
        elif role == "assistant":
            conv_parts.append(("assistant", content))
        else:
            conv_parts.append((role, content))

    prompt_pieces = []

    # ── System prompt → natural context note ──
    # Instead of <system> tags (which scream "API"), we weave system instructions
    # into a natural "by the way" or "for context" note at the top
    if system_parts:
        system_text = "\n".join(system_parts).strip()
        if system_text:
            # Natural framing that doesn't look like an API system tag
            prompt_pieces.append(system_text)

    # ── Conversation turns → natural dialogue ──
    for role, content in conv_parts:
        if role == "user":
            prompt_pieces.append(f"Human: {content}")
        elif role == "assistant":
            prompt_pieces.append(f"Assistant: {content}")
        else:
            prompt_pieces.append(f"{role.capitalize()}: {content}")

    prompt_text = "\n\n".join(prompt_pieces)

    # ── Artifact format instruction ──
    # Tell Claude to use standard Markdown code blocks instead of <antArtifact> XML.
    # This ensures any frontend (not just Claude.ai) can parse the output.
    # We append it naturally so it doesn't look like an API system tag.
    artifact_instruction = (
        "\n\n---\n"
        "Output format note: When writing code, UI components, HTML, SVG, or any "
        "file content, use standard Markdown code blocks (```html, ```tsx, ```python, "
        "```csv, etc.) with the appropriate language label. Do NOT use <antArtifact> "
        "XML tags or <antThinking> tags — output everything as standard Markdown."
    )
    prompt_text = prompt_text + artifact_instruction

    # Transformation happened if we had system messages or multi-turn
    was_transformed = len(system_parts) > 0 or len(conv_parts) > 2

    return prompt_text, was_transformed


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
    except:
        return jsonify({"error": "Invalid JSON body"}), 400
    
    if not messages:
        return jsonify({"error": "messages array is required"}), 400

    # ── Build natural prompt from OpenAI-format messages ──
    # build_natural_prompt replaces the old Mistral humanization:
    # - Converts system prompts to natural context (not <system> tags)
    # - Preserves full multi-turn context (user + assistant messages)
    # - No external API call — pure local transformation
    try:
        prompt_text, was_transformed = build_natural_prompt(messages)
    except Exception as e:
        app.logger.error(f"[claude] build_natural_prompt error: {e}")
        return jsonify({"error": "Prompt construction failed", "detail": str(e)}), 500

    if not prompt_text.strip():
        return jsonify({"error": "Empty prompt — no user content found"}), 400

    last_role = messages[-1].get("role") if messages else None
    if last_role != "user":
        return jsonify({"error": "Bad Request", "message": "Claude requires the last message to be from 'user'.", "last_role": last_role}), 400
    
    # ── Smart rotation: get available tokens sorted by least-used ──
    available = _get_available_tokens(cookie_sets)
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
        
        start = time.time()
        
        def _claude_http_call(prompt_override=None):
            """Inner function: use curl_cffi with Chrome 131 impersonation for Cloudflare bypass.
            
            prompt_override: if set, uses this prompt instead of the default (for retry with anti-tool instructions)
            """
            effective_prompt = prompt_override if prompt_override else prompt_text
            
            headers = {
                "Cookie": cookie_header,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Origin": "https://claude.ai",
            }
            
            common_kwargs = {
                "impersonate": "chrome131",
                "timeout": 120,
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
                def generate():
                    """Transform Anthropic SSE stream → OpenAI-compatible SSE stream with tool artifact filtering."""
                    yield from transform_claude_stream(resp2.text, conv_uuid, real_model)
                return Response(stream_with_context(generate()), status=200, headers={
                    "Content-Type": "text/event-stream", "X-Proxy-Provider": "claude",
                    "X-Proxy-Cookie": str(cookie_set["id"]), "X-Proxy-Latency": str(latency),
                    "X-Proxy-Rotation": f"token {cookie_set['id']} (used {_get_token_state(cookie_set['id'])['usage']}x)",
                })
            else:
                # ── Cleanup: delete conversation from Claude.ai ──
                _cleanup_claude_conversation(org_uuid, conv_uuid, cookie_header, proxy_url)

                # Token estimation (~4 chars/token for English, ~2 for CJK)
                prompt_chars = len(prompt_text)
                completion_chars = len(full_text)
                est_prompt_tokens = max(1, prompt_chars // 4)
                est_completion_tokens = max(1, completion_chars // 4)

                return jsonify({
                    "id": f"claude-{conv_uuid[:8]}", "object": "chat.completion",
                    "created": int(time.time()), "model": real_model,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": full_text}, "finish_reason": finish}],
                    "usage": {"prompt_tokens": est_prompt_tokens, "completion_tokens": est_completion_tokens, "total_tokens": est_prompt_tokens + est_completion_tokens},
                }), 200, {
                    "X-Proxy-Provider": "claude", "X-Proxy-Cookie": str(cookie_set["id"]),
                    "X-Proxy-Latency": str(latency),
                    "X-Proxy-IP": proxy_ip or "unknown",
                    "X-Proxy-Country": proxy_country or "unknown",
                    "X-Proxy-Rotation": f"token {cookie_set['id']} (used {_get_token_state(cookie_set['id'])['usage']}x)",
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
    
    # All tokens exhausted in this request
    return jsonify({
        "error": "Service Unavailable",
        "message": "All Claude sessions are currently unavailable.",
        "tried": tried,
        "retry_after_ms": COOLDOWN_SECONDS * 1000,
        "model": model_slug,
    }), 503


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
    
    # Cohere-specific: ensure max_tokens is present
    if provider_slug == "cohere":
        if "max_tokens" not in data:
            data["max_tokens"] = 1024
    
    return json.dumps(data).encode()

# ═══════════════════════════════════════════════════════════════════════════
# PROXY AUTH — check API key on /v1/* if configured
# ═══════════════════════════════════════════════════════════════════════════

def check_proxy_auth():
    """If PROXY_API_KEY_HASH is set, require Bearer token on all /v1/* routes."""
    if not PROXY_API_KEY_HASH:
        return None
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Unauthorized — valid API key required", "hint": "Use Authorization: Bearer <key>"}), 401
    key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
    if key_hash != PROXY_API_KEY_HASH:
        return jsonify({"error": "Unauthorized — invalid API key"}), 401
    return None

# ═══════════════════════════════════════════════════════════════════════════
# PROXY ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/v1/chat/completions", methods=["POST"])
def proxy_chat_standard():
    """OpenAI-standard endpoint — reads model from JSON body."""
    auth_err = check_proxy_auth()
    if auth_err: return auth_err
    
    body = request.get_data()
    try:
        data = json.loads(body)
        model_slug = data.get("model", "")
    except:
        return jsonify({"error": "Invalid JSON body", "hint": "Send {\"model\":\"...\",\"messages\":[...]}"}), 400
    
    if not model_slug or model_slug not in MODELS:
        return jsonify({
            "error": f"Unknown model: '{model_slug}'",
            "available_models": list(MODELS.keys()),
            "hint": "Use /v1/chat/completions with \"model\" in the JSON body, or /v1/{model}/chat/completions",
            "docs": "https://aicookies.elliaa.com/docs"
        }), 404
    
    model_info = MODELS[model_slug]
    return proxy_to_provider(model_info["provider"], model_info["real_model"], model_slug)


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
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "models_available": len(MODELS),
        "claude_sessions": claude_count,
        "active_api_keys": active_keys,
        "version": "2.0.0",
        "proxy_provider": "IPRoyal" if PROXY_ENABLED else "direct",
    })


@app.after_request
def add_cors_headers(response):
    """Add permissive CORS headers so API works from any frontend."""
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
        return jsonify({
            "error": f"Unknown model: '{model_slug}'",
            "available_models": list(MODELS.keys()),
            "hint": "Use /v1/chat/completions with \"model\" in the JSON body instead",
            "docs": "https://aicookies.elliaa.com/docs"
        }), 404
    
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
        models.append({
            "id": slug,
            "object": "model",
            "provider": info["provider"],
            "description": info["desc"],
            "active_keys": key_count,
            "endpoint": f"/v1/{slug}/chat/completions",
        })
    return jsonify({"object": "list", "data": models})

# ═══════════════════════════════════════════════════════════════════════════
# PAGES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        if request.form.get("username") == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, request.form.get("password", "")):
            session["logged_in"] = True
            session["username"] = AUTH_USERNAME
            flash("✅ Login successful", "success")
            return redirect(url_for("dashboard"))
        flash("❌ Invalid credentials", "danger")
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
    providers = conn.execute("SELECT p.*, COUNT(k.id) as key_count FROM api_providers p LEFT JOIN api_keys k ON k.provider_id = p.id AND k.is_active = 1 AND k.dead = 0 GROUP BY p.id ORDER BY p.name").fetchall()
    dead_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE dead = 1").fetchone()[0]
    conn.close()
    return render_template("dashboard.html", files=cookie_files, claude_count=claude_count, providers=providers, dead_keys=dead_keys, models=MODELS)

@app.route("/docs")
def docs_page():
    return render_template("docs.html", models=MODELS)

@app.route("/docs.md")
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
    md.append("### ⚡ Direct Response\nModels that reply immediately — just the answer. **All** Mistral, Cohere, SambaNova, and `kimi-k2p7-code`.\n\n")
    md.append("### 🧠 Reasoning Response\nModels that show thinking process before answering: `glm-5p2`, `qwen3p7-plus`, `deepseek-v4-pro`.\n**Important:** set `max_tokens ≥ 500` or answer may be cut off.\n\n")
    md.append("## Streaming (SSE)\n\nAdd `\"stream\": true` to the request body for real-time token streaming:\n\n```bash\ncurl -X POST https://aicookies.elliaa.com/v1/chat/completions \\\n  -H \"Authorization: Bearer YOUR_AICOOKIES_API_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"model\":\"mistral-small\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Hello!\"}]}'\n```\n\n")
    md.append("## cURL Example\n\n```bash\ncurl -X POST https://aicookies.elliaa.com/v1/chat/completions \\\n  -H \"Authorization: Bearer YOUR_AICOOKIES_API_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"model\":\"mistral-small\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello!\"}]}'\n```\n\n")
    md.append("## Python (OpenAI SDK)\n\n```python\nfrom openai import OpenAI\nclient = OpenAI(base_url=\"https://aicookies.elliaa.com/v1\", api_key=\"YOUR_AICOOKIES_API_KEY\")\nresponse = client.chat.completions.create(model=\"mistral-small\", messages=[{\"role\":\"user\",\"content\":\"Hello!\"}])\n```\n\n")
    md.append("## Smart Key Rotation\n\n- 429/402 → rotate to next key (free providers recover; Fireworks 💀 dies)\n- All keys busy → 503 with `retry_after_ms: 5000`\n- Keys ordered by usage count (least-used first)\n\n")
    md.append(f"*Generated from https://aicookies.elliaa.com/docs*\n")
    return "".join(md), 200, {"Content-Type": "text/markdown; charset=utf-8", "Content-Disposition": "attachment; filename=aicookies-api-docs.md"}

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
    return render_template("cookies.html", file=f, cookies=cookies)

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
        pid = request.form.get("provider_id")
        label = request.form.get("label", "").strip()
        key_val = request.form.get("key_value", "").strip()
        if pid and key_val:
            conn.execute("INSERT INTO api_keys (provider_id, label, key_value) VALUES (?,?,?)", (int(pid), label, key_val))
            conn.commit()
            flash("✅ Key added", "success")
        else:
            flash("❌ Provider and key required", "danger")
        return redirect(url_for("keys_page"))
    
    providers = conn.execute("SELECT * FROM api_providers ORDER BY name").fetchall()
    keys = conn.execute("""SELECT k.*, p.name as provider_name, p.slug as provider_slug, p.provider_type
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id ORDER BY p.name, k.dead ASC, k.created_at DESC""").fetchall()
    providers_parsed = []
    for p in providers:
        pd = dict(p)
        try: pd["free_models_parsed"] = json.loads(p["free_models"]) if p["free_models"] else []
        except: pd["free_models_parsed"] = []
        providers_parsed.append(pd)
    conn.close()
    return render_template("keys.html", providers=providers_parsed, keys=keys)

@app.route("/delete-key/<int:key_id>", methods=["POST"])
@login_required
def delete_key(key_id):
    conn = get_db(); conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,)); conn.commit(); conn.close()
    flash("🗑️ Deleted", "info")
    return redirect(url_for("keys_page"))

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
        WHERE k.is_active=1 AND k.dead=0""" + (" AND p.slug=?" if prov else "") + " ORDER BY k.usage_count ASC",
        (prov,) if prov else ()).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys/next/<provider>")
@login_required
def api_next_key(provider):
    conn = get_db()
    key = conn.execute("""SELECT k.*, p.base_url, p.provider_type FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug=? AND k.is_active=1 AND k.dead=0 ORDER BY k.usage_count ASC, k.created_at ASC LIMIT 1""", (provider,)).fetchone()
    if key:
        conn.execute("UPDATE api_keys SET usage_count=usage_count+1, last_used_at=CURRENT_TIMESTAMP WHERE id=?", (key["id"],))
        conn.commit()
    conn.close()
    if not key: return jsonify({"error": f"No active key for {provider}"}), 404
    return jsonify(dict(key))

@app.route("/api/keys/mark-rate-limited/<int:key_id>", methods=["POST"])
@login_required
def api_mark_rl(key_id): mark_key_rate_limited(key_id, "manual"); return jsonify({"status": "ok"})

@app.route("/api/keys/reset-usage/<provider>", methods=["POST"])
@login_required
def api_reset_usage(provider):
    conn = get_db(); conn.execute("UPDATE api_keys SET usage_count=0 WHERE provider_id=(SELECT id FROM api_providers WHERE slug=?)", (provider,)); conn.commit(); conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/providers")
@login_required
def api_list_providers():
    conn = get_db()
    rows = conn.execute("""SELECT p.*, COUNT(k.id) as key_count FROM api_providers p LEFT JOIN api_keys k ON k.provider_id=p.id AND k.is_active=1 AND k.dead=0 GROUP BY p.id ORDER BY p.name""").fetchall()
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
        kc = conn.execute("SELECT COUNT(*) FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE p.slug=? AND k.is_active=1 AND k.dead=0", (info["provider"],)).fetchone()[0]
        dead = conn.execute("SELECT COUNT(*) FROM api_keys k JOIN api_providers p ON k.provider_id=p.id WHERE p.slug=? AND k.dead=1", (info["provider"],)).fetchone()[0]
        result.append({"slug": slug, "provider": info["provider"], "real_model": info["real_model"], "desc": info["desc"], "active_keys": kc, "dead_keys": dead, "endpoint": f"/v1/{slug}/chat/completions"})
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

# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
