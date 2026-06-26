#!/usr/bin/env python3
"""AI Proxy Gateway — Smart model-level proxy with automatic key rotation."""

import os, re, json, sqlite3, secrets, time, uuid
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
import urllib.request
import ssl

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Auth ──────────────────────────────────────────────────────────────────
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "mahmoud")
AUTH_PASSWORD_HASH = generate_password_hash(os.environ.get("AUTH_PASSWORD", "Mmm12011305"))

# ── Database ──────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/data/cookies.db")

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
        raw_content TEXT NOT NULL, cookie_count INTEGER DEFAULT 0, uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
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
    for col, col_type in [("dead", "INTEGER DEFAULT 0"), ("error_count", "INTEGER DEFAULT 0"),
                           ("last_error_at", "TIMESTAMP"), ("last_error_msg", "TEXT")]:
        try: conn.execute(f"ALTER TABLE api_keys ADD COLUMN {col} {col_type}")
        except: pass
    for col, col_type in [("provider_type", "TEXT DEFAULT 'free'")]:
        try: conn.execute(f"ALTER TABLE api_providers ADD COLUMN {col} {col_type}")
        except: pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_dead ON api_keys(dead)")

    # ── Seed providers ──
    providers = [
        ("mistral", "Mistral AI", "https://api.mistral.ai/v1", "free",
         '["mistral-small-latest","mistral-medium-latest","open-mistral-nemo","codestral-latest","ministral-8b-latest"]',
         "Free tier: 1 req/sec, 1M tokens/month."),
        ("cohere", "Cohere", "https://api.cohere.com/v2", "free",
         '["command-a-03-2025","command-r7b-12-2024","command-r-plus-08-2024"]',
         "Free trial: 1000 req/month. Uses /v2/chat endpoint."),
        ("sambanova", "SambaNova", "https://api.sambanova.ai/v1", "free",
         '["Meta-Llama-3.3-70B-Instruct","Meta-Llama-4-Scout-17B-16E-Instruct","Qwen2.5-72B-Instruct","DeepSeek-R1-Distill-Llama-70B"]',
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
    # Mistral
    "mistral-small":     {"provider": "mistral", "real_model": "mistral-small-latest",     "desc": "Mistral Small — fast, efficient"},
    "mistral-medium":    {"provider": "mistral", "real_model": "mistral-medium-latest",    "desc": "Mistral Medium — balanced"},
    "mistral-nemo":      {"provider": "mistral", "real_model": "open-mistral-nemo",        "desc": "Open Mistral Nemo — 12B"},
    "codestral":         {"provider": "mistral", "real_model": "codestral-latest",         "desc": "Codestral — code generation"},
    "ministral-8b":      {"provider": "mistral", "real_model": "ministral-8b-latest",      "desc": "Ministral 8B — lightweight"},
    # Cohere
    "command-a":         {"provider": "cohere",  "real_model": "command-a-03-2025",        "desc": "Command A — latest flagship"},
    "command-r7b":       {"provider": "cohere",  "real_model": "command-r7b-12-2024",      "desc": "Command R7B — fast & capable"},
    "command-r-plus":    {"provider": "cohere",  "real_model": "command-r-plus-08-2024",   "desc": "Command R+ — most powerful"},
    # SambaNova
    "llama-3.3-70b":     {"provider": "sambanova", "real_model": "Meta-Llama-3.3-70B-Instruct",          "desc": "Llama 3.3 70B — powerful"},
    "llama-4-scout":     {"provider": "sambanova", "real_model": "Meta-Llama-4-Scout-17B-16E-Instruct",  "desc": "Llama 4 Scout 17B"},
    "qwen2.5-72b":       {"provider": "sambanova", "real_model": "Qwen2.5-72B-Instruct",                 "desc": "Qwen 2.5 72B"},
    "deepseek-r1-70b":   {"provider": "sambanova", "real_model": "DeepSeek-R1-Distill-Llama-70B",        "desc": "DeepSeek R1 Distill 70B"},
    # Fireworks
    "glm-5p2":           {"provider": "fireworks", "real_model": "accounts/fireworks/models/glm-5p2",          "desc": "GLM 5P2 — reasoning"},
    "kimi-k2p7-code":    {"provider": "fireworks", "real_model": "accounts/fireworks/models/kimi-k2p7-code",   "desc": "Kimi K2.7 Code"},
    "qwen3p7-plus":      {"provider": "fireworks", "real_model": "accounts/fireworks/models/qwen3p7-plus",     "desc": "Qwen 3.7 Plus — multimodal"},
    "deepseek-v4-pro":   {"provider": "fireworks", "real_model": "accounts/fireworks/models/deepseek-v4-pro",  "desc": "DeepSeek V4 Pro — reasoning"},
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

def record_proxy_request(model_slug, provider_slug, key_id, status, latency_ms, error_msg=None):
    conn = get_db()
    conn.execute("INSERT INTO proxy_requests (model_slug, provider_slug, key_id, status, latency_ms, error_msg) VALUES (?,?,?,?,?,?)",
                 (model_slug, provider_slug, key_id, status, latency_ms, error_msg))
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
    keys = get_provider_keys(provider_slug)
    if not keys:
        return jsonify({"error": f"No active keys for provider '{provider_slug}'", "model": model_slug}), 503
    
    body = request.get_data()
    incoming_headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length', 'authorization', 'accept-encoding')}
    
    ctx = ssl.create_default_context()
    tried_keys = []
    last_error = None
    
    for key_info in keys:
        key_id = key_info["id"]
        base_url = key_info["base_url"]
        key_val = key_info["key_value"]
        provider_type = key_info.get("provider_type", "free")
        
        start = time.time()
        status = "error"
        error_msg = None
        
        try:
            # Determine the actual URL and payload
            if provider_slug == "cohere":
                url = f"{base_url}/chat"
                payload = inject_model_into_body(body, real_model, provider_slug)
            else:
                url = f"{base_url}/chat/completions"
                payload = inject_model_into_body(body, real_model, provider_slug)
            
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Authorization", f"Bearer {key_val}")
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept", "application/json" if "stream" not in str(body).lower() else "text/event-stream")
            for h, v in incoming_headers.items():
                try: req.add_header(h, v)
                except: pass
            
            resp = urllib.request.urlopen(req, timeout=120, context=ctx)
            latency = int((time.time() - start) * 1000)
            status = "ok"
            bump_key_usage(key_id)
            record_proxy_request(model_slug, provider_slug, key_id, status, latency)
            
            # Stream response back
            def generate():
                while True:
                    chunk = resp.read(8192)
                    if not chunk: break
                    yield chunk
            return Response(stream_with_context(generate()), status=resp.status, headers={
                "Content-Type": resp.headers.get("Content-Type", "application/json"),
                "X-Proxy-Provider": provider_slug,
                "X-Proxy-Key": str(key_id),
                "X-Proxy-Latency": str(latency),
                "X-Proxy-Model": real_model,
            })
            
        except urllib.error.HTTPError as e:
            latency = int((time.time() - start) * 1000)
            body_err = e.read().decode(errors="replace")[:500]
            code = e.code
            
            if code == 402 or "insufficient" in body_err.lower() or "quota" in body_err.lower() or "balance" in body_err.lower():
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
    
    # All keys failed
    return jsonify({
        "error": "All keys exhausted",
        "model": model_slug,
        "provider": provider_slug,
        "tried_keys": tried_keys,
    }), 503

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
# PROXY ROUTES — /v1/{model_slug}/chat/completions
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/v1/<model_slug>/chat/completions", methods=["POST"])
def proxy_chat(model_slug):
    """OpenAI-compatible proxy endpoint — routes to the best available key."""
    if model_slug not in MODELS:
        return jsonify({
            "error": f"Unknown model: '{model_slug}'",
            "available_models": list(MODELS.keys()),
            "docs": "https://aicookies.elliaa.com/docs"
        }), 404
    
    model_info = MODELS[model_slug]
    return proxy_to_provider(model_info["provider"], model_info["real_model"], model_slug)

@app.route("/v1/<model_slug>", methods=["GET"])
def proxy_info(model_slug):
    """Get info about a specific model endpoint."""
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
    })

@app.route("/v1/models", methods=["GET"])
def list_models():
    """List all available proxy models."""
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
    return jsonify({"total_requests": total, "successful": ok, "recent": [dict(r) for r in recent], "dead_keys": [dict(d) for d in dead_keys]})

# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
