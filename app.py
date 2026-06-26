#!/usr/bin/env python3
"""AI Credentials Hub — Cookies for Claude + API keys for free-tier providers."""

import os
import re
import json
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

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
    # ── Cookie tables ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cookie_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            filename TEXT,
            raw_content TEXT NOT NULL,
            cookie_count INTEGER DEFAULT 0,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            domain TEXT NOT NULL,
            flag TEXT,
            path TEXT DEFAULT '/',
            secure TEXT DEFAULT 'FALSE',
            expiration TEXT,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES cookie_files(id) ON DELETE CASCADE
        )
    """)

    # ── API Provider tables ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            base_url TEXT,
            api_docs_url TEXT,
            free_models TEXT,          -- JSON array of free model names
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL,
            label TEXT,                -- user-friendly name (e.g. "Account 1")
            key_value TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            usage_count INTEGER DEFAULT 0,
            last_used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (provider_id) REFERENCES api_providers(id) ON DELETE CASCADE
        )
    """)

    # Indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cookies_platform ON cookies(platform)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cookie_files_platform ON cookie_files(platform)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_provider ON api_keys(provider_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)")

    # ── Seed free providers (idempotent) ──
    providers = [
        ("openrouter", "OpenRouter", "https://openrouter.ai/api/v1",
         "https://openrouter.ai/docs", 
         '["google/gemini-2.0-flash-001","google/gemini-2.0-flash-lite-001","mistralai/mistral-7b-instruct","mistralai/mistral-small-3.1-24b-instruct","meta-llama/llama-3.2-3b-instruct","meta-llama/llama-3.1-8b-instruct","deepseek/deepseek-r1-distill-llama-70b","qwen/qwen-2.5-7b-instruct","microsoft/phi-4-mini-instruct"]',
         "339+ free models from all major providers. Needs $5 min credits even for free models. OpenAI-compatible."),
        
        ("mistral", "Mistral AI", "https://api.mistral.ai/v1",
         "https://docs.mistral.ai/",
         '["mistral-small-latest","mistral-medium-latest","open-mistral-nemo","codestral-latest","ministral-8b-latest"]',
         "Free tier: 1 req/sec, 1M tokens/month. Great for coding & reasoning. ✅ Tested working."),
        
        ("google", "Google Gemini", "https://generativelanguage.googleapis.com/v1beta",
         "https://ai.google.dev/gemini-api/docs",
         '["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-1.5-flash","gemini-1.5-pro"]',
         "Free tier: 1500 req/day. Key from aistudio.google.com. Uses ?key= in URL."),
        
        ("groq", "Groq", "https://api.groq.com/openai/v1",
         "https://console.groq.com/docs",
         '["llama-3.3-70b-versatile","llama-3.1-8b-instant","mixtral-8x7b-32768","gemma2-9b-it","deepseek-r1-distill-llama-70b","qwen-2.5-32b"]',
         "Free tier: 30 req/min, very fast. Keys start with gsk_. OpenAI-compatible."),
        
        ("together", "Together AI", "https://api.together.xyz/v1",
         "https://docs.together.ai/",
         '["meta-llama/Llama-3.3-70B-Instruct-Turbo","deepseek-ai/DeepSeek-R1-Distill-Llama-70B-free","Qwen/Qwen2.5-7B-Instruct-Turbo","mistralai/Mixtral-8x7B-Instruct-v0.1"]',
         "Free credits on signup. OpenAI-compatible API."),
        
        ("cohere", "Cohere", "https://api.cohere.com/v2",
         "https://docs.cohere.com/",
         '["command-a-03-2025","command-r7b-12-2024","command-r-plus-08-2024"]',
         "Free trial: 1000 req/month. Uses /v2/chat endpoint. ✅ Tested working."),
        
        ("deepseek", "DeepSeek", "https://api.deepseek.com/v1",
         "https://platform.deepseek.com/api-docs/",
         '["deepseek-chat","deepseek-reasoner"]',
         "Very cheap API. OpenAI-compatible. Top up $2 for months of usage."),
        
        ("huggingface", "HuggingFace Inference", "https://api-inference.huggingface.co",
         "https://huggingface.co/docs/api-inference/",
         '["mistralai/Mistral-7B-Instruct-v0.3","meta-llama/Llama-3.1-8B-Instruct","google/gemma-2-2b-it","HuggingFaceH4/zephyr-7b-beta"]',
         "Free tier: limited rate. Token from huggingface.co/settings/tokens. HF token starts with hf_."),
        
        ("fireworks", "Fireworks AI", "https://api.fireworks.ai/inference/v1",
         "https://docs.fireworks.ai/",
         '["accounts/fireworks/models/llama-v3p1-8b-instruct","accounts/fireworks/models/mixtral-8x7b-instruct","accounts/fireworks/models/deepseek-r1-basic"]',
         "Free tier: 10 req/sec. OpenAI-compatible. Keys start with fw_."),
        
        ("xai", "xAI (Grok)", "https://api.x.ai/v1",
         "https://docs.x.ai/",
         '["grok-3-beta","grok-2-1212"]',
         "xAI Grok API. Keys start with xai-. OpenAI-compatible. Free credits on signup."),
        
        ("cerebras", "Cerebras", "https://api.cerebras.ai/v1",
         "https://cloud.cerebras.ai/",
         '["llama3.1-8b","llama-3.3-70b","llama-4-scout-17b-16e","mistral-7b","mixtral-8x7b"]',
         "Free tier: very fast inference on Cerebras wafer-scale hardware. OpenAI-compatible. Get key from cloud.cerebras.ai."),
        
        ("sambanova", "SambaNova", "https://api.sambanova.ai/v1",
         "https://cloud.sambanova.ai/",
         '["Meta-Llama-3.1-8B-Instruct","Meta-Llama-3.3-70B-Instruct","Meta-Llama-4-Scout-17B-16E-Instruct","Qwen2.5-72B-Instruct","DeepSeek-R1-Distill-Llama-70B"]',
         "Free tier: generous rate limits on SambaNova RDU hardware. OpenAI-compatible. Get key from cloud.sambanova.ai."),
    ]

    for slug, name, base_url, docs_url, models, desc in providers:
        conn.execute("""
            INSERT OR IGNORE INTO api_providers (slug, name, base_url, api_docs_url, free_models, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (slug, name, base_url, docs_url, models, desc))

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

# ── Cookie parser (Claude-focused) ───────────────────────────────────────
def detect_platform_from_content(raw: str) -> str:
    raw_lower = raw.lower()
    if "claude.ai" in raw_lower or "anthropic" in raw_lower:
        return "claude"
    return "unknown"

def parse_netscape_cookies(raw: str) -> list[dict]:
    cookies = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        cookies.append({
            "domain": parts[0], "flag": parts[1], "path": parts[2],
            "secure": parts[3], "expiration": parts[4],
            "name": parts[5], "value": parts[6],
        })
    return cookies

# ═══════════════════════════════════════════════════════════════════════════
# PAGES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, password):
            session["logged_in"] = True
            session["username"] = username
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
    cookie_files = conn.execute(
        "SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files ORDER BY uploaded_at DESC"
    ).fetchall()
    claude_count = conn.execute(
        "SELECT COUNT(*) FROM cookie_files WHERE platform = 'claude'"
    ).fetchone()[0]
    providers = conn.execute(
        "SELECT p.*, COUNT(k.id) as key_count FROM api_providers p LEFT JOIN api_keys k ON k.provider_id = p.id AND k.is_active = 1 GROUP BY p.id ORDER BY p.name"
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", files=cookie_files, claude_count=claude_count, providers=providers)

# ── Cookie routes ─────────────────────────────────────────────────────────
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
            flash("⚠️ No valid cookies found in file", "warning")
            return redirect(url_for("upload_page"))
        conn = get_db()
        cursor = conn.execute(
            "INSERT INTO cookie_files (platform, filename, raw_content, cookie_count) VALUES (?, ?, ?, ?)",
            (platform, file.filename, raw, len(cookies))
        )
        file_id = cursor.lastrowid
        for c in cookies:
            conn.execute(
                "INSERT INTO cookies (file_id, platform, domain, flag, path, secure, expiration, name, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, platform, c["domain"], c["flag"], c["path"], c["secure"], c["expiration"], c["name"], c["value"])
            )
        conn.commit()
        conn.close()
        flash(f"✅ Uploaded {len(cookies)} cookies for {platform.upper()}", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")

@app.route("/cookies/<int:file_id>")
@login_required
def view_cookies(file_id: int):
    conn = get_db()
    file_info = conn.execute("SELECT * FROM cookie_files WHERE id = ?", (file_id,)).fetchone()
    if not file_info:
        conn.close()
        flash("❌ Not found", "danger")
        return redirect(url_for("dashboard"))
    cookies = conn.execute("SELECT * FROM cookies WHERE file_id = ? ORDER BY domain, name", (file_id,)).fetchall()
    conn.close()
    return render_template("cookies.html", file=file_info, cookies=cookies)

@app.route("/delete-cookie/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id: int):
    conn = get_db()
    conn.execute("DELETE FROM cookie_files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    flash("🗑️ Cookie set deleted", "info")
    return redirect(url_for("dashboard"))

# ── API Keys routes (web) ────────────────────────────────────────────────
@app.route("/keys", methods=["GET", "POST"])
@login_required
def keys_page():
    conn = get_db()
    if request.method == "POST":
        provider_id = request.form.get("provider_id")
        label = request.form.get("label", "").strip()
        key_value = request.form.get("key_value", "").strip()
        if not provider_id or not key_value:
            flash("❌ Provider and key are required", "danger")
        else:
            conn.execute(
                "INSERT INTO api_keys (provider_id, label, key_value) VALUES (?, ?, ?)",
                (int(provider_id), label, key_value)
            )
            conn.commit()
            flash("✅ API key added successfully", "success")
        return redirect(url_for("keys_page"))

    providers = conn.execute("SELECT * FROM api_providers ORDER BY name").fetchall()
    keys = conn.execute("""
        SELECT k.*, p.name as provider_name, p.slug as provider_slug, p.free_models
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        ORDER BY p.name, k.created_at DESC
    """).fetchall()
    # Pre-parse free_models JSON for templates
    providers_parsed = []
    for p in providers:
        pd = dict(p)
        try:
            pd["free_models_parsed"] = json.loads(p["free_models"]) if p["free_models"] else []
        except (json.JSONDecodeError, TypeError):
            pd["free_models_parsed"] = []
        providers_parsed.append(pd)
    conn.close()
    return render_template("keys.html", providers=providers_parsed, keys=keys)

@app.route("/delete-key/<int:key_id>", methods=["POST"])
@login_required
def delete_key(key_id: int):
    conn = get_db()
    conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    flash("🗑️ API key deleted", "info")
    return redirect(url_for("keys_page"))

@app.route("/toggle-key/<int:key_id>", methods=["POST"])
@login_required
def toggle_key(key_id: int):
    conn = get_db()
    key = conn.execute("SELECT is_active FROM api_keys WHERE id = ?", (key_id,)).fetchone()
    if key:
        new_state = 0 if key["is_active"] else 1
        conn.execute("UPDATE api_keys SET is_active = ? WHERE id = ?", (new_state, key_id))
        conn.commit()
    conn.close()
    return redirect(url_for("keys_page"))

# ═══════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

# ── Cookies API ────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    if data.get("username") == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, data.get("password", "")):
        session["logged_in"] = True
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/cookies", methods=["GET"])
@login_required
def api_list_cookies():
    conn = get_db()
    platform = request.args.get("platform")
    q = "SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files"
    params = ()
    if platform:
        q += " WHERE platform = ?"
        params = (platform,)
    q += " ORDER BY uploaded_at DESC"
    files = conn.execute(q, params).fetchall()
    conn.close()
    return jsonify([dict(f) for f in files])

@app.route("/api/cookies/raw/<int:file_id>", methods=["GET"])
@login_required
def api_get_raw(file_id: int):
    conn = get_db()
    f = conn.execute("SELECT * FROM cookie_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    if not f:
        return jsonify({"error": "Not found"}), 404
    return f["raw_content"], 200, {"Content-Type": "text/plain"}

@app.route("/api/cookies/latest", methods=["GET"])
@login_required
def api_latest():
    conn = get_db()
    platform = request.args.get("platform", "claude")
    f = conn.execute(
        "SELECT * FROM cookie_files WHERE platform = ? ORDER BY uploaded_at DESC LIMIT 1",
        (platform,)
    ).fetchone()
    conn.close()
    if not f:
        return jsonify({"error": f"No cookies for {platform}"}), 404
    return jsonify(dict(f))

# ── API Keys API (for Hermes) ────────────────────────────────────────────
@app.route("/api/keys", methods=["GET"])
@login_required
def api_list_keys():
    """List all API keys grouped by provider."""
    provider = request.args.get("provider")
    conn = get_db()
    if provider:
        keys = conn.execute("""
            SELECT k.*, p.name as provider_name, p.slug as provider_slug, p.base_url, p.free_models
            FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
            WHERE p.slug = ? AND k.is_active = 1
            ORDER BY k.usage_count ASC, k.created_at ASC
        """, (provider,)).fetchall()
    else:
        keys = conn.execute("""
            SELECT k.*, p.name as provider_name, p.slug as provider_slug, p.base_url, p.free_models
            FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
            WHERE k.is_active = 1
            ORDER BY p.name, k.usage_count ASC
        """).fetchall()
    conn.close()
    return jsonify([dict(k) for k in keys])

@app.route("/api/keys/next/<provider>", methods=["GET"])
@login_required
def api_next_key(provider: str):
    """Get the next available API key for rotation (round-robin by lowest usage)."""
    conn = get_db()
    # Get the least-used active key
    key = conn.execute("""
        SELECT k.*, p.base_url, p.free_models, p.slug as provider_slug
        FROM api_keys k JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = ? AND k.is_active = 1
        ORDER BY k.usage_count ASC, k.created_at ASC
        LIMIT 1
    """, (provider,)).fetchone()
    
    if key:
        # Increment usage
        conn.execute("UPDATE api_keys SET usage_count = usage_count + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?", (key["id"],))
        conn.commit()
    conn.close()
    
    if not key:
        return jsonify({"error": f"No active API key for provider '{provider}'"}), 404
    
    return jsonify(dict(key))

@app.route("/api/keys/mark-rate-limited/<int:key_id>", methods=["POST"])
@login_required
def api_mark_rate_limited(key_id: int):
    """Mark a key as rate-limited (disable for 1 hour via usage_count bump)."""
    conn = get_db()
    # Set usage_count very high so it rotates to the back
    conn.execute("UPDATE api_keys SET usage_count = usage_count + 100 WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Key marked as rate-limited, will rotate"})

@app.route("/api/keys/reset-usage/<provider>", methods=["POST"])
@login_required
def api_reset_usage(provider: str):
    """Reset usage counters for all keys of a provider."""
    conn = get_db()
    conn.execute("""
        UPDATE api_keys SET usage_count = 0 
        WHERE provider_id = (SELECT id FROM api_providers WHERE slug = ?)
    """, (provider,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/keys", methods=["POST"])
@login_required
def api_add_key():
    """Add a new API key via API."""
    data = request.get_json(force=True, silent=True) or {}
    provider_slug = data.get("provider")
    label = data.get("label", "")
    key_value = data.get("key")

    if not provider_slug or not key_value:
        return jsonify({"error": "provider and key are required"}), 400

    conn = get_db()
    prov = conn.execute("SELECT id FROM api_providers WHERE slug = ?", (provider_slug,)).fetchone()
    if not prov:
        conn.close()
        return jsonify({"error": f"Unknown provider: {provider_slug}"}), 404

    conn.execute(
        "INSERT INTO api_keys (provider_id, label, key_value) VALUES (?, ?, ?)",
        (prov["id"], label, key_value)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Key added"}), 201

# ── API: List providers with free models ─────────────────────────────────
@app.route("/api/providers", methods=["GET"])
@login_required
def api_list_providers():
    conn = get_db()
    provs = conn.execute("""
        SELECT p.*, COUNT(k.id) as key_count
        FROM api_providers p LEFT JOIN api_keys k ON k.provider_id = p.id AND k.is_active = 1
        GROUP BY p.id ORDER BY p.name
    """).fetchall()
    conn.close()
    result = []
    for p in provs:
        d = dict(p)
        d["free_models"] = json.loads(p["free_models"]) if p["free_models"] else []
        result.append(d)
    return jsonify(result)

# ── Main ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
