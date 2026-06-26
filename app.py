#!/usr/bin/env python3
"""AI Cookies Manager - Upload, store, and retrieve browser cookies for AI platforms."""

import os
import re
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from io import StringIO

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Auth config (from env) ──────────────────────────────────────────────
AUTH_USERNAME = os.environ.get("AUTH_USERNAME", "mahmoud")
AUTH_PASSWORD_HASH = generate_password_hash(os.environ.get("AUTH_PASSWORD", "Mmm12011305"))

# ── Database ─────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/data/cookies.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cookie_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,       -- claude / chatgpt / gemini / unknown
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
    # Index for fast lookups
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cookies_platform ON cookies(platform)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cookies_name ON cookies(platform, name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cookie_files_platform ON cookie_files(platform)")
    conn.commit()
    conn.close()


init_db()

# ── Auth decorator ───────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Please login first"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ── Cookie parser ────────────────────────────────────────────────────────
def detect_platform_from_content(raw: str) -> str:
    """Detect AI platform from cookie domains."""
    raw_lower = raw.lower()
    if "claude.ai" in raw_lower or "anthropic" in raw_lower:
        return "claude"
    if "chatgpt.com" in raw_lower or "chat.gateway" in raw_lower or "openai" in raw_lower:
        return "chatgpt"
    if "gemini.google.com" in raw_lower or "google.com" in raw_lower:
        # Check for Gemini-specific cookies (COMPASS, etc.)
        if "gemini" in raw_lower or "COMPASS" in raw:
            return "gemini"
    return "unknown"


def detect_platform_from_filename(filename: str) -> str:
    """Detect platform from filename hints."""
    fn = filename.lower()
    if "claude" in fn:
        return "claude"
    if "chatgpt" in fn or "gpt" in fn or "openai" in fn:
        return "chatgpt"
    if "gemini" in fn or "google" in fn or "bard" in fn:
        return "gemini"
    return None


def parse_netscape_cookies(raw: str) -> list[dict]:
    """Parse Netscape HTTP Cookie File format into list of cookie dicts."""
    cookies = []
    for line in raw.splitlines():
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, flag, path, secure, expiration, name, value = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        # Clean up domain (remove leading dot for storage)
        cookies.append({
            "domain": domain,
            "flag": flag,
            "path": path,
            "secure": secure,
            "expiration": expiration,
            "name": name,
            "value": value,
        })
    return cookies


# ── Pages ─────────────────────────────────────────────────────────────────
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
    """Main dashboard — shows all stored cookie sets."""
    conn = get_db()
    files = conn.execute(
        "SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files ORDER BY uploaded_at DESC"
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", files=files)


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

        # Detect platform
        platform = detect_platform_from_filename(file.filename) or detect_platform_from_content(raw)
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
        flash("❌ File not found", "danger")
        return redirect(url_for("dashboard"))

    cookies = conn.execute(
        "SELECT * FROM cookies WHERE file_id = ? ORDER BY domain, name", (file_id,)
    ).fetchall()
    conn.close()
    return render_template("cookies.html", file=file_info, cookies=cookies)


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id: int):
    conn = get_db()
    conn.execute("DELETE FROM cookie_files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    flash("🗑️ Cookie set deleted", "info")
    return redirect(url_for("dashboard"))


# ── API endpoints (for Hermes Agent) ──────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    """API login — returns a session token."""
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username == AUTH_USERNAME and check_password_hash(AUTH_PASSWORD_HASH, password):
        session["logged_in"] = True
        return jsonify({"status": "ok", "message": "Logged in"})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/cookies", methods=["GET"])
@login_required
def api_list_cookies():
    """List all available cookie sets."""
    platform = request.args.get("platform")
    conn = get_db()
    query = "SELECT id, platform, filename, cookie_count, uploaded_at FROM cookie_files"
    params = ()
    if platform:
        query += " WHERE platform = ?"
        params = (platform,)
    query += " ORDER BY uploaded_at DESC"
    files = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(f) for f in files])


@app.route("/api/cookies/<int:file_id>", methods=["GET"])
@login_required
def api_get_cookies(file_id: int):
    """Get all cookies from a specific file as Netscape-format text."""
    conn = get_db()
    file_info = conn.execute("SELECT * FROM cookie_files WHERE id = ?", (file_id,)).fetchone()
    if not file_info:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    # Return raw Netscape content + parsed cookies
    cookies = conn.execute("SELECT * FROM cookies WHERE file_id = ?", (file_id,)).fetchall()
    conn.close()

    return jsonify({
        "id": file_info["id"],
        "platform": file_info["platform"],
        "filename": file_info["filename"],
        "uploaded_at": file_info["uploaded_at"],
        "cookie_count": file_info["cookie_count"],
        "raw_content": file_info["raw_content"],
        "cookies": [dict(c) for c in cookies],
    })


@app.route("/api/cookies/raw/<int:file_id>", methods=["GET"])
@login_required
def api_get_raw(file_id: int):
    """Get raw Netscape-format cookie text (for direct use with curl)."""
    conn = get_db()
    file_info = conn.execute("SELECT * FROM cookie_files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    if not file_info:
        return jsonify({"error": "Not found"}), 404
    return file_info["raw_content"], 200, {"Content-Type": "text/plain"}


@app.route("/api/cookies/latest", methods=["GET"])
@login_required
def api_latest():
    """Get the latest cookie file for a platform."""
    platform = request.args.get("platform", "claude")
    conn = get_db()
    file_info = conn.execute(
        "SELECT * FROM cookie_files WHERE platform = ? ORDER BY uploaded_at DESC LIMIT 1",
        (platform,)
    ).fetchone()
    conn.close()
    if not file_info:
        return jsonify({"error": f"No cookies found for {platform}"}), 404
    return jsonify({
        "id": file_info["id"],
        "platform": file_info["platform"],
        "filename": file_info["filename"],
        "uploaded_at": file_info["uploaded_at"],
        "cookie_count": file_info["cookie_count"],
        "raw_content": file_info["raw_content"],
    })


# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
