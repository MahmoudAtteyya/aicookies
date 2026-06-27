#!/usr/bin/env python3
"""
Claude Cookie Capture Script (IPRoyal Residential Proxy)
=========================================================
Opens a Chrome browser through IPRoyal residential proxy.
You log in manually. Script auto-captures cookies + saves to DB.

Usage:
  PROXY_SESSION_ID=my-session-123 python3 capture_claude.py

Env vars needed:
  PROXY_USER, PROXY_PASS  (IPRoyal credentials)
  PROXY_HOST=geo.iproyal.com  (default)
  PROXY_PORT=12321  (default)
  PROXY_SESSION_ID  (optional — for tracking. IPRoyal sticky is dashboard-controlled)
"""

import os, sys, json, uuid, subprocess, sqlite3
from pathlib import Path

def main():
    # ── Config ──
    proxy_user = os.environ.get("PROXY_USER", "7MbCthZqPB0y1E1T")
    proxy_pass = os.environ.get("PROXY_PASS", "sTj24Oqhz2RPrIM8")
    proxy_host = os.environ.get("PROXY_HOST", "geo.iproyal.com")
    proxy_port = os.environ.get("PROXY_PORT", "12321")
    session_id = os.environ.get("PROXY_SESSION_ID") or str(uuid.uuid4())[:8]
    
    proxy_url = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
    
    print(f"🔑 Session ID: {session_id}")
    print(f"🌐 Proxy: {proxy_host}:{proxy_port} (IPRoyal residential)")
    print()
    print("📋 Instructions:")
    print("   1. A Chrome window will open")
    print("   2. Navigate to https://claude.ai")
    print("   3. Log in with your Google/email account")
    print("   4. Once logged in, come back to this terminal and press Enter")
    print("   5. Script will capture cookies and save to DB")
    print()
    input("Press Enter to launch browser...")
    
    # ── Launch Playwright with proxy ──
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("❌ Playwright not installed. Run: pip install playwright && playwright install chromium")
        sys.exit(1)
    
    cookie_file_path = f"/tmp/claude_cookies_{session_id}.txt"
    
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            proxy={"server": f"http://{proxy_host}:{proxy_port}", "username": proxy_user, "password": proxy_pass}
        )
        context = browser.new_context()
        page = context.new_page()
        page.goto("https://claude.ai")
        
        print("\n⏳ Browser opened. Log in to Claude, then press Enter here...")
        input()
        
        # ── Capture cookies ──
        all_cookies = context.cookies()
        claude_cookies = [c for c in all_cookies if "claude.ai" in c.get("domain", "")]
        
        # Write Netscape format
        with open(cookie_file_path, "w") as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write(f"# Captured via IPRoyal proxy (geo.iproyal.com:12321)\n")
            f.write(f"# Session: {session_id}\n\n")
            for c in claude_cookies:
                domain = c.get("domain", ".claude.ai")
                flag = "TRUE" if domain.startswith(".") else "FALSE"
                path = c.get("path", "/")
                secure = "TRUE" if c.get("secure") else "FALSE"
                exp = str(int(c.get("expires", 0))) if c.get("expires", -1) > 0 else "0"
                name = c.get("name", "")
                value = c.get("value", "")
                f.write(f"{domain}\t{flag}\t{path}\t{secure}\t{exp}\t{name}\t{value}\n")
        
        print(f"\n✅ {len(claude_cookies)} cookies saved to {cookie_file_path}")
        browser.close()
    
    # ── Upload to local DB ──
    db_path = "/data/cookies.db"
    if not os.path.exists(db_path):
        db_path = os.path.expanduser("~/cookies.db")
    
    with open(cookie_file_path) as f:
        raw_content = f.read()
    
    conn = sqlite3.connect(db_path)
    conn.execute("""
        INSERT INTO cookie_files (platform, filename, raw_content, cookie_count, proxy_session_id, proxy_enabled)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("claude", f"captured_{session_id}.txt", raw_content, len(claude_cookies), session_id, 1))
    conn.commit()
    conn.close()
    
    print(f"💾 Saved to database with proxy_session_id={session_id}")
    print(f"\n📝 To use this account through the gateway:")
    print(f"   PROXY_ENABLED=true (already enabled by default)")
    print(f"   IPRoyal sticky session: enable in IPRoyal Dashboard → Proxy Settings → Sticky Session")


if __name__ == "__main__":
    main()
