#!/usr/bin/env python3
"""
Claude Cookie Capture Script (Requires Bright Data Proxy)
==========================================================
Opens a Chrome browser through Bright Data residential proxy.
You log in manually. Script auto-captures cookies + saves to DB.

Usage:
  PROXY_SESSION_ID=my-session-123 python3 capture_claude.py

Env vars needed:
  BRD_CUSTOMER_ID, BRD_ZONE, BRD_PASSWORD  (Bright Data credentials)
  PROXY_SESSION_ID  (optional — for sticky IP. If omitted, generates UUID)
"""

import os, sys, json, uuid, subprocess, sqlite3
from pathlib import Path

def main():
    # ── Config ──
    customer_id = os.environ.get("BRD_CUSTOMER_ID")
    zone = os.environ.get("BRD_ZONE")
    password = os.environ.get("BRD_PASSWORD")
    session_id = os.environ.get("PROXY_SESSION_ID") or str(uuid.uuid4())[:8]
    
    if not all([customer_id, zone, password]):
        print("❌ Set BRD_CUSTOMER_ID, BRD_ZONE, BRD_PASSWORD env vars")
        sys.exit(1)
    
    proxy_user = f"brd-customer-{customer_id}-zone-{zone}-session-{session_id}"
    proxy_url = f"http://{proxy_user}:{password}@brd.superproxy.io:33335"
    
    print(f"🔑 Session ID: {session_id}")
    print(f"🌐 Proxy: brd.superproxy.io:33335 (sticky IP via session-{session_id})")
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
            proxy={"server": f"http://brd.superproxy.io:33335", "username": proxy_user, "password": password}
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
            f.write("# Captured via Bright Data proxy\n\n")
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
    print(f"\n📝 To use this account through the gateway, enable proxy in docker-compose:")
    print(f"   PROXY_ENABLED=true")
    print(f"   The gateway will use session-{session_id} for this account's sticky IP.")


if __name__ == "__main__":
    main()
