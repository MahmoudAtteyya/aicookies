#!/usr/bin/env python3
"""
Claude Multi-Account Auto-Capture Script
========================================
Automates: browser → login → capture cookies → upload to server → clear → repeat.

Usage:
  python3 auto_capture.py

Requirements:
  pip install playwright httpx
  playwright install chromium
"""

import os, sys, json, uuid, subprocess, tempfile, time
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG — set these or export as env vars
# ═══════════════════════════════════════════════════════════════════════════

# IPRoyal residential proxy (no KYC, rotating — sticky via dashboard setting)
PROXY_USER = os.environ.get("PROXY_USER", "7MbCthZqPB0y1E1T")
PROXY_PASS = os.environ.get("PROXY_PASS", "sTj24Oqhz2RPrIM8")
PROXY_HOST = os.environ.get("PROXY_HOST", "geo.iproyal.com")
PROXY_PORT = os.environ.get("PROXY_PORT", "12321")

AICOOKIES_URL = os.environ.get("AICOOKIES_URL", "https://aicookies.elliaa.com")
AICOOKIES_USER = os.environ.get("AICOOKIES_USER", "mahmoud")
AICOOKIES_PASS = os.environ.get("AICOOKIES_PASS", "Mmm12011305")
AICOOKIES_KEY = os.environ.get("AICOOKIES_KEY", "sk-gGpJ6m53XqosM5opVcoHz3-Jh-4Sx6mM1pkZsV-qbpOPgxFfv6NurA6dEaP1HCO5")

# ═══════════════════════════════════════════════════════════════════════════

def get_proxy_config():
    """Build IPRoyal proxy config for Playwright.
    IPRoyal uses simple user:pass auth, no zone/customer/session in URL.
    Sticky sessions are dashboard-controlled."""
    return {
        "server": f"http://{PROXY_HOST}:{PROXY_PORT}",
        "username": PROXY_USER,
        "password": PROXY_PASS,
    }

def upload_cookies(cookie_file_path, session_id):
    """Upload cookie file to aicookies server via API, set proxy session."""
    import httpx
    
    # Login
    resp = httpx.post(f"{AICOOKIES_URL}/api/login", json={
        "username": AICOOKIES_USER, "password": AICOOKIES_PASS
    }, verify=False)
    if resp.status_code != 200:
        print(f"  ❌ Login failed: {resp.text}")
        return False
    
    cookies_jar = resp.cookies
    
    # Upload file
    with open(cookie_file_path, "rb") as f:
        resp = httpx.post(f"{AICOOKIES_URL}/upload",
            cookies=cookies_jar,
            files={"cookie_file": (f"claude_{session_id}.txt", f, "text/plain")},
            verify=False
        )
    
    if resp.status_code not in (200, 302):
        print(f"  ❌ Upload failed: {resp.status_code}")
        return False
    
    print(f"  ✅ Uploaded to {AICOOKIES_URL}")
    return True

def capture_single_account(account_num, session_id):
    """Open browser, user logs in, capture cookies, upload, clear."""
    from playwright.sync_api import sync_playwright
    
    proxy = get_proxy_config()
    
    print(f"\n{'='*60}")
    print(f"🍪 حساب #{account_num} | Session: {session_id}")
    print(f"🌐 Proxy: {PROXY_HOST}:{PROXY_PORT} (IPRoyal residential)")
    print(f"{'='*60}")
    print()
    print("📋 هيتم فتح متصفح — سجل دخولك لكلود، وبعدين ارجع هنا واضغط Enter")
    input("اضغط Enter لفتح المتصفح...")
    
    cookie_file = tempfile.NamedTemporaryFile(suffix=".txt", delete=False, prefix=f"claude_{session_id}_")
    cookie_file_path = cookie_file.name
    cookie_file.close()
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=False,  # Visible so user can login
                proxy=proxy,
                args=['--no-sandbox', '--disable-gpu']
            )
            context = browser.new_context()
            page = context.new_page()
            page.goto("https://claude.ai", timeout=30000)
            
            print()
            print("⏳ سجل دخولك لكلود...")
            print("   (لما تخلص تسجيل الدخول، ارجع هنا واضغط Enter)")
            input()
            
            # Capture cookies
            all_cookies = context.cookies()
            claude_cookies = [c for c in all_cookies if "claude.ai" in c.get("domain", "")]
            
            if not claude_cookies:
                print("  ⚠️ مفيش كوكيز لكلود! متأكد إنك سجلت دخول؟")
                browser.close()
                return False
            
            # Write Netscape format
            with open(cookie_file_path, "w") as f:
                f.write("# Netscape HTTP Cookie File\n")
                f.write(f"# Session: {session_id}\n")
                f.write(f"# Proxy: IPRoyal (geo.iproyal.com:12321)\n\n")
                for c in claude_cookies:
                    domain = c.get("domain", ".claude.ai")
                    flag = "TRUE" if domain.startswith(".") else "FALSE"
                    path = c.get("path", "/")
                    secure = "TRUE" if c.get("secure") else "FALSE"
                    exp = str(int(c.get("expires", 0))) if c.get("expires", -1) > 0 else "0"
                    f.write(f"{domain}\t{flag}\t{path}\t{secure}\t{exp}\t{c['name']}\t{c['value']}\n")
            
            cookie_count = len(claude_cookies)
            print(f"  🍪 تم سحب {cookie_count} كوكيز")
            
            # Clear browser data
            context.clear_cookies()
            browser.close()
            print(f"  🧹 تم مسح بيانات المتصفح")
        
        # Upload to server
        print(f"  📤 بيتم الرفع للسيرفر...")
        success = upload_cookies(cookie_file_path, session_id)
        
        # Clean up
        os.unlink(cookie_file_path)
        
        if success:
            print(f"\n  ✅ الحساب #{account_num} جاهز! session_id={session_id}")
            return True
        else:
            print(f"\n  ❌ فشل رفع الحساب #{account_num}")
            return False
            
    except Exception as e:
        print(f"  ❌ خطأ: {e}")
        try:
            os.unlink(cookie_file_path)
        except:
            pass
        return False

def main():
    print("""
╔══════════════════════════════════════════╗
║   🍪 Claude Multi-Account Capture       ║
║   Auto: Browser → Cookies → Upload      ║
║   Proxy: IPRoyal (geo.iproyal.com:12321)║
╚══════════════════════════════════════════╝
""")
    
    try:
        count = int(input("كم حساب عايز تسجل؟ "))
    except ValueError:
        print("❌ رقم غير صالح")
        sys.exit(1)
    
    if count < 1:
        print("❌ لازم رقم موجب")
        sys.exit(1)
    
    print(f"\n🎯 {count} حسابات. كل حساب هيفتح متصفح جديد بـ IP سكني مختلف.\n")
    
    success_count = 0
    for i in range(1, count + 1):
        session_id = str(uuid.uuid4())[:8]
        
        if capture_single_account(i, session_id):
            success_count += 1
        
        if i < count:
            print(f"\n⏸  خلصت {i}/{count}. الحساب الجاي بعد ما تضغط Enter...")
            input()
    
    print(f"\n{'='*60}")
    print(f"🏁 خلصنا! {success_count}/{count} حسابات تم تسجيلهم بنجاح")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
