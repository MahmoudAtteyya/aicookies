#!/usr/bin/env python3
"""
Fireworks Key Recovery Script
Checks all suspended/inactive Fireworks keys against the live API.
Reactivates keys whose accounts are now active. Updates key_account_info table.

Run on the VPS: python3 /opt/aicookies-data/check_fireworks_suspended.py
"""

import sqlite3
import json
import urllib.request
import urllib.error
import re
import time
from datetime import datetime

DB_PATH = "/opt/aicookies-data/cookies.db"
FIREWORKS_BASE = "https://api.fireworks.ai/inference/v1"
FIREWORKS_MODEL = "accounts/fireworks/models/glm-5p2"


def check_fireworks_key(api_key):
    """
    Make a minimal API call to Fireworks to check account status.
    Returns dict with account_status, account_name, suspension_reason, rate_limits.
    """
    result = {
        "account_status": "unknown",
        "account_name": None,
        "suspension_reason": None,
        "rate_limit_prompt": None,
        "rate_limit_remaining_prompt": None,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = json.dumps({
        "model": FIREWORKS_MODEL,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1,
        "temperature": 0,
    }).encode()

    req = urllib.request.Request(
        f"{FIREWORKS_BASE}/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_headers = dict(resp.headers)
            result["account_status"] = "active"
            result["rate_limit_prompt"] = int(resp_headers.get("x-ratelimit-limit-tokens-prompt", 0)) or None
            result["rate_limit_remaining_prompt"] = int(resp_headers.get("x-ratelimit-remaining-tokens-prompt", 0)) or None
            return result

    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        code = e.code
        resp_headers = dict(e.headers) if hasattr(e, "headers") else {}

        msg = ""
        try:
            err = json.loads(body_text)
            msg = err.get("error", {}).get("message", "")
        except Exception:
            msg = body_text[:500]

        if code in (403, 422, 412):
            result["account_status"] = "suspended"
            result["suspension_reason"] = msg
            name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
            if name_match:
                result["account_name"] = name_match.group(1)
        elif code == 401:
            result["account_status"] = "invalid_key"
            result["suspension_reason"] = "Authentication failed — invalid API key"
        elif code == 429:
            result["account_status"] = "rate_limited"
            result["suspension_reason"] = "Rate limit exceeded"
        elif code == 402:
            result["account_status"] = "payment_required"
            result["suspension_reason"] = msg or "Payment required"
        else:
            result["account_status"] = "error"
            result["suspension_reason"] = f"HTTP {code}: {msg[:300]}"

        return result

    except urllib.error.URLError as e:
        result["account_status"] = "network_error"
        result["suspension_reason"] = f"Network error: {str(e.reason)[:300]}" if hasattr(e, "reason") else str(e)[:300]
        return result

    except Exception as e:
        result["account_status"] = "fetch_failed"
        result["suspension_reason"] = f"{type(e).__name__}: {str(e)[:400]}"
        return result


def main():
    print(f"{'='*70}")
    print(f"Fireworks Key Recovery Check — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"DB: {DB_PATH}")
    print(f"{'='*70}")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Get all Fireworks keys (provider_id=9) that are inactive (is_active=0) or dead
    suspended_keys = list(cur.execute(
        "SELECT id, key_value, label, is_active, dead, last_error_msg "
        "FROM api_keys WHERE provider_id=9 AND (is_active=0 OR dead=1) ORDER BY id"
    ))

    # Also get all Fireworks keys for context
    all_fw_keys = list(cur.execute(
        "SELECT id, is_active, dead FROM api_keys WHERE provider_id=9"
    ))
    total_fw = len(all_fw_keys)
    active_count = sum(1 for k in all_fw_keys if k["is_active"] == 1 and k["dead"] == 0)

    print(f"\nFireworks keys total: {total_fw}")
    print(f"Currently active: {active_count}")
    print(f"Suspended/inactive to check: {len(suspended_keys)}")
    print()

    if not suspended_keys:
        print("No suspended Fireworks keys to check. Nothing to do.")
        conn.close()
        return

    reactivated = []
    still_suspended = []
    errors = []

    for i, key_row in enumerate(suspended_keys, 1):
        key_id = key_row["id"]
        key_value = key_row["key_value"]
        label = key_row["label"] or "(no label)"
        old_status = key_row["last_error_msg"] or ""

        # Small delay to avoid hammering the API
        if i > 1:
            time.sleep(0.5)

        print(f"[{i}/{len(suspended_keys)}] Checking key #{key_id} ({label})...")

        result = check_fireworks_key(key_value)
        status = result["account_status"]

        if status == "active":
            # Reactivate!
            remaining = result.get("rate_limit_remaining_prompt")
            prompt_limit = result.get("rate_limit_prompt")
            print(f"  → ACTIVE! Reactivating. Rate limit: {remaining}/{prompt_limit}")

            cur.execute(
                "UPDATE api_keys SET is_active=1, dead=0, error_count=0, "
                "last_error_msg=NULL, last_error_at=NULL WHERE id=?",
                (key_id,)
            )

            # Update key_account_info
            cur.execute(
                "UPDATE key_account_info SET account_status='active', "
                "rate_limit_prompt=?, rate_limit_remaining_prompt=?, "
                "suspension_reason=NULL, last_fetched_at=datetime('now') "
                "WHERE key_id=?",
                (prompt_limit, remaining, key_id)
            )

            reactivated.append({
                "key_id": key_id,
                "label": label,
                "account_name": result.get("account_name"),
                "rate_limit_remaining": remaining,
                "rate_limit_total": prompt_limit,
            })

        elif status == "suspended":
            account_name = result.get("account_name", "?")
            reason = result.get("suspension_reason", "")[:120]
            print(f"  → Still SUSPENDED. Account: {account_name}")

            # Update key_account_info with fresh data
            cur.execute(
                "UPDATE key_account_info SET account_status='suspended', "
                "suspension_reason=?, last_fetched_at=datetime('now') "
                "WHERE key_id=?",
                (result.get("suspension_reason"), key_id)
            )

            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": account_name,
                "reason": reason,
            })

        else:
            reason = result.get("suspension_reason", "unknown")[:120]
            print(f"  → {status.upper()}: {reason}")

            errors.append({
                "key_id": key_id,
                "label": label,
                "status": status,
                "reason": reason,
            })

    conn.commit()

    # Print summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total checked:    {len(suspended_keys)}")
    print(f"Reactivated:      {len(reactivated)}")
    print(f"Still suspended:  {len(still_suspended)}")
    print(f"Other errors:     {len(errors)}")

    if reactivated:
        print(f"\n{'─'*70}")
        print(f"✅ REACTIVATED KEYS ({len(reactivated)})")
        print(f"{'─'*70}")
        for r in reactivated:
            print(f"  Key #{r['key_id']:>2} ({r['label']}) — {r['account_name'] or 'active'} "
                  f"| rate_limit: {r['rate_limit_remaining']}/{r['rate_limit_total']}")

    if still_suspended:
        print(f"\n{'─'*70}")
        print(f"💀 STILL SUSPENDED ({len(still_suspended)})")
        print(f"{'─'*70}")
        for r in still_suspended:
            print(f"  Key #{r['key_id']:>2} ({r['label']}) — {r['account_name']}")

    if errors:
        print(f"\n{'─'*70}")
        print(f"⚠️  ERRORS ({len(errors)})")
        print(f"{'─'*70}")
        for r in errors:
            print(f"  Key #{r['key_id']:>2} ({r['label']}) — {r['status']}: {r['reason']}")

    # Final DB state
    final_active = cur.execute(
        "SELECT count(*) FROM api_keys WHERE provider_id=9 AND is_active=1 AND dead=0"
    ).fetchone()[0]
    final_suspended = cur.execute(
        "SELECT count(*) FROM api_keys WHERE provider_id=9 AND is_active=0 AND dead=0"
    ).fetchone()[0]
    final_dead = cur.execute(
        "SELECT count(*) FROM api_keys WHERE provider_id=9 AND dead=1"
    ).fetchone()[0]

    print(f"\n{'─'*70}")
    print(f"FINAL DB STATE (Fireworks keys):")
    print(f"  Active:    {final_active}")
    print(f"  Inactive:  {final_suspended}")
    print(f"  Dead:      {final_dead}")
    print(f"{'='*70}")

    conn.close()


if __name__ == "__main__":
    main()
