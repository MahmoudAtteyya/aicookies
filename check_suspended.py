#!/usr/bin/env python3
"""
Check all suspended Fireworks API keys and reactivate them if their accounts are active again.

This script:
1. Queries the database for all Fireworks keys with suspended=1
2. For each suspended key, calls the Fireworks API to check account status
3. If account_status is "active", unsuspend the key (set suspended=0, is_active=1)
4. If account_status is still "suspended" or "dead", keep it suspended
5. Logs results for monitoring
"""

import sqlite3
import json
import urllib.request
import urllib.error
import re
import time
from datetime import datetime

DB_PATH = "/opt/data/aicookies/data/cookies.db"
FIREWORKS_BASE = "https://api.fireworks.ai/inference/v1"


def fetch_fireworks_account_info(api_key):
    """
    Fetch Fireworks account info by making a minimal API call.
    Returns dict with account_status, account_name, suspension_reason, rate limits, etc.
    """
    info = {
        "account_status": "unknown",
        "account_name": None,
        "suspension_reason": None,
        "rate_limit_prompt": None,
        "rate_limit_remaining_prompt": None,
        "rate_limit_generated": None,
        "rate_limit_remaining_generated": None,
        "models_available": [],
        "raw_response": None,
    }

    # Step 1: Try a minimal chat completion to extract rate-limit headers
    payload = json.dumps({
        "model": "accounts/fireworks/models/llama-v3p1-8b-instruct",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{FIREWORKS_BASE}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Active key — extract rate limit headers
            info["account_status"] = "active"
            info["rate_limit_prompt"] = resp.headers.get("x-ratelimit-limit-tokens-prompt")
            info["rate_limit_remaining_prompt"] = resp.headers.get("x-ratelimit-remaining-tokens-prompt")
            info["rate_limit_generated"] = resp.headers.get("x-ratelimit-limit-tokens-generated")
            info["rate_limit_remaining_generated"] = resp.headers.get("x-ratelimit-remaining-tokens-generated")
            info["raw_response"] = f"HTTP {resp.status} — active"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        info["raw_response"] = f"HTTP {e.code}: {body[:500]}"

        if e.code == 412:
            # Suspended account
            info["account_status"] = "suspended"
            # Extract account name from error message
            match = re.search(r"Account\s+(\S+)\s+is\s+suspended", body)
            if match:
                info["account_name"] = match.group(1)
            info["suspension_reason"] = body[:500]
        elif e.code == 401 or e.code == 403:
            info["account_status"] = "invalid_key"
            info["suspension_reason"] = body[:300]
        elif e.code == 429:
            info["account_status"] = "rate_limited"
            info["suspension_reason"] = "Rate limited"
        else:
            info["account_status"] = "error"
            info["suspension_reason"] = f"HTTP {e.code}: {body[:300]}"
    except Exception as e:
        info["account_status"] = "fetch_failed"
        info["suspension_reason"] = f"{type(e).__name__}: {str(e)[:300]}"

    # Step 2: Try to list available models (only if active)
    if info["account_status"] == "active":
        try:
            req2 = urllib.request.Request(
                f"{FIREWORKS_BASE}/models",
                headers={"Authorization": f"Bearer {api_key}"},
                method="GET",
            )
            with urllib.request.urlopen(req2, timeout=30) as resp2:
                models_data = json.loads(resp2.read().decode("utf-8"))
                if isinstance(models_data, list):
                    info["models_available"] = [m.get("id", "") for m in models_data[:50]]
                elif isinstance(models_data, dict) and "data" in models_data:
                    info["models_available"] = [m.get("id", "") for m in models_data["data"][:50]]
        except Exception:
            pass  # Non-critical

    return info


def main():
    print(f"=== Fireworks Suspended Key Recovery Check ===")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"DB: {DB_PATH}")
    print()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Find Fireworks provider ID
    fw_provider = conn.execute(
        "SELECT id, slug, name FROM api_providers WHERE slug = 'fireworks' OR slug LIKE '%fireworks%'"
    ).fetchone()

    if not fw_provider:
        print("ERROR: Could not find 'fireworks' provider in api_providers table.")
        # Show all providers for debugging
        all_providers = conn.execute("SELECT id, slug, name FROM api_providers").fetchall()
        print("Available providers:")
        for p in all_providers:
            print(f"  id={p['id']}, slug={p['slug']}, name={p['name']}")
        conn.close()
        return

    fw_provider_id = fw_provider["id"]
    print(f"Fireworks provider: id={fw_provider_id}, slug={fw_provider['slug']}, name={fw_provider['name']}")
    print()

    # Get all suspended Fireworks keys
    # Check if 'suspended' column exists
    cols = [c[1] for c in conn.execute("PRAGMA table_info(api_keys)").fetchall()]
    print(f"api_keys columns: {cols}")
    print()

    # Build query based on available columns
    if "suspended" in cols:
        suspended_keys = conn.execute(
            "SELECT id, key, label, provider_id, is_active, dead, suspended FROM api_keys WHERE provider_id = ? AND suspended = 1",
            (fw_provider_id,)
        ).fetchall()
    else:
        # If no 'suspended' column, look for keys marked dead or inactive that might be suspended
        print("NOTE: No 'suspended' column found. Checking for dead/inactive Fireworks keys...")
        suspended_keys = conn.execute(
            "SELECT id, key, label, provider_id, is_active, dead FROM api_keys WHERE provider_id = ? AND (dead = 1 OR is_active = 0)",
            (fw_provider_id,)
        ).fetchall()

    # Also check key_account_info for known suspended accounts
    try:
        known_suspended = conn.execute(
            """SELECT k.id, k.key, k.label, k.is_active, k.dead, 
                      ai.account_status, ai.account_name, ai.suspension_reason, ai.last_fetched_at
               FROM api_keys k 
               JOIN key_account_info ai ON k.id = ai.key_id 
               WHERE k.provider_id = ? AND ai.account_status = 'suspended'""",
            (fw_provider_id,)
        ).fetchall()
        print(f"Known suspended accounts from key_account_info: {len(known_suspended)}")
        for ks in known_suspended:
            print(f"  Key #{ks['id']} ({ks['label']}): status={ks['account_status']}, name={ks['account_name']}, last_checked={ks['last_fetched_at']}")
        print()
    except Exception as e:
        print(f"key_account_info query error: {e}")
        known_suspended = []

    print(f"Suspended Fireworks keys found (from api_keys): {len(suspended_keys)}")
    print()

    if not suspended_keys and not known_suspended:
        print("No suspended Fireworks keys found. Nothing to do.")
        conn.close()
        return

    # Merge: use all unique key IDs from both sources
    all_keys_to_check = {}
    for k in suspended_keys:
        all_keys_to_check[k["id"]] = dict(k)
    for k in known_suspended:
        if k["id"] not in all_keys_to_check:
            all_keys_to_check[k["id"]] = dict(k)

    print(f"Total keys to check: {len(all_keys_to_check)}")
    print("=" * 80)
    print()

    reactivated = []
    still_suspended = []
    errors = []

    for key_id, key_data in all_keys_to_check.items():
        api_key = key_data["key"]
        label = key_data.get("label", "(no label)")
        current_active = key_data.get("is_active", 0)
        current_dead = key_data.get("dead", 0)

        print(f"--- Key #{key_id} ({label}) ---")
        print(f"  Current state: is_active={current_active}, dead={current_dead}")

        # Fetch fresh account info
        print(f"  Checking Fireworks API...")
        time.sleep(0.5)  # Small delay to avoid hammering
        info = fetch_fireworks_account_info(api_key)

        print(f"  Account status: {info['account_status']}")
        if info.get("account_name"):
            print(f"  Account name: {info['account_name']}")
        if info.get("suspension_reason"):
            print(f"  Suspension reason: {info['suspension_reason'][:200]}")
        if info.get("rate_limit_prompt"):
            print(f"  Rate limit (prompt): {info['rate_limit_prompt']}")
            print(f"  Rate limit remaining: {info['rate_limit_remaining_prompt']}")

        # Update key_account_info table
        try:
            conn.execute("""
                INSERT INTO key_account_info 
                    (key_id, provider_slug, account_name, account_status, plan_type,
                     rate_limit_prompt, rate_limit_generated, 
                     rate_limit_remaining_prompt, rate_limit_remaining_generated,
                     models_available, suspension_reason, raw_response, last_fetched_at)
                VALUES (?, 'fireworks', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(key_id) DO UPDATE SET
                    account_name = excluded.account_name,
                    account_status = excluded.account_status,
                    rate_limit_prompt = excluded.rate_limit_prompt,
                    rate_limit_generated = excluded.rate_limit_generated,
                    rate_limit_remaining_prompt = excluded.rate_limit_remaining_prompt,
                    rate_limit_remaining_generated = excluded.rate_limit_remaining_generated,
                    models_available = excluded.models_available,
                    suspension_reason = excluded.suspension_reason,
                    raw_response = excluded.raw_response,
                    last_fetched_at = datetime('now')
            """, (
                key_id,
                info.get("account_name"),
                info["account_status"],
                "free" if info.get("rate_limit_prompt") and int(info["rate_limit_prompt"] or 0) < 10000000 else "standard",
                info.get("rate_limit_prompt"),
                info.get("rate_limit_generated"),
                info.get("rate_limit_remaining_prompt"),
                info.get("rate_limit_remaining_generated"),
                json.dumps(info.get("models_available", [])),
                info.get("suspension_reason"),
                info.get("raw_response"),
            ))
            conn.commit()
            print(f"  ✓ Updated key_account_info table")
        except Exception as e:
            print(f"  ⚠ Could not update key_account_info: {e}")

        # Decide action based on account status
        if info["account_status"] == "active":
            # Reactivate the key!
            if "suspended" in cols:
                conn.execute(
                    "UPDATE api_keys SET suspended = 0, is_active = 1, dead = 0 WHERE id = ?",
                    (key_id,)
                )
            else:
                conn.execute(
                    "UPDATE api_keys SET is_active = 1, dead = 0 WHERE id = ?",
                    (key_id,)
                )
            conn.commit()
            reactivated.append({
                "key_id": key_id,
                "label": label,
                "account_name": info.get("account_name"),
                "rate_limit_prompt": info.get("rate_limit_prompt"),
            })
            print(f"  ✅ REACTIVATED — account is active again!")
        elif info["account_status"] == "suspended":
            # Keep suspended
            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": info.get("account_name"),
                "reason": info.get("suspension_reason", "")[:150],
            })
            print(f"  ⛔ Still suspended — keeping key suspended")
        elif info["account_status"] == "invalid_key":
            # Key is dead/invalid, not just suspended
            if "suspended" in cols:
                conn.execute(
                    "UPDATE api_keys SET suspended = 0, dead = 1, is_active = 0 WHERE id = ?",
                    (key_id,)
                )
            else:
                conn.execute(
                    "UPDATE api_keys SET dead = 1, is_active = 0 WHERE id = ?",
                    (key_id,)
                )
            conn.commit()
            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": info.get("account_name"),
                "reason": "Invalid/dead key",
            })
            print(f"  💀 Invalid key — marking as dead")
        else:
            errors.append({
                "key_id": key_id,
                "label": label,
                "status": info["account_status"],
                "reason": info.get("suspension_reason", "")[:150],
            })
            print(f"  ❓ Unknown status ({info['account_status']}) — leaving as-is")

        print()

    conn.close()

    # Print summary
    print("=" * 80)
    print("=== SUMMARY ===")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Total keys checked: {len(all_keys_to_check)}")
    print(f"Reactivated: {len(reactivated)}")
    print(f"Still suspended/dead: {len(still_suspended)}")
    print(f"Errors/unknown: {len(errors)}")
    print()

    if reactivated:
        print("✅ REACTIVATED KEYS:")
        for r in reactivated:
            print(f"  Key #{r['key_id']} ({r['label']}) — account: {r['account_name'] or 'N/A'}, rate_limit: {r['rate_limit_prompt'] or 'N/A'}")
        print()

    if still_suspended:
        print("⛔ STILL SUSPENDED:")
        for s in still_suspended:
            print(f"  Key #{s['key_id']} ({s['label']}) — account: {s['account_name'] or 'N/A'}, reason: {s['reason'][:100]}")
        print()

    if errors:
        print("❓ ERRORS/UNKNOWN:")
        for e in errors:
            print(f"  Key #{e['key_id']} ({e['label']}) — status: {e['status']}, reason: {e['reason'][:100]}")
        print()

    # Also show current state of ALL Fireworks keys
    print("--- Current Fireworks key pool state ---")
    conn2 = sqlite3.connect(DB_PATH)
    conn2.row_factory = sqlite3.Row
    if "suspended" in cols:
        all_fw = conn2.execute(
            "SELECT id, label, is_active, dead, suspended FROM api_keys WHERE provider_id = ? ORDER BY id",
            (fw_provider_id,)
        ).fetchall()
    else:
        all_fw = conn2.execute(
            "SELECT id, label, is_active, dead FROM api_keys WHERE provider_id = ? ORDER BY id",
            (fw_provider_id,)
        ).fetchall()
    active_count = sum(1 for k in all_fw if k["is_active"])
    dead_count = sum(1 for k in all_fw if k["dead"])
    suspended_count = sum(1 for k in all_fw if "suspended" in k.keys() and k["suspended"])
    print(f"Total Fireworks keys: {len(all_fw)}")
    print(f"  Active: {active_count}")
    print(f"  Dead: {dead_count}")
    print(f"  Suspended: {suspended_count}")
    conn2.close()

    print()
    print("=== Done ===")


if __name__ == "__main__":
    main()
