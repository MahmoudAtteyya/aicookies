#!/usr/bin/env python3
"""
Fireworks Suspended Key Recovery — runs inside the aicookies Docker container.
Checks each suspended Fireworks key against the live Fireworks API.
If the account is active again, reactivates the key (suspended=0, is_active=1).
Updates key_account_info with fresh data.
"""
import sqlite3
import json
import urllib.request
import urllib.error
import re
import time
from datetime import datetime

DB = "/data/cookies.db"
FIREWORKS_BASE = "https://api.fireworks.ai/inference/v1"


def fetch_fireworks_account_info(api_key):
    """Check Fireworks account status via minimal API call."""
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

    # Step 1: Use GET /models as the primary account-status check.
    # This returns:
    #   - 200 + model list → account is ACTIVE
    #   - 412 → account is SUSPENDED (with account name in error message)
    #   - 401/403 → invalid key
    # Using GET /models avoids the model-not-found 404 issue that masks
    # the real account status (Fireworks checks model existence before
    # account suspension on chat completions).
    req = urllib.request.Request(
        f"{FIREWORKS_BASE}/models",
        headers={"Authorization": f"Bearer {api_key}"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            info["account_status"] = "active"
            info["raw_response"] = f"HTTP {resp.status} — active"
            models_data = json.loads(resp.read().decode("utf-8"))
            if isinstance(models_data, list):
                info["models_available"] = [m.get("id", "") for m in models_data[:50]]
            elif isinstance(models_data, dict) and "data" in models_data:
                info["models_available"] = [m.get("id", "") for m in models_data["data"][:50]]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        info["raw_response"] = f"HTTP {e.code}: {body[:500]}"

        if e.code == 412:
            info["account_status"] = "suspended"
            match = re.search(r"Account\s+(\S+)\s+is\s+suspended", body)
            if match:
                info["account_name"] = match.group(1)
            info["suspension_reason"] = body[:500]
        elif e.code in (401, 403):
            info["account_status"] = "invalid_key"
            info["suspension_reason"] = body[:300]
        elif e.code == 429:
            info["account_status"] = "rate_limited"
            info["suspension_reason"] = "Rate limited"
        elif e.code == 402:
            info["account_status"] = "suspended"
            info["suspension_reason"] = f"Payment required: {body[:300]}"
        else:
            info["account_status"] = "error"
            info["suspension_reason"] = f"HTTP {e.code}: {body[:300]}"
    except Exception as e:
        info["account_status"] = "fetch_failed"
        info["suspension_reason"] = f"{type(e).__name__}: {str(e)[:300]}"

    # Step 2: If active, do a minimal chat completion to extract rate-limit headers
    if info["account_status"] == "active":
        payload = json.dumps({
            "model": "accounts/fireworks/models/glm-5p2",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
        }).encode("utf-8")

        req2 = urllib.request.Request(
            f"{FIREWORKS_BASE}/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req2, timeout=30) as resp2:
                info["rate_limit_prompt"] = resp2.headers.get("x-ratelimit-limit-tokens-prompt")
                info["rate_limit_remaining_prompt"] = resp2.headers.get("x-ratelimit-remaining-tokens-prompt")
                info["rate_limit_generated"] = resp2.headers.get("x-ratelimit-limit-tokens-generated")
                info["rate_limit_remaining_generated"] = resp2.headers.get("x-ratelimit-remaining-tokens-generated")
        except Exception:
            pass  # Non-critical — we already know the account is active

    return info


def main():
    print("=" * 80)
    print("Fireworks Suspended Key Recovery Check")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"DB: {DB}")
    print("=" * 80)
    print()

    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row

    # Find Fireworks provider
    fw = conn.execute("SELECT id, slug FROM api_providers WHERE slug = 'fireworks'").fetchone()
    if not fw:
        print("ERROR: Fireworks provider not found!")
        conn.close()
        return
    fw_id = fw["id"]
    print(f"Fireworks provider: id={fw_id}")

    # Get all suspended Fireworks keys
    suspended_keys = conn.execute(
        "SELECT id, key_value, label, is_active, dead, suspended, usage_count, error_count, last_error_msg "
        "FROM api_keys WHERE provider_id = ? AND suspended = 1 ORDER BY id",
        (fw_id,)
    ).fetchall()

    print(f"Suspended Fireworks keys: {len(suspended_keys)}")
    print()

    if not suspended_keys:
        print("No suspended keys to check. Done.")
        conn.close()
        return

    reactivated = []
    still_suspended = []
    errors = []

    for i, k in enumerate(suspended_keys):
        d = dict(k)
        key_id = d["id"]
        api_key = d["key_value"]
        label = d.get("label", "(no label)")

        print(f"[{i+1}/{len(suspended_keys)}] Key #{key_id} ({label})")

        # Fetch fresh account info
        info = fetch_fireworks_account_info(api_key)

        status = info["account_status"]
        print(f"  Status: {status}", end="")
        if info.get("account_name"):
            print(f" | Account: {info['account_name']}", end="")
        if info.get("rate_limit_prompt"):
            print(f" | Rate limit: {info['rate_limit_prompt']}", end="")
        print()

        if info.get("suspension_reason"):
            print(f"  Reason: {info['suspension_reason'][:150]}")

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
                "free" if info.get("rate_limit_prompt") and int(str(info["rate_limit_prompt"]) or 0) < 10000000 else "standard",
                info.get("rate_limit_prompt"),
                info.get("rate_limit_generated"),
                info.get("rate_limit_remaining_prompt"),
                info.get("rate_limit_remaining_generated"),
                json.dumps(info.get("models_available", [])),
                info.get("suspension_reason"),
                info.get("raw_response"),
            ))
            conn.commit()
        except Exception as e:
            print(f"  Warning: Could not update key_account_info: {e}")

        # Take action based on status
        if status == "active":
            conn.execute(
                "UPDATE api_keys SET suspended = 0, is_active = 1, dead = 0, error_count = 0 WHERE id = ?",
                (key_id,)
            )
            conn.commit()
            reactivated.append({
                "key_id": key_id,
                "label": label,
                "account_name": info.get("account_name"),
                "rate_limit": info.get("rate_limit_prompt"),
            })
            print(f"  >> REACTIVATED! suspended=0, is_active=1")
        elif status == "suspended":
            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": info.get("account_name"),
                "reason": (info.get("suspension_reason") or "")[:120],
            })
            print(f"  >> Still suspended")
        elif status == "invalid_key":
            conn.execute(
                "UPDATE api_keys SET suspended = 0, dead = 1, is_active = 0 WHERE id = ?",
                (key_id,)
            )
            conn.commit()
            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": info.get("account_name"),
                "reason": "Invalid/dead key",
            })
            print(f"  >> Marked as dead (invalid key)")
        else:
            errors.append({
                "key_id": key_id,
                "label": label,
                "status": status,
                "reason": (info.get("suspension_reason") or "")[:120],
            })
            print(f"  >> Unknown status ({status}) — leaving as-is")

        print()

        # Small delay to avoid hammering the API
        if i < len(suspended_keys) - 1:
            time.sleep(0.3)

    conn.close()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print(f"  Total keys checked: {len(suspended_keys)}")
    print(f"  Reactivated: {len(reactivated)}")
    print(f"  Still suspended: {len(still_suspended)}")
    print(f"  Errors/unknown: {len(errors)}")
    print()

    if reactivated:
        print("REACTIVATED KEYS:")
        for r in reactivated:
            print(f"  Key #{r['key_id']} ({r['label']}) — account: {r['account_name'] or 'N/A'}, rate_limit: {r['rate_limit'] or 'N/A'}")
        print()

    if still_suspended:
        print("STILL SUSPENDED:")
        for s in still_suspended:
            print(f"  Key #{s['key_id']} ({s['label']}) — account: {s['account_name'] or 'N/A'}, reason: {s['reason'][:100]}")
        print()

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  Key #{e['key_id']} ({e['label']}) — status: {e['status']}, reason: {e['reason'][:100]}")
        print()

    # Current pool state
    conn2 = sqlite3.connect(DB)
    conn2.row_factory = sqlite3.Row
    all_fw = conn2.execute(
        "SELECT id, label, is_active, dead, suspended FROM api_keys WHERE provider_id = ? ORDER BY id",
        (fw_id,)
    ).fetchall()
    active_count = sum(1 for k in all_fw if k["is_active"] and not k["suspended"])
    suspended_count = sum(1 for k in all_fw if k["suspended"])
    dead_count = sum(1 for k in all_fw if k["dead"])
    print(f"Current Fireworks pool: {len(all_fw)} total | {active_count} active | {suspended_count} suspended | {dead_count} dead")
    conn2.close()

    print()
    print("=== Done ===")


if __name__ == "__main__":
    main()
