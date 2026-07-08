#!/usr/bin/env python3
"""
Check all suspended Fireworks API keys and reactivate them if their
accounts are active again.

Uses GET /inference/v1/models for account status checks — returns 200
for active accounts, 412 for suspended accounts. This is more reliable
than POST /chat/completions (which checks model existence before account
suspension, so retired models return 404 and mask the real status).

Usage:
    docker exec aicookies python3 /data/scripts/recover_fireworks_keys.py
    python3 recover_fireworks_keys.py  # if running outside Docker
"""

import sqlite3
import json
import urllib.request
import urllib.error
import re
import time
from datetime import datetime, timezone

DB_PATH = "/data/cookies.db"
FIREWORKS_BASE = "https://api.fireworks.ai/inference/v1"


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def check_account_status(api_key):
    """
    Check if a Fireworks account is active or suspended via GET /models.
    Returns dict with status, account_name, reason.
    """
    result = {"status": "unknown", "account_name": None, "reason": None, "rate_limits": None}
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        req = urllib.request.Request(
            f"{FIREWORKS_BASE}/models",
            headers=headers,
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.code == 200:
                result["status"] = "active"
                # Extract rate limits from headers if present
                rl = {}
                for h in ["x-ratelimit-limit-tokens-prompt", "x-ratelimit-remaining-tokens-prompt",
                           "x-ratelimit-limit-tokens-generated", "x-ratelimit-remaining-tokens-generated"]:
                    val = resp.headers.get(h)
                    if val:
                        rl[h] = int(val) if val.isdigit() else val
                if rl:
                    result["rate_limits"] = rl
                # Try to extract account name from models list
                try:
                    data = json.loads(resp.read().decode())
                    models = data.get("data", [])
                    if models:
                        first = models[0]
                        owned_by = first.get("owned_by", "")
                        if owned_by and not owned_by.startswith("accounts/"):
                            result["account_name"] = owned_by
                        else:
                            model_id = first.get("id", "")
                            if "/" in model_id:
                                parts = model_id.split("/")
                                if len(parts) >= 2:
                                    result["account_name"] = parts[1]
                except Exception:
                    pass
                return result

    except urllib.error.HTTPError as e:
        code = e.code
        body_text = ""
        try:
            body_text = e.read().decode()
        except Exception:
            pass

        msg = ""
        try:
            err = json.loads(body_text)
            msg = err.get("error", {}).get("message", "") if isinstance(err.get("error"), dict) else str(err.get("error", ""))
        except Exception:
            msg = body_text[:500]

        if code == 412:
            result["status"] = "suspended"
            result["reason"] = msg[:300]
            name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
            if name_match:
                result["account_name"] = name_match.group(1)
        elif code == 401:
            result["status"] = "invalid_key"
            result["reason"] = "Authentication failed — invalid API key"
        elif code == 403:
            result["status"] = "suspended"
            result["reason"] = msg[:300]
            name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
            if name_match:
                result["account_name"] = name_match.group(1)
        elif code == 429:
            result["status"] = "rate_limited"
            result["reason"] = "Rate limit exceeded — try again later"
        elif code == 404:
            result["status"] = "error"
            result["reason"] = f"HTTP 404 on /models: {msg[:200]}"
        else:
            result["status"] = "error"
            result["reason"] = f"HTTP {code}: {msg[:300]}"

        return result

    except urllib.error.URLError as e:
        result["status"] = "network_error"
        result["reason"] = f"Network error: {str(e.reason)[:300] if hasattr(e, 'reason') else str(e)[:300]}"
        return result

    except Exception as e:
        result["status"] = "fetch_failed"
        result["reason"] = f"{type(e).__name__}: {str(e)[:300]}"
        return result

    return result


def main():
    print(f"{'='*70}")
    print("Fireworks Suspended Key Recovery Check")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"DB: {DB_PATH}")
    print(f"{'='*70}")

    conn = get_db()

    # Find Fireworks provider
    fw = conn.execute("SELECT id, slug FROM api_providers WHERE slug='fireworks'").fetchone()
    if not fw:
        print("ERROR: No 'fireworks' provider found in api_providers table")
        conn.close()
        return

    fw_id = fw["id"]
    print(f"Fireworks provider_id: {fw_id}")

    # Get all suspended Fireworks keys
    suspended_keys = conn.execute(
        "SELECT id, label, key_value, suspended, is_active, dead, "
        "error_count, last_error_msg "
        "FROM api_keys WHERE provider_id=? AND suspended=1 ORDER BY id",
        (fw_id,),
    ).fetchall()

    print(f"Suspended Fireworks keys: {len(suspended_keys)}")
    print(f"{'─'*70}")

    if not suspended_keys:
        print("No suspended keys to check. All clear!")
        conn.close()
        return

    results = {
        "reactivated": [],
        "still_suspended": [],
        "invalid_key": [],
        "rate_limited": [],
        "errors": [],
    }

    for i, key in enumerate(suspended_keys, 1):
        key_id = key["id"]
        label = key["label"] or f"(unlabeled #{key_id})"
        key_value = key["key_value"]
        old_error = (key["last_error_msg"] or "")[:80]

        print(f"\n[{i}/{len(suspended_keys)}] Key #{key_id} ({label})")
        print(f"  Previous: {old_error}...")

        # Check account status
        check = check_account_status(key_value)
        status = check["status"]
        account_name = check.get("account_name")
        reason = check.get("reason")
        rate_limits = check.get("rate_limits")

        print(f"  Current status: {status}", end="")
        if account_name:
            print(f" (account: {account_name})", end="")
        if reason:
            print(f" — {reason[:100]}", end="")
        print()

        if status == "active":
            # Reactivate the key!
            conn.execute(
                "UPDATE api_keys SET suspended=0, is_active=1, dead=0, "
                "last_error_msg=NULL, last_error_at=NULL "
                "WHERE id=?",
                (key_id,),
            )
            conn.commit()
            print(f"  ✅ REACTIVATED — Key #{key_id} is now active")

            # Update key_account_info
            try:
                rl = rate_limits or {}
                conn.execute(
                    "UPDATE key_account_info SET "
                    "account_status='active', "
                    "credits_remaining=?, "
                    "rate_limit_prompt=?, "
                    "rate_limit_remaining_prompt=?, "
                    "rate_limit_generated=?, "
                    "rate_limit_remaining_generated=?, "
                    "suspension_reason=NULL, "
                    "last_fetched_at=CURRENT_TIMESTAMP "
                    "WHERE key_id=?",
                    (
                        str(rl.get("x-ratelimit-remaining-tokens-prompt", "")),
                        rl.get("x-ratelimit-limit-tokens-prompt"),
                        rl.get("x-ratelimit-remaining-tokens-prompt"),
                        rl.get("x-ratelimit-limit-tokens-generated"),
                        rl.get("x-ratelimit-remaining-tokens-generated"),
                        key_id,
                    ),
                )
                conn.commit()
            except Exception as e:
                print(f"  Warning: could not update key_account_info for #{key_id}: {e}")

            results["reactivated"].append({
                "key_id": key_id,
                "label": label,
                "account_name": account_name,
            })

        elif status == "suspended":
            new_msg = f"Account suspended: {reason[:200]}" if reason else "Account suspended"
            conn.execute(
                "UPDATE api_keys SET last_error_msg=?, last_error_at=CURRENT_TIMESTAMP "
                "WHERE id=?",
                (new_msg, key_id),
            )
            conn.commit()
            print(f"  💀 Still suspended — keeping suspended")
            results["still_suspended"].append({
                "key_id": key_id,
                "label": label,
                "account_name": account_name,
                "reason": reason,
            })

        elif status == "invalid_key":
            conn.execute(
                "UPDATE api_keys SET dead=1, is_active=0, "
                "last_error_msg='Invalid API key (401)', "
                "last_error_at=CURRENT_TIMESTAMP "
                "WHERE id=?",
                (key_id,),
            )
            conn.commit()
            print(f"  ❌ Invalid key — marked as dead")
            results["invalid_key"].append({"key_id": key_id, "label": label})

        elif status == "rate_limited":
            print(f"  ⏳ Rate limited — skipping (retry later)")
            results["rate_limited"].append({"key_id": key_id, "label": label})

        else:
            print(f"  ⚠️  Error checking status — no changes made")
            results["errors"].append({
                "key_id": key_id,
                "label": label,
                "reason": reason,
            })

        # Small delay between API calls
        if i < len(suspended_keys):
            time.sleep(0.5)

    conn.close()

    # ── Summary ──
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Total suspended keys checked: {len(suspended_keys)}")
    print(f"  ✅ Reactivated (account now active):  {len(results['reactivated'])}")
    print(f"  💀 Still suspended:                   {len(results['still_suspended'])}")
    print(f"  ❌ Invalid key (marked dead):         {len(results['invalid_key'])}")
    print(f"  ⏳ Rate limited (skip):               {len(results['rate_limited'])}")
    print(f"  ⚠️  Check errors (no change):          {len(results['errors'])}")

    if results["reactivated"]:
        print(f"\n{'─'*70}")
        print("REACTIVATED KEYS:")
        for item in results["reactivated"]:
            acct = f" [{item['account_name']}]" if item.get("account_name") else ""
            print(f"  ✅ Key #{item['key_id']:>3} — {item['label']}{acct}")

    if results["still_suspended"]:
        print(f"\n{'─'*70}")
        print("STILL SUSPENDED:")
        for item in results["still_suspended"]:
            acct = f" [{item['account_name']}]" if item.get("account_name") else ""
            print(f"  💀 Key #{item['key_id']:>3} — {item['label']}{acct}")

    if results["errors"]:
        print(f"\n{'─'*70}")
        print("CHECK ERRORS:")
        for item in results["errors"]:
            print(f"  ⚠️  Key #{item['key_id']:>3} — {item['label']}: {item.get('reason', 'unknown')[:80]}")

    # Final active key count
    conn = get_db()
    active_count = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=? AND is_active=1 AND dead=0 AND suspended=0",
        (fw_id,),
    ).fetchone()[0]
    suspended_count = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=? AND suspended=1",
        (fw_id,),
    ).fetchone()[0]
    dead_count = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=? AND dead=1",
        (fw_id,),
    ).fetchone()[0]
    total = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=?",
        (fw_id,),
    ).fetchone()[0]
    conn.close()

    print(f"\n{'─'*70}")
    print(f"FINAL Fireworks key pool status:")
    print(f"  Total: {total} | Active: {active_count} | Suspended: {suspended_count} | Dead: {dead_count}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
