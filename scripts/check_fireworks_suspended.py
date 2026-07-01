#!/usr/bin/env python3
"""
Check all suspended Fireworks API keys and reactivate them if their accounts are active again.

This script:
1. Connects to the SQLite DB at /data/cookies.db
2. Gets all Fireworks keys with suspended=1
3. For each, calls the Fireworks API to check fresh account status
4. If account_status is "active", unsuspends the key (suspended=0, is_active=1, dead=0)
5. If account_status is still "suspended"/"invalid_key", keeps it suspended
6. Updates key_account_info table with fresh data
7. Prints a summary of changes
"""
import sqlite3
import json
import urllib.request
import urllib.error
import re
import time
import sys
from datetime import datetime

DB_PATH = "/data/cookies.db"
FIREWORKS_BASE = "https://api.fireworks.ai/inference/v1"
FW_CREDITS_DOLLAR_INITIAL = 6.00
FW_CREDITS_TOKEN_LIMIT = 7200000

def fetch_fireworks_account_info(api_key):
    """Fetch account info for a Fireworks AI key by making a minimal API call."""
    result = {
        "provider_slug": "fireworks",
        "account_name": None,
        "account_email": None,
        "account_status": "unknown",
        "plan_type": None,
        "credits_remaining": None,
        "credits_total": None,
        "credits_dollar": None,
        "credits_initial": None,
        "rate_limit_prompt": None,
        "rate_limit_generated": None,
        "rate_limit_remaining_prompt": None,
        "rate_limit_remaining_generated": None,
        "models_available": None,
        "models_count": None,
        "billing_url": "https://fireworks.ai/account/billing",
        "suspension_reason": None,
        "raw_response": None,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Step 1: Minimal chat completion to extract rate-limit headers
    try:
        payload = json.dumps({
            "model": "accounts/fireworks/models/glm-5p2",
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
                body = json.loads(resp.read().decode())

                result["account_status"] = "active"
                result["plan_type"] = "promotional"

                prompt_limit = int(resp_headers.get("x-ratelimit-limit-tokens-prompt", 0))
                prompt_remaining = int(resp_headers.get("x-ratelimit-remaining-tokens-prompt", 0))
                gen_limit = int(resp_headers.get("x-ratelimit-limit-tokens-generated", 0))
                gen_remaining = int(resp_headers.get("x-ratelimit-remaining-tokens-generated", 0))

                result["rate_limit_prompt"] = prompt_limit or FW_CREDITS_TOKEN_LIMIT
                result["rate_limit_remaining_prompt"] = prompt_remaining if prompt_remaining else (prompt_limit - 13 if prompt_limit else None)
                result["rate_limit_generated"] = gen_limit or None
                result["rate_limit_remaining_generated"] = gen_remaining or None

                if prompt_limit and prompt_limit >= FW_CREDITS_TOKEN_LIMIT * 0.8:
                    prompt_rem = prompt_remaining if prompt_remaining else (prompt_limit - 13)
                    dollar_remaining = round((prompt_rem / FW_CREDITS_TOKEN_LIMIT) * FW_CREDITS_DOLLAR_INITIAL, 2)
                    result["credits_remaining"] = f"{prompt_rem:,}"
                    result["credits_total"] = f"{prompt_limit:,}"
                    result["credits_dollar"] = f"${dollar_remaining:.2f}"
                    result["credits_initial"] = f"${FW_CREDITS_DOLLAR_INITIAL:.2f}"
                else:
                    result["credits_remaining"] = str(prompt_limit)
                    result["credits_total"] = str(prompt_limit)

                result["raw_response"] = json.dumps({
                    "status": "ok",
                    "headers": {k: v for k, v in resp_headers.items()
                                if any(p in k.lower() for p in ("x-ratelimit", "fireworks"))}
                })

        except urllib.error.HTTPError as e:
            body_text = e.read().decode()
            resp_headers = dict(e.headers) if hasattr(e, 'headers') else {}
            result["raw_response"] = body_text[:2000]

            code = e.code
            msg = ""
            try:
                err = json.loads(body_text)
                msg = err.get("error", {}).get("message", "")
            except:
                msg = body_text[:500]

            if code in (403, 422, 412):
                result["account_status"] = "suspended"
                result["suspension_reason"] = msg
                result["plan_type"] = "promotional"

                name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
                if name_match:
                    result["account_name"] = name_match.group(1)

                email_match = re.search(r'([\w.+-]+@[\w-]+\.[\w.]+)', msg)
                if email_match:
                    result["account_email"] = email_match.group(1)

                dollar_match = re.search(r'\$([\d.]+)', msg)
                if dollar_match:
                    result["credits_initial"] = f"${FW_CREDITS_DOLLAR_INITIAL:.2f}"
                    result["credits_dollar"] = "$0.00"
                    result["credits_remaining"] = "0"
                    result["credits_total"] = str(FW_CREDITS_TOKEN_LIMIT)

            elif code == 401:
                result["account_status"] = "invalid_key"
                result["suspension_reason"] = "Authentication failed — invalid API key"
            elif code == 429:
                result["account_status"] = "rate_limited"
                result["suspension_reason"] = "Rate limit exceeded — try again later"
            elif code == 402:
                result["account_status"] = "suspended"
                result["suspension_reason"] = f"Payment required: {msg[:300]}"
            else:
                result["account_status"] = "error"
                result["suspension_reason"] = f"HTTP {code}: {msg[:300]}"

    except urllib.error.URLError as e:
        result["account_status"] = "network_error"
        result["suspension_reason"] = f"Network error: {str(e.reason)[:300]}" if hasattr(e, 'reason') else str(e)[:300]
    except Exception as e:
        result["account_status"] = "fetch_failed"
        result["suspension_reason"] = f"{type(e).__name__}: {str(e)[:400]}"

    # Step 2: Fetch available models
    try:
        req2 = urllib.request.Request(
            f"{FIREWORKS_BASE}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        with urllib.request.urlopen(req2, timeout=10) as resp:
            models_data = json.loads(resp.read().decode())
            model_ids = [m.get("id", "") for m in models_data.get("data", [])]
            result["models_available"] = json.dumps(model_ids[:50])
            result["models_count"] = len(model_ids)

            if model_ids and not result.get("account_name"):
                first_model = models_data.get("data", [{}])[0] if models_data.get("data") else {}
                owned_by = first_model.get("owned_by", "")
                if owned_by and not owned_by.startswith("accounts/"):
                    result["account_name"] = owned_by
    except urllib.error.HTTPError as e:
        if e.code == 412 and result["account_status"] != "suspended":
            try:
                err = json.loads(e.read().decode())
                msg = err.get("error", {}).get("message", "")
                if "suspended" in msg.lower():
                    result["account_status"] = "suspended"
                    result["suspension_reason"] = msg
                    name_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', msg)
                    if name_match:
                        result["account_name"] = name_match.group(1)
            except:
                pass
    except:
        pass

    # Step 3: Post-processing
    if result["account_status"] == "active":
        if not result["account_name"]:
            try:
                models_list = json.loads(result["models_available"]) if result["models_available"] else []
                if models_list:
                    result["account_name"] = models_list[0].split("/")[1] if "/" in models_list[0] else None
            except:
                pass

    if result["account_status"] == "suspended" and not result.get("credits_dollar"):
        result["credits_remaining"] = "0"
        result["credits_total"] = str(FW_CREDITS_TOKEN_LIMIT)
        result["credits_dollar"] = "$0.00"
        result["credits_initial"] = f"${FW_CREDITS_DOLLAR_INITIAL:.2f}"

    return result


def save_account_info(conn, key_id, info):
    """Save or update account info in the key_account_info table."""
    # Check if table exists
    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='key_account_info'")]
    if not tables:
        # Create the table
        conn.execute("""CREATE TABLE IF NOT EXISTS key_account_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id INTEGER NOT NULL UNIQUE,
            provider_slug TEXT NOT NULL,
            account_name TEXT,
            account_email TEXT,
            account_status TEXT,
            plan_type TEXT,
            credits_remaining TEXT,
            credits_total TEXT,
            credits_dollar TEXT,
            credits_initial TEXT,
            rate_limit_prompt INTEGER,
            rate_limit_generated INTEGER,
            rate_limit_remaining_prompt INTEGER,
            rate_limit_remaining_generated INTEGER,
            models_available TEXT,
            models_count INTEGER,
            billing_url TEXT,
            suspension_reason TEXT,
            raw_response TEXT,
            last_fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
        )""")
        conn.commit()

    conn.execute("""INSERT OR REPLACE INTO key_account_info
        (key_id, provider_slug, account_name, account_email, account_status, plan_type,
         credits_remaining, credits_total, credits_dollar, credits_initial,
         rate_limit_prompt, rate_limit_generated,
         rate_limit_remaining_prompt, rate_limit_remaining_generated,
         models_available, models_count, billing_url, suspension_reason, raw_response, last_fetched_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (key_id, info.get("provider_slug"), info.get("account_name"),
         info.get("account_email"), info.get("account_status"), info.get("plan_type"),
         info.get("credits_remaining"), info.get("credits_total"),
         info.get("credits_dollar"), info.get("credits_initial"),
         info.get("rate_limit_prompt"), info.get("rate_limit_generated"),
         info.get("rate_limit_remaining_prompt"), info.get("rate_limit_remaining_generated"),
         info.get("models_available"), info.get("models_count"), info.get("billing_url"),
         info.get("suspension_reason"), info.get("raw_response")))
    conn.commit()


def main():
    print(f"{'='*70}")
    print(f"Fireworks Suspended Key Recovery Check")
    print(f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Database: {DB_PATH}")
    print(f"{'='*70}")
    print()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")

    # Get Fireworks provider_id
    fw_row = conn.execute("SELECT id FROM api_providers WHERE slug='fireworks'").fetchone()
    if not fw_row:
        print("ERROR: No 'fireworks' provider found in api_providers!")
        conn.close()
        return
    fw_id = fw_row[0]

    # Get all suspended Fireworks keys
    suspended_keys = conn.execute("""
        SELECT id, label, key_value, is_active, dead, suspended, last_error_msg
        FROM api_keys
        WHERE provider_id = ? AND suspended = 1
        ORDER BY id
    """, (fw_id,)).fetchall()

    total_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE provider_id = ?", (fw_id,)).fetchone()[0]
    active_keys = conn.execute("SELECT COUNT(*) FROM api_keys WHERE provider_id = ? AND is_active = 1 AND suspended = 0", (fw_id,)).fetchone()[0]

    print(f"Fireworks keys summary:")
    print(f"  Total keys:     {total_keys}")
    print(f"  Active keys:    {active_keys}")
    print(f"  Suspended keys: {len(suspended_keys)}")
    print()

    if not suspended_keys:
        print("✅ No suspended Fireworks keys to check. All keys are active.")
        conn.close()
        return

    reactivated = []
    still_suspended = []
    errors = []

    print(f"Checking {len(suspended_keys)} suspended keys against Fireworks API...")
    print(f"{'-'*70}")

    for i, key_row in enumerate(suspended_keys, 1):
        key_id = key_row["id"]
        key_val = key_row["key_value"]
        label = key_row["label"] or "(no label)"
        old_err = (key_row["last_error_msg"] or "")[:60]
        key_preview = f"...{key_val[-8:]}" if key_val else "(empty)"

        print(f"\n[{i}/{len(suspended_keys)}] Key #{key_id} ({label}) {key_preview}")
        print(f"  Previous error: {old_err}")

        # Fetch fresh account info
        try:
            info = fetch_fireworks_account_info(key_val)
        except Exception as e:
            print(f"  ❌ FETCH ERROR: {type(e).__name__}: {str(e)[:200]}")
            errors.append({"key_id": key_id, "label": label, "error": str(e)[:200]})
            continue

        status = info.get("account_status", "unknown")
        account_name = info.get("account_name", "N/A")
        suspension_reason = (info.get("suspension_reason") or "")[:100]

        print(f"  Fresh status: {status}")
        print(f"  Account name: {account_name}")

        # Save updated account info
        try:
            save_account_info(conn, key_id, info)
        except Exception as e:
            print(f"  ⚠️ Could not save account info: {e}")

        if status == "active":
            # Reactivate the key!
            conn.execute("""
                UPDATE api_keys 
                SET suspended = 0, is_active = 1, dead = 0, last_error_msg = NULL
                WHERE id = ?
            """, (key_id,))
            conn.commit()

            credits = info.get("credits_dollar", "N/A")
            print(f"  ✅ REACTIVATED! Credits: {credits}")
            reactivated.append({
                "key_id": key_id,
                "label": label,
                "account_name": account_name,
                "credits": credits
            })

        elif status in ("suspended", "invalid_key"):
            # Keep suspended
            # Update the error message with the fresh reason
            new_err = f"Account {status}: {suspension_reason}"
            conn.execute("""
                UPDATE api_keys 
                SET last_error_msg = ?, dead = ?
                WHERE id = ?
            """, (new_err[:200], 1 if status == "invalid_key" else 0, key_id))
            conn.commit()

            print(f"  🔒 Still {status}: {suspension_reason}")
            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": account_name,
                "status": status,
                "reason": suspension_reason
            })

        elif status in ("rate_limited",):
            # Rate limited — not permanently suspended, but don't reactivate yet
            print(f"  ⏳ Rate limited (not permanent): {suspension_reason}")
            still_suspended.append({
                "key_id": key_id,
                "label": label,
                "account_name": account_name,
                "status": status,
                "reason": suspension_reason
            })

        elif status in ("network_error", "fetch_failed", "error"):
            print(f"  ⚠️ Could not verify: {status} — {suspension_reason}")
            errors.append({
                "key_id": key_id,
                "label": label,
                "error": f"{status}: {suspension_reason}"
            })

        else:
            print(f"  ❓ Unknown status: {status}")
            errors.append({
                "key_id": key_id,
                "label": label,
                "error": f"Unknown status: {status}"
            })

        # Small delay to avoid hammering the API
        if i < len(suspended_keys):
            time.sleep(0.5)

    # Final summary
    print()
    print(f"{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Total checked:     {len(suspended_keys)}")
    print(f"  ✅ Reactivated:     {len(reactivated)}")
    print(f"  🔒 Still suspended:  {len(still_suspended)}")
    print(f"  ⚠️ Errors:          {len(errors)}")
    print()

    if reactivated:
        print("REACTIVATED KEYS:")
        for r in reactivated:
            print(f"  ✅ Key #{r['key_id']} ({r['label']}) — {r['account_name']} — Credits: {r['credits']}")
        print()

    if still_suspended:
        print("STILL SUSPENDED:")
        for s in still_suspended:
            print(f"  🔒 Key #{s['key_id']} ({s['label']}) — {s['account_name']} — {s['status']}: {s['reason'][:80]}")
        print()

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  ⚠️ Key #{e['key_id']} ({e['label']}) — {e['error'][:100]}")
        print()

    # Final state
    final_active = conn.execute("SELECT COUNT(*) FROM api_keys WHERE provider_id = ? AND is_active = 1 AND suspended = 0", (fw_id,)).fetchone()[0]
    final_suspended = conn.execute("SELECT COUNT(*) FROM api_keys WHERE provider_id = ? AND suspended = 1", (fw_id,)).fetchone()[0]
    print(f"Final Fireworks key state:")
    print(f"  Active:    {final_active}")
    print(f"  Suspended: {final_suspended}")
    print()
    print(f"Done at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    conn.close()


if __name__ == "__main__":
    main()
