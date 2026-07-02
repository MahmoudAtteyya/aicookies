#!/usr/bin/env python3
"""
Cron job: Check all suspended Fireworks API keys and reactivate if accounts are active.

This script:
1. Queries the database for all Fireworks keys with is_active=0 and dead=0 (suspended)
2. For each suspended key, calls fetch_fireworks_account_info() to get fresh account status
3. If account_status is "active", unsuspends the key (set is_active=1)
4. Updates key_account_info table with latest data
5. Logs results for monitoring
"""

import sys
import os
import sqlite3
import json
from datetime import datetime

# Add app.py directory to path so we can import fetch_fireworks_account_info
sys.path.insert(0, "/app")

# DB path inside container
DB_PATH = "/data/cookies.db"

def fetch_fireworks_account_info(api_key):
    """
    Inline copy of fetch_fireworks_account_info from app.py.
    We inline it because importing from app.py triggers Flask initialization.
    """
    import urllib.request, urllib.error, re
    import json as _json
    
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
    
    FW_CREDITS_DOLLAR_INITIAL = 6.00
    FW_CREDITS_TOKEN_LIMIT = 7200000

    base_url = "https://api.fireworks.ai/inference/v1"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Step 1: Make a minimal chat completion to extract rate-limit headers
    try:
        payload = _json.dumps({
            "model": "accounts/fireworks/models/glm-5p2",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
            "temperature": 0,
        }).encode()
        
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_headers = dict(resp.headers)
                body = _json.loads(resp.read().decode())

                result["account_status"] = "active"
                result["plan_type"] = "promotional"
                
                # Extract rate limit headers
                prompt_limit = int(resp_headers.get("x-ratelimit-limit-tokens-prompt", 0))
                prompt_remaining = int(resp_headers.get("x-ratelimit-remaining-tokens-prompt", 0))
                gen_limit = int(resp_headers.get("x-ratelimit-limit-tokens-generated", 0))
                gen_remaining = int(resp_headers.get("x-ratelimit-remaining-tokens-generated", 0))
                
                result["rate_limit_prompt"] = prompt_limit or FW_CREDITS_TOKEN_LIMIT
                result["rate_limit_remaining_prompt"] = prompt_remaining if prompt_remaining else prompt_limit - 13 if prompt_limit else None
                result["rate_limit_generated"] = gen_limit or None
                result["rate_limit_remaining_generated"] = gen_remaining or None
                
                # Calculate credit in dollars
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
                    result["credits_dollar"] = None

                result["raw_response"] = _json.dumps({
                    "status": "ok",
                    "headers": {k: v for k, v in resp_headers.items()
                                if any(p in k.lower() for p in ("x-ratelimit", "fireworks"))}
                })

        except urllib.error.HTTPError as e:
            body_text = e.read().decode()
            result["raw_response"] = body_text[:2000]
            
            code = e.code
            msg = ""
            try:
                err = _json.loads(body_text)
                msg = err.get("error", {}).get("message", "")
            except:
                msg = body_text[:500]

            if code in (403, 422, 412):
                # Account suspended
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
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        with urllib.request.urlopen(req2, timeout=10) as resp:
            models_data = _json.loads(resp.read().decode())
            model_ids = [m.get("id", "") for m in models_data.get("data", [])]
            result["models_available"] = _json.dumps(model_ids[:50])
            result["models_count"] = len(model_ids)
            
            if model_ids and not result.get("account_name"):
                first_model = models_data.get("data", [{}])[0] if models_data.get("data") else {}
                owned_by = first_model.get("owned_by", "")
                if owned_by and not owned_by.startswith("accounts/"):
                    result["account_name"] = owned_by
    except urllib.error.HTTPError as e:
        if e.code == 412 and result["account_status"] != "suspended":
            try:
                err = _json.loads(e.read().decode())
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

    return result


def update_key_account_info(conn, key_id, info):
    """Update or insert key_account_info row."""
    c = conn.cursor()
    
    c.execute("""
        INSERT OR REPLACE INTO key_account_info (
            key_id, provider_slug, account_name, account_email, account_status,
            plan_type, credits_remaining, credits_total, rate_limit_prompt,
            rate_limit_generated, rate_limit_remaining_prompt, rate_limit_remaining_generated,
            models_available, billing_url, suspension_reason, raw_response, last_fetched_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (
        key_id, info.get("provider_slug"), info.get("account_name"), info.get("account_email"),
        info.get("account_status"), info.get("plan_type"), info.get("credits_remaining"),
        info.get("credits_total"), info.get("rate_limit_prompt"), info.get("rate_limit_generated"),
        info.get("rate_limit_remaining_prompt"), info.get("rate_limit_remaining_generated"),
        info.get("models_available"), info.get("billing_url"), info.get("suspension_reason"),
        info.get("raw_response")
    ))
    
    conn.commit()


def main():
    print(f"\n{'='*60}")
    print(f"Fireworks Key Reactivation Job — {datetime.now().isoformat()}")
    print(f"{'='*60}\n")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get all suspended Fireworks keys
    c.execute("""
        SELECT k.id, k.label, k.key_value, k.last_error_msg
        FROM api_keys k
        JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = 'fireworks' AND k.is_active = 0 AND k.dead = 0
        ORDER BY k.id
    """)
    suspended_keys = c.fetchall()
    
    print(f"Found {len(suspended_keys)} suspended Fireworks keys")
    
    if not suspended_keys:
        print("\nNo suspended keys to check.")
        conn.close()
        return
    
    reactivated = []
    still_suspended = []
    errors = []
    
    for i, (key_id, label, key_value, last_err) in enumerate(suspended_keys, 1):
        key_preview = (key_value[:12] + "...") if key_value else "NULL"
        label_str = label or f"ID={key_id}"
        
        print(f"\n[{i}/{len(suspended_keys)}] Checking {label_str} (key={key_preview})...")
        print(f"  Last error: {(last_err or '')[:80]}")
        
        try:
            # Fetch fresh account info
            info = fetch_fireworks_account_info(key_value)
            status = info.get("account_status", "unknown")
            account_name = info.get("account_name", "N/A")
            
            print(f"  Account: {account_name}")
            print(f"  Status: {status}")
            
            # Update key_account_info table
            update_key_account_info(conn, key_id, info)
            
            if status == "active":
                # Reactivate the key
                c.execute("""
                    UPDATE api_keys
                    SET is_active = 1, error_count = 0, last_error_msg = NULL
                    WHERE id = ?
                """, (key_id,))
                conn.commit()
                
                reactivated.append({
                    "id": key_id,
                    "label": label_str,
                    "account": account_name,
                    "credits": info.get("credits_dollar", "N/A")
                })
                print(f"  ✅ REACTIVATED — {info.get('credits_dollar', 'N/A')} credits remaining")
                
            elif status == "suspended":
                still_suspended.append({
                    "id": key_id,
                    "label": label_str,
                    "account": account_name,
                    "reason": (info.get("suspension_reason") or "")[:100]
                })
                print(f"  ❌ STILL SUSPENDED")
                
            else:
                errors.append({
                    "id": key_id,
                    "label": label_str,
                    "status": status,
                    "reason": (info.get("suspension_reason") or "Unknown error")[:100]
                })
                print(f"  ⚠️ ERROR: {status}")
                
        except Exception as e:
            errors.append({
                "id": key_id,
                "label": label_str,
                "status": "exception",
                "reason": str(e)[:100]
            })
            print(f"  ⚠️ EXCEPTION: {e}")
    
    conn.close()
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"  Total checked: {len(suspended_keys)}")
    print(f"  Reactivated:   {len(reactivated)}")
    print(f"  Still suspended: {len(still_suspended)}")
    print(f"  Errors:        {len(errors)}")
    
    if reactivated:
        print(f"\n✅ REACTIVATED KEYS ({len(reactivated)}):")
        for k in reactivated:
            print(f"  - ID={k['id']} {k['label']} ({k['account']}) — {k['credits']}")
    
    if still_suspended:
        print(f"\n❌ STILL SUSPENDED ({len(still_suspended)}):")
        for k in still_suspended[:10]:  # Show first 10
            print(f"  - ID={k['id']} {k['label']} ({k['account']})")
        if len(still_suspended) > 10:
            print(f"  ... and {len(still_suspended) - 10} more")
    
    if errors:
        print(f"\n⚠️ ERRORS ({len(errors)}):")
        for k in errors[:5]:
            print(f"  - ID={k['id']} {k['label']}: {k['status']} — {k['reason']}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more")
    
    print(f"\n{'='*60}")
    print("Job complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
