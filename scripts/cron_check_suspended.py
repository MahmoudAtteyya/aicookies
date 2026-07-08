#!/usr/bin/env python3
"""
Cron job: Check all suspended Fireworks API keys and reactivate if accounts are active again.

Flow:
1. Connect to SQLite DB at /opt/data/aicookies/data/cookies.db
2. Query all Fireworks keys with suspended=1
3. For each suspended key, call Fireworks API (GET /inference/v1/models) to check account status
4. If account is active (HTTP 200), unsuspend the key (suspended=0, is_active=1)
5. If account is still suspended (HTTP 412), keep it suspended
6. Print a summary of changes

Uses the same approach as the app's fetch_fireworks_account_info():
- GET /inference/v1/models returns 200 for active accounts, 412 for suspended
- This is more reliable than chat/completions because model existence check
  happens before account suspension check on POST endpoints
"""

import sqlite3
import httpx
import sys
import os
from datetime import datetime

DB_PATH = "/opt/data/aicookies/data/cookies.db"
FIREWORKS_API_BASE = "https://api.fireworks.ai/inference/v1"
MODELS_ENDPOINT = f"{FIREWORKS_API_BASE}/models"


def get_db_connection():
    """Connect to the SQLite database with busy timeout for concurrent access."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_suspended_fireworks_keys(conn):
    """Get all Fireworks keys that are currently suspended."""
    rows = conn.execute(
        """
        SELECT k.id, k.provider_id, k.label, k.key, k.is_active, k.dead, k.suspended,
               k.usage_count, k.last_used_at
        FROM api_keys k
        JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = 'fireworks' AND k.suspended = 1
        ORDER BY k.id
        """
    ).fetchall()
    return rows


def check_account_status(api_key, timeout=15):
    """
    Check Fireworks account status via GET /inference/v1/models.
    
    Returns:
        tuple: (status, detail)
            status: 'active' | 'suspended' | 'dead' | 'error'
            detail: human-readable string with additional info
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(MODELS_ENDPOINT, headers=headers)
        
        if resp.status_code == 200:
            # Try to count models
            try:
                models = resp.json()
                model_count = len(models) if isinstance(models, list) else "?"
            except Exception:
                model_count = "?"
            return ("active", f"HTTP 200, {model_count} models available")
        
        elif resp.status_code == 412:
            # Precondition Failed = account suspended
            body = resp.text[:500]
            # Extract account name from error message
            import re
            account_match = re.search(r'Account\s+(\S+)\s+is\s+suspended', body)
            account_name = account_match.group(1) if account_match else "unknown"
            return ("suspended", f"HTTP 412, account={account_name}, reason={body[:200]}")
        
        elif resp.status_code == 401:
            return ("dead", f"HTTP 401, invalid or revoked key")
        
        elif resp.status_code == 403:
            return ("dead", f"HTTP 403, forbidden (key may be revoked)")
        
        elif resp.status_code == 429:
            return ("error", f"HTTP 429, rate limited (try again later)")
        
        else:
            return ("error", f"HTTP {resp.status_code}, unexpected response: {resp.text[:200]}")
    
    except httpx.TimeoutException:
        return ("error", "Timeout connecting to Fireworks API")
    except httpx.ConnectError as e:
        return ("error", f"Connection error: {str(e)[:200]}")
    except Exception as e:
        return ("error", f"Unexpected error: {type(e).__name__}: {str(e)[:200]}")


def update_key_status(conn, key_id, new_suspended, new_is_active, status_detail):
    """Update a key's suspended/is_active flags and log the change."""
    conn.execute(
        """
        UPDATE api_keys 
        SET suspended = ?, is_active = ?
        WHERE id = ?
        """,
        (new_suspended, new_is_active, key_id)
    )
    
    # Also update the key_account_info table if it exists
    try:
        conn.execute(
            """
            UPDATE key_account_info 
            SET account_status = ?, last_fetched_at = CURRENT_TIMESTAMP
            WHERE key_id = ?
            """,
            (new_suspended and "suspended" or "active", key_id)
        )
    except sqlite3.OperationalError:
        pass  # Table doesn't exist or no row for this key


def main():
    print(f"=== Fireworks Suspended Key Recovery Check ===")
    print(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Database: {DB_PATH}")
    print()
    
    # Connect to DB
    try:
        conn = get_db_connection()
    except Exception as e:
        print(f"ERROR: Cannot connect to database: {e}")
        sys.exit(1)
    
    # Get all suspended Fireworks keys
    try:
        suspended_keys = get_suspended_fireworks_keys(conn)
    except Exception as e:
        print(f"ERROR: Cannot query suspended keys: {e}")
        conn.close()
        sys.exit(1)
    
    print(f"Found {len(suspended_keys)} suspended Fireworks key(s)")
    print()
    
    if not suspended_keys:
        print("No suspended Fireworks keys to check. Nothing to do.")
        conn.close()
        return
    
    # Track results
    reactivated = []
    still_suspended = []
    errors = []
    dead_keys = []
    
    for key in suspended_keys:
        key_id = key["id"]
        label = key["label"] or f"key-{key_id}"
        key_value = key["key"]
        
        # Mask the key for logging
        masked_key = key_value[:10] + "..." if key_value else "NULL"
        
        print(f"--- Key ID={key_id} label='{label}' key={masked_key} ---")
        
        # Check account status via Fireworks API
        status, detail = check_account_status(key_value)
        
        print(f"  Status: {status}")
        print(f"  Detail: {detail}")
        
        if status == "active":
            # Reactivate the key
            update_key_status(conn, key_id, new_suspended=0, new_is_active=1, status_detail=detail)
            conn.commit()
            reactivated.append({"id": key_id, "label": label, "detail": detail})
            print(f"  ✅ REACTIVATED — suspended=0, is_active=1")
        
        elif status == "suspended":
            # Keep suspended
            still_suspended.append({"id": key_id, "label": label, "detail": detail})
            print(f"  ⏸️  Still suspended — keeping suspended=1")
        
        elif status == "dead":
            # Mark as dead
            conn.execute(
                "UPDATE api_keys SET suspended = 1, is_active = 0, dead = 1 WHERE id = ?",
                (key_id,)
            )
            conn.commit()
            dead_keys.append({"id": key_id, "label": label, "detail": detail})
            print(f"  💀 Key is dead — marking dead=1")
        
        else:
            # Error - don't change anything
            errors.append({"id": key_id, "label": label, "detail": detail})
            print(f"  ⚠️  Error checking status — leaving unchanged")
        
        print()
    
    conn.close()
    
    # Print summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total checked:     {len(suspended_keys)}")
    print(f"  Reactivated:       {len(reactivated)}")
    print(f"  Still suspended:   {len(still_suspended)}")
    print(f"  Dead (new):        {len(dead_keys)}")
    print(f"  Errors:            {len(errors)}")
    print()
    
    if reactivated:
        print("REACTIVATED KEYS:")
        for r in reactivated:
            print(f"  ✅ ID={r['id']} label='{r['label']}' — {r['detail']}")
        print()
    
    if still_suspended:
        print("STILL SUSPENDED KEYS:")
        for s in still_suspended:
            print(f"  ⏸️  ID={s['id']} label='{s['label']}' — {s['detail']}")
        print()
    
    if dead_keys:
        print("DEAD KEYS:")
        for d in dead_keys:
            print(f"  💀 ID={d['id']} label='{d['label']}' — {d['detail']}")
        print()
    
    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  ⚠️  ID={e['id']} label='{e['label']}' — {e['detail']}")
        print()
    
    print(f"Recovery check complete at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")


if __name__ == "__main__":
    main()
