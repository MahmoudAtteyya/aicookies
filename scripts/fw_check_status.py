#!/usr/bin/env python3
"""Check Fireworks keys status in the live database inside the Docker container."""
import sqlite3
import sys

DB_PATH = "/data/cookies.db"

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Check if 'suspended' column exists
    cols = [row[1] for row in conn.execute("PRAGMA table_info(api_keys)")]
    has_suspended = "suspended" in cols
    print(f"api_keys columns: {cols}")
    print(f"Has 'suspended' column: {has_suspended}")
    print()

    # Check all tables
    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    print(f"Tables: {tables}")
    print()

    # Get Fireworks provider id
    fw_row = conn.execute("SELECT id FROM api_providers WHERE slug='fireworks'").fetchone()
    if not fw_row:
        print("ERROR: No 'fireworks' provider found in api_providers!")
        conn.close()
        return
    fw_id = fw_row[0]
    print(f"Fireworks provider_id = {fw_id}")
    print()

    # Build query based on whether 'suspended' column exists
    if has_suspended:
        query = """
            SELECT id, label, key_value, is_active, dead, suspended, last_error_msg
            FROM api_keys
            WHERE provider_id = ?
            ORDER BY id
        """
    else:
        query = """
            SELECT id, label, key_value, is_active, dead, 0 as suspended, last_error_msg
            FROM api_keys
            WHERE provider_id = ?
            ORDER BY id
        """

    rows = conn.execute(query, (fw_id,)).fetchall()
    print(f"=== All Fireworks keys ({len(rows)} total) ===")
    for row in rows:
        kv = row["key_value"] or ""
        le = row["last_error_msg"] or ""
        print(f"  id={row['id']}, label={row['label']}, is_active={row['is_active']}, dead={row['dead']}, suspended={row['suspended']}, key=...{kv[-8:]}, err={le[:80]}")

    # Suspended or inactive/dead
    suspended_rows = [r for r in rows if (has_suspended and r["suspended"] == 1) or (not has_suspended and (r["is_active"] == 0 or r["dead"] == 1))]
    print(f"\n  Suspended/inactive/dead: {len(suspended_rows)}")
    for row in suspended_rows:
        kv = row["key_value"] or ""
        le = row["last_error_msg"] or ""
        status = "SUSPENDED" if (has_suspended and row["suspended"] == 1) else "INACTIVE/DEAD"
        print(f"  [{status}] id={row['id']}, label={row['label']}, key=...{kv[-8:]}, err={le[:100]}")

    # Check key_account_info
    print()
    if "key_account_info" in tables:
        print("=== key_account_info (cached) ===")
        for row in conn.execute("SELECT key_id, account_name, account_status, suspension_reason FROM key_account_info").fetchall():
            sr = row["suspension_reason"] or ""
            print(f"  key_id={row['key_id']}, name={row['account_name']}, status={row['account_status']}, reason={sr[:100]}")
    else:
        print("key_account_info table does NOT exist")

    conn.close()

if __name__ == "__main__":
    main()
