#!/usr/bin/env python3
"""Check suspended Fireworks keys on the production VPS."""
import sqlite3, json, sys

DB = "/data/cookies.db"
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# Schema
for table in ["api_keys", "key_account_info"]:
    print(f"=== {table} ===")
    try:
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        for c in cols:
            print(f"  {c[1]} ({c[2]})")
    except Exception as e:
        print(f"  Error: {e}")
    print()

# Find Fireworks provider
providers = conn.execute("SELECT * FROM api_providers WHERE slug LIKE '%fireworks%'").fetchall()
print("Fireworks providers:")
for p in providers:
    print(f"  id={p['id']}, slug={p['slug']}")
print()

if not providers:
    print("No Fireworks provider found!")
    sys.exit(1)

fw_id = providers[0]["id"]

# Check for 'suspended' column
cols = [c[1] for c in conn.execute("PRAGMA table_info(api_keys)").fetchall()]
has_suspended = "suspended" in cols
print(f"api_keys has 'suspended' column: {has_suspended}")
print(f"api_keys columns: {cols}")
print()

# Get all Fireworks keys
if has_suspended:
    keys = conn.execute(
        f"SELECT id, key_value, label, is_active, dead, suspended, usage_count, error_count, last_error_msg FROM api_keys WHERE provider_id = ? ORDER BY id",
        (fw_id,)
    ).fetchall()
    suspended_keys = [k for k in keys if k["suspended"] == 1]
else:
    keys = conn.execute(
        f"SELECT id, key_value, label, is_active, dead, usage_count, error_count, last_error_msg FROM api_keys WHERE provider_id = ? ORDER BY id",
        (fw_id,)
    ).fetchall()
    suspended_keys = [k for k in keys if k["dead"] == 1 or k["is_active"] == 0]

print(f"Total Fireworks keys: {len(keys)}")
print(f"Keys to check (suspended/dead/inactive): {len(suspended_keys)}")
print()

for k in keys:
    d = dict(k)
    badge = "OK" if d["is_active"] and not d["dead"] else ("DEAD" if d["dead"] else "INACTIVE")
    susp = d.get("suspended", "N/A")
    print(f"  [{badge}] Key #{d['id']} ({d['label']}): active={d['is_active']}, dead={d['dead']}, suspended={susp}, usage={d['usage_count']}, errors={d['error_count']}")
    if d.get("last_error_msg"):
        print(f"        last_error: {d['last_error_msg'][:150]}")

# Check key_account_info
print()
try:
    ai_rows = conn.execute("SELECT * FROM key_account_info").fetchall()
    print(f"key_account_info rows: {len(ai_rows)}")
    for r in ai_rows:
        d = dict(r)
        print(f"  key_id={d['key_id']}, status={d.get('account_status','?')}, name={d.get('account_name','?')}, last_fetched={d.get('last_fetched_at','?')}")
except Exception as e:
    print(f"key_account_info: {e}")

conn.close()
