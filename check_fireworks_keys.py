#!/usr/bin/env python3
"""Check suspended Fireworks keys on the VPS Docker container."""
import sqlite3

DB_PATH = "/data/cookies.db"

print("=== TABLES ===")
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
for t in tables:
    print(f"  {t[0]}")

print("\n=== api_providers ===")
for r in cur.execute("SELECT id, slug, name FROM api_providers ORDER BY id").fetchall():
    print(f"  id={r[0]}, slug={r[1]}, name={r[2]}")

# Find Fireworks provider id
prov = cur.execute("SELECT id FROM api_providers WHERE slug='fireworks'").fetchone()
fw_id = prov[0] if prov else 9
total = cur.execute("SELECT COUNT(*) FROM api_keys WHERE provider_id=?", (fw_id,)).fetchone()[0]
print(f"\n=== ALL FIREWORKS KEYS (provider_id={fw_id}) ===")
print(f"Total: {total}")

print(f"\n=== KEY DETAILS ===")
for r in cur.execute(
    "SELECT id, label, is_active, dead, usage_count, error_count, last_error_msg FROM api_keys WHERE provider_id=? ORDER BY id",
    (fw_id,)
).fetchall():
    label = r[1][:30] if r[1] else "?"
    err = (r[6] or "")[:60] if r[6] else ""
    print(f"  id={r[0]:3d}  label={label:30s}  is_active={r[2]}  dead={r[3]}  usage={r[4]:4d}  errors={r[5]:3d}  err={err}")

print("\n=== key_account_info ===")
for r in cur.execute(
    "SELECT key_id, account_name, account_status, plan_type, rate_limit_prompt, suspension_reason FROM key_account_info ORDER BY key_id"
).fetchall():
    name = (r[1] or "")[:30]
    reason = (r[5] or "")[:80] if r[5] else ""
    print(f"  key_id={r[0]:3d}  account={name:30s}  status={r[2]:12s}  plan={r[3]}  rl_prompt={r[4]}  reason={reason}")

conn.close()
