import sqlite3

conn = sqlite3.connect("/data/cookies.db")
c = conn.cursor()

# List all tables
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables:", [r[0] for r in c.fetchall()])

# Check key_account_info schema
c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='key_account_info'")
row = c.fetchone()
if row:
    print("\nkey_account_info schema exists")
else:
    print("\nkey_account_info table does NOT exist")

# Get all Fireworks keys
c.execute("""
    SELECT k.id, k.label, k.key_value, k.is_active, k.dead, k.error_count, k.last_error_msg
    FROM api_keys k
    JOIN api_providers p ON k.provider_id = p.id
    WHERE p.slug = 'fireworks'
    ORDER BY k.id
""")
rows = c.fetchall()
print(f"\n=== All Fireworks keys ({len(rows)} total) ===")
for row in rows:
    kv = row[2][:12] + "..." if row[2] else "NULL"
    err = (row[6] or "")[:80]
    print(f"  ID={row[0]} label={row[1]} key={kv} active={row[3]} dead={row[4]} errors={row[5]} err={err}")

# Suspended = is_active=0, dead=0
c.execute("""
    SELECT k.id, k.label, k.key_value, k.is_active, k.dead, k.error_count, k.last_error_msg
    FROM api_keys k
    JOIN api_providers p ON k.provider_id = p.id
    WHERE p.slug = 'fireworks' AND k.is_active = 0 AND k.dead = 0
    ORDER BY k.id
""")
rows = c.fetchall()
print(f"\n=== Suspended (is_active=0, dead=0): {len(rows)} keys ===")
for row in rows:
    kv = row[2][:12] + "..." if row[2] else "NULL"
    err = (row[6] or "")[:80]
    print(f"  ID={row[0]} label={row[1]} key={kv} active={row[3]} dead={row[4]} errors={row[5]} err={err}")

# Dead = dead=1
c.execute("""
    SELECT k.id, k.label, k.key_value, k.is_active, k.dead, k.error_count, k.last_error_msg
    FROM api_keys k
    JOIN api_providers p ON k.provider_id = p.id
    WHERE p.slug = 'fireworks' AND k.dead = 1
    ORDER BY k.id
""")
rows = c.fetchall()
print(f"\n=== Dead (dead=1): {len(rows)} keys ===")
for row in rows:
    kv = row[2][:12] + "..." if row[2] else "NULL"
    err = (row[6] or "")[:80]
    print(f"  ID={row[0]} label={row[1]} key={kv} active={row[3]} dead={row[4]} errors={row[5]} err={err}")

conn.close()
