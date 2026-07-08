import sqlite3

conn = sqlite3.connect("/opt/data/aicookies/data/cookies.db")
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("All tables:")
for row in cursor.fetchall():
    print(" ", row[0])

# Check if key_account_info exists
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='key_account_info'")
result = cursor.fetchone()
if result:
    print("\n=== key_account_info schema ===")
    print(result[0])
else:
    print("\nkey_account_info table does NOT exist")

# Check all Fireworks keys current state
cursor.execute("""
    SELECT k.id, k.label, k.key_value, k.is_active, k.dead, k.error_count, k.last_error_msg
    FROM api_keys k
    JOIN api_providers p ON k.provider_id = p.id
    WHERE p.slug = 'fireworks'
    ORDER BY k.id
""")
print("\n=== All Fireworks keys ===")
for row in cursor.fetchall():
    kv = row[2][:12] + "..." if row[2] else "NULL"
    print(f"  ID={row[0]} label={row[1]} key={kv} active={row[3]} dead={row[4]} errors={row[5]} last_err={row[6]}")

# Check if there's a suspended column - the skill says "suspended=1" but schema doesn't show it
# The skill mentions keys with is_active=0 and dead=0 could be "suspended"
# Let's check for keys that are inactive but not dead
cursor.execute("""
    SELECT k.id, k.label, k.key_value, k.is_active, k.dead, k.error_count, k.last_error_msg
    FROM api_keys k
    JOIN api_providers p ON k.provider_id = p.id
    WHERE p.slug = 'fireworks' AND k.is_active = 0 AND k.dead = 0
    ORDER BY k.id
""")
print("\n=== Suspended Fireworks keys (is_active=0, dead=0) ===")
rows = cursor.fetchall()
if not rows:
    print("  (none)")
for row in rows:
    kv = row[2][:12] + "..." if row[2] else "NULL"
    print(f"  ID={row[0]} label={row[1]} key={kv} active={row[3]} dead={row[4]} errors={row[5]} last_err={row[6]}")

# Also check dead keys
cursor.execute("""
    SELECT k.id, k.label, k.key_value, k.is_active, k.dead, k.error_count, k.last_error_msg
    FROM api_keys k
    JOIN api_providers p ON k.provider_id = p.id
    WHERE p.slug = 'fireworks' AND k.dead = 1
    ORDER BY k.id
""")
print("\n=== Dead Fireworks keys (dead=1) ===")
rows = cursor.fetchall()
if not rows:
    print("  (none)")
for row in rows:
    kv = row[2][:12] + "..." if row[2] else "NULL"
    print(f"  ID={row[0]} label={row[1]} key={kv} active={row[3]} dead={row[4]} errors={row[5]} last_err={row[6]}")

conn.close()
