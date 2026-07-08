import sqlite3

conn = sqlite3.connect("/opt/data/aicookies/data/cookies.db")
cursor = conn.cursor()

# Get schema for relevant tables
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name IN ('api_keys','api_providers','key_account_info')")
for row in cursor.fetchall():
    print(row[0])
    print("---")

# Check providers
cursor.execute("SELECT * FROM api_providers")
print("=== Providers ===")
for row in cursor.fetchall():
    print(row)

# Check if there's a suspended column in api_keys
cursor.execute("PRAGMA table_info(api_keys)")
print("\n=== api_keys columns ===")
for col in cursor.fetchall():
    print(col)

conn.close()
