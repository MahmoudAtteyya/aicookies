#!/usr/bin/env python3
"""Check all suspended Fireworks keys and reactivate if accounts are active again.

Uses GET /inference/v1/models which returns:
  - HTTP 200 for active accounts
  - HTTP 412 for suspended accounts (PRECONDITION_FAILED)
  - HTTP 401/403 for dead/revoked keys
"""
import sqlite3
import json
import urllib.request
import urllib.error
import re
import sys
from datetime import datetime

DB_PATH = "/data/cookies.db"
FW_BASE = "https://api.fireworks.ai/inference/v1"


def check_status(api_key, timeout=15):
    """Check account status via GET /inference/v1/models."""
    headers = {"Authorization": "Bearer " + api_key}
    try:
        req = urllib.request.Request(
            FW_BASE + "/models", headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode())
                count = len(body) if isinstance(body, list) else "?"
                return ("active", "HTTP 200, {} models".format(count))
        except urllib.error.HTTPError as e:
            code = e.code
            err_body = e.read().decode()[:500]
            if code == 412:
                m = re.search(r"Account\s+(\S+)\s+is\s+suspended", err_body)
                acct = m.group(1) if m else "unknown"
                return ("suspended", "HTTP 412, account={}".format(acct))
            elif code == 401:
                return ("dead", "HTTP 401, invalid/revoked key")
            elif code == 403:
                return ("dead", "HTTP 403, forbidden")
            elif code == 429:
                return ("error", "HTTP 429, rate limited")
            else:
                return ("error", "HTTP {}: {}".format(code, err_body[:100]))
    except Exception as e:
        return ("error", "{}: {}".format(type(e).__name__, str(e)[:100]))


def main():
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=== Fireworks Suspended Key Recovery Check ===")
    print("Timestamp: " + ts)
    print("Database: " + DB_PATH)
    print()

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT k.id, k.key_value, k.label, k.last_error_msg
        FROM api_keys k
        JOIN api_providers p ON k.provider_id = p.id
        WHERE p.slug = 'fireworks' AND k.suspended = 1
        ORDER BY k.id
        """
    ).fetchall()

    total = len(rows)
    print("Found {} suspended Fireworks key(s)".format(total))
    print()

    if total == 0:
        print("No suspended Fireworks keys to check. Nothing to do.")
        conn.close()
        return

    reactivated = []
    still_suspended = []
    dead_keys = []
    errors = []

    for key in rows:
        kid = key["id"]
        label = key["label"] or "key-{}".format(kid)
        kv = key["key_value"]
        masked = kv[:12] + "..." if kv else "NULL"

        status, detail = check_status(kv)
        print("ID={} label='{}' key={} => {} | {}".format(kid, label, masked, status, detail))

        if status == "active":
            conn.execute(
                "UPDATE api_keys SET suspended=0, is_active=1, dead=0, "
                "error_count=0, last_error_msg=NULL WHERE id=?",
                (kid,),
            )
            conn.commit()
            reactivated.append((kid, label, detail))
            print("  >> REACTIVATED")
        elif status == "suspended":
            still_suspended.append((kid, label, detail))
        elif status == "dead":
            conn.execute(
                "UPDATE api_keys SET suspended=1, is_active=0, dead=1 WHERE id=?",
                (kid,),
            )
            conn.commit()
            dead_keys.append((kid, label, detail))
            print("  >> DEAD")
        else:
            errors.append((kid, label, detail))
            print("  >> ERROR (unchanged)")

    conn.close()

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  Total checked:     {}".format(total))
    print("  Reactivated:       {}".format(len(reactivated)))
    print("  Still suspended:   {}".format(len(still_suspended)))
    print("  Dead (new):        {}".format(len(dead_keys)))
    print("  Errors:            {}".format(len(errors)))
    print()

    if reactivated:
        print("REACTIVATED KEYS:")
        for kid, label, detail in reactivated:
            print("  [OK] ID={} label='{}' - {}".format(kid, label, detail))
        print()

    if dead_keys:
        print("DEAD KEYS:")
        for kid, label, detail in dead_keys:
            print("  [DEAD] ID={} label='{}' - {}".format(kid, label, detail))
        print()

    if errors:
        print("ERRORS:")
        for kid, label, detail in errors:
            print("  [ERR] ID={} label='{}' - {}".format(kid, label, detail))
        print()

    # Final pool status
    conn2 = sqlite3.connect(DB_PATH, timeout=10)
    conn2.row_factory = sqlite3.Row
    active_fw = conn2.execute(
        "SELECT COUNT(*) as cnt FROM api_keys k "
        "JOIN api_providers p ON k.provider_id=p.id "
        "WHERE p.slug='fireworks' AND k.is_active=1 "
        "AND k.dead=0 AND k.suspended=0"
    ).fetchone()["cnt"]
    total_fw = conn2.execute(
        "SELECT COUNT(*) as cnt FROM api_keys k "
        "JOIN api_providers p ON k.provider_id=p.id "
        "WHERE p.slug='fireworks'"
    ).fetchone()["cnt"]
    conn2.close()

    print("Fireworks key pool: {} active / {} total".format(active_fw, total_fw))
    done_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print("Recovery check complete at " + done_ts)


if __name__ == "__main__":
    main()
