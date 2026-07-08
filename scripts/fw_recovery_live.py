#!/usr/bin/env python3
"""
Fireworks Suspended Key Recovery Job
Checks all inactive Fireworks keys and reactivates them if their accounts are active again.
"""
import sqlite3
import urllib.request
import urllib.error
import json
import time
from datetime import datetime, timezone

DB_PATH = "/data/cookies.db"
FW_BASE_URL = "https://api.fireworks.ai/inference/v1"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def check_account_status(api_key):
    headers = {"Authorization": "Bearer " + api_key}
    try:
        req = urllib.request.Request(
            FW_BASE_URL + "/models",
            headers=headers,
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                return "active", None
    except urllib.error.HTTPError as e:
        code = e.code
        body = ""
        try:
            body = e.read().decode()[:500]
        except:
            pass
        if code == 412:
            msg = ""
            try:
                err = json.loads(body)
                msg = err.get("error", {}).get("message", "")
            except:
                msg = body
            return "suspended", msg
        elif code == 401:
            return "invalid_key", "Authentication failed"
        elif code == 429:
            return "rate_limited", "Rate limit exceeded"
        elif code == 403:
            return "suspended", "HTTP 403: " + body[:200]
        else:
            return "error", "HTTP " + str(code) + ": " + body[:200]
    except urllib.error.URLError as e:
        return "network_error", "Network error: " + str(e.reason)[:200]
    except Exception as e:
        return "error", type(e).__name__ + ": " + str(e)[:200]
    return "active", None

def main():
    now = datetime.now(timezone.utc).isoformat()
    print("=" * 70)
    print("Fireworks Suspended Key Recovery Job - " + now)
    print("=" * 70)

    conn = get_db()

    p = conn.execute("SELECT id FROM api_providers WHERE slug='fireworks'").fetchone()
    if not p:
        print("ERROR: Fireworks provider not found in api_providers table")
        return
    fw_provider_id = p[0]

    all_keys = conn.execute(
        "SELECT id, label, key_value, is_active, dead, usage_count, error_count, last_error_msg "
        "FROM api_keys WHERE provider_id=? ORDER BY id",
        (fw_provider_id,)
    ).fetchall()

    check_keys = [k for k in all_keys if not k["is_active"]]
    active_keys = [k for k in all_keys if k["is_active"]]

    print()
    print("Total Fireworks keys: " + str(len(all_keys)))
    print("  Active:   " + str(len(active_keys)))
    print("  Inactive: " + str(len(check_keys)) + " (will check these)")
    print()

    if not check_keys:
        print("No inactive keys to check. All Fireworks keys are already active.")
        conn.close()
        return

    reactivated = []
    still_suspended = []
    invalid_keys = []
    errors = []

    for key in check_keys:
        key_id = key["id"]
        label = key["label"] or "no-label"
        was_dead = key["dead"]

        time.sleep(0.5)
        status, reason = check_account_status(key["key_value"])

        if status == "active":
            conn.execute(
                "UPDATE api_keys SET is_active=1, dead=0, last_error_msg=NULL, last_error_at=NULL WHERE id=?",
                (key_id,)
            )
            conn.commit()
            reactivated.append({"id": key_id, "label": label, "was_dead": was_dead})
            print("  [REACTIVATED] #" + str(key_id).rjust(3) + " (" + label + ") - account is active again!")
            try:
                conn.execute(
                    "UPDATE key_account_info SET account_status='active', suspension_reason=NULL, "
                    "last_fetched_at=CURRENT_TIMESTAMP WHERE key_id=?",
                    (key_id,)
                )
                conn.commit()
            except:
                pass
        elif status == "suspended":
            still_suspended.append({"id": key_id, "label": label, "reason": reason})
            reason_short = str(reason)[:80] if reason else ""
            print("  [SUSPENDED]  #" + str(key_id).rjust(3) + " (" + label + ") - " + reason_short)
        elif status == "invalid_key":
            conn.execute(
                "UPDATE api_keys SET dead=1, is_active=0, "
                "last_error_msg='Invalid API key (401)', last_error_at=CURRENT_TIMESTAMP WHERE id=?",
                (key_id,)
            )
            conn.commit()
            invalid_keys.append({"id": key_id, "label": label})
            print("  [INVALID]    #" + str(key_id).rjust(3) + " (" + label + ") - marked as dead")
        else:
            errors.append({"id": key_id, "label": label, "status": status, "reason": reason})
            reason_short = str(reason)[:80] if reason else ""
            print("  [ERROR]      #" + str(key_id).rjust(3) + " (" + label + ") - " + status + ": " + reason_short)

    conn.close()

    print()
    print("=" * 70)
    print("SUMMARY - " + datetime.now(timezone.utc).isoformat())
    print("=" * 70)
    print("  Total checked:        " + str(len(check_keys)))
    print("  [REACTIVATED]         " + str(len(reactivated)))
    print("  [STILL SUSPENDED]     " + str(len(still_suspended)))
    print("  [INVALID/DEAD]        " + str(len(invalid_keys)))
    print("  [ERRORS]              " + str(len(errors)))
    print()

    if reactivated:
        print("Reactivated keys:")
        for r in reactivated:
            dead_note = " (was dead=1)" if r["was_dead"] else ""
            print("  [OK] #" + str(r["id"]).rjust(3) + " " + r["label"] + dead_note)
        print()

    if still_suspended:
        print("Still suspended (" + str(len(still_suspended)) + " keys):")
        for s in still_suspended:
            print("  [SUSP] #" + str(s["id"]).rjust(3) + " " + s["label"])
        print()

    if invalid_keys:
        print("Invalid keys marked dead (" + str(len(invalid_keys)) + " keys):")
        for i in invalid_keys:
            print("  [DEAD] #" + str(i["id"]).rjust(3) + " " + i["label"])
        print()

    if errors:
        print("Errors (" + str(len(errors)) + " keys):")
        for e in errors:
            print("  [ERR]  #" + str(e["id"]).rjust(3) + " " + e["label"] + " - " + e["status"])
        print()

    conn = get_db()
    final_active = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=? AND is_active=1 AND dead=0",
        (fw_provider_id,)
    ).fetchone()[0]
    final_suspended = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=? AND is_active=0 AND dead=0",
        (fw_provider_id,)
    ).fetchone()[0]
    final_dead = conn.execute(
        "SELECT COUNT(*) FROM api_keys WHERE provider_id=? AND dead=1",
        (fw_provider_id,)
    ).fetchone()[0]
    conn.close()
    print("Fireworks key pool: " + str(final_active) + " active / " + str(final_suspended) + " suspended / " + str(final_dead) + " dead")

if __name__ == "__main__":
    main()
