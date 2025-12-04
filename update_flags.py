#!/usr/bin/env python3
"""
update_flags.py

Utility to update challenge flags in the CyberRange database to match
the values used by the local vulnerable app. Run this if you don't want
to re-run the `init_challenges.py` initializer.

Usage:
  python3 update_flags.py

It will attempt to update existing Challenge rows by `name` and print a
summary of changes. Back up your DB first if you care about existing progress.
"""
import sqlite3
import os

DB_PATH = os.path.join('instance', 'cyber_range.db')
if not os.path.exists(DB_PATH):
    print(f"Database not found at {DB_PATH}. Are you in the repo root?")
    exit(1)

mapping = {
    'SQL Injection - Login Bypass': 'FLAG{sql_injection_bypass_123}',
    'Cross-Site Scripting (XSS)': 'FLAG{xss_reflected_456}',
    'Command Injection': 'FLAG{command_injection_789}',
    'Path Traversal - Local File Inclusion': 'FLAG{path_traversal_234}',
    'Authentication Bypass - API Exploitation': 'FLAG{auth_bypass_success_789}',
}

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

updated = 0
for name, flag in mapping.items():
    cur.execute('SELECT id, name, flag FROM challenge WHERE name = ?', (name,))
    row = cur.fetchone()
    if not row:
        print(f"Challenge not found in DB: {name}")
        continue
    if row['flag'] == flag:
        print(f"No change for '{name}' (already set)")
        continue
    print(f"Updating '{name}': '{row['flag']}' -> '{flag}'")
    cur.execute('UPDATE challenge SET flag = ? WHERE id = ?', (flag, row['id']))
    updated += 1

conn.commit()
conn.close()
print(f"Done. Updated {updated} challenge(s).")
