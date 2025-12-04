#!/usr/bin/env python3
"""
Advanced diagnostics to troubleshoot vulnerable_app.py
Run this on Kali to identify startup issues
"""
import os
import subprocess
import sys
import time

print("=" * 80)
print("VULNERABLE APP DIAGNOSTICS - Checking Why App Won't Start")
print("=" * 80)

# 1. Check environment
print("\n📍 STEP 1: Environment Check")
print(f"   Current directory: {os.getcwd()}")
print(f"   Python version: ", end="")
result = subprocess.run(['python3', '--version'], capture_output=True, text=True)
print(result.stdout.strip())

# 2. Check vulnerable_app.py exists
print("\n📍 STEP 2: File Check")
if not os.path.exists('vulnerable_app.py'):
    print("   ❌ vulnerable_app.py NOT FOUND!")
    sys.exit(1)
print("   ✅ vulnerable_app.py exists")

# 3. Check dependencies
print("\n📍 STEP 3: Dependency Check")
deps_ok = True
try:
    import flask
    print(f"   ✅ Flask {flask.__version__}")
except ImportError as e:
    print(f"   ❌ Flask missing: {e}")
    deps_ok = False

try:
    import flask_sqlalchemy
    print(f"   ✅ Flask-SQLAlchemy installed")
except ImportError as e:
    print(f"   ❌ Flask-SQLAlchemy missing: {e}")
    deps_ok = False

try:
    import sqlite3
    print(f"   ✅ sqlite3 available")
except ImportError as e:
    print(f"   ❌ sqlite3 missing: {e}")
    deps_ok = False

if not deps_ok:
    print("\n⚠️  Installing missing dependencies...")
    subprocess.run(['pip3', 'install', 'flask', 'flask-sqlalchemy'], check=False)
    print("   Try running again.")
    sys.exit(1)

# 4. Try to start app and capture errors
print("\n📍 STEP 4: Attempting App Startup")
print("   Starting vulnerable_app.py (5 second wait)...")

try:
    proc = subprocess.Popen(
        ['python3', 'vulnerable_app.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(5)
    
    # Check if process is still running
    if proc.poll() is not None:
        # Process exited
        stdout, stderr = proc.communicate()
        print(f"\n   ❌ App crashed during startup!")
        if stderr:
            print(f"\n   Error Output:\n{stderr}")
        if stdout:
            print(f"\n   Standard Output:\n{stdout}")
        sys.exit(1)
    
    # Check if database was created
    if os.path.exists('vulnerable.db'):
        print("   ✅ vulnerable.db CREATED!")
        try:
            import sqlite3
            conn = sqlite3.connect('vulnerable.db')
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users;")
            count = cursor.fetchone()[0]
            conn.close()
            print(f"   ✅ Database has {count} users")
            print("\n✅ SUCCESS: App is working! Database initialized.")
        except Exception as e:
            print(f"   ⚠️  Database error: {e}")
    else:
        print("   ❌ Database NOT created (app may not be initializing properly)")
    
    # Kill process
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        
except Exception as e:
    print(f"   ❌ Exception: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

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
