# NEXT STEPS - Run These Commands Now

## On Your Kali VM

Open a terminal and run these commands exactly:

### Terminal 1: Start the Vulnerable App
```bash
cd ~/Cyberrange
git pull origin main
python3 start_vulnerable_app.py
```

**Expected Output:**
```
✅ STARTUP SUCCESSFUL
✅ Vulnerable app is running on http://localhost:8080/
Press Ctrl+C to stop the app
```

**⚠️  IMPORTANT: Keep this terminal open and running!**

---

### Terminal 2: Run the Test Suite
Open a NEW terminal window and run:

```bash
cd ~/Cyberrange
python3 full_test.py
```

**This will:**
1. Wait for the app (or connect if already running)
2. Test all 5 challenges
3. Try different payloads for each
4. Show which ones work
5. Display any flags found
6. Provide a summary

**Expected Output:**
- 13 total tests
- Each test shows ✅ or ❌
- Flags like `FLAG{sql_injection_bypass_123}` shown in output
- Summary showing pass rate

---

## If Something Goes Wrong

### The app won't start?
In Terminal 1, run:
```bash
python3 diagnose_vulnerable.py
```
This will show you what's wrong.

### Missing Python packages?
Run:
```bash
pip3 install flask flask-sqlalchemy requests
python3 start_vulnerable_app.py
```

### Still having issues?
1. Delete old database: `rm vulnerable.db`
2. Make sure you're in the right directory: `pwd` should show `/home/kali/Cyberrange`
3. Try again with the startup script

---

## Quick Checklist

- [ ] Terminal 1: Started `python3 start_vulnerable_app.py`
- [ ] Sees "✅ STARTUP SUCCESSFUL" message
- [ ] Terminal 2: Started `python3 full_test.py`
- [ ] Test output shows tests running
- [ ] See flags in the output
- [ ] See summary at the end

---

## What to Report Back

Once you run the tests, please share:

1. **Did the app start successfully?** (yes/no)
2. **Did the tests run?** (yes/no)
3. **How many tests passed?** (number out of 13)
4. **Did you see any flags?** (yes/no, which ones?)
5. **Any error messages?** (paste the text)

---

## Success = You See This

```
======================================================================
TEST SUMMARY
======================================================================

Total Tests: 13
Passed: 13
Failed: 0
Success Rate: 100.0%

Detailed Results:
------
SQLi:
  ✅ Classic OR injection
     → FLAG{sql_injection_bypass_123}
  ✅ Admin bypass with comment
     → FLAG{sql_injection_bypass_123}
  ✅ OR on both fields
     → FLAG{sql_injection_bypass_123}
  ✅ Comment block
     → FLAG{sql_injection_bypass_123}

XSS:
  ✅ Script injection
     → FLAG{xss_reflected_456}
  ...and more...

Command Injection:
  ✅ Semicolon injection
     → FLAG{command_injection_789}
  ...and more...

Path Traversal:
  ✅ Simple traversal
     → FLAG{path_traversal_234}
  ...and more...

API Auth Bypass:
  ✅ SQLi in API
     → FLAG{auth_bypass_success_789}
  ✅ SQLi password
     → FLAG{auth_bypass_success_789}

======================================================================
Testing complete!
======================================================================
```

---

## Commands at a Glance

```bash
# Terminal 1
cd ~/Cyberrange
git pull origin main
python3 start_vulnerable_app.py

# Terminal 2 (new window)
cd ~/Cyberrange
python3 full_test.py
```

That's it! Run these and let me know what happens. 🚀
