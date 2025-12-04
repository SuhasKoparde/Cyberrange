# How to Test the Vulnerable Application

This guide explains how to test all the challenge payloads and verify that flags are displaying correctly.

## Quick Start (3 Steps)

### Step 1: Pull Latest Code
On Kali, run:
```bash
cd ~/Cyberrange
git pull origin main
```

### Step 2: Start the Vulnerable App (Terminal 1)
Open a terminal and run:
```bash
cd ~/Cyberrange
python3 start_vulnerable_app.py
```

You should see:
```
✅ STARTUP SUCCESSFUL
✅ Vulnerable app is running on http://localhost:8080/
```

**Leave this terminal running!**

### Step 3: Run Tests (Terminal 2)
Open a second terminal and run:
```bash
cd ~/Cyberrange
python3 full_test.py
```

This will automatically:
- Wait for the app to start
- Test all 5 challenges with their payloads
- Show which payloads work
- Display any flags that appear
- Provide a summary report

## Tools Provided

### 1. `diagnose_vulnerable.py` - Check What's Wrong
Use this first if the app won't start:
```bash
python3 diagnose_vulnerable.py
```

This will:
- Check Python version and dependencies
- Try to start the app and show any errors
- Verify the database is created properly
- Identify missing packages

### 2. `start_vulnerable_app.py` - Start App with Monitoring
Start the app with detailed startup output:
```bash
python3 start_vulnerable_app.py
```

This will:
- Check all dependencies
- Remove old database to force fresh initialization
- Start the app and show all startup messages
- Monitor if database is created successfully
- Show any errors in real-time

### 3. `full_test.py` - Comprehensive Payload Testing
Run all payload tests against the vulnerable app:
```bash
python3 full_test.py
```

Tests include:
- **Challenge 1 (SQLi)**: Multiple SQL injection bypass payloads
- **Challenge 2 (XSS)**: Script injection and reflection tests
- **Challenge 3 (Command Injection)**: Semicolon, pipe, AND injections
- **Challenge 4 (Path Traversal)**: Directory traversal attempts
- **Challenge 5 (API Auth)**: JSON API authentication bypass

Each test shows:
- ✅ if the payload worked
- 🚩 the flag if displayed
- ❌ if the payload failed

## Expected Results

When working correctly, you should see flags like:

- SQLi: `FLAG{sql_injection_bypass_123}`
- XSS: `FLAG{xss_reflected_456}`
- Command Injection: `FLAG{command_injection_789}`
- Path Traversal: `FLAG{path_traversal_234}`
- Auth Bypass: `FLAG{auth_bypass_success_789}`

## Troubleshooting

### App won't start?
```bash
python3 diagnose_vulnerable.py
```
This will show you exactly what's wrong.

### Still getting errors?
1. Delete the old database: `rm vulnerable.db`
2. Make sure dependencies are installed: `pip3 install flask flask-sqlalchemy requests`
3. Try starting the app directly: `python3 vulnerable_app.py`

### Payloads not working?
1. Check the app started successfully (should create `vulnerable.db`)
2. Check the database has users: `sqlite3 vulnerable.db "SELECT * FROM users;"`
3. Verify the app is running on localhost:8080: `curl http://localhost:8080/`

## What Happens Inside

When you run the tests:

1. **App Startup**: 
   - SQLAlchemy creates vulnerable.db if it doesn't exist
   - Sample users are inserted (admin, user1, user2)
   
2. **Payload Testing**:
   - Each payload is sent to the vulnerable endpoint
   - Response is checked for the flag string
   - Results are collected and summarized

3. **Results**:
   - Summary shows pass/fail for each test
   - Failed tests indicate issues with either:
     - The vulnerability implementation
     - The flag display logic
     - Network/connectivity

## Next Steps

Once all tests are passing and you see flags:

1. You can test in a browser: `http://localhost:8080/`
2. Manually try different payloads
3. Try more advanced variations
4. Challenge students to find more ways to exploit each vulnerability

Good luck! 🚀
