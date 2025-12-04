# Vulnerable Web Application Setup

This is a deliberately vulnerable web application for cybersecurity training on the CyberRange platform.

## Features

- **SQL Injection Challenge**: Vulnerable login form that allows SQL injection attacks
- **XSS Challenge**: Reflected XSS vulnerability in the search functionality
- **Admin Panel**: Protected admin area that can only be accessed after successful exploitation

## Quick Start

### On Kali Linux:

1. Copy `vulnerable_app.py` to Kali in the `/home/kali/Cyberrange/` directory

2. Install dependencies (if not already installed):
```bash
pip install flask flask-sqlalchemy
```

3. Run the vulnerable application in a new terminal:
```bash
cd /home/kali/Cyberrange
python3 vulnerable_app.py
```

4. The application will run on:
   - Local access: `http://localhost:8080`
   - Network access: `http://10.0.2.7:8080`

## Challenges

### Challenge 1: SQL Injection - Login Bypass

**Objective**: Bypass the login form using SQL injection to access the admin account

**Target**: `http://localhost:8080/login` or `http://10.0.2.7:8080/login`

**Payloads to try**:
- Username: `' OR '1'='1` (Password: anything)
- Username: `admin'--` (Password: anything)
- Username: `' OR "1"="1"--` (Password: anything)

**Expected Result**: 
- You'll see the admin profile with the flag: `FLAG{sql_injection_bypass_123}`

### Challenge 2: Cross-Site Scripting (XSS)

**Objective**: Execute JavaScript code in the search functionality

**Target**: `http://localhost:8080/search?q=<payload>`

**Payloads to try**:
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert(1)>`

**Expected Result**: 
- JavaScript alert box appears in your browser

## Database

The application uses SQLite with the following test users:
- **admin** / **admin123** (Admin account with flag access)
- **user1** / **password123** (Regular user)
- **user2** / **pass456** (Regular user)

## Security Warning

⚠️ **This application is intentionally vulnerable and insecure!**

- It contains SQL injection vulnerabilities
- It reflects user input without escaping (XSS)
- It uses weak session management
- **DO NOT use this in production**
- **Only use for authorized training and educational purposes**

## Integration with CyberRange

Once running, update your CyberRange challenges to point to this vulnerable app:

- SQL Injection Challenge target: `http://10.0.2.7:8080/login`
- XSS Challenge target: `http://10.0.2.7:8080/search`

## Troubleshooting

**Port 8080 already in use?**
```bash
python3 vulnerable_app.py  # Change port in the script if needed
```

**Module not found error?**
```bash
pip install flask flask-sqlalchemy
```

**Permission denied?**
```bash
chmod +x vulnerable_app.py
```

