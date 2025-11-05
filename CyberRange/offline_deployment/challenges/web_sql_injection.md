# Challenge: Basic Web Exploitation - SQL Injection

## Objective
Find and exploit a SQL injection vulnerability in the vulnerable web application to retrieve sensitive information.

## Target Information
- **Target IP**: 192.168.1.10
- **Target Service**: HTTP (Port 80)
- **Application**: DVWA (Damn Vulnerable Web Application)

## Challenge Description
The target web server is running a vulnerable web application with multiple security flaws. Your task is to identify and exploit a SQL injection vulnerability to extract sensitive data from the database.

## Learning Objectives
- Understand SQL injection attack vectors
- Learn to identify vulnerable input fields
- Practice manual SQL injection techniques
- Understand the impact of SQL injection vulnerabilities

## Hints
1. Look for login forms or search functionality
2. Try common SQL injection payloads like `' OR 1=1 --`
3. Use tools like Burp Suite to intercept and modify requests
4. The DVWA application has different security levels - start with "Low"

## Tools Needed
- Web browser
- Burp Suite (optional)
- SQLmap (for advanced testing)

## Step-by-Step Guide

### Step 1: Reconnaissance
```bash
# Scan the target for open ports
nmap -sV 192.168.1.10

# Check for web directories
dirb http://192.168.1.10/
```

### Step 2: Application Analysis
1. Navigate to `http://192.168.1.10/DVWA/`
2. Login with default credentials: `admin:password`
3. Set security level to "Low" in DVWA Security settings
4. Navigate to SQL Injection section

### Step 3: Vulnerability Testing
1. Try entering normal input first
2. Test with single quote `'` to see if it causes an error
3. Try basic SQL injection payloads:
   - `1' OR '1'='1`
   - `1' UNION SELECT null,null--`

### Step 4: Data Extraction
1. Determine number of columns using UNION SELECT
2. Identify data types for each column
3. Extract sensitive information from database tables

## Expected Results
- Successfully bypass authentication or extract data
- Understand the underlying SQL query structure
- Identify the root cause of the vulnerability

## Flag Location
The flag can be found by extracting data from the users table in the database.

## Remediation
- Use prepared statements/parameterized queries
- Implement input validation and sanitization
- Apply principle of least privilege to database accounts
- Use web application firewalls (WAF)

## Difficulty: Easy
**Points**: 100
**Estimated Time**: 30-45 minutes
