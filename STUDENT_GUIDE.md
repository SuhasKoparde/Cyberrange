# 🎓 CyberRange Student Learning Guide

Welcome to the CyberRange platform! This guide will help you understand how to use the system and learn cybersecurity through hands-on challenges.

## 📋 Table of Contents
1. [Getting Started](#getting-started)
2. [Challenge Categories](#challenge-categories)
3. [How to Solve Challenges](#how-to-solve-challenges)
4. [Tools and Commands Reference](#tools-and-commands-reference)
5. [Common Issues and Solutions](#common-issues-and-solutions)
6. [Learning Path](#learning-path)
7. [Best Practices](#best-practices)

---

## 🚀 Getting Started

### System Requirements
- **OS**: Linux (Kali Linux recommended), macOS, or Windows with WSL2
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB free space
- **Network**: Internet connection (for some challenges)

### First Login
1. Open the CyberRange application (default: `http://localhost:5000`)
2. Login with provided credentials
3. Navigate to the Challenges section
4. Choose a difficulty level to start with

### Dashboard Overview
- **Home**: Quick stats and progress overview
- **Challenges**: All available security challenges
- **Dashboard**: Your learning progress and statistics
- **Security Tools**: Integrated security tools reference

---

## 📚 Challenge Categories

### 1. **Web Security** 🌐
Focuses on web application vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication Bypass

**Tools You'll Need:**
- Browser Developer Tools (F12)
- Burp Suite
- OWASP ZAP
- SQLmap

### 2. **Network Security** 🔒
Covers network-level attacks and analysis:
- Password Cracking
- SSH Brute Force
- Network Traffic Analysis
- Packet Capture Analysis

**Tools You'll Need:**
- Wireshark
- Nmap
- Hydra
- TCPdump

### 3. **System Security** 💻
Focuses on operating system vulnerabilities:
- Privilege Escalation
- File Permissions
- Service Exploitation
- Kernel Exploits

**Tools You'll Need:**
- Linux command-line tools
- GTFOBins
- LinPEAS
- GDB

### 4. **Cryptography** 🔐
Involves cryptographic vulnerabilities:
- Password Hashing
- Symmetric Encryption
- Asymmetric Encryption
- Hash Functions

**Tools You'll Need:**
- Hashcat
- John the Ripper
- OpenSSL
- Python (PyCryptodome)

### 5. **Digital Forensics** 🔍
Focuses on investigation and analysis:
- File Recovery
- Memory Forensics
- Log Analysis
- Timeline Reconstruction

**Tools You'll Need:**
- Autopsy
- Foremost
- Sleuth Kit
- strings, hexdump

### 6. **Reverse Engineering** 🔬
Analyzing compiled code:
- Binary Analysis
- Disassembly
- Debugging
- Code Patching

**Tools You'll Need:**
- Ghidra
- IDA Pro (paid)
- Radare2
- GDB
- Hopper

### 7. **Exploit Development** 💣
Creating and understanding exploits:
- Buffer Overflow
- Return-Oriented Programming (ROP)
- Format String Attacks
- Heap Exploitation

**Tools You'll Need:**
- GDB with GEF/PEDA
- Pwntools
- ROPgadget
- msfvenom

---

## ✅ How to Solve Challenges

### Step-by-Step Process

#### 1. **Read & Understand** 📖
- Read the challenge description carefully
- Understand what vulnerability is being demonstrated
- Note the learning objectives

#### 2. **Review Real-World Impact** 🌍
- Learn about actual incidents involving this vulnerability
- Understand why this matters in cybersecurity
- Connect theory to practice

#### 3. **Follow Execution Guide** 🎯
- Read the "Step-by-Step Execution Guide" section
- Each step explains what to do and why
- Take notes on new concepts

#### 4. **Use Commands Reference** 💻
- Copy commands from the provided examples
- Click the copy button (📋) on code blocks
- Paste into your terminal
- Run each command carefully

#### 5. **Analyze Results** 🔍
- Observe the output
- Compare with expected results
- Debug if something goes wrong

#### 6. **Use Hints if Stuck** 💡
- Hints are available in collapsible sections
- They provide direction without spoiling
- Progressive hints from general to specific

#### 7. **Submit Flag** 🚩
- Once you find the flag, enter it in the submission box
- Flags are typically in format: `FLAG{key_words}`
- Receive points upon successful submission

---

## 🛠️ Tools and Commands Reference

### Web Security Tools

#### Burp Suite
```bash
# Start Burp Suite (GUI)
burpsuite

# Common workflow:
# 1. Set browser proxy to localhost:8080
# 2. Browse target application
# 3. Analyze requests in Proxy tab
# 4. Use Scanner for automated checks
# 5. Intruder for parameter fuzzing
```

#### SQLmap
```bash
# Basic SQL injection test
sqlmap -u "http://target.com/page.php?id=1" -p id

# Advanced options
sqlmap -u "http://target.com/login" --data "user=test&pass=test" \
  --dbs --level=5 --risk=3

# Extract data
sqlmap -u "http://target.com/page.php?id=1" -D database -T table --dump
```

#### OWASP ZAP
```bash
# Start ZAP from command line
zaproxy

# Automated scanning
zaproxy -cmd -quickurl http://target.com -quickout report.html
```

### Network Security Tools

#### Nmap - Port Scanning
```bash
# Simple scan
nmap target.com

# Detailed scan with version detection
nmap -sV -sC -A target.com

# UDP port scan
nmap -sU target.com

# OS detection
nmap -O target.com

# Aggressive scan (takes longer)
nmap -A -T4 target.com
```

#### Hydra - Password Cracking
```bash
# SSH brute force
hydra -l username -P /path/to/wordlist.txt ssh://target.com

# HTTP basic auth
hydra -l admin -P passwords.txt http-basic://target.com

# FTP brute force
hydra -l ftp_user -P passwords.txt ftp://target.com

# With parallelization
hydra -l admin -P wordlist.txt -t 16 http://target.com
```

#### Wireshark - Network Analysis
```bash
# Open pcap file
wireshark capture.pcap

# Command line analysis
tshark -r capture.pcap -Y "http.request"

# Filter HTTP traffic
# Filter: http or http.request or http.response

# Follow TCP stream
# Right-click packet > Follow > TCP Stream
```

### System Security Tools

#### Linux Enumeration
```bash
# Basic information
uname -a
id
whoami
pwd

# File permissions issues
find / -perm -4000 -type f 2>/dev/null  # SUID binaries
find / -perm -2000 -type f 2>/dev/null  # SGID binaries
find / -writable -type f 2>/dev/null     # World-writable files

# Sudo permissions
sudo -l
sudo -l -U username

# Cron jobs
crontab -l
ls -la /etc/cron.d/
```

#### GTFOBins - Binary Exploitation
```bash
# Online database of exploitable binaries
# https://gtfobins.github.io/

# Example: vim privilege escalation
sudo vim -c '!sh'

# Example: find with SUID
find . -exec /bin/sh \; -quit
```

#### LinPEAS - Automated Enumeration
```bash
# Download and run
curl https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Look for red flags and warnings
```

### Cryptography Tools

#### Hashcat - GPU Password Cracking
```bash
# Identify hash type
hashcat --help | grep -i md5

# Dictionary attack
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Brute force (4 character lowercase)
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a

# Show cracked passwords
hashcat -m 0 hashes.txt --show
```

#### John the Ripper
```bash
# Dictionary attack
john --wordlist=/path/to/wordlist.txt hashes.txt

# Specific format
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt

# Show results
john hashes.txt --show

# Incremental mode (slow)
john --incremental hashes.txt
```

### Forensics Tools

#### Foremost - File Recovery
```bash
# Basic file recovery
foremost -i disk.img -o output_folder/

# Recover specific file type
foremost -i disk.img -t jpg,png -o output_folder/

# Verbose output
foremost -v -i disk.img -o output_folder/
```

#### Binwalk - Firmware Analysis
```bash
# Search for embedded files
binwalk image.bin

# Extract files
binwalk -e image.bin

# Entropy analysis
binwalk -E image.bin
```

### Reverse Engineering Tools

#### GDB - GNU Debugger
```bash
# Start debugging
gdb ./binary

# Common GDB commands:
(gdb) run                    # Run program
(gdb) break main             # Set breakpoint at main
(gdb) disassemble main       # Show assembly code
(gdb) step                   # Step into
(gdb) next                   # Step over
(gdb) continue               # Continue execution
(gdb) print $rax             # Print register value
(gdb) info registers         # Show all registers
```

#### Ghidra - Reverse Engineering Tool
```bash
# Start Ghidra
ghidra

# Workflow:
# 1. File > New Project
# 2. Drag binary into project
# 3. Double-click to analyze
# 4. View assembly in Listing window
# 5. Rename functions and variables
# 6. Use decompiler to view C code
```

#### Strings - Extract ASCII Strings
```bash
# Find all strings in binary
strings binary | less

# Search for specific string
strings binary | grep flag

# Export strings to file
strings binary > strings.txt
```

---

## ❌ Common Issues and Solutions

### Issue 1: Command Not Found
**Problem:** `command: command not found`

**Solutions:**
1. Install the missing tool: `apt install tool-name`
2. Check if it's in your PATH: `which toolname`
3. Use full path: `/usr/bin/toolname`

### Issue 2: Permission Denied
**Problem:** `Permission denied`

**Solutions:**
1. Use sudo: `sudo command`
2. Make executable: `chmod +x file.sh`
3. Check file permissions: `ls -la filename`

### Issue 3: Connection Refused
**Problem:** `Connection refused`

**Solutions:**
1. Check if target is running: `ping target_ip`
2. Check port is open: `nmap -p port target_ip`
3. Verify correct IP/port: `netstat -tuln`

### Issue 4: No Internet Access
**Problem:** Cannot reach external resources

**Solutions:**
1. Check network connectivity: `ping 8.8.8.8`
2. Check DNS: `nslookup google.com`
3. Use offline wordlists: `/usr/share/wordlists/`

### Issue 5: Out of Memory
**Problem:** Tool crashes due to memory limits

**Solutions:**
1. Reduce target size
2. Use lighter tools
3. Increase VM RAM
4. Process in chunks

---

## 🎯 Learning Path

### Recommended Challenge Order

#### **Beginner Level** (Start here!)
1. **SQL Injection - Login Bypass** (Easy)
   - Learn: Basic SQL syntax, injection techniques
   - Time: 20-30 minutes
   - Points: 100

2. **Cross-Site Scripting (XSS)** (Medium)
   - Learn: JavaScript, browser security, payload crafting
   - Time: 30-40 minutes
   - Points: 150

3. **Network Traffic Analysis** (Medium)
   - Learn: Packet analysis, protocol understanding
   - Time: 30-40 minutes
   - Points: 200

#### **Intermediate Level**
4. **Password Cracking** (Hard)
   - Learn: Hashing, rainbow tables, wordlist attacks
   - Time: 40-50 minutes
   - Points: 250

5. **Privilege Escalation** (Hard)
   - Learn: File permissions, SUID, kernel exploits
   - Time: 50-60 minutes
   - Points: 300

6. **File Recovery (Forensics)** (Medium)
   - Learn: File systems, data recovery, carving
   - Time: 40-50 minutes
   - Points: 175

#### **Advanced Level**
7. **Reverse Engineering** (Hard)
   - Learn: Assembly, disassembly, debugging
   - Time: 60-90 minutes
   - Points: 275

8. **WAF Bypass** (Hard)
   - Learn: Filter evasion, encoding techniques
   - Time: 50-60 minutes
   - Points: 225

9. **SSH Brute Force** (Medium)
   - Learn: Authentication, credential testing
   - Time: 30-40 minutes
   - Points: 175

#### **Expert Level**
10. **Buffer Overflow** (Expert)
    - Learn: Memory layout, exploitation, shellcode
    - Time: 120+ minutes
    - Points: 400

---

## 💡 Best Practices

### 1. **Take Notes**
- Document commands and their purposes
- Create personal cheat sheets
- Note new concepts learned

### 2. **Search for Help**
- Read error messages carefully
- Google the error message
- Check tool documentation
- Ask on security forums

### 3. **Try Different Approaches**
- If stuck, try a different tool
- Look for alternative payload formats
- Modify parameters and test again

### 4. **Understand, Don't Memorize**
- Learn WHY the attack works
- Understand the underlying concepts
- Think about real-world implications

### 5. **Practice Safely**
- Only use on authorized targets
- Never use skills for illegal purposes
- Follow all applicable laws and policies

### 6. **Keep Learning**
- Complete challenges multiple times
- Try to solve without hints
- Research related vulnerabilities
- Follow cybersecurity news

### 7. **Share Knowledge**
- Help other students
- Explain solutions in your own words
- Write about what you learned
- Contribute to documentation

---

## 📞 Getting Help

### Resources
- **Man Pages**: `man command_name`
- **Tool Help**: `command_name --help`
- **Search Engines**: Google, DuckDuckGo
- **Forums**: Stack Overflow, Security.SE
- **Communities**: Reddit r/cybersecurity, Discord servers
- **Official Docs**: Tool documentation websites

### When Asking for Help
1. Explain the problem clearly
2. Show the commands you ran
3. Include full error messages
4. Describe what you've already tried
5. Provide context about the challenge

---

## 🏆 Scoring and Achievement

### Point System
- **Easy**: 50-100 points
- **Medium**: 150-200 points
- **Hard**: 225-300 points
- **Expert**: 350-400 points

### Leaderboard
- Rankings update in real-time
- Based on total points earned
- Bonus for completing without hints
- Special badges for achievements

---

## ⚠️ Important Reminders

1. **Always Follow Laws**: These skills should only be used legally and ethically
2. **Respect Privacy**: Never target systems you don't own/have permission for
3. **Document Learning**: Keep records of what you learn
4. **Ask Questions**: No question is too basic, everyone starts somewhere
5. **Enjoy the Process**: Cybersecurity is challenging but rewarding

---

## 🎓 Glossary of Terms

**Flag**: The secret string you submit to complete a challenge (e.g., `FLAG{secret}`)

**Vulnerability**: A weakness in a system that can be exploited

**Exploit**: Code or technique used to leverage a vulnerability

**Payload**: The malicious code or data sent to trigger an exploit

**Privilege Escalation**: Gaining higher access levels on a system

**Reverse Shell**: Remote access shell with interactive command execution

**Shellcode**: Assembly code that provides a shell on the target system

**Wordlist**: Dictionary of passwords used in brute force attacks

**Packet Capture (PCAP)**: Recorded network traffic for analysis

**Hash**: One-way cryptographic function of data

---

## 📅 Challenge Completion Checklist

Before submitting a challenge:
- [ ] I understand the vulnerability being tested
- [ ] I know why the attack works
- [ ] I can explain it in simple terms
- [ ] I've tried at least one alternative approach
- [ ] I've documented the commands used
- [ ] I'm ready to move to the next challenge

---

**Happy Learning! 🎉**

Remember: Security is a journey, not a destination. Each challenge teaches valuable skills that will make you a better cybersecurity professional.

Good luck! 🚀
