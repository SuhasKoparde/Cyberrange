# Challenge: Network Reconnaissance

## Objective
Perform comprehensive network scanning and service enumeration to identify open services and potential attack vectors on the target system.

## Target Information
- **Target IP**: 192.168.1.20
- **Network Range**: 192.168.1.0/24
- **Challenge Type**: Information Gathering

## Challenge Description
You have been given access to a network segment containing various systems. Your task is to perform thorough reconnaissance to identify active hosts, open ports, running services, and potential vulnerabilities.

## Learning Objectives
- Master network scanning techniques using Nmap
- Understand service enumeration and fingerprinting
- Learn to identify potential attack vectors
- Practice systematic reconnaissance methodology

## Tools Required
- Nmap
- Netcat
- Telnet
- Web browser

## Methodology

### Phase 1: Network Discovery
```bash
# Ping sweep to identify live hosts
nmap -sn 192.168.1.0/24

# Alternative host discovery
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "64 bytes" & done
```

### Phase 2: Port Scanning
```bash
# TCP SYN scan for common ports
nmap -sS 192.168.1.20

# Full TCP port scan
nmap -p- 192.168.1.20

# UDP scan for common services
nmap -sU --top-ports 100 192.168.1.20
```

### Phase 3: Service Enumeration
```bash
# Service version detection
nmap -sV 192.168.1.20

# OS detection
nmap -O 192.168.1.20

# Aggressive scan with scripts
nmap -A 192.168.1.20

# Specific service enumeration
nmap --script=http-enum 192.168.1.20
nmap --script=smb-enum-shares 192.168.1.20
```

### Phase 4: Manual Verification
```bash
# Test HTTP service
curl -I http://192.168.1.20

# Test FTP service
ftp 192.168.1.20

# Test SSH service
ssh 192.168.1.20

# Banner grabbing with netcat
nc 192.168.1.20 80
nc 192.168.1.20 22
```

## Expected Findings
You should discover several services running on the target:
- HTTP web server (Port 80)
- SSH service (Port 22)
- FTP service (Port 21)
- Telnet service (Port 23)
- SMB shares (Port 445)

## Flag Discovery
The flag is hidden in one of the service banners or can be found through proper enumeration of the discovered services.

## Advanced Techniques
```bash
# Script scanning for vulnerabilities
nmap --script vuln 192.168.1.20

# Timing templates for stealth
nmap -T2 192.168.1.20  # Polite scan
nmap -T4 192.168.1.20  # Aggressive scan

# Firewall evasion techniques
nmap -f 192.168.1.20   # Fragment packets
nmap -D RND:10 192.168.1.20  # Decoy scan
```

## Documentation Template
Create a reconnaissance report including:
1. **Executive Summary**
2. **Methodology Used**
3. **Live Hosts Discovered**
4. **Open Ports and Services**
5. **Potential Vulnerabilities**
6. **Recommendations**

## Common Pitfalls
- Scanning too aggressively and triggering IDS
- Missing UDP services
- Not following up on interesting findings
- Inadequate documentation

## Remediation Advice
- Implement network segmentation
- Use firewalls to restrict unnecessary services
- Keep services updated and patched
- Implement intrusion detection systems
- Use fail2ban for brute force protection

## Difficulty: Easy
**Points**: 150
**Estimated Time**: 45-60 minutes

## Success Criteria
- Identify at least 4 open services
- Document service versions
- Find the hidden flag
- Create a professional reconnaissance report
