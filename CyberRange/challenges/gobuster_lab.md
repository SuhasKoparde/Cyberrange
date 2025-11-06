# Gobuster Directory Enumeration Lab

## Basic Directory Enumeration

### Common Directories
```bash
# Basic directory scan
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt

# With status codes
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307,403"

# Verbose output
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -v

# Save results
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -o results.txt
```

### File Extension Discovery
```bash
# Common web files
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js,css

# Backup files
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,tmp

# Configuration files
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x conf,config,ini,xml,json

# Archive files
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -x zip,tar,gz,rar
```

## Advanced Techniques

### Custom Wordlists
```bash
# Admin directories
gobuster dir -u http://192.168.1.10 -w admin_dirs.txt

# Technology-specific
gobuster dir -u http://192.168.1.10 -w php_dirs.txt -x php

# Combined wordlists
cat /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt > combined.txt
gobuster dir -u http://192.168.1.10 -w combined.txt
```

### Performance Tuning
```bash
# Increase threads
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt -t 50

# Add delays (stealth)
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt --delay 100ms

# Timeout settings
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt --timeout 10s
```

## Subdomain Enumeration

### DNS Enumeration
```bash
# Basic subdomain scan
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt

# With custom resolvers
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt -r 8.8.8.8,1.1.1.1

# Wildcard detection
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt --wildcard
```

## Custom Wordlists

### admin_dirs.txt
```
admin
administrator
admin_panel
control_panel
cpanel
dashboard
manage
manager
management
backend
admin_area
admin_login
admin_console
webadmin
sysadmin
admincp
admins
admin123
```

### backup_files.txt
```
backup
backups
bak
old
tmp
temp
archive
archives
dump
dumps
sql
database
db_backup
site_backup
web_backup
config_backup
```

### common_files.txt
```
index
home
main
default
login
admin
config
settings
about
contact
search
upload
download
test
demo
example
sample
```

## Alternative Tools

### Dirb Usage
```bash
# Basic dirb scan
dirb http://192.168.1.10

# Custom wordlist
dirb http://192.168.1.10 /usr/share/wordlists/dirb/common.txt

# File extensions
dirb http://192.168.1.10 -X .php,.html,.txt

# Save results
dirb http://192.168.1.10 -o dirb_results.txt
```

### Dirbuster (GUI)
```bash
# Launch dirbuster
dirbuster

# Command line version
java -jar DirBuster-1.0-RC1.jar -H -u http://192.168.1.10 -l /usr/share/wordlists/dirb/common.txt
```

## Stealth Techniques

### Avoiding Detection
```bash
# Slow scan with delays
gobuster dir -u http://192.168.1.10 -w wordlist.txt --delay 500ms -t 1

# Custom User-Agent
gobuster dir -u http://192.168.1.10 -w wordlist.txt -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Random User-Agents
gobuster dir -u http://192.168.1.10 -w wordlist.txt --random-agent

# Proxy through Tor
gobuster dir -u http://192.168.1.10 -w wordlist.txt --proxy socks5://127.0.0.1:9050
```

### HTTP Headers
```bash
# Custom headers
gobuster dir -u http://192.168.1.10 -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1"

# Authentication
gobuster dir -u http://192.168.1.10 -w wordlist.txt -U username -P password

# Cookies
gobuster dir -u http://192.168.1.10 -w wordlist.txt -c "PHPSESSID=abc123"
```

## Results Analysis

### Interesting Findings
```bash
# Filter by status codes
grep "Status: 200" results.txt

# Look for admin panels
grep -i "admin" results.txt

# Find configuration files
grep -E "\.(conf|config|ini|xml)$" results.txt

# Backup files
grep -E "\.(bak|backup|old|tmp)$" results.txt
```

### Manual Verification
```bash
# Check found directories
curl -I http://192.168.1.10/admin/

# Download interesting files
wget http://192.168.1.10/config.php.bak

# Check permissions
curl -X OPTIONS http://192.168.1.10/admin/
```

## Integration with Other Tools

### Nmap Integration
```bash
# HTTP enumeration script
nmap --script http-enum 192.168.1.10

# Directory traversal
nmap --script http-dir-traversal 192.168.1.10

# Common web apps
nmap --script http-wordpress-enum 192.168.1.10
```

### Nikto Integration
```bash
# Web vulnerability scan
nikto -h http://192.168.1.10

# Specific directories
nikto -h http://192.168.1.10/admin/

# Custom ports
nikto -h http://192.168.1.10:8080
```

## Defense and Mitigation

### Server Configuration
```apache
# Apache .htaccess
<Files "*.bak">
    Order allow,deny
    Deny from all
</Files>

<Files "*.backup">
    Order allow,deny
    Deny from all
</Files>

# Block directory listing
Options -Indexes
```

### Nginx Configuration
```nginx
# Block sensitive files
location ~* \.(bak|backup|old|tmp)$ {
    deny all;
    return 404;
}

# Block admin access
location /admin {
    allow 192.168.1.0/24;
    deny all;
}
```

### Monitoring
```bash
# Monitor access logs
tail -f /var/log/apache2/access.log | grep -E "(40[0-9]|50[0-9])"

# Detect scanning
grep -E "(dirb|gobuster|dirbuster)" /var/log/apache2/access.log

# Rate limiting detection
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -10
```

## Challenge Objectives

### Learning Goals
1. Understand directory enumeration techniques
2. Learn to use various enumeration tools
3. Practice stealth and evasion techniques
4. Analyze and interpret results
5. Implement proper defenses

### Flag Locations
- Hidden admin panel: `/admin_secret/flag.txt`
- Backup file: `/config.php.bak` (contains database credentials)
- Development directory: `/dev/test/flag.php`
- Archive file: `/backups/site_backup.zip`
