# Kali Linux Cyber Range Deployment Guide

## 🐉 Why Kali Linux for Cyber Range?

Kali Linux is the **perfect choice** for your cyber range because:

✅ **Pre-installed Security Tools**: nmap, sqlmap, burpsuite, metasploit, nikto, dirb  
✅ **Penetration Testing Environment**: Industry-standard platform  
✅ **Real-world Experience**: Same tools used by security professionals  
✅ **Complete Toolkit**: Everything needed for cybersecurity challenges  
✅ **Linux Command Line**: Better for system security and privilege escalation  

## 📥 Download Kali Linux

**Option 1: Pre-built VM (Recommended)**
- Download from: https://www.kali.org/get-kali/#kali-virtual-machines
- Choose VirtualBox or VMware version
- Username: `kali` / Password: `kali`

**Option 2: Fresh Installation**
- Download ISO from: https://www.kali.org/get-kali/#kali-installer-images
- Create new VM and install from ISO

## ⚙️ VM Configuration

**Minimum Requirements:**
- **RAM**: 6GB (8GB recommended)
- **Storage**: 30GB minimum
- **Processors**: 2-4 cores
- **Network**: NAT or Host-only

**VirtualBox Settings:**
```
Memory: 6144 MB (6GB)
Processors: 2-4 cores
Storage: 30GB dynamic
Network: NAT (for internet) or Host-only (isolated)
```

## 🚀 Deployment Steps

### Step 1: Prepare Kali VM
1. Start your Kali Linux VM
2. Open terminal
3. Update system:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

### Step 2: Transfer Cyber Range Package
1. Copy `CyberRange_VM_Package.zip` to Kali VM
2. Extract the package:
   ```bash
   unzip CyberRange_VM_Package.zip
   cd offline_deployment
   ```

### Step 3: Run Setup Script
```bash
# Make script executable
chmod +x vm_setup.sh

# Run setup (installs dependencies)
./vm_setup.sh

# Install Python packages
pip3 install -r requirements.txt
```

### Step 4: Start Cyber Range
```bash
# Start the application
python3 offline_app.py
```

### Step 5: Access Web Interface
- Open Firefox in Kali
- Go to: http://localhost:5000
- Login: **admin** / **admin123**

## 🛠️ Integration with Kali Tools

Your cyber range challenges can now use Kali's built-in tools:

**Network Reconnaissance Challenge:**
```bash
# Use nmap for port scanning
nmap -sS -O target_ip

# Use nikto for web vulnerability scanning
nikto -h http://target_ip
```

**Web Exploitation Challenge:**
```bash
# Use sqlmap for SQL injection
sqlmap -u "http://target/login.php" --data="user=admin&pass=test"

# Use dirb for directory enumeration
dirb http://target_ip
```

**Privilege Escalation Challenge:**
```bash
# Use LinEnum for enumeration
./LinEnum.sh

# Check for SUID binaries
find / -perm -u=s -type f 2>/dev/null
```

## 🌐 Network Configuration

**For Isolated Environment:**
1. Set VM network to "Host-only"
2. Cyber range accessible only from host machine
3. Perfect for safe penetration testing practice

**For Internet Access:**
1. Set VM network to "NAT"
2. Can download additional tools if needed
3. Update Kali packages: `sudo apt update && sudo apt upgrade`

## 🎯 Educational Benefits

**Realistic Learning Environment:**
- Same tools used in professional penetration testing
- Authentic command-line experience
- Industry-standard workflow

**Hands-on Practice:**
- Real vulnerability scanning
- Actual exploitation techniques
- Professional-grade tools

**Career Preparation:**
- OSCP exam preparation
- Penetration testing skills
- Cybersecurity tool proficiency

## 🔧 Troubleshooting

**If Python packages fail to install:**
```bash
sudo apt install python3-dev python3-pip
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

**If web interface doesn't load:**
```bash
# Check if port 5000 is available
netstat -tulpn | grep 5000

# Try different port
python3 offline_app.py --port 8080
```

**Memory issues:**
- Increase VM RAM to 8GB
- Close unnecessary applications
- Use lightweight desktop environment

## 📋 Quick Commands Reference

```bash
# Start cyber range
cd /opt/cyberrange/offline_deployment
python3 offline_app.py

# Access tools
nmap --help
sqlmap --help
metasploit

# System monitoring
htop
netstat -tulpn
ps aux
```

## 🎉 You're Ready!

Your Kali Linux cyber range is now set up with:
- Professional penetration testing environment
- All security tools pre-installed
- Offline cyber range web interface
- Real-world cybersecurity challenges

Perfect for your final year project demonstration!
