# Kali Linux VM Deployment Guide

## Recommended: Kali Linux VM (Best for Cyber Range)
1. **Download Kali Linux VM**: 
   - Get from: https://www.kali.org/get-kali/#kali-virtual-machines
   - Or install fresh Kali Linux ISO

2. **VM Configuration**:
   - **RAM**: 6GB minimum, 8GB recommended
   - **Storage**: 30GB minimum (Kali needs more space)
   - **Network**: NAT or Host-only for isolated environment
   - **Processors**: 2-4 cores recommended

3. **Setup Steps**:
   ```bash
   # Copy offline_deployment folder to Kali VM
   # Make setup script executable
   chmod +x vm_setup.sh
   
   # Run setup script
   ./vm_setup.sh
   
   # Install Python dependencies
   cd offline_deployment
   pip3 install -r requirements.txt
   
   # Start cyber range
   python3 offline_app.py
   ```

## Alternative: Windows VM
1. Create Windows 10/11 VM with 4GB+ RAM
2. Install Python 3.8+ from https://www.python.org/downloads/
3. Copy `offline_deployment` folder to VM
4. Run `setup.bat` to install dependencies
5. Run `start.bat` to launch cyber range

## Why Kali Linux is Better for Cyber Range:
✅ **Pre-installed Security Tools**: nmap, sqlmap, burpsuite, metasploit
✅ **Penetration Testing Environment**: Perfect for hands-on challenges
✅ **Linux Command Line**: Better for system security challenges
✅ **Network Tools**: Built-in tools for network reconnaissance
✅ **Authentic Experience**: Real-world penetration testing environment

## Access:
- **URL**: http://localhost:5000 (or VM_IP:5000)
- **Username**: admin
- **Password**: admin123

## Features Available Offline:
✅ Web dashboard and interface
✅ User authentication and management
✅ 3 cybersecurity challenges with real-world scenarios
✅ System monitoring and metrics
✅ Progress tracking and scoring
✅ Admin panel for management
✅ Integration with Kali's security tools

## Kali Linux Advantages:
- **Realistic Environment**: Same tools used by security professionals
- **Challenge Integration**: Can use built-in tools for challenges
- **Educational Value**: Learn industry-standard tools
- **Complete Toolkit**: Everything needed for penetration testing

## Note:
This offline version works perfectly on Kali Linux and provides an authentic
cybersecurity learning environment with all necessary tools pre-installed.
