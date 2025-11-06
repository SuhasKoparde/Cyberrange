# 🚀 Quick Start Guide - Cyber Range

## Prerequisites Installation (Do This First!)

### 1. Install Python
- Go to https://www.python.org/downloads/
- Download Python 3.8 or newer
- **IMPORTANT**: Check "Add Python to PATH" during installation
- Restart your computer after installation

### 2. Install VirtualBox
- Go to https://www.virtualbox.org/wiki/Downloads
- Download "Windows hosts" version
- Install with default settings

### 3. Install Vagrant
- Go to https://www.vagrantup.com/downloads
- Download Windows 64-bit version
- Install and restart your computer

## Quick Setup Commands

After installing the prerequisites, open PowerShell as Administrator and run these commands:

```powershell
# Navigate to project directory
cd C:\Users\SUSHIL\CascadeProjects\CyberRange

# Install Python dependencies
pip install -r requirements.txt

# Check if everything is installed correctly
python --version
vagrant --version
VBoxManage --version
```

## Option 1: Quick Demo (Web Interface Only)
If you want to see the web interface without VMs:

```powershell
# Start the web application
python app.py
```

Then open your browser to: http://localhost:5000
- Login with: admin / admin123

## Option 2: Full Setup (With Virtual Machines)
For the complete cyber range experience:

```powershell
# Check prerequisites
python scripts/vm_manager.py check

# Deploy all VMs (this will take 20-30 minutes)
python scripts/vm_manager.py deploy

# Start the web application
python app.py
```

## Troubleshooting

### If Python is not recognized:
1. Reinstall Python with "Add to PATH" checked
2. Restart PowerShell
3. Try `py` instead of `python`

### If VirtualBox issues:
1. Enable virtualization in BIOS
2. Disable Hyper-V if enabled
3. Run PowerShell as Administrator

### If Vagrant issues:
1. Restart computer after installation
2. Check Windows Defender/Antivirus isn't blocking

## What You'll Get

### Web Interface Features:
- Dashboard with system monitoring
- Challenge management system
- Progress tracking
- Admin panel for VM control

### Virtual Machines:
- **Vulnerable Web Server** (192.168.1.10) - For web security testing
- **Linux Target** (192.168.1.30) - For privilege escalation
- **Kali Attacker** (192.168.1.100) - Pre-loaded with security tools

### Challenges:
1. **SQL Injection** - Web application security
2. **Network Reconnaissance** - Information gathering
3. **Privilege Escalation** - System security

## Next Steps After Setup:
1. Access web interface at http://localhost:5000
2. Create student accounts or use admin account
3. Start with the "Basic Web Exploitation" challenge
4. Use the monitoring dashboard to track activities

## Need Help?
- Check the full setup guide: `docs/setup_guide.md`
- Review project documentation: `docs/project_report.md`
- Check VM status: `python scripts/vm_manager.py status`
