# Cyber Range Setup Guide

## Prerequisites

### Software Requirements
- **VirtualBox** 6.1+ or VMware Workstation
- **Vagrant** 2.2+
- **Python** 3.8+
- **Git** (for cloning repositories)

### System Requirements
- **RAM**: Minimum 8GB (16GB recommended)
- **Storage**: 50GB free space
- **CPU**: Multi-core processor with virtualization support
- **Network**: Internet connection for initial setup

## Installation Steps

### 1. Install Prerequisites

#### Windows
```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install required software
choco install virtualbox vagrant python git -y
```

#### Linux (Ubuntu/Debian)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install VirtualBox
sudo apt install virtualbox virtualbox-ext-pack -y

# Install Vagrant
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vagrant -y

# Install Python and Git
sudo apt install python3 python3-pip git -y
```

### 2. Clone and Setup Project
```bash
# Clone the project
git clone <your-repo-url> CyberRange
cd CyberRange

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Configure Virtual Networks
```bash
# Create VirtualBox host-only networks
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.1.1 --netmask 255.255.255.0

# Verify network creation
VBoxManage list hostonlyifs
```

### 4. Deploy Virtual Machines

#### Option A: Deploy All VMs at Once
```bash
python scripts/vm_manager.py deploy
```

#### Option B: Deploy VMs Individually
```bash
# Deploy vulnerable web server
python scripts/vm_manager.py deploy vulnerable-web

# Deploy Linux target
python scripts/vm_manager.py deploy linux-target

# Deploy Kali attacker
python scripts/vm_manager.py deploy kali-attacker
```

### 5. Start the Web Interface
```bash
# Initialize database and start Flask app
python app.py
```

### 6. Access the System
- **Web Interface**: http://localhost:5000
- **Admin Login**: admin / admin123
- **Student Registration**: Create new account via web interface

## VM Management Commands

### Basic Operations
```bash
# Check VM status
python scripts/vm_manager.py status

# Start all VMs
python scripts/vm_manager.py start

# Stop all VMs
python scripts/vm_manager.py stop

# Restart specific VM
python scripts/vm_manager.py restart vulnerable-web
```

### Advanced Operations
```bash
# SSH into VMs
vagrant ssh  # From VM directory

# Reset entire environment
python scripts/vm_manager.py reset

# Destroy specific VM
python scripts/vm_manager.py destroy vm-name
```

## Network Configuration

### IP Address Scheme
| Component | IP Address | Purpose |
|-----------|------------|---------|
| Host System | 192.168.1.1 | Gateway/Router |
| Vulnerable Web | 192.168.1.10 | Web application testing |
| Target Server | 192.168.1.20 | Network reconnaissance |
| Linux Target | 192.168.1.30 | Privilege escalation |
| Kali Attacker | 192.168.1.100 | Attack platform |

### Firewall Rules
The network is configured with the following isolation rules:
- Lab network (192.168.1.0/24) is isolated from internet
- VMs can communicate within lab network
- Management access from host system only

## Troubleshooting

### Common Issues

#### VirtualBox Issues
```bash
# Check VirtualBox service
sudo systemctl status vboxdrv

# Reinstall VirtualBox kernel modules
sudo /sbin/vboxconfig
```

#### Vagrant Issues
```bash
# Update Vagrant boxes
vagrant box update

# Reload VM configuration
vagrant reload

# Check Vagrant status
vagrant global-status
```

#### Network Connectivity Issues
```bash
# Verify host-only networks
VBoxManage list hostonlyifs

# Check VM network settings
VBoxManage showvminfo "VM-Name" | grep NIC
```

#### Python Dependencies
```bash
# Reinstall requirements
pip install --upgrade -r requirements.txt

# Check Flask application
python -c "from app import app; print('Flask app loads successfully')"
```

### Performance Optimization

#### System Resources
- Allocate sufficient RAM to VMs (minimum 1GB each)
- Enable hardware virtualization in BIOS
- Close unnecessary applications during lab sessions

#### VM Performance
```bash
# Adjust VM memory allocation
VBoxManage modifyvm "VM-Name" --memory 2048

# Enable hardware acceleration
VBoxManage modifyvm "VM-Name" --hwvirtex on --vtxvpid on
```

## Security Considerations

### Host System Protection
- Keep host system updated and patched
- Use antivirus software
- Monitor VM network traffic
- Regularly backup VM snapshots

### Lab Environment Isolation
- Verify network isolation before starting exercises
- Monitor for any unexpected external connections
- Use snapshots to restore clean VM states

## Backup and Recovery

### VM Snapshots
```bash
# Create snapshot
VBoxManage snapshot "VM-Name" take "snapshot-name"

# Restore snapshot
VBoxManage snapshot "VM-Name" restore "snapshot-name"

# List snapshots
VBoxManage snapshot "VM-Name" list
```

### Configuration Backup
```bash
# Backup VM configurations
cp -r ~/.VirtualBox/Machines/ ~/vm-backup/

# Backup Vagrant configurations
tar -czf vagrant-backup.tar.gz vms/
```

## Monitoring and Logging

### Start Monitoring System
```bash
# Start security monitoring
python monitoring/log_monitor.py &

# View monitoring logs
tail -f cyber_range_monitor.log
```

### Log Locations
- **Application Logs**: `cyber_range_monitor.log`
- **VM Logs**: `~/.VirtualBox/Machines/*/Logs/`
- **Vagrant Logs**: Use `vagrant up --debug`

## Support and Documentation

### Getting Help
- Check troubleshooting section above
- Review VM-specific Vagrantfiles for configuration details
- Consult VirtualBox and Vagrant documentation
- Create GitHub issues for project-specific problems

### Additional Resources
- [VirtualBox Documentation](https://www.virtualbox.org/wiki/Documentation)
- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Cybersecurity Learning Resources](https://www.cybrary.it/)

## Academic Usage Notes

This cyber range is designed for educational purposes and should be used in accordance with your institution's IT policies and applicable laws. Always ensure proper authorization before conducting security testing activities.
