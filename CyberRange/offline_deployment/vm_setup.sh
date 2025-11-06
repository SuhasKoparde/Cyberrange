#!/bin/bash
# Kali Linux VM Setup Script for Cyber Range

echo "Setting up Cyber Range on Kali Linux..."

# Update Kali repositories
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies (usually already available in Kali)
sudo apt install -y python3 python3-pip python3-venv python3-dev

# Install additional development tools
sudo apt install -y git curl wget unzip build-essential

# Install useful penetration testing tools (if not already present)
sudo apt install -y nmap sqlmap burpsuite metasploit-framework

# Create cyber range user (optional - can use kali user)
if ! id "cyberrange" &>/dev/null; then
    sudo useradd -m -s /bin/bash cyberrange
    sudo usermod -aG sudo cyberrange
    echo "Created cyberrange user"
else
    echo "Using existing kali user"
fi

# Set up cyber range directory
sudo mkdir -p /opt/cyberrange
sudo chown $USER:$USER /opt/cyberrange

# Install Python packages globally for easier access
sudo pip3 install --upgrade pip

echo "[SUCCESS] Kali Linux VM setup complete!"
echo "Copy the offline_deployment folder to /opt/cyberrange/"
echo "Then run: cd /opt/cyberrange/offline_deployment && python3 offline_app.py"
echo "Access: http://localhost:5000 (admin/admin123)"
