#!/usr/bin/env python3
"""
Offline Cyber Range Setup Script
Creates a portable, self-contained cyber range deployment
"""

import os
import sys
import shutil
import subprocess
import json
from pathlib import Path

class OfflineCyberRange:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.offline_dir = self.project_root / "offline_deployment"
        self.static_assets = self.project_root / "static_assets"
        
    def create_offline_package(self):
        """Create offline deployment package"""
        print("🚀 Creating offline cyber range package...")
        
        # Create directories
        self.offline_dir.mkdir(exist_ok=True)
        self.static_assets.mkdir(exist_ok=True)
        
        # Download and cache external dependencies
        self.download_static_assets()
        
        # Modify templates for offline use
        self.modify_templates_offline()
        
        # Create portable Python environment setup
        self.create_portable_setup()
        
        # Create VM deployment scripts
        self.create_vm_scripts()
        
        print("✅ Offline package created successfully!")
        print(f"📁 Package location: {self.offline_dir}")
        
    def download_static_assets(self):
        """Download external assets for offline use"""
        print("📦 Downloading static assets...")
        
        assets = {
            "bootstrap.min.css": "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css",
            "bootstrap.bundle.min.js": "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js",
            "fontawesome.min.css": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css",
            "jquery.min.js": "https://code.jquery.com/jquery-3.6.0.min.js",
            "chart.min.js": "https://cdn.jsdelivr.net/npm/chart.js"
        }
        
        try:
            import requests
            for filename, url in assets.items():
                asset_path = self.static_assets / filename
                if not asset_path.exists():
                    print(f"  Downloading {filename}...")
                    response = requests.get(url)
                    with open(asset_path, 'w', encoding='utf-8') as f:
                        f.write(response.text)
        except ImportError:
            print("⚠️  requests not available, creating fallback assets...")
            self.create_fallback_assets()
            
    def create_fallback_assets(self):
        """Create minimal fallback assets"""
        # Create minimal CSS
        minimal_css = """
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: rgba(255,255,255,0.1); padding: 20px; margin: 10px 0; border-radius: 10px; }
        .btn { padding: 10px 20px; background: #e94560; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #d63447; }
        .navbar { background: #16213e; padding: 15px; margin-bottom: 20px; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; background: #0f3460; }
        """
        
        with open(self.static_assets / "bootstrap.min.css", 'w') as f:
            f.write(minimal_css)
            
        # Create minimal JS
        minimal_js = """
        // Minimal JavaScript for offline functionality
        function updateSystemMetrics() {
            fetch('/system_status')
                .then(response => response.json())
                .then(data => console.log('System status updated'))
                .catch(error => console.log('Offline mode - using cached data'));
        }
        """
        
        with open(self.static_assets / "bootstrap.bundle.min.js", 'w') as f:
            f.write(minimal_js)
            
        # Create empty files for other assets
        for asset in ["fontawesome.min.css", "jquery.min.js", "chart.min.js"]:
            with open(self.static_assets / asset, 'w') as f:
                f.write("/* Offline fallback */")
    
    def modify_templates_offline(self):
        """Modify templates to use local assets"""
        print("🔧 Modifying templates for offline use...")
        
        # Read base template
        base_template = self.project_root / "templates" / "base.html"
        if base_template.exists():
            with open(base_template, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Replace CDN links with local assets
            replacements = {
                'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css': '/static/bootstrap.min.css',
                'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css': '/static/fontawesome.min.css',
                'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js': '/static/bootstrap.bundle.min.js',
                'https://code.jquery.com/jquery-3.6.0.min.js': '/static/jquery.min.js',
                'https://cdn.jsdelivr.net/npm/chart.js': '/static/chart.min.js'
            }
            
            for old_url, new_url in replacements.items():
                content = content.replace(old_url, new_url)
            
            # Save offline version
            offline_templates = self.offline_dir / "templates"
            offline_templates.mkdir(exist_ok=True)
            
            with open(offline_templates / "base.html", 'w', encoding='utf-8') as f:
                f.write(content)
                
            # Copy other templates
            for template_file in (self.project_root / "templates").glob("*.html"):
                if template_file.name != "base.html":
                    shutil.copy2(template_file, offline_templates)
    
    def create_portable_setup(self):
        """Create portable setup scripts"""
        print("📦 Creating portable setup...")
        
        # Create requirements for offline install
        offline_requirements = """Flask==2.3.3
Flask-SQLAlchemy==3.0.5
Flask-Login==0.6.3
Flask-WTF==1.1.1
WTForms==3.0.1
Werkzeug==2.3.7
Jinja2==3.1.2
psutil==5.9.5
bcrypt==4.0.1
"""
        
        with open(self.offline_dir / "requirements.txt", 'w') as f:
            f.write(offline_requirements)
        
        # Create offline app.py
        self.create_offline_app()
        
        # Create setup script
        setup_script = """@echo off
echo Installing Offline Cyber Range...
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found, installing dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Installation complete!
echo.
echo To start the cyber range:
echo   python offline_app.py
echo.
echo Then open your browser to: http://localhost:5000
echo Login: admin / admin123
echo.
pause
"""
        
        with open(self.offline_dir / "setup.bat", 'w', encoding='utf-8') as f:
            f.write(setup_script)
            
        # Create start script
        start_script = """@echo off
echo Starting Offline Cyber Range...
echo.
echo Opening browser to http://localhost:5000
echo Login: admin / admin123
echo.
echo Press Ctrl+C to stop the server
echo.

start http://localhost:5000
python offline_app.py
"""
        
        with open(self.offline_dir / "start.bat", 'w', encoding='utf-8') as f:
            f.write(start_script)
    
    def create_offline_app(self):
        """Create offline version of app.py"""
        print("Creating offline application...")
        
        # Read original app.py
        with open(self.project_root / "app.py", 'r', encoding='utf-8') as f:
            app_content = f.read()
        
        # Modify for offline use
        offline_app_content = app_content.replace(
            "app = Flask(__name__)",
            """app = Flask(__name__)

# Serve static assets locally
@app.route('/static/<path:filename>')
def static_files(filename):
    return app.send_static_file(filename)"""
        )
        
        with open(self.offline_dir / "offline_app.py", 'w', encoding='utf-8') as f:
            f.write(offline_app_content)
        
        # Copy static assets to Flask static directory
        static_dir = self.offline_dir / "static"
        static_dir.mkdir(exist_ok=True)
        
        for asset_file in self.static_assets.glob("*"):
            shutil.copy2(asset_file, static_dir)
        
        # Copy database and other files
        for file_to_copy in ["instance", "monitoring", "scripts", "challenges", "docs"]:
            src_path = self.project_root / file_to_copy
            if src_path.exists():
                if src_path.is_dir():
                    shutil.copytree(src_path, self.offline_dir / file_to_copy, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, self.offline_dir)
    
    def create_vm_scripts(self):
        """Create VM deployment scripts"""
        print("Creating VM deployment scripts...")
        
        vm_setup = """#!/bin/bash
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
"""
        
        with open(self.offline_dir / "vm_setup.sh", 'w', encoding='utf-8', newline='\n') as f:
            f.write(vm_setup)
        
        # Create VM deployment guide
        vm_guide = """# Kali Linux VM Deployment Guide

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
"""
        
        with open(self.offline_dir / "VM_DEPLOYMENT.md", 'w', encoding='utf-8') as f:
            f.write(vm_guide)

def main():
    """Main function"""
    print("Cyber Range Offline Packager")
    print("=" * 50)
    
    packager = OfflineCyberRange()
    packager.create_offline_package()
    
    print("\n[SUCCESS] Offline package created successfully!")
    print(f"Location: {packager.offline_dir}")
    print("\nNext steps:")
    print("1. Copy the 'offline_deployment' folder to your VM")
    print("2. Run setup.bat (Windows) or follow VM_DEPLOYMENT.md (Linux)")
    print("3. Start the cyber range with start.bat or python offline_app.py")
    print("\nAccess: http://localhost:5000 (admin/admin123)")

if __name__ == "__main__":
    main()
