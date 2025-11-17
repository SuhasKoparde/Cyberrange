# CyberRange - Kali Linux Deployment Commands

## Quick Start (Copy & Paste)

### 1. Clone and Deploy (Fastest Way - 3 Commands)

```bash
# Command 1: Clone the repository
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange

# Command 2: Make deployment script executable
chmod +x deploy/kali_deploy.sh

# Command 3: Run deployment (install + setup + start)
sudo ./deploy/kali_deploy.sh
```

**After 2-3 minutes, application will be running on port 8000!**

---

## Verify Deployment is Working

```bash
# Check if server is running
curl -I http://127.0.0.1:8000
# Expected output: HTTP/1.1 200 OK

# Or open in browser
# http://localhost:8000
# Login: admin / admin123
```

---

## Full Manual Setup (Step-by-Step)

If you prefer to set up manually instead of using the script:

### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Dependencies
```bash
sudo apt install -y python3-pip python3-venv git build-essential python3-dev libpq-dev
```

### Step 3: Clone Repository
```bash
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange
```

### Step 4: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Install Python Packages
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 6: Initialize Database
```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
python3 populate_challenge_guides.py
```

### Step 7: Start Application with Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

**Application is now running on http://localhost:8000**

---

## Run as Background Service (Systemd)

### Option 1: Using the Provided Service File

```bash
# Copy the service file
sudo cp deploy/cyberrange.service /etc/systemd/system/cyberrange.service

# Edit to set your username and paths
sudo nano /etc/systemd/system/cyberrange.service
```

Update these lines:
```ini
User=YOUR_USERNAME                    # Change to your username
WorkingDirectory=/home/YOUR_USERNAME/Cyberrange    # Update path
```

Then enable and start:
```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable to auto-start on boot
sudo systemctl enable cyberrange

# Start the service
sudo systemctl start cyberrange

# Check status
sudo systemctl status cyberrange
```

### Option 2: Create New Service File

```bash
# Create service file
sudo tee /etc/systemd/system/cyberrange.service > /dev/null << EOF
[Unit]
Description=CyberRange Security Training Platform
After=network.target

[Service]
Type=notify
User=$USER
WorkingDirectory=$HOME/Cyberrange
ExecStart=$HOME/Cyberrange/venv/bin/gunicorn -w 4 -b 0.0.0.0:8000 app:app
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable cyberrange
sudo systemctl start cyberrange
```

### Check Service Logs
```bash
# View real-time logs
sudo journalctl -u cyberrange -f

# View last 50 lines
sudo journalctl -u cyberrange -n 50
```

---

## Setup Nginx Reverse Proxy (Optional but Recommended)

### Install Nginx
```bash
sudo apt install -y nginx
sudo systemctl enable nginx
```

### Configure Nginx
```bash
# Create config file
sudo tee /etc/nginx/sites-available/cyberrange > /dev/null << 'EOF'
upstream cyberrange_app {
    server 127.0.0.1:8000;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location / {
        proxy_pass http://cyberrange_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/cyberrange /etc/nginx/sites-enabled/cyberrange
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

### Access via Nginx
```bash
# Now accessible on port 80 instead of 8000
curl -I http://127.0.0.1
http://localhost
# Login: admin / admin123
```

---

## Important Commands Reference

### Start/Stop Service
```bash
sudo systemctl start cyberrange      # Start the service
sudo systemctl stop cyberrange       # Stop the service
sudo systemctl restart cyberrange    # Restart the service
sudo systemctl status cyberrange     # Check status
```

### Check Ports
```bash
# Check if port 8000 is in use
sudo lsof -i :8000

# Check if port 80 is in use
sudo lsof -i :80

# Check all listening ports
sudo netstat -tlnp
```

### View Application Logs
```bash
# If running with screen/tmux
screen -r cyberrange

# If running as service
sudo journalctl -u cyberrange -f

# Check Flask debug output
# (if you ran it without gunicorn)
ps aux | grep app.py
```

### Restart Application
```bash
# If running as service
sudo systemctl restart cyberrange

# If running manually
# Press Ctrl+C then restart
```

### Update Application
```bash
cd ~/Cyberrange
git pull origin main
sudo systemctl restart cyberrange
```

---

## Available Challenges (All with 4,700+ Word Guides)

Each challenge includes:
- ✅ 15+ Step-by-Step Instructions
- ✅ Copy-Paste Ready Commands
- ✅ Real-World Attack Scenarios
- ✅ Prevention Methods
- ✅ Detailed Explanations

### Challenge List:
1. **SQL Injection Mastery** (4,761 words)
   - Login bypass, UNION queries, blind injection, automation
   
2. **XSS (Cross-Site Scripting)** (5,720 words)
   - Stored XSS, Reflected XSS, cookie stealing, BeEF framework
   
3. **Network Reconnaissance** (5,537 words)
   - Port scanning, service enumeration, Nmap scripting, DNS enumeration
   
4. **Man-in-the-Middle Attack** (4,872 words)
   - ARP spoofing, traffic interception, SSL stripping, DNS poisoning
   
5. **Privilege Escalation** (5,207 words)
   - Sudo abuse, SUID exploitation, kernel exploits, cron manipulation
   
6. **Windows Privilege Escalation** (5,376 words)
   - UAC bypass, token impersonation, unquoted paths, DLL hijacking

---

## Troubleshooting

### Port Already in Use
```bash
# Find what's using port 8000
sudo lsof -i :8000

# Kill the process
sudo kill -9 <PID>

# Or change port in gunicorn command
gunicorn -w 4 -b 0.0.0.0:9000 app:app
```

### Permission Denied
```bash
# Make sure script is executable
chmod +x deploy/kali_deploy.sh

# Run with sudo if needed
sudo ./deploy/kali_deploy.sh
```

### Virtual Environment Not Activating
```bash
# If source command doesn't work, try:
. venv/bin/activate

# Or for bash specifically:
bash -c "source venv/bin/activate && python app.py"
```

### Database Errors
```bash
# Recreate database
rm instance/cyber_range.db
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
python3 populate_challenge_guides.py
```

### Application Not Responding
```bash
# Check if port is listening
netstat -tlnp | grep 8000

# Check service status
sudo systemctl status cyberrange

# Restart service
sudo systemctl restart cyberrange

# View logs
sudo journalctl -u cyberrange -n 100
```

---

## Security Notes

⚠️ **For Production:**
- Change default admin password: `admin123` → strong password
- Use HTTPS/TLS with Nginx (add SSL certificate)
- Configure firewall to allow only necessary ports
- Run behind NAT/VPN for internet exposure
- Keep system and packages updated
- Use PostgreSQL instead of SQLite for scaling

---

## Performance Tips

**For Better Performance:**
```bash
# Use multiple Gunicorn workers
gunicorn -w 8 -b 0.0.0.0:8000 app:app

# Enable Nginx caching
# Add to Nginx config:
# proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m;
# proxy_cache my_cache;
```

---

## Need Help?

- 📖 Full documentation: [GitHub README](https://github.com/SuhasKoparde/Cyberrange#readme)
- 🐛 Report issues: [GitHub Issues](https://github.com/SuhasKoparde/Cyberrange/issues)
- 💬 Questions: Open a discussion on GitHub

---

**Last Updated:** November 17, 2025  
**Project:** CyberRange v1.0  
**Repository:** https://github.com/SuhasKoparde/Cyberrange
