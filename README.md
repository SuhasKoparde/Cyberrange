<div align="center">
  <h1>🔥 Cyber Range</h1>
  <h3>Comprehensive Cybersecurity Training Platform</h3>
  
  [![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
  [![Flask](https://img.shields.io/badge/Flask-2.0%2B-green.svg)](https://flask.palletsprojects.com/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  
</div>

## 🚀 Overview

CyberRange is a comprehensive cybersecurity training platform designed to provide hands-on experience with real-world attack scenarios in a controlled, safe environment. The platform includes:

- **5+ Interactive Challenges**: SQL Injection, XSS, Command Injection, Path Traversal, Authentication Bypass
- **Vulnerable Web Application**: Deliberately vulnerable app for practicing exploitation techniques
- **Web Dashboard**: Track progress, view detailed challenge instructions, and access target systems
- **Real-World Context**: Each challenge includes real-world examples and impact scenarios
- **Comprehensive Guides**: Step-by-step walkthroughs with commands, tools, and hints

## 🎯 Features

### Challenge System
- **SQL Injection** - Login bypass and database exploitation
- **Cross-Site Scripting (XSS)** - Reflected XSS and JavaScript injection
- **Command Injection** - OS command execution through vulnerable input
- **Path Traversal** - File system access and Local File Inclusion (LFI)
- **Authentication Bypass** - API exploitation and weak auth bypass
- **Network Analysis, Privilege Escalation, Reverse Engineering, and more**

### Web Dashboard
- User authentication and progress tracking
- Detailed challenge descriptions with execution steps
- Direct links to vulnerable target applications
- Real-world use cases for each vulnerability
- Hint system for guidance
- Points and achievement system

### Security Focus
- Realistic attack scenarios
- Best practices and mitigation strategies
- Real-world breach case studies
- Tool recommendations and command examples

## 🛠️ Technology Stack

| Component      | Technology |
|---------------|-----------|
| **Backend**   | Python 3.8+, Flask, SQLAlchemy |
| **Frontend**  | HTML5, CSS3, Bootstrap 5, JavaScript |
| **Database**  | SQLite (Development) |
| **Target App**| Flask-based vulnerable web application |

## 🚀 Quick Start

### Prerequisites
- **Linux** (Kali Linux recommended) or **WSL2**
- **Python 3.8+**
- **pip** (Python package manager)
- **Git**

### Installation & Setup

#### Step 1: Clone the Repository
```bash
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange
```

#### Step 2: Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\Activate.ps1
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Initialize Database
```bash
python3 init_challenges.py
```

This command populates the database with all challenges including SQL Injection, XSS, Command Injection, Path Traversal, and Authentication Bypass scenarios.

#### Step 5: Start the Services

**Terminal 1 - Main Platform** (port 5000):
```bash
python3 app.py
```

**Terminal 2 - Vulnerable Target App** (port 8080):
```bash
python3 vulnerable_app.py
```

### Exact Commands (copy & paste)

Below are exact sequences for a clean setup. Pick the block for your environment.

- Kali / Linux (bash)

```bash
# clone and enter repo
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange

# create and activate virtualenv
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip install -r requirements.txt

# initialize challenges (creates instance/cyber_range.db)
python3 init_challenges.py

# (optional) sync flags if you edited vulnerable app flags
python3 update_flags.py

# Terminal 1: start main platform (port 5000)
python3 app.py

# Terminal 2: start vulnerable target (port 8080)
python3 vulnerable_app.py
```

- Windows (PowerShell)

```powershell
# clone and enter repo
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange

# create and activate virtualenv
python -m venv venv
.\venv\Scripts\Activate.ps1

# install dependencies
pip install -r requirements.txt

# initialize challenges (creates instance\cyber_range.db)
python init_challenges.py

# (optional) sync flags if you edited vulnerable app flags
python update_flags.py

# Terminal 1: start main platform (PowerShell)
python app.py

# Terminal 2: start vulnerable target (PowerShell)
python vulnerable_app.py
```

Notes:
- If you change flags in `vulnerable_app.py`, run `python3 update_flags.py` (or `python update_flags.py` on Windows) to sync the platform DB without deleting progress.
- To fully reset challenges and clear progress: delete `instance/cyber_range.db` and re-run `python3 init_challenges.py`.


#### Step 6: Access the Platform

Open your browser and navigate to:
```
http://localhost:5000
```

**Login Credentials:**
- **Username:** `admin`
- **Password:** `admin123`

## 🎓 How to Use

### Accessing Challenges

1. **Login to the Platform**
   - Navigate to `http://localhost:5000`
   - Use credentials: `admin` / `admin123`

2. **Browse Challenges**
   - Click on "Challenges" in the dashboard
   - Each challenge shows difficulty level, category, and points

3. **Start a Challenge**
   - Click on a challenge to view detailed instructions
   - Red button shows direct link to the vulnerable target application
   - Read the step-by-step execution guide

4. **Exploit the Vulnerability**
   - Click the target link to access the vulnerable application
   - Follow the hints and commands provided
   - Use provided tools (curl, Burp Suite, sqlmap, etc.)

5. **Capture the Flag**
   - Complete the exploitation steps
   - The flag appears when successful
   - Return to the dashboard and enter the flag to complete the challenge

## 📚 Challenge Categories

### Web Security (Primary Focus)
- **SQL Injection - Login Bypass** (Easy, 100 XP)
  - Bypass authentication using `' OR '1'='1` technique
  - Target: `http://localhost:8080/login`
  
- **Cross-Site Scripting (XSS)** (Medium, 150 XP)
  - Execute JavaScript in search functionality
  - Target: `http://localhost:8080/search`
  
- **Command Injection** (Medium, 175 XP)
  - Execute OS commands through vulnerable input
  - Target: `http://localhost:8080/ping`
  
- **Path Traversal** (Easy, 150 XP)
  - Access files outside intended directory
  - Target: `http://localhost:8080/files`
  
- **Authentication Bypass** (Medium, 200 XP)
  - Exploit weak API authentication
  - Target: `http://localhost:8080/auth-challenge`

### Additional Challenges
- Network Traffic Analysis
- Password Cracking
- Reverse Engineering
- Privilege Escalation
- SSH Brute Force
- And more...

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the project root (optional):
```env
FLASK_ENV=development
SECRET_KEY=your-secret-key
```

### Customizing Challenges
Edit `init_challenges.py` to:
- Add new challenges
- Modify existing challenge details
- Update difficulty levels and points
- Change target application URLs

## 🛡️ Important Security Notes

⚠️ **This platform contains intentionally vulnerable code for training purposes only.**

- **Do NOT use in production environments**
- **Do NOT expose to the public internet**
- **Only use on isolated lab networks**
- **Use for authorized security training and education only**
- **Respect the ethical hacking principles**

## 📝 Project Structure

```
Cyberrange/
├── app.py                    # Main Flask application
├── vulnerable_app.py         # Vulnerable target application
├── init_challenges.py        # Challenge initialization script
├── requirements.txt          # Python dependencies
├── instance/                 # Database and instance files
├── templates/                # HTML templates
│   ├── base.html
│   ├── challenge_detail.html
│   ├── challenges.html
│   └── ...
├── static_assets/            # CSS, JavaScript, images
└── vms/                       # VM configuration files
```

## 🚀 Deployment on Kali Linux

### Using the Deployment Script
```bash
chmod +x deploy/kali_deploy.sh
./deploy/kali_deploy.sh
```

### Manual Deployment
```bash
# Install system dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip python3-venv -y

# Clone and setup
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize and run
python3 init_challenges.py
python3 app.py
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000
# Kill process
kill -9 <PID>
```

### Database Errors
```bash
# Reset database
rm instance/cyber_range.db
python3 init_challenges.py
```

### Module Not Found
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Permission Denied
```bash
# Fix database permissions
sudo chown -R $USER:$USER instance/
chmod -R u+w instance/
```

## 📖 Documentation

- [Kali Linux Setup Guide](KALI_UPDATE_GUIDE.md) - Complete Linux setup
- [Vulnerable App README](VULNERABLE_APP_README.md) - Target application details
- [Contributing Guide](CODE_OF_CONDUCT.md) - Community guidelines

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Create a Pull Request

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security community for inspiration
- Kali Linux project
- Open-source contributors
- Bug reporters and testers

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on [GitHub](https://github.com/SuhasKoparde/Cyberrange/issues)
- Check existing documentation

---

<div align="center">
  <p><strong>🔒 Learn Ethical Hacking in a Safe, Controlled Environment</strong></p>
  <p>Made with ❤️ for the InfoSec Community</p>
  <p>Keep Learning. Keep Hacking. Stay Ethical.</p>
</div>







