# Kali Linux Setup Guide for Cyber Range

This guide will help you set up and run the Cyber Range project on Kali Linux in an offline environment.

## Prerequisites

- Kali Linux (2023.3 or later recommended)
- Python 3.8+
- pip (Python package manager)
- Git (for initial setup)
- Required system packages

## Initial Setup (Online - One Time)

### 1. Install Required System Packages
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv git
```

### 2. Clone the Repository
```bash
git clone https://github.com/SuhasKoparde/Cyberrange.git
cd Cyberrange
```

## Offline Setup

### 1. Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies (Using Local Requirements)
```bash
# If you have the requirements.txt file
pip install --no-index --find-links=/path/to/offline/packages -r requirements.txt

# Or if you have a local wheelhouse
pip install --no-index --find-links=./wheelhouse -r requirements.txt
```

### 3. Initialize the Database
```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
python3 -c "from app import init_db; init_db()"
```

## Running the Application

### 1. Start the Development Server
```bash
# Make sure you're in the project directory and virtual environment is activated
python3 app.py
```

### 2. Access the Application
Open your web browser and navigate to:
```
http://localhost:5000
```

### 3. Default Credentials
- **Admin Panel**: `http://localhost:5000/admin`
  - Username: `admin`
  - Password: `admin123`

## Creating an Offline Package

To create an offline installation package on an internet-connected machine:

### 1. Create a Wheelhouse
```bash
mkdir wheelhouse
pip wheel --wheel-dir=wheelhouse -r requirements.txt
```

### 2. Copy to Offline Machine
```bash
# Create a tarball of the project
tar -czvf cyberrange_offline.tar.gz Cyberrange wheelhouse

# Transfer to offline machine using USB or other media
```

## Troubleshooting

### Port Already in Use
If port 5000 is in use, you can specify a different port:
```bash
flask run --port=5001
```

### Database Issues
If you encounter database problems, you can reset it:
```bash
rm -f instance/cyber_range.db
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
python3 -c "from app import init_db; init_db()"
```

### Missing Dependencies
Ensure all required system packages are installed:
```bash
sudo apt install -y python3-dev default-libmysqlclient-dev build-essential
```

## Running as a Service (Optional)

To run the application as a systemd service:

1. Create a service file:
```bash
sudo nano /etc/systemd/system/cyberrange.service
```

2. Add the following content (adjust paths as needed):
```ini
[Unit]
Description=Cyber Range Application
After=network.target

[Service]
User=your_username
WorkingDirectory=/path/to/Cyberrange
ExecStart=/path/to/Cyberrange/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cyberrange
sudo systemctl start cyberrange
```

## Security Considerations

1. Change the default admin password after first login
2. Use a production WSGI server (like Gunicorn) for production deployments
3. Configure a reverse proxy (like Nginx) for better security and performance
4. Keep your Kali Linux system updated with security patches

## Support

For additional help, please open an issue on our [GitHub repository](https://github.com/SuhasKoparde/Cyberrange/issues).
