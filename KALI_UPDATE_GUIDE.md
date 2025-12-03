# How to Update CyberRange Repository in Kali Linux

## Prerequisites

Before starting, ensure you have:
- Git installed: `sudo apt update && sudo apt install -y git`
- Python 3.8+: `python3 --version`
- Internet connection
- Terminal access with sudo privileges

---

## Step 1: Navigate to Your Repository

```bash
cd ~/CyberRange
# or wherever you cloned it
```

## Step 2: Check Current Status

```bash
git status
```

This shows:
- Current branch
- Any local changes
- Whether you're ahead/behind origin

## Step 3: Pull Latest Updates from GitHub

### Option A: Simple Pull (Recommended)

```bash
git pull origin main
```

This will:
- Fetch latest changes from GitHub
- Merge them into your local main branch
- Update all files automatically

### Option B: Fetch Then Review Before Merging

```bash
# Fetch without applying changes
git fetch origin

# Review what changed
git log main..origin/main

# Then merge
git merge origin/main
```

---

## Step 4: Update Virtual Environment & Dependencies

After pulling, update Python packages:

```bash
# Activate virtual environment
source venv/bin/activate

# Upgrade pip
python3 -m pip install --upgrade pip

# Install/update requirements
pip install -r requirements.txt
```

## Step 5: Reinitialize Database (If Needed)

If there are database changes, reinitialize:

```bash
# Activate venv first
source venv/bin/activate

# Backup old database
cp instance/cyber_range.db instance/cyber_range.db.backup

# Reinitialize
python3 init_challenges.py

# Populate guides
python3 populate_challenge_guides.py
```

## Step 6: Verify Everything Works

```bash
# Check database
python3 -c "import sqlite3; conn = sqlite3.connect('instance/cyber_range.db'); c = conn.cursor(); c.execute('SELECT COUNT(*) FROM challenge'); print(f'Challenges: {c.fetchone()[0]}'); conn.close()"

# Start the app
python3 app.py
```

Then open browser: `http://localhost:5000`

---

## Using the Automated Deployment Script

The fastest way to update everything:

```bash
# Make script executable
chmod +x deploy/kali_deploy.sh

# Run deployment (handles everything automatically)
sudo ./deploy/kali_deploy.sh
```

This will:
- ✅ Update system packages
- ✅ Recreate virtual environment
- ✅ Install latest dependencies
- ✅ Reinitialize database
- ✅ Populate guides
- ✅ Start the application

---

## Common Update Scenarios

### Scenario 1: Just Pull Changes (No Local Changes)

```bash
cd ~/CyberRange
git pull origin main
```

### Scenario 2: You Made Local Changes

If you made changes but want the latest from GitHub:

```bash
# Option 1: Keep your changes (merge)
git pull origin main

# Option 2: Discard your changes (use GitHub version)
git fetch origin
git reset --hard origin/main
```

### Scenario 3: Update Specific Files Only

```bash
# Update deployment script only
git checkout origin/main -- deploy/kali_deploy.sh

# Update app.py only
git checkout origin/main -- app.py
```

### Scenario 4: See What Changed Before Updating

```bash
# See what's different
git diff main origin/main

# See which files changed
git diff --name-only main origin/main

# Then pull
git pull origin main
```

---

## Step-by-Step: Complete Update Process

### Full Update (Recommended)

```bash
# 1. Navigate to repo
cd ~/CyberRange

# 2. Check status
git status

# 3. Pull latest changes
git pull origin main

# 4. Activate virtual environment
source venv/bin/activate

# 5. Update dependencies
pip install -r requirements.txt --upgrade

# 6. Reinitialize database
python3 init_challenges.py
python3 populate_challenge_guides.py

# 7. Start application
python3 app.py

# 8. Test in browser
# Open: http://localhost:5000
```

### Using Deployment Script (Faster)

```bash
cd ~/CyberRange
chmod +x deploy/kali_deploy.sh
sudo ./deploy/kali_deploy.sh
```

---

## Useful Git Commands for Updates

```bash
# See update history
git log --oneline -5

# See what's new on GitHub
git fetch origin
git log main..origin/main

# See changes in a specific file
git diff main origin/main -- app.py

# Check remote URL
git remote -v

# Update repository URL (if changed)
git remote set-url origin https://github.com/SuhasKoparde/Cyberrange.git

# See current branch
git branch -a

# Switch to different branch
git checkout develop

# Pull from different branch
git pull origin develop
```

---

## Troubleshooting Update Issues

### Issue 1: "Permission Denied" When Running Script

```bash
# Fix permissions
chmod +x deploy/kali_deploy.sh

# Then run
sudo ./deploy/kali_deploy.sh
```

### Issue 2: Merge Conflicts

If you have conflicting local changes:

```bash
# See conflicts
git status

# Resolve manually, then:
git add .
git commit -m "Resolved merge conflicts"
```

### Issue 3: Virtual Environment Issues

```bash
# Remove old environment
rm -rf venv

# Create new one
python3 -m venv venv

# Activate
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### Issue 4: Database Lock Error

```bash
# Remove database to reinitialize
rm instance/cyber_range.db

# Then reinitialize
python3 init_challenges.py
python3 populate_challenge_guides.py
```

### Issue 5: Port Already in Use

```bash
# Find what's using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use different port in app.py
# Change: app.run(host='0.0.0.0', port=5001)
```

---

## Automated Daily Updates (Optional)

Create a cron job to auto-update:

```bash
# Edit crontab
crontab -e

# Add this line (updates daily at 2 AM):
0 2 * * * cd ~/CyberRange && git pull origin main > /tmp/cyberrange_update.log 2>&1

# Then reinstall packages:
0 2 * * * cd ~/CyberRange && source venv/bin/activate && pip install -r requirements.txt >> /tmp/cyberrange_update.log 2>&1
```

---

## Quick Reference: Update Commands

```bash
# Quick update (pull + restart)
cd ~/CyberRange && git pull origin main && python3 app.py

# Full update (pull + dependencies + database)
cd ~/CyberRange && git pull origin main && source venv/bin/activate && pip install -r requirements.txt && python3 init_challenges.py && python3 app.py

# Using deployment script (recommended)
cd ~/CyberRange && sudo ./deploy/kali_deploy.sh

# Check if updates available
cd ~/CyberRange && git fetch origin && git log main..origin/main
```

---

## What Gets Updated

When you pull from GitHub:

| File | Updated By | What It Does |
|------|-----------|-------------|
| `app.py` | Pull | Main application logic |
| `init_challenges.py` | Pull | Database initialization |
| `populate_challenge_guides.py` | Pull | Challenge content |
| `requirements.txt` | Pull | Python dependencies |
| `deploy/kali_deploy.sh` | Pull | Deployment script |
| `venv/` | Manual | Virtual environment |
| `instance/cyber_range.db` | Manual | Database (back it up!) |

---

## Before & After Comparison

### What Gets Updated from GitHub
✅ Application code
✅ Deployment scripts
✅ Configuration
✅ Documentation

### What You Manage Locally
⚠️ Virtual environment (`venv/`)
⚠️ Database (`instance/cyber_range.db`)
⚠️ `.env` files (if any)
⚠️ Local configuration changes

---

## Safety Tips

1. **Always backup database before major updates:**
   ```bash
   cp instance/cyber_range.db instance/cyber_range.db.backup
   ```

2. **Check changes before merging:**
   ```bash
   git diff main origin/main
   ```

3. **Keep a log of updates:**
   ```bash
   git log --oneline -10
   ```

4. **Use branches for testing:**
   ```bash
   git checkout -b test-branch
   git pull origin main
   # Test changes
   git checkout main
   ```

---

## Support

If you encounter issues:

1. Check GitHub Issues: https://github.com/SuhasKoparde/Cyberrange/issues
2. Review the error message
3. Try: `git status` and `git log`
4. Reinitialize database if needed
5. Check Python version: `python3 --version`

---

## Next Steps

After updating:

1. ✅ Verify with: `python3 app.py`
2. ✅ Open: `http://localhost:5000`
3. ✅ Log in: `admin/admin123`
4. ✅ Test challenges
5. ✅ Report any issues

---

**Your CyberRange is now updated! 🚀**

Run `./deploy/kali_deploy.sh` for automated setup or manually follow the steps above.
