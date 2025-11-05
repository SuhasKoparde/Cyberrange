from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import subprocess
import psutil
from datetime import datetime

app = Flask(__name__)

# Serve static assets locally
@app.route('/static/<path:filename>')
def static_files(filename):
    return app.send_static_file(filename)
app.config['SECRET_KEY'] = 'cyber-range-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyber_range.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    points = db.Column(db.Integer, default=100)
    vm_name = db.Column(db.String(100))
    target_ip = db.Column(db.String(15))
    flag = db.Column(db.String(100))
    hints = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, default=0)

class VMStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='stopped')
    ip_address = db.Column(db.String(15))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    challenges = Challenge.query.all()
    user_progress = UserProgress.query.filter_by(user_id=current_user.id).all()
    completed_challenges = [p.challenge_id for p in user_progress if p.completed]
    
    vm_status = VMStatus.query.all()
    
    return render_template('dashboard.html', 
                         challenges=challenges, 
                         completed_challenges=completed_challenges,
                         vm_status=vm_status)

@app.route('/challenges')
@login_required
def challenges():
    challenges = Challenge.query.all()
    user_progress = UserProgress.query.filter_by(user_id=current_user.id).all()
    progress_dict = {p.challenge_id: p for p in user_progress}
    
    return render_template('challenges.html', 
                         challenges=challenges, 
                         progress_dict=progress_dict)

@app.route('/challenge/<int:challenge_id>')
@login_required
def challenge_detail(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    progress = UserProgress.query.filter_by(
        user_id=current_user.id, 
        challenge_id=challenge_id
    ).first()
    
    return render_template('challenge_detail.html', 
                         challenge=challenge, 
                         progress=progress)

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    challenge_id = request.form['challenge_id']
    submitted_flag = request.form['flag']
    
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'message': 'Challenge not found'})
    
    progress = UserProgress.query.filter_by(
        user_id=current_user.id, 
        challenge_id=challenge_id
    ).first()
    
    if not progress:
        progress = UserProgress(
            user_id=current_user.id,
            challenge_id=challenge_id
        )
        db.session.add(progress)
    
    progress.attempts += 1
    
    if submitted_flag.strip() == challenge.flag:
        progress.completed = True
        progress.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Congratulations! Flag accepted!'})
    else:
        db.session.commit()
        return jsonify({'success': False, 'message': 'Incorrect flag. Try again!'})

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    challenges = Challenge.query.all()
    vm_status = VMStatus.query.all()
    
    return render_template('admin.html', 
                         users=users, 
                         challenges=challenges,
                         vm_status=vm_status)

@app.route('/vm_control/<action>/<vm_name>')
@login_required
def vm_control(action, vm_name):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        if action == 'start':
            # Simulate VM start (replace with actual VM management code)
            vm = VMStatus.query.filter_by(name=vm_name).first()
            if vm:
                vm.status = 'running'
                vm.last_updated = datetime.utcnow()
                db.session.commit()
            return jsonify({'success': True, 'message': f'VM {vm_name} started'})
        
        elif action == 'stop':
            vm = VMStatus.query.filter_by(name=vm_name).first()
            if vm:
                vm.status = 'stopped'
                vm.last_updated = datetime.utcnow()
                db.session.commit()
            return jsonify({'success': True, 'message': f'VM {vm_name} stopped'})
        
        elif action == 'restart':
            vm = VMStatus.query.filter_by(name=vm_name).first()
            if vm:
                vm.status = 'restarting'
                vm.last_updated = datetime.utcnow()
                db.session.commit()
            return jsonify({'success': True, 'message': f'VM {vm_name} restarting'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/system_status')
@login_required
def system_status():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        # Use C: drive for Windows
        try:
            disk = psutil.disk_usage('C:')
        except:
            disk = psutil.disk_usage('.')
        
        return jsonify({
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory.percent, 1),
            'memory_used': memory.used // (1024**3),  # GB
            'memory_total': memory.total // (1024**3),  # GB
            'disk_percent': round(disk.percent, 1),
            'disk_used': disk.used // (1024**3),  # GB
            'disk_total': disk.total // (1024**3)  # GB
        })
    except Exception as e:
        # Return dummy data if monitoring fails
        return jsonify({
            'cpu_percent': 25.0,
            'memory_percent': 60.0,
            'memory_used': 4,
            'memory_total': 8,
            'disk_percent': 45.0,
            'disk_used': 50,
            'disk_total': 100
        })

def init_db():
    """Initialize database with sample data"""
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@cyberrange.local',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
    
    # Create sample challenges
    if not Challenge.query.first():
        challenges = [
            {
                'name': 'Basic Web Exploitation',
                'description': 'Find and exploit a simple SQL injection vulnerability',
                'difficulty': 'Easy',
                'category': 'Web Security',
                'points': 100,
                'vm_name': 'vulnerable-web',
                'target_ip': '192.168.1.10',
                'flag': 'CTF{sql_injection_basic}',
                'hints': 'Look for login forms that might not validate input properly'
            },
            {
                'name': 'Network Reconnaissance',
                'description': 'Perform network scanning and identify open services',
                'difficulty': 'Easy',
                'category': 'Network Security',
                'points': 150,
                'vm_name': 'target-server',
                'target_ip': '192.168.1.20',
                'flag': 'CTF{nmap_discovery}',
                'hints': 'Use nmap to scan for open ports and services'
            },
            {
                'name': 'Privilege Escalation',
                'description': 'Gain root access on a Linux system',
                'difficulty': 'Medium',
                'category': 'System Security',
                'points': 250,
                'vm_name': 'linux-target',
                'target_ip': '192.168.1.30',
                'flag': 'CTF{root_access_gained}',
                'hints': 'Check for SUID binaries and misconfigurations'
            },
            {
                'name': 'Password Cracking with John the Ripper',
                'description': 'Crack various password hashes using John the Ripper and advanced techniques',
                'difficulty': 'Medium',
                'category': 'Cryptography',
                'points': 300,
                'vm_name': 'kali-attacker',
                'target_ip': '192.168.1.100',
                'flag': 'CTF{john_the_ripper_master}',
                'hints': 'Use different attack modes: dictionary, brute force, and rule-based attacks'
            },
            {
                'name': 'Brute Force Attack Simulation',
                'description': 'Perform brute force attacks against SSH, HTTP, and FTP services',
                'difficulty': 'Medium',
                'category': 'Authentication Security',
                'points': 250,
                'vm_name': 'linux-target',
                'target_ip': '192.168.1.30',
                'flag': 'CTF{hydra_brute_force}',
                'hints': 'Use Hydra with custom wordlists and learn about rate limiting'
            },
            {
                'name': 'Directory Enumeration with Gobuster',
                'description': 'Discover hidden directories and files using Gobuster and similar tools',
                'difficulty': 'Easy',
                'category': 'Web Security',
                'points': 200,
                'vm_name': 'vulnerable-web',
                'target_ip': '192.168.1.10',
                'flag': 'CTF{gobuster_directory_found}',
                'hints': 'Use different wordlists and file extensions to find hidden content'
            },
            {
                'name': 'DoS Attack Simulation',
                'description': 'Simulate Denial of Service attacks using hping3 and learn mitigation',
                'difficulty': 'Hard',
                'category': 'Network Security',
                'points': 400,
                'vm_name': 'target-server',
                'target_ip': '192.168.1.20',
                'flag': 'CTF{dos_attack_successful}',
                'hints': 'Use SYN flood, UDP flood, and HTTP flood techniques responsibly'
            },
            {
                'name': 'Vulnerability Assessment',
                'description': 'Perform comprehensive vulnerability scanning using Nikto and Nmap scripts',
                'difficulty': 'Medium',
                'category': 'Vulnerability Management',
                'points': 350,
                'vm_name': 'vulnerable-web',
                'target_ip': '192.168.1.10',
                'flag': 'CTF{vuln_assessment_complete}',
                'hints': 'Use Nikto for web vulnerabilities and Nmap NSE scripts for system vulnerabilities'
            },
            {
                'name': 'Social Engineering & OSINT',
                'description': 'Gather intelligence using theHarvester and OSINT techniques',
                'difficulty': 'Medium',
                'category': 'Information Gathering',
                'points': 300,
                'vm_name': 'kali-attacker',
                'target_ip': '192.168.1.100',
                'flag': 'CTF{osint_master}',
                'hints': 'Use theHarvester, sublist3r, and manual OSINT techniques'
            },
            {
                'name': 'Wireless Security Assessment',
                'description': 'Assess wireless network security using Aircrack-ng suite',
                'difficulty': 'Hard',
                'category': 'Wireless Security',
                'points': 450,
                'vm_name': 'kali-attacker',
                'target_ip': '192.168.1.100',
                'flag': 'CTF{wireless_security_expert}',
                'hints': 'Practice WEP/WPA cracking and understand wireless attack vectors'
            }
        ]
        
        for challenge_data in challenges:
            challenge = Challenge(**challenge_data)
            db.session.add(challenge)
    
    # Create sample VM status entries
    if not VMStatus.query.first():
        vms = [
            {'name': 'vulnerable-web', 'status': 'stopped', 'ip_address': '192.168.1.10'},
            {'name': 'target-server', 'status': 'stopped', 'ip_address': '192.168.1.20'},
            {'name': 'linux-target', 'status': 'stopped', 'ip_address': '192.168.1.30'},
            {'name': 'kali-attacker', 'status': 'running', 'ip_address': '192.168.1.100'}
        ]
        
        for vm_data in vms:
            vm = VMStatus(**vm_data)
            db.session.add(vm)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
