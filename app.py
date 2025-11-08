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
    how_to_execute = db.Column(db.Text, nullable=True)
    real_world_use = db.Column(db.Text, nullable=True)
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

import os
import markdown

def read_challenge_content(challenge_name):
    """Read challenge content from markdown file"""
    try:
        # Convert challenge name to filename format
        filename = challenge_name.lower().replace(' ', '_') + '.md'
        filepath = os.path.join('challenges', filename)
        
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Convert markdown to HTML
            html_content = markdown.markdown(
                content,
                extensions=[
                    'fenced_code',
                    'tables',
                    'codehilite',
                    'nl2br',
                    'sane_lists'
                ]
            )
            return html_content
    except Exception as e:
        print(f"Error reading challenge content: {str(e)}")
    
    return None

@app.route('/challenge/<int:challenge_id>')
@login_required
def challenge_detail(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    progress = UserProgress.query.filter_by(
        user_id=current_user.id, 
        challenge_id=challenge_id
    ).first()
    
    # Get challenge content from markdown file
    challenge_content = read_challenge_content(challenge.name)
    
    return render_template('challenge_detail.html', 
                         challenge=challenge, 
                         progress=progress,
                         challenge_content=challenge_content)

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

@app.route('/security-tools')
@login_required
def security_tools():
    return render_template('security_tools.html')

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    vms = VMStatus.query.all()
    return render_template('admin.html', users=users, vms=vms)

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
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Clear existing data to refresh challenges
        db.session.query(Challenge).delete()
        db.session.commit()
        
        # Sample challenges data
        challenges = [
            # Web Security Challenges
            {
                'name': 'SQL Injection Mastery',
                'description': 'Master SQL injection techniques from basic to advanced, including UNION-based, boolean-based, and time-based attacks.',
                'how_to_execute': '1. Identify input fields\n2. Test for SQL injection vulnerabilities\n3. Exploit the vulnerability to extract data\n4. Document findings and remediation steps',
                'real_world_use': 'SQL injection is one of the most common web vulnerabilities. Understanding it is crucial for securing web applications and conducting security assessments.',
                'difficulty': 'Easy',
                'category': 'Web Security',
                'points': 200,
                'vm_name': 'vulnerable-web',
                'target_ip': '192.168.1.10',
                'flag': 'CTF{sql_injection_master}',
                'hints': 'Try different SQL injection techniques like UNION-based, boolean-based, and time-based attacks.'
            },
            {
                'name': 'XSS (Cross-Site Scripting)',
                'description': 'Learn to exploit and prevent XSS vulnerabilities in web applications.',
                'how_to_execute': '1. Identify input fields\n2. Test for XSS vulnerabilities\n3. Craft payloads to steal cookies\n4. Implement protection mechanisms',
                'real_world_use': 'XSS is a common web vulnerability that can lead to account takeover and data theft.',
                'difficulty': 'Medium',
                'category': 'Web Security',
                'points': 300,
                'vm_name': 'web-app-1',
                'target_ip': '192.168.1.11',
                'flag': 'CTF{xss_mastery_achieved}',
                'hints': 'Try different contexts: HTML, JavaScript, and DOM-based XSS.'
            },
            
            # Network Security Challenges
            {
                'name': 'Network Reconnaissance',
                'description': 'Master network scanning and host discovery techniques using tools like Nmap, Masscan, and custom scripts.',
                'how_to_execute': '1. Perform host discovery\n2. Conduct port scanning\n3. Identify services and versions\n4. Document the network map',
                'real_world_use': 'Network reconnaissance is the first step in penetration testing and security assessments, helping to identify potential attack surfaces.',
                'difficulty': 'Medium',
                'category': 'Network Security',
                'points': 300,
                'vm_name': 'network-target',
                'target_ip': '192.168.1.20',
                'flag': 'CTF{network_scan_complete}',
                'hints': 'Start with host discovery, then move to port scanning. Use version detection to identify running services.'
            },
            {
                'name': 'Man-in-the-Middle Attack',
                'description': 'Learn to perform and defend against MITM attacks using ARP spoofing and SSL stripping.',
                'how_to_execute': '1. Set up network interception\n2. Perform ARP spoofing\n3. Analyze captured traffic\n4. Implement countermeasures',
                'real_world_use': 'Understanding MITM attacks is crucial for securing network communications and implementing proper encryption.',
                'difficulty': 'Hard',
                'category': 'Network Security',
                'points': 450,
                'vm_name': 'network-target-2',
                'target_ip': '192.168.1.21',
                'flag': 'CTF{mitm_prevented}',
                'hints': 'Look for unencrypted traffic and weak encryption protocols.'
            },
            
            # System Security Challenges
            {
                'name': 'Privilege Escalation',
                'description': 'Learn to escalate privileges from a standard user to root/administrator on Linux and Windows systems.',
                'how_to_execute': '1. Enumerate system information\n2. Check for misconfigurations\n3. Exploit vulnerabilities\n4. Document the escalation path',
                'real_world_use': 'Privilege escalation is a critical skill for penetration testers and system administrators to secure systems against unauthorized access.',
                'difficulty': 'Hard',
                'category': 'System Security',
                'points': 500,
                'vm_name': 'linux-target',
                'target_ip': '192.168.1.30',
                'flag': 'CTF{root_obtained}',
                'hints': 'Check for SUID binaries, kernel vulnerabilities, and misconfigured permissions.'
            },
            {
                'name': 'Windows Privilege Escalation',
                'description': 'Learn Windows privilege escalation techniques and common misconfigurations.',
                'how_to_execute': '1. Enumerate Windows system information\n2. Check for vulnerable services\n3. Exploit misconfigurations\n4. Gain SYSTEM privileges',
                'real_world_use': 'Windows privilege escalation is essential for penetration testers and security professionals assessing Windows environments.',
                'difficulty': 'Hard',
                'category': 'System Security',
                'points': 500,
                'vm_name': 'windows-target',
                'target_ip': '192.168.1.31',
                'flag': 'CTF{admin_escalated}',
                'hints': 'Check for unquoted service paths, vulnerable drivers, and weak service permissions.'
            },
            
            # Digital Forensics Challenges
            {
                'name': 'Memory Forensics',
                'description': 'Analyze memory dumps to find evidence of malicious activity and extract artifacts.',
                'how_to_execute': '1. Acquire memory dump\n2. Analyze processes and network connections\n3. Extract suspicious files\n4. Document findings',
                'real_world_use': 'Memory forensics is crucial for incident response and malware analysis.',
                'difficulty': 'Advanced',
                'category': 'Digital Forensics',
                'points': 600,
                'vm_name': 'forensics-vm',
                'target_ip': '192.168.1.40',
                'flag': 'CTF{memory_analyzed}',
                'hints': 'Look for hidden processes, injected code, and unusual network connections.'
            },
            
            # Reverse Engineering Challenges
            {
                'name': 'Malware Analysis',
                'description': 'Analyze and reverse engineer a piece of malware to understand its behavior.',
                'how_to_execute': '1. Perform static analysis\n2. Set up a safe analysis environment\n3. Conduct dynamic analysis\n4. Document the malware\'s capabilities',
                'real_world_use': 'Malware analysis is essential for developing detection signatures and understanding attack techniques.',
                'difficulty': 'Expert',
                'category': 'Reverse Engineering',
                'points': 700,
                'vm_name': 'malware-lab',
                'target_ip': '192.168.1.50',
                'flag': 'CTF{malware_reversed}',
                'hints': 'Look for anti-analysis techniques and obfuscation methods.'
            },
            
            # Cryptography Challenges
            {
                'name': 'Cryptographic Failures',
                'description': 'Exploit common cryptographic weaknesses and implementation flaws.',
                'how_to_execute': '1. Analyze the encryption scheme\n2. Identify weaknesses\n3. Develop an exploit\n4. Decrypt the flag',
                'real_world_use': 'Understanding cryptographic failures helps in implementing secure encryption and hashing.',
                'difficulty': 'Hard',
                'category': 'Cryptography',
                'points': 500,
                'vm_name': 'crypto-challenge',
                'target_ip': '192.168.1.60',
                'flag': 'CTF{crypto_cracked}',
                'hints': 'Look for weak random number generation and predictable keys.'
            },
            
            # Mobile Security Challenges
            {
                'name': 'Android App Reverse Engineering',
                'description': 'Reverse engineer an Android application to find and exploit vulnerabilities.',
                'how_to_execute': '1. Decompile the APK\n2. Analyze the code\n3. Identify vulnerabilities\n4. Exploit them to get the flag',
                'real_world_use': 'Mobile app security is crucial as mobile devices store sensitive personal and corporate data.',
                'difficulty': 'Advanced',
                'category': 'Mobile Security',
                'points': 600,
                'vm_name': 'android-lab',
                'target_ip': '192.168.1.70',
                'flag': 'CTF{android_hacked}',
                'hints': 'Check for hardcoded credentials and insecure data storage.'
            },
            
            # Cloud Security Challenges
            {
                'name': 'AWS Security Assessment',
                'description': 'Identify and exploit common misconfigurations in AWS environments.',
                'how_to_execute': '1. Enumerate AWS resources\n2. Check for misconfigurations\n3. Exploit weaknesses\n4. Document findings',
                'real_world_use': 'Cloud security is critical as more organizations migrate to cloud platforms.',
                'difficulty': 'Advanced',
                'category': 'Cloud Security',
                'points': 650,
                'vm_name': 'cloud-env',
                'target_ip': '192.168.1.80',
                'flag': 'CTF{cloud_breach}',
                'hints': 'Check for overly permissive IAM policies and exposed storage buckets.'
            }
        ]
        
        # Add challenges to database
        for challenge_data in challenges:
            challenge = Challenge(
                name=challenge_data['name'],
                description=challenge_data['description'],
                how_to_execute=challenge_data['how_to_execute'],
                real_world_use=challenge_data['real_world_use'],
                difficulty=challenge_data['difficulty'],
                category=challenge_data['category'],
                points=challenge_data['points'],
                vm_name=challenge_data['vm_name'],
                target_ip=challenge_data['target_ip'],
                flag=challenge_data['flag'],
                hints=challenge_data['hints']
            )
            db.session.add(challenge)
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@cyberrange.local',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
        
        # Commit all changes
        db.session.commit()
        print("Database initialized successfully!")

# Initialize database if this file is run directly
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
                'hints': 'Start with basic Nmap scans and gradually use more advanced options. Pay attention to service versions and potential vulnerabilities.'
            },
            {
                'name': 'Denial of Service (DoS) Lab',
                'description': 'Understand and simulate various DoS/DDoS attack vectors, including application layer and network layer attacks, along with their mitigations.',
                'how_to_execute': '1. Identify potential attack vectors in the target system\n2. Simulate different types of DoS attacks (SYN flood, HTTP flood, etc.)\n3. Monitor system resources during attacks\n4. Implement and test mitigation strategies\n5. Document the impact and effectiveness of mitigations',
                'real_world_use': 'Understanding DoS attacks is critical for:\n- Building resilient network architectures\n- Implementing effective rate limiting and traffic filtering\n- Incident response to DDoS attacks\n- Compliance with service level agreements (SLAs)\n- Capacity planning and resource allocation',
                'difficulty': 'Hard',
                'category': 'Network Security',
                'points': 450,
                'vm_name': 'target-server',
                'target_ip': '192.168.1.20',
                'flag': 'CTF{dos_mitigation_success}',
                'hints': 'Focus on different layers of the OSI model for attack vectors. Consider both network and application layer attacks.'
            },
            
            # System Security Challenges
            {
                'name': 'Privilege Escalation',
                'description': 'Escalate privileges from a low-level user to root on a Linux system by exploiting various system misconfigurations and vulnerabilities.',
                'how_to_execute': '1. Enumerate the system for potential privilege escalation vectors\n2. Check for misconfigured file permissions (SUID/SGID binaries, writable files)\n3. Look for kernel vulnerabilities and outdated software\n4. Exploit identified vulnerabilities to gain root access\n5. Document the process and suggest remediation steps',
                'real_world_use': 'Privilege escalation is essential for:\n- System hardening and security assessments\n- Identifying and fixing security misconfigurations\n- Understanding attacker techniques for blue team operations\n- Compliance with security standards (CIS Benchmarks, STIGs)\n- Security operations and incident response',
                'difficulty': 'Hard',
                'category': 'System Security',
                'points': 500,
                'vm_name': 'linux-target',
                'target_ip': '192.168.1.30',
                'flag': 'CTF{root_escalation_complete}',
                'hints': 'Check for misconfigurations in sudo rules, SUID binaries, and kernel exploits. Use tools like LinPEAS for automated enumeration.'
            },
            
            # Cryptography Challenges
            {
                'name': 'Password Cracking Techniques',
                'description': 'Learn and practice password cracking techniques using tools like John the Ripper, Hashcat, and rainbow tables.',
                'how_to_execute': '1. Identify the hash type (MD5, SHA-1, bcrypt, etc.)\n2. Choose the appropriate cracking tool and attack mode\n3. Use wordlists or generate custom password candidates\n4. Optimize cracking performance with rules and masks\n5. Analyze results and suggest stronger password policies',
                'real_world_use': 'Password cracking is important for:\n- Security assessments and penetration testing\n- Password policy evaluation and improvement\n- Digital forensics and incident response\n- Security awareness training\n- Compliance with password security standards',
                'difficulty': 'Medium',
                'category': 'Cryptography',
                'points': 400,
                'vm_name': 'kali-attacker',
                'target_ip': '192.168.1.100',
                'flag': 'CTF{password_cracking_master}',
                'hints': 'Try different attack modes: dictionary, hybrid, and rule-based attacks'
            },
            
            # Advanced Challenges
            {
                'name': 'Advanced Web Exploitation',
                'description': 'Tackle advanced web vulnerabilities including XXE (XML External Entity), SSTI (Server-Side Template Injection), and deserialization vulnerabilities that are commonly found in modern web applications.',
                'how_to_execute': '1. Map the application and identify input points\n2. Test for XXE in XML processing endpoints\n3. Identify template injection points for SSTI\n4. Look for serialized objects that might be vulnerable to deserialization attacks\n5. Develop and execute exploits for identified vulnerabilities',
                'real_world_use': 'Advanced web exploitation skills are crucial for:\n- Identifying complex security flaws in web applications\n- Conducting thorough penetration tests\n- Understanding modern web application attack vectors\n- Developing secure coding practices\n- Security research and bug bounty programs',
                'difficulty': 'Hard',
                'category': 'Web Security',
                'points': 600,
                'vm_name': 'vulnerable-web',
                'target_ip': '192.168.1.10',
                'flag': 'CTF{advanced_web_exploit}',
                'hints': 'Look for less common injection points and edge cases. Pay attention to how the application processes different types of input.'
            },
            {
                'name': 'Wireless Security Assessment',
                'description': 'Learn to assess and exploit wireless network security, including WPA2-PSK, WPA3, and enterprise wireless networks, using tools like Aircrack-ng, Wireshark, and Hashcat.',
                'how_to_execute': '1. Set up your wireless adapter in monitor mode\n2. Capture wireless traffic and identify target networks\n3. Capture WPA handshakes\n4. Perform offline password cracking\n5. Test for WPS vulnerabilities\n6. Document findings and suggest security improvements',
                'real_world_use': 'Wireless security assessment is essential for:\n- Securing organizational wireless networks\n- Conducting wireless penetration tests\n- Identifying rogue access points\n- Complying with wireless security standards\n- Security research and responsible disclosure',
                'difficulty': 'Hard',
                'category': 'Wireless Security',
                'points': 500,
                'vm_name': 'kali-attacker',
                'target_ip': '192.168.1.100',
                'flag': 'CTF{wifi_security_expert}',
                'hints': 'Focus on WPA2 handshake capture and offline cracking. Consider using GPU acceleration for faster password cracking.'
            },
            {
                'name': 'Digital Forensics Challenge',
                'description': 'Master digital forensics techniques by analyzing disk images, memory dumps, and network traffic to uncover hidden data, recover deleted files, and investigate security incidents.',
                'how_to_execute': '1. Acquire disk images and memory dumps using forensic tools\n2. Analyze file systems for hidden or deleted files\n3. Examine network traffic captures for suspicious activity\n4. Recover and analyze browser history and system artifacts\n5. Document findings in a forensically sound manner\n6. Create a comprehensive incident report',
                'real_world_use': 'Digital forensics is critical for:\n- Incident response and investigation\n- Data recovery and evidence collection\n- Legal proceedings and compliance\n- Security breach analysis\n- Malware analysis and reverse engineering',
                'difficulty': 'Medium',
                'category': 'Digital Forensics',
                'points': 400,
                'vm_name': 'kali-attacker',
                'target_ip': '192.168.1.100',
                'flag': 'CTF{forensics_solved}',
                'hints': 'Look for hidden files, steganography, unusual network patterns, and timestamps. Pay attention to file signatures and headers.'
            }
        ]
        
        for challenge_data in challenges:
            challenge = Challenge(
                name=challenge_data['name'],
                description=challenge_data['description'],
                how_to_execute=challenge_data.get('how_to_execute', ''),
                real_world_use=challenge_data.get('real_world_use', ''),
                difficulty=challenge_data['difficulty'],
                category=challenge_data['category'],
                points=challenge_data['points'],
                vm_name=challenge_data.get('vm_name', ''),
                target_ip=challenge_data.get('target_ip', ''),
                flag=challenge_data.get('flag', ''),
                hints=challenge_data.get('hints', '')
            )
            db.session.add(challenge)
        
        db.session.commit()
    
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
