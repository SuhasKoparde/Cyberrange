from app import app, db, User, Challenge, VMStatus, UserProgress
from werkzeug.security import generate_password_hash

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        # Drop and recreate all tables
        db.drop_all()
        db.create_all()
        
        # Clear existing data
        UserProgress.query.delete()
        VMStatus.query.delete()
        Challenge.query.delete()
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
            }
        ]
        
        # Add challenges to database
        for challenge_data in challenges:
            challenge = Challenge(**challenge_data)
            db.session.add(challenge)
        
        # Create default admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@cyberrange.local',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
        
        # Add VM statuses
        vm_statuses = [
            {'name': 'vulnerable-web', 'status': 'stopped', 'ip_address': '192.168.1.10'},
            {'name': 'web-app-1', 'status': 'stopped', 'ip_address': '192.168.1.11'},
            {'name': 'network-target', 'status': 'stopped', 'ip_address': '192.168.1.20'},
            {'name': 'network-target-2', 'status': 'stopped', 'ip_address': '192.168.1.21'},
            {'name': 'linux-target', 'status': 'stopped', 'ip_address': '192.168.1.30'},
            {'name': 'windows-target', 'status': 'stopped', 'ip_address': '192.168.1.31'}
        ]
        
        for vm_data in vm_statuses:
            vm = VMStatus(**vm_data)
            db.session.add(vm)
        
        db.session.commit()
        print("Database initialized successfully with all challenges!")

if __name__ == '__main__':
    init_db()
