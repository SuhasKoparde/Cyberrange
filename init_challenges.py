from app import app, db, Challenge, User, VMStatus
from datetime import datetime

def init_challenges():
    print("Initializing challenges...")
    
    # Clear existing data
    Challenge.query.delete()
    VMStatus.query.delete()
    
    # Sample challenges
    challenges = [
        {
            'name': 'SQL Injection - Login Bypass',
            'description': 'Exploit a SQL injection vulnerability to bypass authentication and log in as an admin.',
            'how_to_execute': "1. Navigate to the login page\n2. Enter a SQL injection payload in the username field\n3. Use ' OR '1'='1 as the username and anything as password\n4. Submit the form to bypass authentication",
            'real_world_use': 'SQL injection is a common web vulnerability that can lead to unauthorized access, data theft, and database manipulation.',
            'difficulty': 'Easy',
            'category': 'Web Security',
            'points': 100,
            'vm_name': 'web-server-1',
            'target_ip': '192.168.1.10',
            'flag': 'FLAG{sql_injection_bypass_123}',
            'hints': 'Think about how SQL queries are constructed. What happens if you can modify the WHERE clause?'
        },
        {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Inject a malicious script into a vulnerable web application to steal user sessions.',
            'how_to_execute': "1. Find a text input field that reflects user input\n2. Inject a script tag with alert()\n3. Submit the form to execute the script\n4. Try to steal cookies using document.cookie",
            'real_world_use': 'XSS attacks can be used to steal sensitive information, deface websites, or perform actions on behalf of users.',
            'difficulty': 'Medium',
            'category': 'Web Security',
            'points': 150,
            'vm_name': 'web-server-2',
            'target_ip': '192.168.1.11',
            'flag': 'FLAG{xss_attack_success_456}',
            'hints': 'Look for places where user input is displayed without proper escaping.'
        },
        {
            'name': 'Network Traffic Analysis',
            'description': 'Analyze a packet capture file to find sensitive information.',
            'how_to_execute': "1. Download the provided pcap file\n2. Open it with Wireshark\n3. Look for HTTP traffic\n4. Find the flag in the packet data",
            'real_world_use': 'Network analysis is crucial for incident response and identifying malicious activity on a network.',
            'difficulty': 'Medium',
            'category': 'Network Security',
            'points': 200,
            'vm_name': 'network-monitor',
            'target_ip': '192.168.1.20',
            'flag': 'FLAG{packet_analysis_789}',
            'hints': 'Check the HTTP traffic for any interesting strings or credentials.'
        },
        {
            'name': 'Password Cracking',
            'description': 'Crack password hashes using a wordlist and a password cracking tool.',
            'how_to_execute': "1. Use hash-identifier to determine the hash type\n2. Use hashcat or John the Ripper with the provided wordlist\n3. Crack the password hash to get the flag",
            'real_world_use': 'Password cracking is used in penetration testing to test password strength and in digital forensics.',
            'difficulty': 'Hard',
            'category': 'Cryptography',
            'points': 250,
            'vm_name': 'cracking-station',
            'target_ip': '192.168.1.30',
            'flag': 'FLAG{password_cracked_101}',
            'hints': 'The password is a common word found in most wordlists.'
        },
        {
            'name': 'Privilege Escalation',
            'description': 'Exploit a misconfiguration to escalate privileges to root.',
            'how_to_execute': "1. Find SUID binaries with 'find / -perm -u=s -type f 2>/dev/null'\n2. Check for known vulnerabilities in the binaries\n3. Exploit the vulnerability to get root",
            'real_world_use': 'Privilege escalation is a critical step in penetration testing to gain higher-level access to systems.',
            'difficulty': 'Hard',
            'category': 'System Security',
            'points': 300,
            'vm_name': 'linux-server',
            'target_ip': '192.168.1.40',
            'flag': 'FLAG{root_escalation_202}',
            'hints': 'Check for SUID binaries and known exploits.'
        },
        {
            'name': 'Forensics - File Recovery',
            'description': 'Recover deleted files from a disk image.',
            'how_to_execute': "1. Use tools like foremost or binwalk to extract files\n2. Look for the flag in the recovered files\n3. Analyze file metadata for hidden information",
            'real_world_use': 'File recovery is essential in digital forensics for investigating security incidents.',
            'difficulty': 'Medium',
            'category': 'Digital Forensics',
            'points': 175,
            'vm_name': 'forensics-pc',
            'target_ip': '192.168.1.50',
            'flag': 'FLAG{recovered_file_303}',
            'hints': 'Look for file signatures and headers in the disk image.'
        },
        {
            'name': 'Reverse Engineering',
            'description': 'Analyze a binary to find the correct password.',
            'how_to_execute': "1. Use tools like Ghidra or IDA Pro to analyze the binary\n2. Look for string comparisons\n3. Find the correct password to get the flag",
            'real_world_use': 'Reverse engineering is used for malware analysis and software security research.',
            'difficulty': 'Hard',
            'category': 'Reverse Engineering',
            'points': 275,
            'vm_name': 'reversing-lab',
            'target_ip': '192.168.1.60',
            'flag': 'FLAG{reverse_engineering_404}',
            'hints': 'Look for string comparisons and hardcoded values in the binary.'
        },
        {
            'name': 'Web Application Firewall Bypass',
            'description': 'Bypass a web application firewall (WAF) to perform an XSS attack.',
            'how_to_execute': "1. Identify the WAF and its rules\n2. Use encoding and obfuscation to bypass the WAF\n3. Execute the XSS payload",
            'real_world_use': 'Understanding WAF bypass techniques is important for testing web application security.',
            'difficulty': 'Hard',
            'category': 'Web Security',
            'points': 225,
            'vm_name': 'waf-server',
            'target_ip': '192.168.1.70',
            'flag': 'FLAG{waf_bypassed_505}',
            'hints': 'Try different encoding techniques like URL encoding or Unicode encoding.'
        },
        {
            'name': 'SSH Brute Force',
            'description': 'Use a password spraying attack to gain SSH access to a server.',
            'how_to_execute': "1. Use a tool like Hydra or Medusa\n2. Use the provided username list and common passwords\n3. Find the correct credentials to log in",
            'real_world_use': 'Password spraying is a common attack technique and understanding it helps in securing systems.',
            'difficulty': 'Medium',
            'category': 'Network Security',
            'points': 175,
            'vm_name': 'ssh-server',
            'target_ip': '192.168.1.80',
            'flag': 'FLAG{ssh_access_granted_606}',
            'hints': 'Try common usernames like admin, root, and guest with common passwords.'
        },
        {
            'name': 'Buffer Overflow',
            'description': 'Exploit a buffer overflow vulnerability to gain a shell.',
            'how_to_execute': "1. Identify the vulnerable function\n2. Find the offset to control EIP\n3. Overwrite the return address with your shellcode\n4. Get a reverse shell",
            'real_world_use': 'Buffer overflows are a common vulnerability that can lead to remote code execution.',
            'difficulty': 'Expert',
            'category': 'Exploit Development',
            'points': 400,
            'vm_name': 'vuln-server',
            'target_ip': '192.168.1.90',
            'flag': 'FLAG{shell_obtained_707}',
            'hints': 'Use a debugger like GDB to analyze the crash and find the offset.'
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
            hints=challenge_data['hints'],
            created_at=datetime.utcnow()
        )
        db.session.add(challenge)
    
    # Add VM statuses
    vms = [
        {'name': 'web-server-1', 'status': 'running', 'ip_address': '192.168.1.10'},
        {'name': 'web-server-2', 'status': 'running', 'ip_address': '192.168.1.11'},
        {'name': 'network-monitor', 'status': 'running', 'ip_address': '192.168.1.20'},
        {'name': 'cracking-station', 'status': 'running', 'ip_address': '192.168.1.30'},
        {'name': 'linux-server', 'status': 'running', 'ip_address': '192.168.1.40'},
        {'name': 'forensics-pc', 'status': 'running', 'ip_address': '192.168.1.50'},
        {'name': 'reversing-lab', 'status': 'running', 'ip_address': '192.168.1.60'},
        {'name': 'waf-server', 'status': 'running', 'ip_address': '192.168.1.70'},
        {'name': 'ssh-server', 'status': 'running', 'ip_address': '192.168.1.80'},
        {'name': 'vuln-server', 'status': 'running', 'ip_address': '192.168.1.90'}
    ]
    
    for vm_data in vms:
        vm = VMStatus(
            name=vm_data['name'],
            status=vm_data['status'],
            ip_address=vm_data['ip_address'],
            last_updated=datetime.utcnow()
        )
        db.session.add(vm)
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@cyberrange.local',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            created_at=datetime.utcnow()
        )
        db.session.add(admin)
    
    # Create test user if not exists
    if not User.query.filter_by(username='user1').first():
        user = User(
            username='user1',
            email='user1@cyberrange.local',
            password_hash=generate_password_hash('password123'),
            role='user',
            created_at=datetime.utcnow()
        )
        db.session.add(user)
    
    db.session.commit()
    print("Challenges and VMs initialized successfully!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_challenges()
