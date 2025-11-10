# SQL Injection - Login Bypass

## Description
This challenge demonstrates a classic SQL injection vulnerability in a login form. The application uses string concatenation to build SQL queries, making it vulnerable to injection attacks.

## How to Execute
1. Navigate to the login page
2. In the username field, enter: `admin' -- `
3. Leave the password field empty or enter any value
4. Click the login button

## Detailed Steps
1. The vulnerable SQL query looks like this:
   ```sql
   SELECT * FROM users WHERE username = '[username]' AND password = '[password]'
   ```
2. When you enter `admin' -- ` as the username, the query becomes:
   ```sql
   SELECT * FROM users WHERE username = 'admin' -- ' AND password = ''
   ```
3. The `--` sequence comments out the rest of the query, effectively bypassing the password check

## Real World Use
SQL injection is one of the most common web application vulnerabilities. Attackers can use it to:
- Bypass authentication
- Extract sensitive data
- Modify or delete database content
- Execute administrative operations

## Prevention
To prevent SQL injection:
1. Use parameterized queries or prepared statements
2. Implement proper input validation
3. Use ORM frameworks that handle SQL escaping
4. Apply the principle of least privilege for database users

## Additional Notes
- The flag is stored in the database and will be displayed after successful login
- Try to find other injection points in the application
- Experiment with different payloads to understand the vulnerability better
