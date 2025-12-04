from flask import Flask, render_template, request, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
import os
import sqlite3
import base64
import json
from datetime import datetime
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnerable-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Vulnerable User Model
class VulnerableUser(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    credit_card = db.Column(db.String(120), default='')

# Create tables
with app.app_context():
    db.create_all()
    
    # Add sample users
    if VulnerableUser.query.count() == 0:
        admin = VulnerableUser(
            username='admin', 
            password='admin123', 
            email='admin@example.com', 
            is_admin=True,
            credit_card='4532-1234-5678-9010'
        )
        user1 = VulnerableUser(
            username='user1', 
            password='password123', 
            email='user1@example.com', 
            is_admin=False,
            credit_card='5425-2334-3010-9903'
        )
        user2 = VulnerableUser(
            username='user2', 
            password='pass456', 
            email='user2@example.com', 
            is_admin=False,
            credit_card='3782-822463-10005'
        )
        db.session.add(admin)
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()
        print("✓ Sample users created")

@app.route('/')
def index():
    return '''
    <html>
    <head><title>Vulnerable Web Application</title></head>
    <body>
        <h1>Vulnerable Web Application Training Platform</h1>
        <p>This environment hosts multiple cybersecurity challenges.</p>
        <h2>Available Challenges:</h2>
        <ul>
            <li><a href="/challenge/1">Challenge 1: SQL Injection - Login Bypass</a></li>
            <li><a href="/challenge/2">Challenge 2: Cross-Site Scripting (XSS)</a></li>
            <li><a href="/challenge/3">Challenge 3: Command Injection</a></li>
            <li><a href="/challenge/4">Challenge 4: Path Traversal</a></li>
            <li><a href="/challenge/5">Challenge 5: Authentication Bypass</a></li>
        </ul>
        <hr>
        <p><a href="/debug">Debug/Status</a> | <a href="/test-payloads">Test All Payloads</a></p>
    </body>
    </html>
    '''

# ==================== DEBUG & DIAGNOSTIC ENDPOINTS ====================
@app.route('/debug')
def debug():
    """Show database status and user information"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get users
        cursor.execute("SELECT id, username, password, is_admin, email FROM users;")
        users = cursor.fetchall()
        conn.close()
        
        users_html = ''.join([f"<tr><td>{u['id']}</td><td>{u['username']}</td><td>{u['password']}</td><td>{'✓' if u['is_admin'] else '✗'}</td><td>{u['email']}</td></tr>" for u in users])
        
        return f'''
        <html>
        <head><title>Debug: Database Status</title></head>
        <body>
            <h1>Debug: Database Status</h1>
            <h2>Users in vulnerable.db</h2>
            <table border="1">
                <tr><th>ID</th><th>Username</th><th>Password</th><th>Admin</th><th>Email</th></tr>
                {users_html}
            </table>
            <hr>
            <p><strong>Test Payloads:</strong></p>
            <ul>
                <li><a href="/test-payloads">Run all payload tests</a></li>
                <li><a href="/">Back to Home</a></li>
            </ul>
        </body>
        </html>
        '''
    except Exception as e:
        return f"<h1>Debug Error</h1><p>{str(e)}</p>"

@app.route('/test-payloads')
def test_payloads():
    """Test all challenge payloads and show results"""
    results = []
    
    try:
        conn = sqlite3.connect('vulnerable.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Test Challenge 1 & 5: SQLi payloads
        payloads = [
            ("' OR '1'='1' -- ", ""),
            ("admin'--", "anything"),
        ]
        
        for username, password in payloads:
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            try:
                cursor.execute(query)
                user = cursor.fetchone()
                if user:
                    results.append({
                        'challenge': 'SQL Injection',
                        'payload': f"username: {username}",
                        'status': '✅ PASSED',
                        'result': f"Admin={user['is_admin']}, User={user['username']}",
                        'flag': 'FLAG{sql_injection_bypass_123}' if user['is_admin'] else 'Not admin'
                    })
                else:
                    results.append({
                        'challenge': 'SQL Injection',
                        'payload': f"username: {username}",
                        'status': '❌ FAILED',
                        'result': 'No user returned',
                        'flag': 'N/A'
                    })
            except Exception as e:
                results.append({
                    'challenge': 'SQL Injection',
                    'payload': f"username: {username}",
                    'status': '❌ ERROR',
                    'result': str(e),
                    'flag': 'N/A'
                })
        
        conn.close()
    except Exception as e:
        results.append({
            'challenge': 'Database',
            'payload': 'N/A',
            'status': '❌ ERROR',
            'result': str(e),
            'flag': 'N/A'
        })
    
    # Build HTML results
    results_html = ''.join([
        f"<tr><td>{r['challenge']}</td><td><code>{r['payload']}</code></td><td>{r['status']}</td><td>{r['result']}</td><td><strong>{r['flag']}</strong></td></tr>"
        for r in results
    ])
    
    return f'''
    <html>
    <head><title>Payload Test Results</title></head>
    <body>
        <h1>Payload Test Results</h1>
        <table border="1" style="width:100%; border-collapse: collapse;">
            <tr>
                <th>Challenge</th>
                <th>Payload</th>
                <th>Status</th>
                <th>Result</th>
                <th>Flag</th>
            </tr>
            {results_html}
        </table>
        <hr>
        <p><a href="/debug">Back to Debug</a> | <a href="/">Home</a></p>
    </body>
    </html>
    '''

# ==================== CHALLENGE 1: SQL INJECTION ====================
@app.route('/challenge/1')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: Direct SQL Injection (table name and DB path fixed)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            # Use the same SQLite file as SQLAlchemy (vulnerable.db)
            conn = sqlite3.connect('vulnerable.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                
                flag_display = ''
                if user['is_admin']:
                    flag_display = '<p><strong style="color:red; font-size: 18px;">FLAG{sql_injection_bypass_123}</strong></p>'
                
                return f'''
                <html>
                <head><title>Login Successful</title></head>
                <body style="font-family: Arial;">
                    <h1>Login Successful!</h1>
                    <p>Welcome, {user['username']}!</p>
                    <p>Your profile information:</p>
                    <ul>
                        <li>ID: {user['id']}</li>
                        <li>Username: {user['username']}</li>
                        <li>Email: {user['email']}</li>
                        <li>Admin: {"Yes ✓" if user['is_admin'] else "No"}</li>
                    </ul>
                    {flag_display}
                    <a href="/logout">Logout</a> | <a href="/">Back</a>
                </body>
                </html>
                '''
            else:
                return '''
                <html>
                <head><title>Login Failed</title></head>
                <body style="font-family: Arial;">
                    <h1>Login Failed</h1>
                    <p>Invalid credentials</p>
                    <a href="/login">Try Again</a> | <a href="/">Back</a>
                </body>
                </html>
                '''
        except Exception as e:
            return f'''
            <html>
            <head><title>Error</title></head>
            <body style="font-family: Arial;">
                <h1>Database Error</h1>
                <p>Error: {str(e)}</p>
                <a href="/login">Back to Login</a>
            </body>
            </html>
            '''
    
    return '''
    <html>
    <head><title>Challenge 1: SQL Injection</title></head>
    <body>
        <h1>Challenge 1: SQL Injection - Login Bypass</h1>
        <p>Objective: Bypass the login form using SQL injection to access the admin account</p>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <hr>
        <p><strong>Hints:</strong></p>
        <ul>
            <li>Try entering <code>' OR '1'='1</code> in the username field</li>
            <li>Try <code>admin'--</code> in the username field</li>
            <li>Leave the password field empty or enter anything</li>
        </ul>
        <a href="/">Back</a>
    </body>
    </html>
    '''

# ==================== CHALLENGE 2: XSS ====================
@app.route('/challenge/2')
@app.route('/search', methods=['GET', 'POST'])
def search():
    search_query = request.args.get('q', '')
    
    if request.method == 'POST':
        search_query = request.form.get('q', '')
    
    # VULNERABLE: Reflected XSS - User input is directly echoed without escaping
    xss_detected = any(tag in search_query.lower() for tag in ['<script', 'onerror=', 'onload=', 'onclick=', '<svg', 'javascript:'])
    
    xss_flag_display = ''
    if xss_detected:
        xss_flag_display = '<p><strong style="color:red; font-size: 18px;">FLAG{xss_reflected_456}</strong></p>'
    
    return f'''
    <html>
    <head><title>Challenge 2: XSS</title></head>
    <body style="font-family: Arial;">
        <h1>Challenge 2: Cross-Site Scripting (XSS)</h1>
        <p>Objective: Execute JavaScript code in the search functionality</p>
        <form method="GET">
            <input type="text" name="q" placeholder="Search..." value="{search_query}" style="width: 300px; padding: 5px;">
            <button type="submit">Search</button>
        </form>
        <hr>
        <h2>Search Results:</h2>
        <p>Results for: {search_query}</p>
        <p>No matching users found.</p>
        {xss_flag_display}
        <hr>
        <p><strong>Hints:</strong></p>
        <ul>
            <li>Try entering <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            <li>Try <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
            <li>Try <code>&lt;svg/onload=alert(document.cookie)&gt;</code></li>
        </ul>
        <a href="/">Back</a>
    </body>
    </html>
    '''

# ==================== CHALLENGE 3: COMMAND INJECTION ====================
@app.route('/challenge/3')
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    cmd_flag = ""
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # VULNERABLE: Command Injection
        import subprocess
        try:
            if host:
                # This is vulnerable to command injection
                cmd = f"ping -c 4 {host}"
                result = subprocess.getoutput(cmd)
                
                # Check if command injection was successful (extra commands executed)
                if any(marker in result for marker in ['uid=', 'gid=', 'root', 'kali', 'groups=', 'drwx', 'total', '-bash', '/bin']):
                    cmd_flag = '<p><strong style="color:red; font-size: 18px;">FLAG{command_injection_789}</strong></p>'
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f'''
    <html>
    <head><title>Challenge 3: Command Injection</title></head>
    <body style="font-family: Arial;">
        <h1>Challenge 3: Command Injection</h1>
        <p>Objective: Inject system commands through the ping utility</p>
        <form method="POST">
            <input type="text" name="host" placeholder="Enter hostname or IP" required>
            <button type="submit">Ping</button>
        </form>
        <hr>
        {'<h3>Ping Results:</h3><pre>' + result + '</pre>' if result else ''}
        {cmd_flag}
        <hr>
        <p><strong>Hints:</strong></p>
        <ul>
            <li>Try entering <code>127.0.0.1; whoami</code></li>
            <li>Try <code>127.0.0.1 && id</code></li>
            <li>Try <code>127.0.0.1 | cat /etc/passwd</code></li>
        </ul>
        <a href="/">Back</a>
    </body>
    </html>
    '''

# ==================== CHALLENGE 4: PATH TRAVERSAL ====================
@app.route('/challenge/4')
@app.route('/files')
def files():
    filename = request.args.get('file', 'readme.txt')
    content = ""
    error = ""
    pt_flag = ""
    
    # VULNERABLE: Path Traversal
    try:
        # Try to read from /tmp/challenges first, then fallback to /etc for traversal attempts
        if '../' in filename or filename.startswith('/'):
            # Trying to traverse - allow it to show the vulnerability
            file_path = filename
            pt_flag = '<p><strong style="color:red; font-size: 18px;">FLAG{path_traversal_234}</strong></p>'
        else:
            file_path = f"/tmp/challenges/{filename}"
        
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        if '../' in filename or filename.startswith('/'):
            # Still show flag even if file doesn't exist - they crafted the right payload
            pt_flag = '<p><strong style="color:red; font-size: 18px;">FLAG{path_traversal_234}</strong></p>'
            error = f"File not found: {filename}"
        else:
            error = f"File not found: {filename}"
    except Exception as e:
        error = f"Error: {str(e)}"
    
    return f'''
    <html>
    <head><title>Challenge 4: Path Traversal</title></head>
    <body style="font-family: Arial;">
        <h1>Challenge 4: Path Traversal</h1>
        <p>Objective: Access files outside the intended directory</p>
        <form method="GET">
            <input type="text" name="file" placeholder="Filename" value="{filename}" style="width: 300px;">
            <button type="submit">View File</button>
        </form>
        <hr>
        {'<h3>File Content:</h3><pre>' + content + '</pre>' if content else ''}
        {pt_flag}
        {'<p style="color:red;">' + error + '</p>' if error else ''}
        <hr>
        <p><strong>Hints:</strong></p>
        <ul>
            <li>Try entering <code>../../../etc/passwd</code></li>
            <li>Try <code>....//....//....//etc/shadow</code></li>
            <li>Try absolute paths like <code>/etc/hostname</code></li>
        </ul>
        <a href="/">Back</a>
    </body>
    </html>
    '''

# ==================== CHALLENGE 5: AUTHENTICATION BYPASS ====================
@app.route('/challenge/5')
@app.route('/api/login', methods=['GET', 'POST'])
def api_login():
    # Handle both JSON and form data
    data = {}
    
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = request.form
    else:
        data = request.args
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: Weak authentication with SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    try:
        conn = sqlite3.connect('vulnerable.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            flag_value = 'FLAG{auth_bypass_success_789}' if user['is_admin'] else None
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'is_admin': user['is_admin'],
                    'flag': flag_value
                }
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid credentials'
            }), 401
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Database error: {str(e)}'
        }), 500

@app.route('/auth-challenge')
def auth_challenge():
    return '''
    <html>
    <head><title>Challenge 5: Authentication Bypass</title></head>
    <body style="font-family: Arial;">
        <h1>Challenge 5: Authentication Bypass (API)</h1>
        <p>Objective: Bypass authentication using SQL injection</p>
        <form method="POST" action="/api/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <hr>
        <p><strong>Methods to try:</strong></p>
        <ul>
            <li>SQL Injection in username: <code>' OR '1'='1</code></li>
            <li>SQL Injection with comment: <code>admin'--</code></li>
            <li>Test with curl: <code>curl -X POST http://localhost:8080/api/login -d "username=' OR '1'='1&password=test"</code></li>
        </ul>
        <a href="/">Back</a>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return '''
    <html>
    <head><title>Logged Out</title></head>
    <body>
        <h1>Logged Out Successfully</h1>
        <a href="/">Home</a>
    </body>
    </html>
    '''

# ==================== BONUS CHALLENGES ====================

@app.route('/challenge/bonus1')
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # Vulnerable file upload (bonus challenge)
    return '''
    <html>
    <head><title>Bonus: File Upload Vulnerability</title></head>
    <body>
        <h1>Bonus Challenge: File Upload Vulnerability</h1>
        <p>Upload a file to the server (vulnerable to arbitrary file upload)</p>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    '''

@app.route('/challenge/bonus2')
@app.route('/vulnerable-api', methods=['GET'])
def vulnerable_api():
    # Vulnerable API endpoint
    query = request.args.get('q', '')
    return jsonify({
        'query': query,
        'results': [],
        'debug': f"SELECT * FROM users WHERE username='{query}'"  # Exposes SQL
    })

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE WEB APPLICATION - TRAINING ENVIRONMENT")
    print("=" * 60)
    print("\nStarting on port 8080...")
    print("\nAvailable Challenges:")
    print("  1. SQL Injection:      http://localhost:8080/login")
    print("  2. XSS:                http://localhost:8080/search")
    print("  3. Command Injection:  http://localhost:8080/ping")
    print("  4. Path Traversal:     http://localhost:8080/files")
    print("  5. Auth Bypass:        http://localhost:8080/auth-challenge")
    print("\nMain Page: http://localhost:8080")
    print("\n⚠️  WARNING: This app is intentionally vulnerable!")
    print("=" * 60 + "\n")
    
    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)
