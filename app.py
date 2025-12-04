from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import ast
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

# Custom Jinja2 filters
def nl2br(text):
    """Convert newlines to HTML line breaks"""
    if text is None:
        return ''
    return text.replace('\n', '<br>')

app.jinja_env.filters['nl2br'] = nl2br

def render_markdown(text):
    """Render Markdown text to HTML safely for templates."""
    try:
        import markdown as _md
        if text is None:
            return ''
        # Use fenced_code and tables for richer formatting
        return _md.markdown(text, extensions=['fenced_code', 'tables'])
    except Exception:
        # Fallback to nl2br if markdown fails
        return nl2br(text)

app.jinja_env.filters['render_markdown'] = render_markdown

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
    # Store structured execution steps as a JSON encoded list (optional)
    execution_steps = db.Column(db.Text, nullable=True)
    commands = db.Column(db.Text, nullable=True)
    real_world_use = db.Column(db.Text, nullable=True)
    difficulty = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    points = db.Column(db.Integer, default=100)
    vm_name = db.Column(db.String(100))
    target_ip = db.Column(db.String(15))
    target_url = db.Column(db.String(255), nullable=True)
    flag = db.Column(db.String(100))
    tools = db.Column(db.Text, nullable=True)
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
    return render_template('index.html', 
                         url_for=url_for,  # Pass url_for to template
                         current_user=current_user  # Pass current_user to template
                         )

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
                         vm_status=vm_status,
                         url_for=url_for,
                         current_user=current_user)

@app.route('/challenges')
@login_required
def challenges():
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 6  # Number of challenges per page
    
    # Get all challenges with pagination
    challenges = Challenge.query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get user progress for all challenges
    user_progress = UserProgress.query.filter_by(user_id=current_user.id).all()
    progress_dict = {p.challenge_id: p for p in user_progress}
    
    # Prepare lightweight metadata for each challenge to improve frontend UX (steps preview, parsed tools)
    challenge_meta = {}
    import ast
    for c in challenges.items:
        # steps preview
        steps_preview = []
        try:
            if c.execution_steps:
                # Try JSON first
                try:
                    steps = json.loads(c.execution_steps)
                except Exception:
                    # Fallback: maybe stored as Python-list literal
                    try:
                        parsed = ast.literal_eval(c.execution_steps)
                        steps = list(parsed) if isinstance(parsed, (list, tuple)) else None
                    except Exception:
                        steps = None

                if isinstance(steps, list):
                    steps_preview = [s for s in steps[:2]]
            elif c.how_to_execute:
                steps_preview = [line.strip() for line in c.how_to_execute.split('\n') if line.strip()][:2]
        except Exception:
            steps_preview = []

        # tools parsing (JSON or python-list string)
        tools_list = None
        try:
            if c.tools:
                try:
                    tools_list = json.loads(c.tools)
                except Exception:
                    try:
                        parsed = ast.literal_eval(c.tools)
                        if isinstance(parsed, (list, tuple)):
                            tools_list = list(parsed)
                    except Exception:
                        tools_list = None
        except Exception:
            tools_list = None

        challenge_meta[c.id] = {
            'steps_preview': steps_preview,
            'tools_list': tools_list
        }

    # If it's an AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'html': render_template('_challenges_list.html', 
                                  challenges=challenges.items,
                                  progress_dict=progress_dict,
                                  challenge_meta=challenge_meta),
            'has_next': challenges.has_next,
            'next_page': challenges.next_num if challenges.has_next else None
        })

    return render_template('challenges.html', 
                         challenges=challenges.items, 
                         progress_dict=progress_dict,
                         pagination=challenges,
                         challenge_meta=challenge_meta)

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
    
    # DEBUG: Print what we have in challenge object
    print(f'DEBUG: Challenge ID={challenge.id}, name={challenge.name}')
    print(f'DEBUG: how_to_execute={bool(challenge.how_to_execute)}, length={len(challenge.how_to_execute) if challenge.how_to_execute else 0}')
    print(f'DEBUG: execution_steps={bool(challenge.execution_steps)}')
    print(f'DEBUG: real_world_use={bool(challenge.real_world_use)}, length={len(challenge.real_world_use) if challenge.real_world_use else 0}')
    print(f'DEBUG: hints={bool(challenge.hints)}, length={len(challenge.hints) if challenge.hints else 0}')
    
    # Parse structured execution steps if present, otherwise derive from how_to_execute
    steps_list = None
    try:
        if challenge.execution_steps:
            # Try JSON first
            try:
                steps_list = json.loads(challenge.execution_steps)
            except Exception:
                # Fallback: maybe a Python list literal string
                try:
                    parsed = ast.literal_eval(challenge.execution_steps)
                    if isinstance(parsed, (list, tuple)):
                        steps_list = list(parsed)
                except Exception:
                    steps_list = None

        if not steps_list and challenge.how_to_execute:
            steps_list = [line.strip() for line in challenge.how_to_execute.split('\n') if line.strip()]
    except Exception as e:
        print(f'Error parsing execution_steps: {e}')

    # Parse tools into a list if possible (supports JSON or Python-list string)
    tools_list = None
    try:
        if challenge.tools:
            # Try JSON first
            try:
                tools_list = json.loads(challenge.tools)
            except Exception:
                # Fallback: parse Python list literal safely
                try:
                    parsed = ast.literal_eval(challenge.tools)
                    if isinstance(parsed, (list, tuple)):
                        tools_list = list(parsed)
                except Exception:
                    # Leave as None and let template handle string rendering
                    tools_list = None
    except Exception as e:
        print(f'Error parsing tools: {e}')

    # Get challenge content from markdown file
    challenge_content = read_challenge_content(challenge.name)

    return render_template('challenge_detail.html', 
                         challenge=challenge, 
                         progress=progress,
                         challenge_content=challenge_content,
                         steps_list=steps_list,
                         tools_list=tools_list)

@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    # Return JSON responses even when unauthenticated so the frontend can handle it
    challenge_id = request.form.get('challenge_id')
    submitted_flag = request.form.get('flag', '')

    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'Authentication required. Please log in.'}), 401

    if not challenge_id:
        return jsonify({'success': False, 'message': 'Bad request: missing challenge id'}), 400

    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({'success': False, 'message': 'Challenge not found'}), 404

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

    progress.attempts = (progress.attempts or 0) + 1

    if submitted_flag.strip() == (challenge.flag or '').strip():
        progress.completed = True
        progress.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Congratulations! Flag accepted!'})
    else:
        db.session.commit()
        return jsonify({'success': False, 'message': 'Incorrect flag. Try again!'}), 200

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


@app.route('/admin/challenges')
@login_required
def admin_challenges():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))

    challenges = Challenge.query.order_by(Challenge.id).all()
    return render_template('admin_challenges.html', challenges=challenges)


@app.route('/admin/challenges/<int:challenge_id>', methods=['GET', 'POST'])
@login_required
def edit_challenge(challenge_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))

    challenge = Challenge.query.get_or_404(challenge_id)

    if request.method == 'POST':
        execution_steps_text = request.form.get('execution_steps_text', '')
        # Convert textarea (newline separated) into JSON list
        steps = [line.strip() for line in execution_steps_text.splitlines() if line.strip()]
        try:
            challenge.execution_steps = json.dumps(steps)
            db.session.commit()
            flash('Execution steps updated', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating execution steps: {e}', 'danger')

        return redirect(url_for('admin_challenges'))

    # GET: prepare textarea value
    steps_text = ''
    if challenge.execution_steps:
        try:
            steps_text = '\n'.join(json.loads(challenge.execution_steps))
        except Exception:
            steps_text = challenge.how_to_execute or ''
    else:
        steps_text = challenge.how_to_execute or ''

    return render_template('edit_challenge.html', challenge=challenge, steps_text=steps_text)

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
    # Create all tables
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@cyberrange.local',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            created_at=datetime.utcnow()
        )
        db.session.add(admin)
    
    # Check if test user exists
    if not User.query.filter_by(username='user1').first():
        user = User(
            username='user1',
            email='user1@cyberrange.local',
            password_hash=generate_password_hash('password123'),
            role='user',
            created_at=datetime.utcnow()
        )
        db.session.add(user)
    
    # Add sample challenges if none exist
    if Challenge.query.count() == 0:
        from init_challenges import init_challenges
        init_challenges()
    
    db.session.commit()
    print("Database initialized successfully!")

# Initialize database if this file is run directly
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
