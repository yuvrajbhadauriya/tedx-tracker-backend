from flask import Flask, request, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import os

# --- App setup ---
# DEFINE PATHS FIRST
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)

# NOW INITIALIZE THE APP
app = Flask(__name__, static_folder='.', static_url_path='', instance_path=instance_path)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key')

# NOW CONFIGURE THE DATABASE
# Use the Render PostgreSQL database URL if available, otherwise fall back to SQLite for local dev
database_uri = os.environ.get('DATABASE_URL')
if database_uri and database_uri.startswith("postgres://"):
    database_uri = database_uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_uri or 'sqlite:///' + os.path.join(instance_path, 'sponsors.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure cookies for local development
app.config.update(
    SESSION_COOKIE_SECURE=False
)

CORS(app, supports_credentials=True, origins=[
    'http://127.0.0.1:5000',
    'http://localhost:5000',
    'http://127.0.0.1:5500',
    'http://localhost:5500'
])

# Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(40), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(40), nullable=True)

class Deliverable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    sponsor = db.Column(db.String(100), nullable=False)
    poc_id = db.Column(db.Integer, db.ForeignKey('team_member.id'), nullable=False)
    poc = db.relationship('TeamMember', backref=db.backref('deliverables', lazy=True))
    due_date = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User')
    description = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

def log_activity(description):
    try:
        uid = current_user.id if current_user and current_user.is_authenticated else None
        entry = ActivityLog(user_id=uid, description=description)
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superuser:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- Routes: Serve frontend ---
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# --- Auth routes ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    name = (data.get('name') or '').strip()
    phone = (data.get('phoneNumber') or '').strip()

    if not all([username, password, name]):
        return jsonify({'message': 'Username, name, and password are required.'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists.'}), 409
    
    new_user = User(
        username=username, 
        name=name, 
        phone_number=phone, 
        is_superuser=False, 
        is_active=False
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    log_activity(f"Registration request by '{username}'")
    return jsonify({'message': 'Registration successful. Waiting for admin approval.'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    user = User.query.filter(User.username == username).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials'}), 401
    if not user.is_active:
        return jsonify({'message': 'Account not yet approved by an admin.'}), 403
    login_user(user)
    log_activity(f"{user.username} logged in.")
    return jsonify({'message': 'Login successful', 'username': user.username, 'is_superuser': user.is_superuser}), 200

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    log_activity(f"{current_user.username} logged out.")
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/check_session', methods=['GET'])
def check_session():
    if current_user.is_authenticated:
        return jsonify({'authenticated': True, 'username': current_user.username, 'is_superuser': current_user.is_superuser}), 200
    return jsonify({'authenticated': False}), 401

@app.route('/api/user/settings', methods=['POST'])
@login_required
def update_user_settings():
    data = request.get_json() or {}
    current_password = data.get('current_password')
    new_username = (data.get('new_username') or '').strip()
    new_password = data.get('new_password')

    if not current_user.check_password(current_password):
        return jsonify({'message': 'Incorrect current password.'}), 403

    if new_username and new_username != current_user.username:
        if User.query.filter(User.username == new_username).first():
            return jsonify({'message': 'That username is already taken.'}), 409
        log_activity(f"User '{current_user.username}' changed their username to '{new_username}'.")
        current_user.username = new_username

    if new_password:
        current_user.set_password(new_password)
        log_activity(f"User '{current_user.username}' changed their password.")

    db.session.commit()
    return jsonify({'message': 'Settings updated successfully.'})

# --- Admin: Pending users ---
@app.route('/api/pending-users', methods=['GET'])
@superuser_required
def get_pending_users():
    pending = User.query.filter_by(is_active=False).all()
    return jsonify([{'id': u.id, 'username': u.username} for u in pending])

@app.route('/api/approve-user/<int:user_id>', methods=['POST'])
@superuser_required
def approve_user(user_id):
    user_to_approve = User.query.get_or_404(user_id)
    user_to_approve.is_active = True
    if not TeamMember.query.filter_by(name=user_to_approve.name).first():
        tm = TeamMember(name=user_to_approve.name, phone_number=user_to_approve.phone_number)
        db.session.add(tm)
    db.session.commit()
    log_activity(f"Approved user '{user_to_approve.username}'.")
    return jsonify({'message': 'User approved.'})

@app.route('/api/deny-user/<int:user_id>', methods=['POST'])
@superuser_required
def deny_user(user_id):
    user_to_deny = User.query.get_or_404(user_id)
    username = user_to_deny.username
    db.session.delete(user_to_deny)
    db.session.commit()
    log_activity(f"Denied and deleted user '{username}'.")
    return jsonify({'message': 'User denied and deleted.'})

# --- Team management ---
@app.route('/api/team', methods=['GET'])
@login_required
def get_team():
    members = TeamMember.query.order_by(TeamMember.name).all()
    return jsonify([{'id': m.id, 'name': m.name, 'phoneNumber': m.phone_number} for m in members])

@app.route('/api/team', methods=['POST'])
@superuser_required
def create_team_member():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    phone = data.get('phoneNumber') or None
    if not name:
        return jsonify({'message': 'Name required.'}), 400
    if TeamMember.query.filter_by(name=name).first():
        return jsonify({'message': 'Team member already exists.'}), 409
    m = TeamMember(name=name, phone_number=phone)
    db.session.add(m)
    db.session.commit()
    log_activity(f"Added team member '{name}'.")
    return jsonify({'message': 'Team member added.'}), 201

@app.route('/api/team/<int:member_id>', methods=['PUT'])
@superuser_required
def update_team_member(member_id):
    m = TeamMember.query.get_or_404(member_id)
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    phone = data.get('phoneNumber') or None

    if not name:
        return jsonify({'message': 'Name required.'}), 400

    existing = TeamMember.query.filter(TeamMember.name == name, TeamMember.id != member_id).first()
    if existing:
        return jsonify({'message': 'Another team member already has this name.'}), 409

    m.name = name
    m.phone_number = phone
    db.session.commit()
    log_activity(f"Updated team member '{m.name}'.")
    return jsonify({'message': 'Team member updated.'})

@app.route('/api/team/<int:member_id>', methods=['DELETE'])
@superuser_required
def delete_team_member(member_id):
    m = TeamMember.query.get_or_404(member_id)
    db.session.delete(m)
    db.session.commit()
    log_activity(f"Deleted team member '{m.name}'.")
    return jsonify({'message': 'Team member removed.'})

# --- Deliverables CRUD ---
@app.route('/api/deliverables', methods=['GET'])
@login_required
def list_deliverables():
    items = Deliverable.query.order_by(Deliverable.due_date).all()
    def to_dict(d):
        return {
            'id': d.id, 'name': d.name, 'sponsor': d.sponsor,
            'pocId': d.poc_id, 'pocName': d.poc.name if d.poc else None,
            'dueDate': d.due_date, 'status': d.status, 'notes': d.notes
        }
    return jsonify([to_dict(d) for d in items])

@app.route('/api/deliverables', methods=['POST'])
@login_required
def create_deliverable():
    data = request.get_json() or {}
    required = ['name', 'sponsor', 'pocId', 'dueDate', 'status']
    if not all(k in data for k in required):
        return jsonify({'message': 'Missing required fields.'}), 400
    poc = TeamMember.query.get(data['pocId'])
    if not poc:
        return jsonify({'message': 'Invalid POC selected.'}), 400
    d = Deliverable(
        name=data['name'], sponsor=data['sponsor'], poc_id=poc.id,
        due_date=data['dueDate'], status=data['status'], notes=data.get('notes'), created_by=current_user.id
    )
    db.session.add(d)
    db.session.commit()
    log_activity(f"Created deliverable '{d.name}' for sponsor '{d.sponsor}'.")
    return jsonify({'message': 'Deliverable created.', 'id': d.id}), 201

@app.route('/api/deliverables/<int:item_id>', methods=['PUT'])
@login_required
def update_deliverable(item_id):
    data = request.get_json() or {}
    d = Deliverable.query.get_or_404(item_id)
    if 'name' in data: d.name = data['name']
    if 'sponsor' in data: d.sponsor = data['sponsor']
    if 'pocId' in data:
        poc = TeamMember.query.get(data['pocId'])
        if not poc: return jsonify({'message': 'Invalid POC'}), 400
        d.poc_id = poc.id
    if 'dueDate' in data: d.due_date = data['dueDate']
    if 'status' in data: d.status = data['status']
    if 'notes' in data: d.notes = data['notes']
    db.session.commit()
    log_activity(f"Updated deliverable '{d.name}' (id {d.id}).")
    return jsonify({'message': 'Deliverable updated.'})

@app.route('/api/deliverables/<int:item_id>', methods=['DELETE'])
@login_required
def delete_deliverable(item_id):
    d = Deliverable.query.get_or_404(item_id)
    db.session.delete(d)
    db.session.commit()
    log_activity(f"Deleted deliverable '{d.name}' (id {d.id}).")
    return jsonify({'message': 'Deliverable deleted.'})

@app.route('/api/deliverables/status/<int:item_id>', methods=['PUT'])
@login_required
def update_deliverable_status(item_id):
    data = request.get_json() or {}
    if 'status' not in data:
        return jsonify({'message': 'Status required.'}), 400
    d = Deliverable.query.get_or_404(item_id)
    old = d.status
    d.status = data['status']
    db.session.commit()
    log_activity(f"Changed status of '{d.name}' from '{old}' to '{d.status}'.")
    return jsonify({'message': 'Status updated.'})

# --- Reminders & Trigger ---
@app.route('/api/reminders', methods=['GET'])
@login_required
def get_reminders():
    today = datetime.utcnow().date()
    upcoming = []
    deliverables_to_check = Deliverable.query.filter(Deliverable.status != 'Done').all()
    for d in deliverables_to_check:
        try:
            due = datetime.strptime(d.due_date, '%Y-%m-%d').date()
        except Exception:
            continue
        delta = (due - today).days
        if 0 <= delta <= 3:
            upcoming.append({
                'id': d.id, 'name': d.name, 'sponsor': d.sponsor,
                'dueDate': d.due_date, 'pocName': d.poc.name if d.poc else None,
                'phoneNumber': d.poc.phone_number if d.poc else None
            })
    return jsonify(upcoming)

@app.route('/api/trigger-reminders', methods=['POST'])
@superuser_required
def trigger_reminders():
    reminders = []
    today = datetime.utcnow().date()
    by_phone = {}
    deliverables_to_check = Deliverable.query.filter(Deliverable.status != 'Done').all()
    for d in deliverables_to_check:
        try:
            due = datetime.strptime(d.due_date, '%Y-%m-%d').date()
        except Exception:
            continue
        delta = (due - today).days
        if 0 <= delta <= 3 and d.poc and d.poc.phone_number:
            phone = d.poc.phone_number
            msg = f"Reminder: '{d.name}' for sponsor {d.sponsor} is due on {d.due_date}. Please follow up with sponsor."
            if phone not in by_phone:
                by_phone[phone] = []
            by_phone[phone].append(msg)
    for phone, msgs in by_phone.items():
        full = '\n'.join(msgs)
        reminders.append({'phoneNumber': phone, 'message': full})
    return jsonify(reminders)

# --- Analytics ---
@app.route('/api/analytics', methods=['GET'])
@login_required
def analytics():
    status_counts = {}
    sponsor_counts = {}
    for d in Deliverable.query.all():
        status_counts[d.status] = status_counts.get(d.status, 0) + 1
        sponsor_counts[d.sponsor] = sponsor_counts.get(d.sponsor, 0) + 1
    return jsonify({'status_distribution': status_counts, 'sponsor_distribution': sponsor_counts})

# --- Activity Log ---
@app.route('/api/activity', methods=['GET'])
@superuser_required
def activity():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(200).all()
    result = []
    for l in logs:
        username = l.user.username if l.user else 'System'
        result.append({
            'timestamp': l.timestamp.isoformat(),
            'description': f"({username}) {l.description}",
            'user_id': l.user_id
        })
    return jsonify(result)

# --- Bootstrap DB & default admin ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin', 
                name='Admin',
                phone_number='910000000000',
                is_superuser=True, 
                is_active=True
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            if not TeamMember.query.filter_by(name='Admin').first():
                tm = TeamMember(name='Admin', phone_number='910000000000')
                db.session.add(tm)
            db.session.commit()
            print("Created default admin -> username: 'admin' password: 'admin123'")
    app.run(host='127.0.0.1', port=5000, debug=True)

