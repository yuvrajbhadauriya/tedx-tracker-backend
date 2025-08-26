# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
from datetime import datetime, timedelta

# --- INITIALIZATION ---
# This setup tells Flask to look for the index.html file in the same directory
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app) # Allows the frontend to communicate with this backend

# --- DATABASE CONFIGURATION ---
# This sets up the SQLite database file in the same directory
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'sponsors.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- DATABASE MODELS ---
# These classes define the tables in our database

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)

class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=True) # Added phone number field

class Deliverable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    sponsor = db.Column(db.String(100), nullable=False)
    poc_id = db.Column(db.Integer, db.ForeignKey('team_member.id'), nullable=False)
    poc = db.relationship('TeamMember', backref=db.backref('deliverables', lazy=True))
    due_date = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text, nullable=True)

# --- API ROUTES ---

# --- Route to serve the HTML file ---
@app.route('/')
def serve_index():
    # This function serves the index.html file from the current directory
    return send_from_directory('.', 'index.html')

# --- Authentication ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username'], password=data['password']).first()
    if user:
        return jsonify({
            'message': 'Login successful',
            'is_superuser': user.is_superuser,
            'username': user.username
        }), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# --- Reminders API ---
@app.route('/api/reminders', methods=['GET'])
def get_reminders():
    today = datetime.utcnow().date()
    reminder_limit_date = today + timedelta(days=3)
    
    upcoming_deliverables = Deliverable.query.filter(
        Deliverable.due_date != '',
        Deliverable.status != 'Done'
    ).all()
    
    reminders = []
    for d in upcoming_deliverables:
        try:
            due_date_obj = datetime.strptime(d.due_date, '%Y-%m-%d').date()
            if today <= due_date_obj <= reminder_limit_date:
                reminders.append({
                    'id': d.id,
                    'name': d.name,
                    'sponsor': d.sponsor,
                    'dueDate': d.due_date,
                    'pocName': d.poc.name if d.poc else 'N/A'
                })
        except ValueError:
            continue # Skip if date format is incorrect
            
    return jsonify(sorted(reminders, key=lambda x: x['dueDate']))

# --- WhatsApp Simulation API ---
@app.route('/api/trigger-reminders', methods=['POST'])
def trigger_reminders():
    # In a real app, you'd verify the user is a superuser via JWT token
    print("\n--- TRIGGERING WHATSAPP REMINDER SIMULATION ---")
    reminders_sent = 0
    reminders = get_reminders().get_json() # Reuse the reminders logic
    
    for reminder in reminders:
        poc = TeamMember.query.filter_by(name=reminder['pocName']).first()
        if poc and poc.phone_number:
            message = (
                f"[WHATSAPP SIM] To: {poc.phone_number} (POC: {poc.name})\n"
                f"Message: Hi {poc.name}, this is a reminder from TEDxVIPS. "
                f"The deliverable '{reminder['name']}' for sponsor '{reminder['sponsor']}' "
                f"is due on {reminder['dueDate']}.\n"
            )
            print(message)
            reminders_sent += 1
        else:
            print(f"[WHATSAPP SIM] SKIPPING: No phone number for POC {reminder['pocName']}.\n")
            
    print(f"--- SIMULATION COMPLETE: {reminders_sent} reminders logged. ---")
    return jsonify({'message': f'WhatsApp reminder simulation complete. {reminders_sent} reminders logged to server console.'}), 200


# --- Deliverables API ---
@app.route('/api/deliverables', methods=['GET'])
def get_deliverables():
    deliverables_list = Deliverable.query.order_by(Deliverable.due_date).all()
    result = []
    for d in deliverables_list:
        result.append({
            'id': d.id,
            'name': d.name,
            'sponsor': d.sponsor,
            'pocId': d.poc_id,
            'pocName': d.poc.name if d.poc else 'N/A',
            'dueDate': d.due_date,
            'status': d.status,
            'notes': d.notes
        })
    return jsonify(result)

@app.route('/api/deliverables', methods=['POST'])
def add_deliverable():
    data = request.get_json()
    new_deliverable = Deliverable(
        name=data['name'],
        sponsor=data['sponsor'],
        poc_id=data['pocId'],
        due_date=data['dueDate'],
        status=data['status'],
        notes=data['notes']
    )
    db.session.add(new_deliverable)
    db.session.commit()
    return jsonify({'message': 'Deliverable added'}), 201

@app.route('/api/deliverables/<int:id>', methods=['PUT'])
def update_deliverable(id):
    data = request.get_json()
    deliverable = Deliverable.query.get_or_404(id)
    deliverable.name = data['name']
    deliverable.sponsor = data['sponsor']
    deliverable.poc_id = data['pocId']
    deliverable.due_date = data['dueDate']
    deliverable.status = data['status']
    deliverable.notes = data['notes']
    db.session.commit()
    return jsonify({'message': 'Deliverable updated'})

@app.route('/api/deliverables/<int:id>', methods=['DELETE'])
def delete_deliverable(id):
    deliverable = Deliverable.query.get_or_404(id)
    db.session.delete(deliverable)
    db.session.commit()
    return jsonify({'message': 'Deliverable deleted'})
    
@app.route('/api/deliverables/status/<int:id>', methods=['PUT'])
def update_deliverable_status(id):
    data = request.get_json()
    deliverable = Deliverable.query.get_or_404(id)
    deliverable.status = data['status']
    db.session.commit()
    return jsonify({'message': 'Status updated'})

# --- Team Members API ---
@app.route('/api/team', methods=['GET'])
def get_team():
    team_list = TeamMember.query.order_by(TeamMember.name).all()
    return jsonify([{'id': member.id, 'name': member.name, 'phoneNumber': member.phone_number} for member in team_list])

@app.route('/api/team', methods=['POST'])
def add_team_member():
    data = request.get_json()
    if not data.get('is_superuser'):
        return jsonify({'message': 'Unauthorized'}), 403
    
    # Check if member already exists
    existing_member = TeamMember.query.filter_by(name=data['name']).first()
    if existing_member:
        return jsonify({'message': f"Team member with name '{data['name']}' already exists."}), 409

    new_member = TeamMember(name=data['name'], phone_number=data.get('phoneNumber'))
    db.session.add(new_member)
    db.session.commit()
    return jsonify({'id': new_member.id, 'name': new_member.name}), 201

@app.route('/api/team/<int:id>', methods=['DELETE'])
def delete_team_member(id):
    auth_header = request.headers.get('Authorization')
    if auth_header != 'superuser':
        return jsonify({'message': 'Unauthorized'}), 403

    # Check if member is assigned to any deliverables
    assigned_deliverables = Deliverable.query.filter_by(poc_id=id).count()
    if assigned_deliverables > 0:
        return jsonify({'message': 'Cannot delete team member. They are assigned to one or more deliverables. Please reassign the deliverables first.'}), 409

    member = TeamMember.query.get_or_404(id)
    db.session.delete(member)
    db.session.commit()
    return jsonify({'message': 'Team member deleted'})

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates the database and tables if they don't exist
        if not User.query.filter_by(username='admin').first():
            print("Creating default admin user...")
            admin_user = User(username='admin', password='password', is_superuser=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created with username 'admin' and password 'password'")
    app.run(debug=True)
