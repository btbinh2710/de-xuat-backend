from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import datetime
import os
import logging

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["https://btbinh2710.github.io", "http://127.0.0.1:5000"]}})  # Cho phép CORS
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

JWT_SECRET = os.environ.get('JWT_SECRET')

def get_db():
    conn = sqlite3.connect('data.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    branch = data['branch']
    role = data.get('role', 'branch')
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, branch, role) VALUES (?, ?, ?, ?)',
                  (username, password, branch, role))
        conn.commit()
        return jsonify({'message': 'User created'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password'].encode('utf-8')
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        logger.error(f"Login failed: Username {username} not found")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    try:
        if bcrypt.checkpw(password, user['password'].encode('utf-8')):
            token = jwt.encode({
                'username': username,
                'branch': user['branch'],
                'role': user['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, JWT_SECRET, algorithm='HS256')
            logger.info(f"Login successful for {username}")
            return jsonify({'token': token, 'branch': user['branch'], 'role': user['role']})
        else:
            logger.error(f"Login failed: Incorrect password for {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
    except ValueError as e:
        logger.error(f"Login failed for {username}: Invalid salt - {str(e)}")
        return jsonify({'error': 'Invalid password format in database'}), 500

@app.route('/api/proposals', methods=['POST'])
def create_proposal():
    token = request.headers.get('Authorization', '').split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        data['branch'] = payload['branch']
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO proposals (proposer, department, date, code, proposal, content, supplier, estimated_cost, approved_amount, notes, completed, branch)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (data['proposer'], data['department'], data['date'], data['code'], data['proposal'],
                   data['content'], data['supplier'], data['estimated_cost'], data['approved_amount'],
                   data['notes'], data['completed'], data['branch']))
        conn.commit()
        proposal_id = c.lastrowid
        conn.close()
        return jsonify({'id': proposal_id, **data}), 201
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/proposals', methods=['GET'])
def get_proposals():
    token = request.headers.get('Authorization', '').split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        conn = get_db()
        c = conn.cursor()
        if payload['role'] == 'admin':
            c.execute('SELECT * FROM proposals')
        else:
            c.execute('SELECT * FROM proposals WHERE branch = ?', (payload['branch'],))
        proposals = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify(proposals)
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/proposals/<int:id>', methods=['PUT'])
def update_proposal(id):
    token = request.headers.get('Authorization', '').split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        conn = get_db()
        c = conn.cursor()
        c.execute('''UPDATE proposals SET proposer = ?, department = ?, date = ?, code = ?, proposal = ?, content = ?, supplier = ?, estimated_cost = ?, approved_amount = ?, notes = ?, completed = ?
                     WHERE id = ? AND branch = ?''',
                  (data['proposer'], data['department'], data['date'], data['code'], data['proposal'],
                   data['content'], data['supplier'], data['estimated_cost'], data['approved_amount'],
                   data['notes'], data['completed'], id, payload['branch']))
        conn.commit()
        conn.close()
        if c.rowcount == 0:
            return jsonify({'error': 'Proposal not found or unauthorized'}), 404
        return jsonify(data)
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/proposals/<int:id>', methods=['DELETE'])
def delete_proposal(id):
    token = request.headers.get('Authorization', '').split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM proposals WHERE id = ? AND branch = ?', (id, payload['branch']))
        conn.commit()
        conn.close()
        if c.rowcount == 0:
            return jsonify({'error': 'Proposal not found or unauthorized'}), 404
        return jsonify({'message': 'Proposal deleted'})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401