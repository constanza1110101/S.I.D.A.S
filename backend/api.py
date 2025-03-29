# backend/api.py
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import jwt
import datetime
import threading
import time
import random
import math
from sidas import SIDAS

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
security_system = SIDAS()

# Secret key for JWT
SECRET_KEY = "sidas_secret_key_change_in_production"

# In-memory track database (replace with actual database in production)
tracks_db = {}
system_status = {
    'defense': 'online',
    'attack': 'standby',
    'tracking': 'online',
    'threat_level': 'low',
    'last_updated': datetime.datetime.now().isoformat()
}

def generate_jwt_token(user_id, role):
    """Generate a JWT token for authentication"""
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': expiration
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def token_required(f):
    """Decorator for JWT token verification"""
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = {
                'user_id': data['user_id'],
                'role': data['role']
            }
        except:
            return jsonify({'error': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Add IP address for authentication tracking
    ip_address = request.remote_addr
    credentials = {
        'username': username,
        'password': password,
        'ip_address': ip_address
    }
    
    auth_result = security_system.authenticate(credentials)
    
    if auth_result['success']:
        # In production, get role from user database
        role = 'operator'
        token = generate_jwt_token(username, role)
        
        return jsonify({
            'token': token,
            'user': {
                'username': username,
                'role': role
            }
        })
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/tracks', methods=['GET'])
@token_required
def get_tracks(current_user):
    """Get all tracks"""
    return jsonify(list(tracks_db.values()))

@app.route('/api/status', methods=['GET'])
@token_required
def get_system_status(current_user):
    """Get system status"""
    return jsonify(system_status)

@app.route('/api/tracks/<track_id>', methods=['GET'])
@token_required
def get_track(current_user, track_id):
    """Get a specific track"""
    if track_id in tracks_db:
        # Log access to sensitive data
        security_system.generate_audit_log(
            action='track_access',
            status='success',
            details={'user': current_user['user_id'], 'track_id': track_id}
        )
        return jsonify(tracks_db[track_id])
    else:
        return jsonify({'error': 'Track not found'}), 404

@app.route('/api/command', methods=['POST'])
@token_required
def issue_command(current_user):
    """Issue a command to the system"""
    data = request.get_json()
    command_type = data.get('type')
    target_id = data.get('target_id')
    parameters = data.get('parameters', {})
    
    # Check user permissions for this command
    if current_user['role'] != 'operator' and command_type in ['attack', 'defense_override']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Log the command
    security_system.generate_audit_log(
        action=f'command_{command_type}',
        status='initiated',
        details={
            'user': current_user['user_id'],
            'target': target_id,
            'params': parameters
        }
    )
    
    # Process command (placeholder)
    result = {
        'success': True,
        'command_id': f"cmd-{int(time.time())}",
        'status': 'processing'
    }
    
    # Broadcast status update to all clients
    socketio.emit('command_update', {
        'type': 'command_issued',
        'command': command_type,
        'target': target_id,
        'status': 'processing'
    })
    
    return jsonify(result)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    # In production, verify authentication token here
    emit('connection_status', {'status': 'connected'})

# Simulation thread for generating track updates
def simulation_thread():
    """Simulate track updates for demonstration"""
    while True:
        # Generate or update random tracks
        for i in range(5):
            track_id = f"track-{i}"
            if track_id in tracks_db:
                # Update existing track
                track = tracks_db[track_id]
                # Simple movement simulation
                lon, lat, alt = track['position']
                vx, vy, vz = track['velocity']
                
                # Update position based on velocity
                new_lon = lon + vx * 0.01
                new_lat = lat + vy * 0.01
                new_alt = max(0, alt + vz * 0.01)
                
                # Random velocity changes
                track['velocity'] = [
                    vx + random.uniform(-0.1, 0.1),
                    vy + random.uniform(-0.1, 0.1),
                    vz + random.uniform(-0.05, 0.05)
                ]
                track['position'] = [new_lon, new_lat, new_alt]
            else:
                # Create new track
                tracks_db[track_id] = {
                    'id': track_id,
                    'position': [
                        random.uniform(-180, 180),  # longitude
                        random.uniform(-90, 90),    # latitude
                        random.uniform(0, 10000)    # altitude
                    ],
                    'velocity': [
                        random.uniform(-1, 1),
                        random.uniform(-1, 1),
                        random.uniform(-0.5, 0.5)
                    ],
                    'threatLevel': random.choice(['low', 'medium', 'high', 'unknown']),
                    'type': random.choice(['aircraft', 'vessel', 'ground', 'unknown']),
                    'lastUpdated': datetime.datetime.now().isoformat()
                }
        
        # Randomly update system status
        if random.random() < 0.1:  # 10% chance of status change
            system_status['threat_level'] = random.choice(['low', 'medium', 'high'])
            system_status['last_updated'] = datetime.datetime.now().isoformat()
            
            # Emit system status update
            socketio.emit('system_update', {
                'type': 'system_status',
                'status': system_status
            })
        
        # Emit track updates
        socketio.emit('tracks_update', {
            'type': 'tracks_update',
            'tracks': list(tracks_db.values())
        })
        
        # Sleep before next update
        time.sleep(2)

# Start simulation thread
if __name__ == '__main__':
    # Start simulation in a separate thread
    sim_thread = threading.Thread(target=simulation_thread)
    sim_thread.daemon = True
    sim_thread.start()
    
    # Start the server
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
