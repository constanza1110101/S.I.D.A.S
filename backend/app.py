# backend/app.py
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import random
import logging
import os
import json

from config import HOST, PORT, DEBUG
from database import Database
from auth import Authentication
from sidas import SIDAS
from threat_detection import ThreatDetector, ThreatAnalyzer
from command_processor import CommandProcessor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sidas.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('sidas.app')

# Initialize Flask app
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
db = Database()
auth = Authentication(db)
security_system = SIDAS()
threat_detector = ThreatDetector()
threat_analyzer = ThreatAnalyzer(threat_detector)
command_processor = CommandProcessor(db, security_system, threat_analyzer)

# In-memory track storage for simulation
tracks = {}
system_status = {
    'defense': 'online',
    'attack': 'standby',
    'tracking': 'online',
    'threat_level': 'low',
    'last_updated': int(time.time())
}

# Token required decorator
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        valid, user_data = auth.verify_token(token)
        
        if not valid:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(user_data, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Get client IP
    ip_address = request.remote_addr
    
    # Authenticate user
    success, message, user_data = auth.authenticate(username, password, ip_address)
    
    if success:
        # Generate token
        token = auth.generate_token(user_data)
        
        return jsonify({
            'token': token,
            'user': user_data,
            'message': message
        })
    else:
        return jsonify({'error': message}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Create user
    success, message = auth.create_user(username, password, role)
    
    if success:
        return jsonify({'message': message})
    else:
        return jsonify({'error': message}), 400

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(user_data):
    # Get client IP
    ip_address = request.remote_addr
    
    # Log logout
    auth.logout(user_data['username'], ip_address)
    
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/tracks', methods=['GET'])
@token_required
def get_tracks(user_data):
    # Get all active tracks
    active_tracks = db.get_all_tracks(active_only=True)
    
    # Extract track data
    track_list = [track['data'] for track in active_tracks]
    
    return jsonify(track_list)

@app.route('/api/tracks/<track_id>', methods=['GET'])
@token_required
def get_track(user_data, track_id):
    # Get track from database
    track = db.get_track(track_id)
    
    if track:
        return jsonify(track['data'])
    else:
        return jsonify({'error': 'Track not found'}), 404

@app.route('/api/status', methods=['GET'])
@token_required
def get_status(user_data):
    return jsonify(system_status)

@app.route('/api/command', methods=['POST'])
@token_required
def issue_command(user_data):
    data = request.get_json()
    command_type = data.get('type')
    target_id = data.get('target_id')
    parameters = data.get('parameters')
    
    if not command_type:
        return jsonify({'error': 'Command type required'}), 400
    
    # Process command
    result = command_processor.process_command(
        user_data['username'], command_type, target_id, parameters
    )
    
    if result['success']:
        # Broadcast command update to all clients
        socketio.emit('command_update', {
            'type': 'command_issued',
            'command': command_type,
            'target': target_id,
            'status': 'processing',
            'command_id': result['command_id']
        })
        
        return jsonify(result)
    else:
        return jsonify({'error': result['message']}), 400

@app.route('/api/threat/report', methods=['GET'])
@token_required
def get_threat_report(user_data):
    # Generate threat report
    report = threat_analyzer.generate_threat_report()
    return jsonify(report)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    # In production, verify authentication token here
    emit('connection_status', {'status': 'connected'})

# Simulation thread
def simulation_thread():
    """Simulate track updates and system events"""
    while True:
        # Generate or update random tracks
        for i in range(5):
            track_id = f"track-{i}"
            
            if track_id in tracks:
                # Update existing track
                track = tracks[track_id]
                
                # Update position based on velocity
                lon, lat, alt = track['position']
                vx, vy, vz = track['velocity']
                
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
                track['lastUpdated'] = int(time.time())
            else:
                # Create new track
                tracks[track_id] = {
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
                    'threatLevel': random.choice(['low', 'medium', 'high']),
                    'type': random.choice(['aircraft', 'vessel', 'ground', 'unknown']),
                    'lastUpdated': int(time.time())
                }
            
            # Update track in database
            db.update_track(track_id, tracks[track_id])
        
        # Process tracks through threat detection
        track_list = list(tracks.values())
        processed_tracks = threat_detector.detect_threats(track_list)
        
        # Update tracks with new threat levels
        for track in processed_tracks:
            tracks[track['id']] = track
            db.update_track(track['id'], track)
        
        # Update system threat level
        threat_assessment = threat_analyzer.analyze_system_threat(track_list)
        system_status['threat_level'] = threat_assessment['threat_level']
        system_status['last_updated'] = int(time.time())
        
        # Randomly update other system status
        if random.random() < 0.05:  # 5% chance of status change
            system_status['defense'] = random.choice(['online', 'degraded', 'offline'])
            system_status['attack'] = random.choice(['standby', 'ready', 'active'])
            system_status['tracking'] = random.choice(['online', 'degraded', 'offline'])
        
        # Emit track updates
        socketio.emit('tracks_update', {
            'type': 'tracks_update',
            'tracks': list(tracks.values())
        })
        
        # Emit system status update
        socketio.emit('system_update', {
            'type': 'system_status',
            'status': system_status
        })
        
        # Simulate random events
        if random.random() < 0.1:  # 10% chance of event
            event_type = random.choice([
                'new_track_detected',
                'track_lost',
                'threat_level_change',
                'system_alert'
            ])
            
            event_data = {
                'type': event_type,
                'timestamp': int(time.time())
            }
            
            if event_type == 'new_track_detected':
                random_track = random.choice(list(tracks.values()))
                event_data['track'] = random_track
                
            elif event_type == 'track_lost':
                random_track_id = random.choice(list(tracks.keys()))
                event_data['track_id'] = random_track_id
                
            elif event_type == 'threat_level_change':
                event_data['previous_level'] = system_status['threat_level']
                event_data['new_level'] = random.choice(['low', 'medium', 'high'])
                system_status['threat_level'] = event_data['new_level']
                
            elif event_type == 'system_alert':
                event_data['alert'] = random.choice([
                    'Perimeter breach detected',
                    'Communication system degraded',
                    'Sensor array offline',
                    'Unauthorized access attempt'
                ])
                event_data['severity'] = random.choice(['info', 'warning', 'critical'])
            
            # Emit event
            socketio.emit('system_event', event_data)
            
            # Log event in database
            db.log_system_event(
                event_type=event_type,
                data=event_data,
                severity='info'
            )
        
        # Sleep before next update
        time.sleep(2)

# Start the application
if __name__ == '__main__':
    # Create default admin user if it doesn't exist
    admin_user = db.get_user('admin')
    if not admin_user:
        auth.create_user('admin', 'admin123', 'admin')
        logger.info("Created default admin user")
    
    # Start simulation in a separate thread
    sim_thread = threading.Thread(target=simulation_thread)
    sim_thread.daemon = True
    sim_thread.start()
    
    # Start the server
    logger.info(f"Starting SIDAS server on {HOST}:{PORT}")
    socketio.run(app, debug=DEBUG, host=HOST, port=PORT)
