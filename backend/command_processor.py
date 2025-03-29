# backend/command_processor.py
import logging
import time
import threading
import json
import uuid
from enum import Enum

logger = logging.getLogger('sidas.command')

class CommandStatus(Enum):
    ISSUED = "issued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"

class CommandProcessor:
    def __init__(self, database, security_system, threat_analyzer):
        self.db = database
        self.security_system = security_system
        self.threat_analyzer = threat_analyzer
        self.command_handlers = {
            # Track commands
            'track_focus': self.handle_track_focus,
            'track_analyze': self.handle_track_analyze,
            'track_intercept': self.handle_track_intercept,
            
            # System commands
            'system_scan': self.handle_system_scan,
            'defense_activate': self.handle_defense_activate,
            'system_reset': self.handle_system_reset,
            'emergency_protocol': self.handle_emergency_protocol
        }
        
    def process_command(self, user_id, command_type, target_id=None, parameters=None):
        """
        Process a command
        
        Args:
            user_id: ID of the user issuing the command
            command_type: Type of command
            target_id: Optional target ID
            parameters: Optional command parameters
            
        Returns:
            Dict with command result
        """
        # Log the command
        command_id = self.db.log_command(
            user_id, command_type, target_id, parameters
        )
        
        if not command_id:
            logger.error(f"Failed to log command: {command_type} by {user_id}")
            return {
                'success': False,
                'message': "Failed to process command",
                'command_id': None
            }
            
        # Check if command type is supported
        if command_type not in self.command_handlers:
            logger.warning(f"Unsupported command type: {command_type} by {user_id}")
            self.db.update_command_status(command_id, CommandStatus.REJECTED.value)
            return {
                'success': False,
                'message': f"Unsupported command type: {command_type}",
                'command_id': command_id
            }
            
        # Update command status to processing
        self.db.update_command_status(command_id, CommandStatus.PROCESSING.value)
        
        # Create audit log
        self.db.log_audit(
            action=f"command_{command_type}",
            user_id=user_id,
            details={
                'command_id': command_id,
                'target_id': target_id,
                'parameters': parameters
            }
        )
        
        # Process command in a separate thread
        command_thread = threading.Thread(
            target=self._execute_command,
            args=(command_id, user_id, command_type, target_id, parameters)
        )
        command_thread.daemon = True
        command_thread.start()
        
        return {
            'success': True,
            'message': f"Command {command_type} is being processed",
            'command_id': command_id
        }
    
    def _execute_command(self, command_id, user_id, command_type, target_id, parameters):
        """Execute a command in a separate thread"""
        try:
            # Get the appropriate handler
            handler = self.command_handlers[command_type]
            
            # Execute the handler
            result = handler(user_id, target_id, parameters)
            
            # Update command status based on result
            if result.get('success', False):
                self.db.update_command_status(command_id, CommandStatus.COMPLETED.value)
            else:
                self.db.update_command_status(command_id, CommandStatus.FAILED.value)
                
            # Log the result
            self.db.log_system_event(
                event_type=f"command_result_{command_type}",
                data={
                    'command_id': command_id,
                    'user_id': user_id,
                    'result': result
                },
                severity='info' if result.get('success', False) else 'warning'
            )
            
        except Exception as e:
            logger.error(f"Error executing command {command_type}: {str(e)}")
            self.db.update_command_status(command_id, CommandStatus.FAILED.value)
            
            # Log the error
            self.db.log_system_event(
                event_type=f"command_error_{command_type}",
                data={
                    'command_id': command_id,
                    'user_id': user_id,
                    'error': str(e)
                },
                severity='error'
            )
    
    def handle_track_focus(self, user_id, target_id, parameters):
        """Handle track focus command"""
        if not target_id:
            return {'success': False, 'message': "No target specified"}
            
        # Get track from database
        track = self.db.get_track(target_id)
        
        if not track:
            return {'success': False, 'message': f"Track {target_id} not found"}
            
        # Simulate focusing on the track
        time.sleep(1)  # Simulate processing time
        
        return {
            'success': True,
            'message': f"Focus on track {target_id} complete",
            'track_data': track['data']
        }
    
    def handle_track_analyze(self, user_id, target_id, parameters):
        """Handle track analyze command"""
        if not target_id:
            return {'success': False, 'message': "No target specified"}
            
        # Get track from database
        track = self.db.get_track(target_id)
        
        if not track:
            return {'success': False, 'message': f"Track {target_id} not found"}
            
        # Simulate analysis
        time.sleep(2)  # Simulate processing time
        
        # Generate analysis result
        analysis = {
            'track_id': target_id,
            'threat_level': track['threat_level'],
            'confidence': 0.85,
            'analysis_time': int(time.time()),
            'estimated_type': track['data']['type'],
            'velocity_magnitude': sum(v**2 for v in track['data']['velocity'])**0.5,
            'recommendation': self._generate_track_recommendation(track['data'])
        }
        
        return {
            'success': True,
            'message': f"Analysis of track {target_id} complete",
            'analysis': analysis
        }
    
    def handle_track_intercept(self, user_id, target_id, parameters):
        """Handle track intercept command"""
        if not target_id:
            return {'success': False, 'message': "No target specified"}
            
        # Get track from database
        track = self.db.get_track(target_id)
        
        if not track:
            return {'success': False, 'message': f"Track {target_id} not found"}
            
        # Check threat level - only intercept medium or higher
        if track['threat_level'] not in ['medium', 'high', 'critical']:
            return {
                'success': False, 
                'message': f"Interception rejected: Threat level {track['threat_level']} too low"
            }
            
        # Simulate interception
        time.sleep(3)  # Simulate processing time
        
        # Generate intercept plan
        intercept_id = f"intercept-{uuid.uuid4().hex[:8]}"
        intercept_plan = {
            'intercept_id': intercept_id,
            'track_id': target_id,
            'status': 'initiated',
            'initiation_time': int(time.time()),
            'estimated_intercept_time': int(time.time()) + 300,  # 5 minutes in the future
            'coordinates': track['data']['position'],
            'assets_deployed': ['defensive_system_alpha']
        }
        
        return {
            'success': True,
            'message': f"Interception of track {target_id} initiated",
            'intercept_plan': intercept_plan
        }
    
    def handle_system_scan(self, user_id, target_id, parameters):
        """Handle system scan command"""
        # Simulate system scan
        time.sleep(2)  # Simulate processing time
        
        # Get all active tracks
        tracks = self.db.get_all_tracks(active_only=True)
        
        # Process tracks through threat detector
        track_data = [track['data'] for track in tracks]
        if track_data:
            processed_tracks = self.threat_analyzer.detector.detect_threats(track_data)
            
            # Update tracks in database with new threat levels
            for track in processed_tracks:
                self.db.update_track(track['id'], track)
        
        # Generate scan report
        scan_report = {
            'scan_id': f"scan-{uuid.uuid4().hex[:8]}",
            'scan_time': int(time.time()),
            'tracks_analyzed': len(tracks),
            'threat_summary': {
                'low': sum(1 for t in tracks if t['threat_level'] == 'low'),
                'medium': sum(1 for t in tracks if t['threat_level'] == 'medium'),
                'high': sum(1 for t in tracks if t['threat_level'] == 'high'),
                'critical': sum(1 for t in tracks if t['threat_level'] == 'critical')
            }
        }
        
        # Update system threat level
        system_threat = self.threat_analyzer.analyze_system_threat([t['data'] for t in tracks])
        
        return {
            'success': True,
            'message': "System scan complete",
            'scan_report': scan_report,
            'system_threat': system_threat
        }
    
    def handle_defense_activate(self, user_id, target_id, parameters):
        """Handle defense activation command"""
        defense_level = parameters.get('level', 'standard') if parameters else 'standard'
        
        # Simulate defense activation
        time.sleep(2)  # Simulate processing time
        
        # Generate activation report
        activation_report = {
            'activation_id': f"defense-{uuid.uuid4().hex[:8]}",
            'activation_time': int(time.time()),
            'level': defense_level,
            'status': 'active',
            'systems': ['perimeter', 'core', 'communications'],
            'estimated_duration': 3600  # 1 hour
        }
        
        return {
            'success': True,
            'message': f"Defense systems activated at {defense_level} level",
            'activation_report': activation_report
        }
    
    def handle_system_reset(self, user_id, target_id, parameters):
        """Handle system reset command"""
        reset_type = parameters.get('type', 'soft') if parameters else 'soft'
        
        # Simulate system reset
        time.sleep(3)  # Simulate processing time
        
        # Generate reset report
        reset_report = {
            'reset_id': f"reset-{uuid.uuid4().hex[:8]}",
            'reset_time': int(time.time()),
            'type': reset_type,
            'status': 'completed',
            'systems_affected': ['tracking', 'analysis', 'communications'],
            'duration': 3  # 3 seconds
        }
        
        return {
            'success': True,
            'message': f"System {reset_type} reset completed",
            'reset_report': reset_report
        }
    
    def handle_emergency_protocol(self, user_id, target_id, parameters):
        """Handle emergency protocol command"""
        protocol_type = parameters.get('protocol', 'alpha') if parameters else 'alpha'
        
        # Simulate emergency protocol
        time.sleep(3)  # Simulate processing time
        
        # Generate protocol report
        protocol_report = {
            'protocol_id': f"emergency-{uuid.uuid4().hex[:8]}",
            'activation_time': int(time.time()),
            'type': protocol_type,
            'status': 'active',
            'systems': ['all'],
            'alert_level': 'critical',
            'estimated_duration': 7200  # 2 hours
        }
        
        return {
            'success': True,
            'message': f"Emergency protocol {protocol_type} activated",
            'protocol_report': protocol_report
        }
    
    def _generate_track_recommendation(self, track_data):
        """Generate a recommendation based on track data"""
        threat_level = track_data['threatLevel']
        track_type = track_data['type']
        
        if threat_level == 'high' or threat_level == 'critical':
            if track_type == 'aircraft':
                return "Scramble interceptors and establish communication."
            elif track_type == 'vessel':
                return "Deploy naval assets and issue warning."
            else:
                return "Activate defensive systems and prepare for engagement."
        elif threat_level == 'medium':
            return "Continue monitoring and prepare defensive options."
        else:
            return "Standard monitoring protocol."
