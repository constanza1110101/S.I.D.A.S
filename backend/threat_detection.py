# backend/threat_detection.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import time
import json
import logging
from datetime import datetime

from config import THREAT_LEVELS, THREAT_DETECTION_INTERVAL

logger = logging.getLogger('sidas.threat_detection')

class ThreatDetector:
    def __init__(self, model_path=None):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.load_or_create_model()
        self.feature_columns = [
            'velocity_magnitude', 'altitude', 'direction_change_rate',
            'acceleration', 'proximity_to_restricted', 'signal_pattern_score',
            'historical_threat_score'
        ]
        
    def load_or_create_model(self):
        """Load existing model or create a new one"""
        if self.model_path and os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded threat detection model from {self.model_path}")
                return
            except Exception as e:
                logger.error(f"Failed to load model: {str(e)}")
        
        # Create new model
        logger.info("Creating new threat detection model")
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        
    def save_model(self, path=None):
        """Save the current model"""
        save_path = path or self.model_path
        if save_path:
            try:
                joblib.dump(self.model, save_path)
                logger.info(f"Saved threat detection model to {save_path}")
            except Exception as e:
                logger.error(f"Failed to save model: {str(e)}")
    
    def extract_features(self, track_data):
        """Extract features from track data for anomaly detection"""
        features = {}
        
        # Calculate velocity magnitude
        vx, vy, vz = track_data['velocity']
        features['velocity_magnitude'] = np.sqrt(vx**2 + vy**2 + vz**2)
        
        # Use altitude directly
        features['altitude'] = track_data['position'][2]
        
        # Direction change rate (placeholder - would need historical data)
        features['direction_change_rate'] = track_data.get('direction_change_rate', 0.0)
        
        # Acceleration (placeholder - would need historical data)
        features['acceleration'] = track_data.get('acceleration', 0.0)
        
        # Proximity to restricted areas (placeholder)
        features['proximity_to_restricted'] = track_data.get('proximity_to_restricted', 100.0)
        
        # Signal pattern score (placeholder)
        features['signal_pattern_score'] = track_data.get('signal_pattern_score', 0.0)
        
        # Historical threat score
        features['historical_threat_score'] = self._get_historical_threat_score(track_data['id'])
        
        return features
    
    def _get_historical_threat_score(self, track_id):
        """Get historical threat score for a track ID"""
        # In a real implementation, this would query a database
        # For now, return a random value
        return np.random.random() * 0.3
    
    def detect_threats(self, tracks):
        """
        Detect threats in the given tracks
        
        Args:
            tracks: List of track objects
            
        Returns:
            List of tracks with threat levels assigned
        """
        if not tracks:
            return []
            
        # Extract features for each track
        feature_data = []
        for track in tracks:
            features = self.extract_features(track)
            feature_data.append(features)
            
        # Convert to DataFrame
        df = pd.DataFrame(feature_data)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(df)
        
        # Predict anomaly scores
        if not self.model.get_params().get('_fitted', False):
            # If model not fitted, fit it first
            logger.info("Fitting threat detection model")
            self.model.fit(scaled_features)
            self.save_model()
            
        # Get anomaly scores
        anomaly_scores = self.model.decision_function(scaled_features)
        
        # Normalize scores to 0-1 range where 0 is most anomalous
        normalized_scores = (anomaly_scores - np.min(anomaly_scores)) / (np.max(anomaly_scores) - np.min(anomaly_scores))
        
        # Assign threat levels based on scores
        for i, track in enumerate(tracks):
            score = normalized_scores[i]
            if score < 0.25:
                track['threatLevel'] = 'high'
            elif score < 0.5:
                track['threatLevel'] = 'medium'
            else:
                track['threatLevel'] = 'low'
                
            # Add anomaly score for reference
            track['anomalyScore'] = float(score)
            
        return tracks
    
    def update_model(self, labeled_data):
        """
        Update the model with new labeled data
        
        Args:
            labeled_data: DataFrame with features and labels
        """
        if labeled_data.empty:
            return
            
        # Scale features
        features = labeled_data[self.feature_columns]
        scaled_features = self.scaler.fit_transform(features)
        
        # Update model
        self.model.fit(scaled_features)
        self.save_model()
        logger.info("Updated threat detection model with new data")


class ThreatAnalyzer:
    def __init__(self, detector):
        self.detector = detector
        self.current_threat_level = 'low'
        self.last_analysis_time = 0
        self.threat_history = []
        
    def analyze_system_threat(self, tracks, current_time=None):
        """
        Analyze overall system threat level based on all tracks
        
        Args:
            tracks: List of track objects
            current_time: Current timestamp (defaults to time.time())
            
        Returns:
            Dictionary with system threat assessment
        """
        current_time = current_time or time.time()
        
        # Check if we need to run analysis based on interval
        if current_time - self.last_analysis_time < THREAT_DETECTION_INTERVAL:
            return {
                'threat_level': self.current_threat_level,
                'last_updated': self.last_analysis_time
            }
            
        # Process tracks through detector
        processed_tracks = self.detector.detect_threats(tracks)
        
        # Count threats by level
        threat_counts = {level: 0 for level in THREAT_LEVELS}
        for track in processed_tracks:
            threat_counts[track['threatLevel']] += 1
            
        # Determine overall threat level
        if threat_counts.get('critical', 0) > 0:
            system_threat = 'critical'
        elif threat_counts.get('high', 0) > 2:
            system_threat = 'high'
        elif threat_counts.get('high', 0) > 0 or threat_counts.get('medium', 0) > 3:
            system_threat = 'medium'
        else:
            system_threat = 'low'
            
        # Update state
        self.current_threat_level = system_threat
        self.last_analysis_time = current_time
        
        # Record in history
        self.threat_history.append({
            'timestamp': current_time,
            'threat_level': system_threat,
            'track_count': len(tracks),
            'threat_counts': threat_counts
        })
        
        # Keep history at a reasonable size
        if len(self.threat_history) > 1000:
            self.threat_history = self.threat_history[-1000:]
            
        return {
            'threat_level': system_threat,
            'threat_counts': threat_counts,
            'track_count': len(tracks),
            'last_updated': current_time
        }
    
    def get_threat_history(self, hours=24):
        """Get threat level history for the specified number of hours"""
        current_time = time.time()
        cutoff_time = current_time - (hours * 3600)
        
        filtered_history = [
            entry for entry in self.threat_history 
            if entry['timestamp'] >= cutoff_time
        ]
        
        return filtered_history
    
    def generate_threat_report(self):
        """Generate a comprehensive threat report"""
        current_time = time.time()
        
        # Get recent history
        recent_history = self.get_threat_history(hours=24)
        
        # Calculate time at each threat level
        level_durations = {level: 0 for level in THREAT_LEVELS}
        prev_entry = None
        
        for entry in recent_history:
            if prev_entry:
                duration = entry['timestamp'] - prev_entry['timestamp']
                level_durations[prev_entry['threat_level']] += duration
            prev_entry = entry
            
        # Add time for current level
        if prev_entry:
            duration = current_time - prev_entry['timestamp']
            level_durations[prev_entry['threat_level']] += duration
            
        # Calculate percentages
        total_time = sum(level_durations.values())
        level_percentages = {
            level: (duration / total_time * 100) if total_time > 0 else 0 
            for level, duration in level_durations.items()
        }
        
        return {
            'current_threat_level': self.current_threat_level,
            'last_updated': self.last_analysis_time,
            'report_time': current_time,
            'monitoring_period_hours': 24,
            'level_durations': level_durations,
            'level_percentages': level_percentages,
            'threat_trend': self._calculate_threat_trend(recent_history),
            'peak_threat_time': self._find_peak_threat_time(recent_history),
            'recommendation': self._generate_recommendation()
        }
    
    def _calculate_threat_trend(self, history):
        """Calculate the trend in threat levels"""
        if not history or len(history) < 2:
            return 'stable'
            
        # Convert threat levels to numeric values
        level_values = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        # Get values for last 10 entries or all if fewer
        recent = history[-10:]
        values = [level_values[entry['threat_level']] for entry in recent]
        
        # Simple linear regression to determine trend
        x = np.arange(len(values))
        y = np.array(values)
        
        if len(x) < 2:
            return 'stable'
            
        slope = np.polyfit(x, y, 1)[0]
        
        if slope > 0.1:
            return 'increasing'
        elif slope < -0.1:
            return 'decreasing'
        else:
            return 'stable'
    
    def _find_peak_threat_time(self, history):
        """Find the time with the highest threat level"""
        if not history:
            return None
            
        # Convert threat levels to numeric values
        level_values = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        peak_entry = max(
            history, 
            key=lambda entry: level_values[entry['threat_level']]
        )
        
        return peak_entry['timestamp']
    
    def _generate_recommendation(self):
        """Generate a recommendation based on current threat level"""
        if self.current_threat_level == 'critical':
            return "Activate all defensive measures and alert command personnel immediately."
        elif self.current_threat_level == 'high':
            return "Heighten security protocols and prepare defensive systems."
        elif self.current_threat_level == 'medium':
            return "Increase monitoring frequency and verify defensive readiness."
        else:
            return "Maintain standard monitoring protocols."
