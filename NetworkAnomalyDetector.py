import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import pandas as pd
import logging
import time
import json
import os
import threading
import socket
import ipaddress
import hashlib
import datetime
from typing import Dict, List, Tuple, Any, Optional, Union
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64

class NetworkAnomalyDetector:
    """
    Network Anomaly Detection System for S.I.D.A.S
    
    This class implements multiple anomaly detection algorithms to identify
    suspicious network traffic patterns that may indicate cyber attacks.
    """
    
    def __init__(self, config_path=None, database=None, event_system=None):
        """
        Initialize the Network Anomaly Detector
        
        Args:
            config_path: Path to configuration file
            database: Database connection for logging and persistence
            event_system: Event system for publishing security events
        """
        # Initialize logger
        self.logger = logging.getLogger('sidas.security.anomaly')
        
        # Load configuration
        self.config = self.load_config(config_path)
        
        # Initialize models
        self.isolation_forest = IsolationForest(
            n_estimators=self.config.get('isolation_forest', {}).get('n_estimators', 100),
            contamination=self.config.get('isolation_forest', {}).get('contamination', 0.01),
            random_state=42
        )
        
        self.dbscan = DBSCAN(
            eps=self.config.get('dbscan', {}).get('eps', 0.5),
            min_samples=self.config.get('dbscan', {}).get('min_samples', 5)
        )
        
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=2)  # For visualization
        
        # Model state
        self.is_trained = False
        self.baseline = None
        self.feature_names = None
        self.training_data_stats = None
        
        # Database connection
        self.database = database
        
        # Event system
        self.event_system = event_system
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.stop_monitoring = threading.Event()
        
        # Known attack patterns
        self.attack_patterns = self.load_attack_patterns()
        
        # Anomaly history
        self.anomaly_history = []
        self.max_history_size = self.config.get('max_history_size', 1000)
        
        # Performance metrics
        self.performance_metrics = {
            'detection_time': [],
            'false_positives': 0,
            'true_positives': 0,
            'detection_rate': 0
        }
        
        # Whitelist and blacklist
        self.ip_whitelist = set(self.config.get('ip_whitelist', []))
        self.ip_blacklist = set(self.config.get('ip_blacklist', []))
        
        # Load previous model if available
        model_path = self.config.get('model_path', 'models/anomaly_detector.pkl')
        if os.path.exists(model_path):
            self.load_model(model_path)
        
        self.logger.info("Network Anomaly Detector initialized")
    
    def load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dict with configuration parameters
        """
        default_config = {
            'isolation_forest': {
                'n_estimators': 100,
                'contamination': 0.01
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5
            },
            'monitoring': {
                'interval': 60,  # seconds
                'batch_size': 1000
            },
            'features': {
                'traffic_volume': True,
                'packet_size': True,
                'port_distribution': True,
                'protocol_distribution': True,
                'connection_duration': True,
                'packet_rate': True,
                'ip_entropy': True,
                'payload_entropy': True,
                'tcp_flags': True,
                'time_patterns': True
            },
            'thresholds': {
                'anomaly_score': -0.2,
                'alert_threshold': -0.5,
                'critical_threshold': -0.8
            },
            'visualization': {
                'enabled': True,
                'max_points': 1000
            },
            'model_path': 'models/anomaly_detector.pkl',
            'attack_patterns_path': 'config/attack_patterns.json',
            'max_history_size': 1000,
            'ip_whitelist': [],
            'ip_blacklist': []
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                
                # Update default config with user config
                self._update_dict(default_config, user_config)
                self.logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                self.logger.error(f"Error loading config from {config_path}: {str(e)}")
        
        return default_config
    
    def _update_dict(self, d: Dict, u: Dict) -> Dict:
        """
        Recursively update a dictionary
        
        Args:
            d: Dictionary to update
            u: Dictionary with updates
            
        Returns:
            Updated dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_dict(d[k], v)
            else:
                d[k] = v
        return d
    
    def load_attack_patterns(self) -> List[Dict[str, Any]]:
        """
        Load known attack patterns from file
        
        Returns:
            List of attack pattern dictionaries
        """
        patterns_path = self.config.get('attack_patterns_path', 'config/attack_patterns.json')
        
        if os.path.exists(patterns_path):
            try:
                with open(patterns_path, 'r') as f:
                    patterns = json.load(f)
                self.logger.info(f"Loaded {len(patterns)} attack patterns from {patterns_path}")
                return patterns
            except Exception as e:
                self.logger.error(f"Error loading attack patterns: {str(e)}")
        
        # Default patterns if file not found
        self.logger.warning(f"Attack patterns file not found at {patterns_path}, using defaults")
        return [
            {
                "name": "Port Scan",
                "features": {
                    "unique_ports": {"min": 20},
                    "packet_size": {"max": 100},
                    "duration": {"max": 30}
                },
                "severity": "medium"
            },
            {
                "name": "DDoS Attack",
                "features": {
                    "traffic_volume": {"min": 10000},
                    "unique_ips": {"min": 50},
                    "packet_rate": {"min": 1000}
                },
                "severity": "high"
            },
            {
                "name": "Brute Force",
                "features": {
                    "failed_logins": {"min": 10},
                    "unique_users": {"max": 3},
                    "duration": {"min": 60}
                },
                "severity": "high"
            },
            {
                "name": "Data Exfiltration",
                "features": {
                    "outbound_traffic": {"min": 50000},
                    "destination_entropy": {"min": 0.8},
                    "time_of_day": {"hour_range": [0, 5]}
                },
                "severity": "critical"
            }
        ]
    
    def preprocess_network_data(self, network_data: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess network traffic data for anomaly detection
        
        Args:
            network_data: DataFrame with network traffic data
            
        Returns:
            Preprocessed DataFrame
        """
        # Make a copy to avoid modifying the original
        data = network_data.copy()
        
        # Store feature names
        self.feature_names = list(data.columns)
        
        # Handle missing values
        data.fillna(0, inplace=True)
        
        # Convert categorical features (if any)
        for col in data.select_dtypes(include=['object']).columns:
            data[col] = data[col].astype('category').cat.codes
        
        # Add derived features if enabled in config
        features_config = self.config.get('features', {})
        
        if features_config.get('ip_entropy', True) and 'src_ip' in data.columns:
            data['src_ip_entropy'] = self._calculate_ip_entropy(data['src_ip'])
            
        if features_config.get('payload_entropy', True) and 'payload' in data.columns:
            data['payload_entropy'] = data['payload'].apply(self._calculate_string_entropy)
        
        if features_config.get('time_patterns', True) and 'timestamp' in data.columns:
            # Extract time features
            data['hour'] = pd.to_datetime(data['timestamp']).dt.hour
            data['day_of_week'] = pd.to_datetime(data['timestamp']).dt.dayofweek
            data['is_weekend'] = data['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
            data['is_business_hours'] = data['hour'].apply(lambda x: 1 if 9 <= x <= 17 else 0)
        
        # Remove non-numeric columns
        numeric_data = data.select_dtypes(include=['number'])
        
        return numeric_data
    
    def _calculate_ip_entropy(self, ip_series: pd.Series) -> float:
        """
        Calculate entropy of IP addresses
        
        Args:
            ip_series: Series of IP addresses
            
        Returns:
            Entropy value
        """
        try:
            # Count occurrences of each IP
            ip_counts = ip_series.value_counts(normalize=True)
            
            # Calculate entropy
            entropy = -np.sum(ip_counts * np.log2(ip_counts))
            
            return entropy
        except Exception as e:
            self.logger.error(f"Error calculating IP entropy: {str(e)}")
            return 0.0
    
    def _calculate_string_entropy(self, text: str) -> float:
        """
        Calculate entropy of a string
        
        Args:
            text: Input string
            
        Returns:
            Entropy value
        """
        try:
            if not text:
                return 0.0
                
            # Count occurrences of each character
            counts = {}
            for char in text:
                counts[char] = counts.get(char, 0) + 1
                
            # Calculate probabilities
            length = len(text)
            probabilities = [count / length for count in counts.values()]
            
            # Calculate entropy
            entropy = -sum(p * np.log2(p) for p in probabilities)
            
            return entropy
        except Exception as e:
            self.logger.error(f"Error calculating string entropy: {str(e)}")
            return 0.0
    
    def train(self, baseline_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Train the anomaly detection model
        
        Args:
            baseline_data: DataFrame with normal network traffic data
            
        Returns:
            Dict with training results
        """
        start_time = time.time()
        self.logger.info("Training anomaly detection model...")
        
        try:
            # Preprocess data
            processed_data = self.preprocess_network_data(baseline_data)
            
            # Scale the data
            scaled_data = self.scaler.fit_transform(processed_data)
            
            # Fit the Isolation Forest model
            self.isolation_forest.fit(scaled_data)
            
            # Fit DBSCAN for clustering
            self.dbscan.fit(scaled_data)
            
            # Fit PCA for visualization
            self.pca.fit(scaled_data)
            
            # Calculate baseline statistics
            self.baseline = {
                'mean': processed_data.mean(axis=0),
                'std': processed_data.std(axis=0),
                'quantiles': {
                    '25': np.percentile(processed_data, 25, axis=0),
                    '50': np.percentile(processed_data, 50, axis=0),
                    '75': np.percentile(processed_data, 75, axis=0),
                    '99': np.percentile(processed_data, 99, axis=0)
                }
            }
            
            # Store training data statistics
            self.training_data_stats = {
                'n_samples': len(processed_data),
                'feature_importance': self._calculate_feature_importance(scaled_data),
                'training_time': time.time() - start_time
            }
            
            self.is_trained = True
            
            # Save the model
            self.save_model()
            
            self.logger.info(f"Model training completed in {time.time() - start_time:.2f} seconds")
            
            return {
                'success': True,
                'training_time': time.time() - start_time,
                'n_samples': len(processed_data),
                'feature_names': self.feature_names,
                'message': "Model training completed successfully"
            }
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': "Error training model"
            }
    
    def _calculate_feature_importance(self, scaled_data: np.ndarray) -> Dict[str, float]:
        """
        Calculate feature importance based on Isolation Forest
        
        Args:
            scaled_data: Scaled training data
            
        Returns:
            Dict mapping feature names to importance scores
        """
        try:
            # Get feature importance from Isolation Forest
            feature_importance = np.mean([
                tree.feature_importances_ for tree in self.isolation_forest.estimators_
            ], axis=0)
            
            # Normalize to sum to 1
            feature_importance = feature_importance / np.sum(feature_importance)
            
            # Map to feature names
            importance_dict = {}
            for i, feature in enumerate(self.feature_names):
                importance_dict[feature] = float(feature_importance[i])
            
            return importance_dict
        except Exception as e:
            self.logger.error(f"Error calculating feature importance: {str(e)}")
            return {}
    
    def save_model(self, path: Optional[str] = None) -> bool:
        """
        Save the trained model to disk
        
        Args:
            path: Path to save the model (optional)
            
        Returns:
            Boolean indicating success
        """
        if not self.is_trained:
            self.logger.warning("Cannot save model: Model not trained")
            return False
        
        model_path = path or self.config.get('model_path', 'models/anomaly_detector.pkl')
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            # Save model and metadata
            model_data = {
                'isolation_forest': self.isolation_forest,
                'dbscan': self.dbscan,
                'scaler': self.scaler,
                'pca': self.pca,
                'baseline': self.baseline,
                'feature_names': self.feature_names,
                'training_data_stats': self.training_data_stats,
                'timestamp': datetime.datetime.now().isoformat(),
                'config': self.config
            }
            
            import joblib
            joblib.dump(model_data, model_path)
            
            self.logger.info(f"Model saved to {model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            return False
    
    def load_model(self, path: Optional[str] = None) -> bool:
        """
        Load a trained model from disk
        
        Args:
            path: Path to the model file (optional)
            
        Returns:
            Boolean indicating success
        """
        model_path = path or self.config.get('model_path', 'models/anomaly_detector.pkl')
        
        if not os.path.exists(model_path):
            self.logger.warning(f"Model file not found at {model_path}")
            return False
        
        try:
            import joblib
            model_data = joblib.load(model_path)
            
            self.isolation_forest = model_data['isolation_forest']
            self.dbscan = model_data['dbscan']
            self.scaler = model_data['scaler']
            self.pca = model_data['pca']
            self.baseline = model_data['baseline']
            self.feature_names = model_data['feature_names']
            self.training_data_stats = model_data['training_data_stats']
            
            # Update config if present in model data
            if 'config' in model_data:
                self._update_dict(self.config, model_data['config'])
            
            self.is_trained = True
            
            self.logger.info(f"Model loaded from {model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False
    
    def detect_anomalies(self, network_traffic: pd.DataFrame) -> Dict[str, Any]:
        """
        Detect anomalies in network traffic data
        
        Args:
            network_traffic: DataFrame with network traffic data
            
        Returns:
            Dict with anomaly detection results
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        start_time = time.time()
        
        try:
            # Preprocess data
            processed_data = self.preprocess_network_data(network_traffic)
            
            # Scale the data
            scaled_data = self.scaler.transform(processed_data)
            
            # Detect anomalies using Isolation Forest
            predictions = self.isolation_forest.predict(scaled_data)
            anomaly_scores = self.isolation_forest.decision_function(scaled_data)
            
            # Get DBSCAN clusters
            cluster_labels = self.dbscan.fit_predict(scaled_data)
            
            # Identify anomalies (where prediction is -1)
            anomaly_indices = np.where(predictions == -1)[0]
            anomalies = network_traffic.iloc[anomaly_indices].copy()
            
            if not anomalies.empty:
                # Add anomaly scores and cluster labels
                anomalies['anomaly_score'] = anomaly_scores[anomaly_indices]
                anomalies['cluster'] = cluster_labels[anomaly_indices]
                
                # Classify anomalies by severity
                thresholds = self.config.get('thresholds', {})
                alert_threshold = thresholds.get('alert_threshold', -0.5)
                critical_threshold = thresholds.get('critical_threshold', -0.8)
                
                anomalies['severity'] = 'low'
                anomalies.loc[anomalies['anomaly_score'] <= alert_threshold, 'severity'] = 'medium'
                anomalies.loc[anomalies['anomaly_score'] <= critical_threshold, 'severity'] = 'high'
                
                # Match against known attack patterns
                anomalies['attack_type'] = anomalies.apply(
                    lambda row: self._match_attack_pattern(row), axis=1
                )
                
                # Log anomalies
                for _, anomaly in anomalies.iterrows():
                    self.logger.warning(
                        f"Network anomaly detected: score={anomaly['anomaly_score']:.4f}, "
                        f"severity={anomaly['severity']}, "
                        f"type={anomaly['attack_type'] or 'unknown'}"
                    )
                    
                    # Record in database if available
                    if self.database:
                        self.database.log_security_event(
                            event_type="network_anomaly",
                            data={
                                'timestamp': datetime.datetime.now().isoformat(),
                                'anomaly_score': float(anomaly['anomaly_score']),
                                'severity': anomaly['severity'],
                                'attack_type': anomaly['attack_type'],
                                'details': anomaly.to_dict()
                            },
                            severity=anomaly['severity']
                        )
                    
                    # Publish event if event system is available
                    if self.event_system:
                        self.event_system.publish(
                            'security_alert',
                            {
                                'type': 'network_anomaly',
                                'timestamp': datetime.datetime.now().isoformat(),
                                'anomaly_score': float(anomaly['anomaly_score']),
                                'severity': anomaly['severity'],
                                'attack_type': anomaly['attack_type'],
                                'details': anomaly.to_dict()
                            }
                        )
                
                # Add to anomaly history
                for _, anomaly in anomalies.iterrows():
                    self.anomaly_history.append({
                        'timestamp': datetime.datetime.now().isoformat(),
                        'anomaly_score': float(anomaly['anomaly_score']),
                        'severity': anomaly['severity'],
                        'attack_type': anomaly['attack_type'],
                        'details': anomaly.to_dict()
                    })
                
                # Trim history if it gets too large
                if len(self.anomaly_history) > self.max_history_size:
                    self.anomaly_history = self.anomaly_history[-self.max_history_size:]
            
            # Update performance metrics
            detection_time = time.time() - start_time
            self.performance_metrics['detection_time'].append(detection_time)
            
            # Trim detection time history if it gets too large
            if len(self.performance_metrics['detection_time']) > 100:
                self.performance_metrics['detection_time'] = self.performance_metrics['detection_time'][-100:]
            
            # Generate visualizations if enabled
            visualizations = {}
            if self.config.get('visualization', {}).get('enabled', True):
                visualizations = self._generate_visualizations(
                    network_traffic, scaled_data, predictions, anomaly_scores
                )
            
            return {
                'anomalies': anomalies,
                'indices': anomaly_indices.tolist(),
                'scores': anomaly_scores[anomaly_indices].tolist(),
                'total_samples': len(network_traffic),
                'anomaly_count': len(anomaly_indices),
                'detection_time': detection_time,
                'visualizations': visualizations,
                'clusters': {
                    'labels': cluster_labels.tolist(),
                    'n_clusters': len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {str(e)}")
            raise
    
    def _match_attack_pattern(self, anomaly: pd.Series) -> Optional[str]:
        """
        Match an anomaly against known attack patterns
        
        Args:
            anomaly: Series with anomaly data
            
        Returns:
            String with attack type or None if no match
        """
        for pattern in self.attack_patterns:
            matches = True
            
            for feature, conditions in pattern.get('features', {}).items():
                if feature not in anomaly:
                    matches = False
                    break
                
                value = anomaly[feature]
                
                if 'min' in conditions and value < conditions['min']:
                    matches = False
                    break
                    
                if 'max' in conditions and value > conditions['max']:
                    matches = False
                    break
                    
                if 'equals' in conditions and value != conditions['equals']:
                    matches = False
                    break
                    
                if 'hour_range' in conditions:
                    hour = datetime.datetime.now().hour
                    if not (conditions['hour_range'][0] <= hour <= conditions['hour_range'][1]):
                        matches = False
                        break
            
            if matches:
                return pattern['name']
        
        return None
    
    def _generate_visualizations(
        self, 
        data: pd.DataFrame, 
        scaled_data: np.ndarray, 
        predictions: np.ndarray, 
        scores: np.ndarray
    ) -> Dict[str, str]:
        """
        Generate visualizations for anomaly detection results
        
        Args:
            data: Original data
            scaled_data: Scaled data
            predictions: Anomaly predictions (-1 for anomalies)
            scores: Anomaly scores
            
        Returns:
            Dict with visualization names and base64-encoded images
        """
        try:
            visualizations = {}
            
            # Limit number of points for visualization
            max_points = self.config.get('visualization', {}).get('max_points', 1000)
            if len(data) > max_points:
                indices = np.random.choice(len(data), max_points, replace=False)
                vis_data = data.iloc[indices]
                vis_scaled = scaled_data[indices]
                vis_pred = predictions[indices]
                vis_scores = scores[indices]
            else:
                vis_data = data
                vis_scaled = scaled_data
                vis_pred = predictions
                vis_scores = scores
            
            # PCA visualization
            plt.figure(figsize=(10, 8))
            pca_result = self.pca.transform(vis_scaled)
            
            plt.scatter(
                pca_result[vis_pred == 1, 0],
                pca_result[vis_pred == 1, 1],
                c='blue', label='Normal', alpha=0.5
            )
            
            plt.scatter(
                pca_result[vis_pred == -1, 0],
                pca_result[vis_pred == -1, 1],
                c='red', label='Anomaly', alpha=0.5
            )
            
            plt.title('PCA Visualization of Network Traffic')
            plt.xlabel('Principal Component 1')
            plt.ylabel('Principal Component 2')
            plt.legend()
            plt.grid(True)
            
            # Save to base64
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            visualizations['pca'] = base64.b64encode(buf.read()).decode('utf-8')
            plt.close()
            
            # Anomaly score distribution
            plt.figure(figsize=(10, 6))
            sns.histplot(vis_scores, bins=50, kde=True)
            plt.axvline(
                x=self.config.get('thresholds', {}).get('anomaly_score', -0.2),
                color='r', linestyle='--', label='Anomaly Threshold'
            )
            plt.title('Distribution of Anomaly Scores')
            plt.xlabel('Anomaly Score')
            plt.ylabel('Frequency')
            plt.legend()
            plt.grid(True)
            
            # Save to base64
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            visualizations['score_distribution'] = base64.b64encode(buf.read()).decode('utf-8')
            plt.close()
            
            # Feature importance
            if self.training_data_stats and 'feature_importance' in self.training_data_stats:
                plt.figure(figsize=(12, 8))
                feature_importance = self.training_data_stats['feature_importance']
                features = list(feature_importance.keys())
                importance = list(feature_importance.values())
                
                # Sort by importance
                sorted_idx = np.argsort(importance)
                features = [features[i] for i in sorted_idx]
                importance = [importance[i] for i in sorted_idx]
                
                sns.barplot(x=importance, y=features)
                plt.title('Feature Importance')
                plt.xlabel('Importance')
                plt.ylabel('Feature')
                plt.grid(True)
                
                # Save to base64
                buf = BytesIO()
                plt.savefig(buf, format='png')
                buf.seek(0)
                visualizations['feature_importance'] = base64.b64encode(buf.read()).decode('utf-8')
                plt.close()
            
            return visualizations
            
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {str(e)}")
            return {}
    
    def start_monitoring(self, data_source_callback, interval: Optional[int] = None) -> bool:
        """
        Start continuous monitoring for anomalies
        
        Args:
            data_source_callback: Function that returns new network data
            interval: Monitoring interval in seconds (optional)
            
        Returns:
            Boolean indicating success
        """
        if not self.is_trained:
            self.logger.error("Cannot start monitoring: Model not trained")
            return False
        
        if self.is_monitoring:
            self.logger.warning("Monitoring already active")
            return True
        
        self.stop_monitoring.clear()
        self.is_monitoring = True
        
        monitoring_interval = interval or self.config.get('monitoring', {}).get('interval', 60)
        
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(data_source_callback, monitoring_interval)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.logger.info(f"Started network monitoring with interval {monitoring_interval}s")
        return True
    
    def stop_monitoring(self) -> bool:
        """
        Stop continuous monitoring
        
        Returns:
            Boolean indicating success
        """
        if not self.is_monitoring:
            self.logger.warning("Monitoring not active")
            return True
        
        self.stop_monitoring.set()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.is_monitoring = False
        self.logger.info("Stopped network monitoring")
        return True
    
    def _monitoring_loop(self, data_source_callback, interval: int) -> None:
        """
        Main monitoring loop
        
        Args:
            data_source_callback: Function that returns new network data
            interval: Monitoring interval in seconds
        """
        while not self.stop_monitoring.is_set():
            try:
                # Get new data
                new_data = data_source_callback()
                
                if new_data is not None and not new_data.empty:
                    # Detect anomalies
                    result = self.detect_anomalies(new_data)
                    
                    # Process results if anomalies found
                    if result['anomaly_count'] > 0:
                        self.logger.info(
                                                        f"Detected {result['anomaly_count']} anomalies in {result['total_samples']} samples"
                        )
                        
                        # Trigger alerts for high severity anomalies
                        high_severity = result['anomalies'][result['anomalies']['severity'] == 'high']
                        if not high_severity.empty:
                            self._trigger_high_severity_alert(high_severity)
                    
                # Sleep until next interval
                self.stop_monitoring.wait(interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                # Sleep a bit longer after an error
                self.stop_monitoring.wait(interval * 2)
    
    def _trigger_high_severity_alert(self, high_severity_anomalies: pd.DataFrame) -> None:
        """
        Trigger alerts for high severity anomalies
        
        Args:
            high_severity_anomalies: DataFrame with high severity anomalies
        """
        for _, anomaly in high_severity_anomalies.iterrows():
            alert_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'anomaly_score': float(anomaly['anomaly_score']),
                'severity': 'high',
                'attack_type': anomaly['attack_type'] or 'unknown',
                'details': anomaly.to_dict()
            }
            
            # Log to database
            if self.database:
                self.database.log_security_event(
                    event_type="high_severity_anomaly",
                    data=alert_data,
                    severity="high"
                )
            
            # Publish alert event
            if self.event_system:
                self.event_system.publish(
                    'security_alert',
                    {
                        'type': 'high_severity_anomaly',
                        **alert_data
                    }
                )
            
            self.logger.critical(
                f"HIGH SEVERITY NETWORK ANOMALY: score={anomaly['anomaly_score']:.4f}, "
                f"type={anomaly['attack_type'] or 'unknown'}"
            )
    
    def get_anomaly_history(self, limit: Optional[int] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get history of detected anomalies
        
        Args:
            limit: Maximum number of anomalies to return (optional)
            severity: Filter by severity (optional)
            
        Returns:
            List of anomaly dictionaries
        """
        if severity:
            filtered_history = [a for a in self.anomaly_history if a['severity'] == severity]
        else:
            filtered_history = self.anomaly_history
        
        # Sort by timestamp (newest first)
        sorted_history = sorted(
            filtered_history,
            key=lambda x: x['timestamp'],
            reverse=True
        )
        
        if limit:
            return sorted_history[:limit]
        return sorted_history
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics for the anomaly detector
        
        Returns:
            Dict with performance metrics
        """
        metrics = self.performance_metrics.copy()
        
        # Calculate average detection time
        if metrics['detection_time']:
            metrics['avg_detection_time'] = sum(metrics['detection_time']) / len(metrics['detection_time'])
        else:
            metrics['avg_detection_time'] = 0
        
        # Calculate detection rate
        total_detections = metrics['true_positives'] + metrics['false_positives']
        if total_detections > 0:
            metrics['detection_rate'] = metrics['true_positives'] / total_detections
        else:
            metrics['detection_rate'] = 0
        
        return metrics
    
    def update_whitelist(self, ip_addresses: List[str], add: bool = True) -> Dict[str, Any]:
        """
        Update IP whitelist
        
        Args:
            ip_addresses: List of IP addresses
            add: True to add, False to remove
            
        Returns:
            Dict with update result
        """
        try:
            # Validate IP addresses
            valid_ips = []
            invalid_ips = []
            
            for ip in ip_addresses:
                try:
                    ipaddress.ip_address(ip)
                    valid_ips.append(ip)
                except ValueError:
                    invalid_ips.append(ip)
            
            # Update whitelist
            if add:
                self.ip_whitelist.update(valid_ips)
            else:
                self.ip_whitelist.difference_update(valid_ips)
            
            # Save updated config
            self._save_config_updates()
            
            return {
                'success': True,
                'action': 'add' if add else 'remove',
                'valid_ips': valid_ips,
                'invalid_ips': invalid_ips,
                'whitelist_size': len(self.ip_whitelist)
            }
            
        except Exception as e:
            self.logger.error(f"Error updating whitelist: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_blacklist(self, ip_addresses: List[str], add: bool = True) -> Dict[str, Any]:
        """
        Update IP blacklist
        
        Args:
            ip_addresses: List of IP addresses
            add: True to add, False to remove
            
        Returns:
            Dict with update result
        """
        try:
            # Validate IP addresses
            valid_ips = []
            invalid_ips = []
            
            for ip in ip_addresses:
                try:
                    ipaddress.ip_address(ip)
                    valid_ips.append(ip)
                except ValueError:
                    invalid_ips.append(ip)
            
            # Update blacklist
            if add:
                self.ip_blacklist.update(valid_ips)
            else:
                self.ip_blacklist.difference_update(valid_ips)
            
            # Save updated config
            self._save_config_updates()
            
            return {
                'success': True,
                'action': 'add' if add else 'remove',
                'valid_ips': valid_ips,
                'invalid_ips': invalid_ips,
                'blacklist_size': len(self.ip_blacklist)
            }
            
        except Exception as e:
            self.logger.error(f"Error updating blacklist: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _save_config_updates(self) -> None:
        """Save updated configuration to file"""
        config_path = self.config.get('config_path')
        if not config_path:
            return
            
        try:
            # Update config with current values
            self.config['ip_whitelist'] = list(self.ip_whitelist)
            self.config['ip_blacklist'] = list(self.ip_blacklist)
            
            # Save to file
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
                
            self.logger.info(f"Updated configuration saved to {config_path}")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive security report
        
        Returns:
            Dict with report data
        """
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'model_status': {
                'is_trained': self.is_trained,
                'is_monitoring': self.is_monitoring
            },
            'statistics': {
                'total_anomalies_detected': len(self.anomaly_history),
                'anomalies_by_severity': {
                    'high': len([a for a in self.anomaly_history if a['severity'] == 'high']),
                    'medium': len([a for a in self.anomaly_history if a['severity'] == 'medium']),
                    'low': len([a for a in self.anomaly_history if a['severity'] == 'low'])
                },
                'anomalies_by_type': {}
            },
            'performance': self.get_performance_metrics(),
            'recent_anomalies': self.get_anomaly_history(limit=10),
            'configuration': {
                'thresholds': self.config.get('thresholds', {}),
                'whitelist_size': len(self.ip_whitelist),
                'blacklist_size': len(self.ip_blacklist)
            }
        }
        
        # Count anomalies by attack type
        attack_types = {}
        for anomaly in self.anomaly_history:
            attack_type = anomaly['attack_type'] or 'unknown'
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        report['statistics']['anomalies_by_type'] = attack_types
        
        # Add training data stats if available
        if self.training_data_stats:
            report['model'] = {
                'training_samples': self.training_data_stats.get('n_samples', 0),
                'training_time': self.training_data_stats.get('training_time', 0),
                'top_features': sorted(
                    self.training_data_stats.get('feature_importance', {}).items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
            }
        
        return report


class NetworkTrafficCollector:
    """
    Collects network traffic data for anomaly detection
    """
    def __init__(self, interface=None, config=None):
        """
        Initialize the network traffic collector
        
        Args:
            interface: Network interface to monitor
            config: Configuration dictionary
        """
        self.logger = logging.getLogger('sidas.security.collector')
        self.interface = interface
        self.config = config or {}
        self.packet_buffer = []
        self.max_buffer_size = self.config.get('max_buffer_size', 10000)
        self.is_collecting = False
        self.stop_collection = threading.Event()
        self.collection_thread = None
        
        # Initialize pcap if available
        try:
            import pcap
            self.pcap_available = True
            self.pcap = pcap
        except ImportError:
            self.logger.warning("pcap module not available, falling back to simulated data")
            self.pcap_available = False
    
    def start_collection(self) -> bool:
        """
        Start collecting network traffic
        
        Returns:
            Boolean indicating success
        """
        if self.is_collecting:
            self.logger.warning("Collection already active")
            return True
        
        self.stop_collection.clear()
        self.is_collecting = True
        
        self.collection_thread = threading.Thread(
            target=self._collection_loop
        )
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        self.logger.info(f"Started network traffic collection on interface {self.interface}")
        return True
    
    def stop_collection(self) -> bool:
        """
        Stop collecting network traffic
        
        Returns:
            Boolean indicating success
        """
        if not self.is_collecting:
            self.logger.warning("Collection not active")
            return True
        
        self.stop_collection.set()
        
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        
        self.is_collecting = False
        self.logger.info("Stopped network traffic collection")
        return True
    
    def _collection_loop(self) -> None:
        """Main collection loop"""
        if self.pcap_available and self.interface:
            self._collect_real_traffic()
        else:
            self._generate_simulated_traffic()
    
    def _collect_real_traffic(self) -> None:
        """Collect real network traffic using pcap"""
        try:
            # Open pcap capture
            p = self.pcap.pcap(name=self.interface, promisc=True, immediate=True)
            
            # Set filter if configured
            pcap_filter = self.config.get('pcap_filter')
            if pcap_filter:
                p.setfilter(pcap_filter)
            
            self.logger.info(f"Started pcap capture on {self.interface}")
            
            # Process packets
            for timestamp, packet in p:
                if self.stop_collection.is_set():
                    break
                
                try:
                    # Process packet (simplified)
                    packet_data = self._process_packet(timestamp, packet)
                    
                    if packet_data:
                        self.packet_buffer.append(packet_data)
                        
                        # Trim buffer if it gets too large
                        if len(self.packet_buffer) > self.max_buffer_size:
                            self.packet_buffer = self.packet_buffer[-self.max_buffer_size:]
                
                except Exception as e:
                    self.logger.error(f"Error processing packet: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Error in pcap capture: {str(e)}")
    
    def _process_packet(self, timestamp, packet) -> Dict[str, Any]:
        """
        Process a raw packet into structured data
        
        Args:
            timestamp: Packet timestamp
            packet: Raw packet data
            
        Returns:
            Dict with processed packet data
        """
        # This is a simplified implementation
        # In a real system, this would parse packet headers and extract features
        
        try:
            # Parse Ethernet header
            eth_length = 14
            eth_header = packet[:eth_length]
            
            # Parse IP header
            ip_header = packet[eth_length:20+eth_length]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            
            # Get TCP/UDP header based on protocol
            if protocol == 6:  # TCP
                t = packet[eth_length+iph_length:eth_length+iph_length+20]
                tcph = struct.unpack('!HHLLBBHHH', t)
                
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                flags = tcph[5]
                
                return {
                    'timestamp': timestamp,
                    'protocol': 'TCP',
                    'src_ip': s_addr,
                    'dst_ip': d_addr,
                    'src_port': source_port,
                    'dst_port': dest_port,
                    'length': len(packet),
                    'flags': flags,
                    'sequence': sequence,
                    'acknowledgement': acknowledgement
                }
                
            elif protocol == 17:  # UDP
                u = packet[eth_length+iph_length:eth_length+iph_length+8]
                udph = struct.unpack('!HHHH', u)
                
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                
                return {
                    'timestamp': timestamp,
                    'protocol': 'UDP',
                    'src_ip': s_addr,
                    'dst_ip': d_addr,
                    'src_port': source_port,
                    'dst_port': dest_port,
                    'length': length
                }
                
            else:
                return {
                    'timestamp': timestamp,
                    'protocol': protocol,
                    'src_ip': s_addr,
                    'dst_ip': d_addr,
                    'length': len(packet)
                }
                
        except Exception as e:
            self.logger.error(f"Error parsing packet: {str(e)}")
            return None
    
    def _generate_simulated_traffic(self) -> None:
        """Generate simulated network traffic for testing"""
        self.logger.info("Generating simulated network traffic")
        
        # List of simulated protocols
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH']
        
        # List of simulated IP addresses
        ips = [f'192.168.1.{i}' for i in range(1, 20)] + [f'10.0.0.{i}' for i in range(1, 20)]
        
        # Common ports
        common_ports = [80, 443, 22, 21, 25, 53, 3389, 8080, 8443]
        
        while not self.stop_collection.is_set():
            # Generate a batch of simulated packets
            batch_size = np.random.randint(10, 100)
            
            for _ in range(batch_size):
                # Generate random packet data
                protocol = np.random.choice(protocols)
                src_ip = np.random.choice(ips)
                dst_ip = np.random.choice(ips)
                
                while src_ip == dst_ip:
                    dst_ip = np.random.choice(ips)
                
                src_port = np.random.choice(common_ports) if np.random.random() < 0.7 else np.random.randint(1024, 65535)
                dst_port = np.random.choice(common_ports) if np.random.random() < 0.7 else np.random.randint(1024, 65535)
                
                # Packet length follows a more realistic distribution
                length = int(np.random.exponential(500)) + 40
                
                # Generate timestamp
                timestamp = time.time()
                
                packet_data = {
                    'timestamp': timestamp,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'length': length
                }
                
                # Add TCP-specific fields if TCP
                if protocol == 'TCP':
                    packet_data['flags'] = np.random.randint(0, 64)
                    packet_data['sequence'] = np.random.randint(0, 4294967295)
                    packet_data['acknowledgement'] = np.random.randint(0, 4294967295)
                
                self.packet_buffer.append(packet_data)
            
            # Occasionally inject anomalous traffic
            if np.random.random() < 0.05:  # 5% chance
                self._inject_anomalous_traffic()
            
            # Trim buffer if it gets too large
            if len(self.packet_buffer) > self.max_buffer_size:
                self.packet_buffer = self.packet_buffer[-self.max_buffer_size:]
            
            # Sleep a bit
            self.stop_collection.wait(np.random.uniform(0.1, 0.5))
    
    def _inject_anomalous_traffic(self) -> None:
        """Inject simulated anomalous traffic for testing"""
        anomaly_type = np.random.choice([
            'port_scan',
            'ddos',
            'data_exfiltration',
            'brute_force'
        ])
        
        timestamp = time.time()
        
        if anomaly_type == 'port_scan':
            # Simulate port scan: many connections to different ports from same source
            src_ip = f'192.168.1.{np.random.randint(1, 20)}'
            dst_ip = f'10.0.0.{np.random.randint(1, 20)}'
            
            for port in range(20, 40):  # Scan a range of ports
                packet_data = {
                    'timestamp': timestamp + port * 0.01,
                    'protocol': 'TCP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': np.random.randint(40000, 60000),
                    'dst_port': port,
                    'length': 40,
                    'flags': 2,  # SYN flag
                    'sequence': np.random.randint(0, 4294967295),
                    'acknowledgement': 0
                }
                self.packet_buffer.append(packet_data)
        
        elif anomaly_type == 'ddos':
            # Simulate DDoS: many connections to same destination from different sources
            dst_ip = f'10.0.0.{np.random.randint(1, 20)}'
            dst_port = 80
            
            for i in range(30):  # Many source IPs
                src_ip = f'192.168.{np.random.randint(1, 5)}.{np.random.randint(1, 254)}'
                
                packet_data = {
                    'timestamp': timestamp + i * 0.005,
                    'protocol': 'TCP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': np.random.randint(40000, 60000),
                    'dst_port': dst_port,
                    'length': np.random.randint(40, 100),
                    'flags': 2,  # SYN flag
                    'sequence': np.random.randint(0, 4294967295),
                    'acknowledgement': 0
                }
                self.packet_buffer.append(packet_data)
        
        elif anomaly_type == 'data_exfiltration':
            # Simulate data exfiltration: large outbound transfer
            src_ip = f'10.0.0.{np.random.randint(1, 20)}'
            dst_ip = f'203.0.113.{np.random.randint(1, 254)}'  # External IP
            
            for i in range(5):
                packet_data = {
                    'timestamp': timestamp + i * 0.1,
                    'protocol': 'TCP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': np.random.randint(40000, 60000),
                    'dst_port': 443,
                    'length': np.random.randint(1000, 1500),  # Large packets
                    'flags': 24,  # PSH, ACK flags
                    'sequence': np.random.randint(0, 4294967295),
                    'acknowledgement': np.random.randint(0, 4294967295)
                }
                self.packet_buffer.append(packet_data)
        
        elif anomaly_type == 'brute_force':
            # Simulate brute force: many failed login attempts
            src_ip = f'192.168.1.{np.random.randint(1, 20)}'
            dst_ip = f'10.0.0.{np.random.randint(1, 20)}'
            dst_port = 22  # SSH
            
            for i in range(15):
                packet_data = {
                    'timestamp': timestamp + i * 0.2,
                    'protocol': 'TCP',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': np.random.randint(40000, 60000),
                    'dst_port': dst_port,
                    'length': np.random.randint(60, 100),
                    'flags': 24,  # PSH, ACK flags
                    'sequence': np.random.randint(0, 4294967295),
                    'acknowledgement': np.random.randint(0, 4294967295)
                }
                self.packet_buffer.append(packet_data)
    
    def get_traffic_batch(self, batch_size=None) -> pd.DataFrame:
        """
        Get a batch of collected traffic data
        
        Args:
            batch_size: Number of packets to return (optional)
            
        Returns:
            DataFrame with traffic data
        """
        if not self.packet_buffer:
            return pd.DataFrame()
        
        max_size = len(self.packet_buffer)
        size = min(batch_size or max_size, max_size)
        
        # Get the most recent packets
        batch = self.packet_buffer[-size:]
        
        # Convert to DataFrame
        df = pd.DataFrame(batch)
        
        # Add derived features
        if not df.empty:
            # Time-based features
            if 'timestamp' in df.columns:
                df['hour'] = pd.to_datetime(df['timestamp'], unit='s').dt.hour
                df['minute'] = pd.to_datetime(df['timestamp'], unit='s').dt.minute
                df['second'] = pd.to_datetime(df['timestamp'], unit='s').dt.second
                df['day_of_week'] = pd.to_datetime(df['timestamp'], unit='s').dt.dayofweek
            
            # Protocol features
            if 'protocol' in df.columns:
                df['is_tcp'] = df['protocol'].apply(lambda x: 1 if x == 'TCP' else 0)
                df['is_udp'] = df['protocol'].apply(lambda x: 1 if x == 'UDP' else 0)
                df['is_http'] = df['protocol'].apply(lambda x: 1 if x in ['HTTP', 'HTTPS'] else 0)
            
            # Port features
            if 'dst_port' in df.columns:
                df['is_web_port'] = df['dst_port'].apply(lambda x: 1 if x in [80, 443, 8080, 8443] else 0)
                df['is_mail_port'] = df['dst_port'].apply(lambda x: 1 if x in [25, 465, 587, 993, 995] else 0)
                df['is_file_transfer_port'] = df['dst_port'].apply(lambda x: 1 if x in [21, 22, 69] else 0)
            
            # IP features
            if 'src_ip' in df.columns and 'dst_ip' in df.columns:
                df['is_internal_src'] = df['src_ip'].apply(
                    lambda x: 1 if x.startswith(('10.', '192.168.', '172.16.')) else 0
                )
                df['is_internal_dst'] = df['dst_ip'].apply(
                    lambda x: 1 if x.startswith(('10.', '192.168.', '172.16.')) else 0
                )
                df['is_internal_traffic'] = df['is_internal_src'] & df['is_internal_dst']
                df['is_outbound_traffic'] = df['is_internal_src'] & ~df['is_internal_dst']
                df['is_inbound_traffic'] = ~df['is_internal_src'] & df['is_internal_dst']
            
            # Statistical features
            # Group by source IP and calculate stats
            if 'src_ip' in df.columns and 'length' in df.columns:
                src_ip_stats = df.groupby('src_ip')['length'].agg(['count', 'mean', 'std']).reset_index()
                src_ip_stats.columns = ['src_ip', 'packets_sent', 'avg_packet_size', 'std_packet_size']
                
                # Merge back to original DataFrame
                df = pd.merge(df, src_ip_stats, on='src_ip', how='left')
            
            # Group by destination IP and calculate stats
            if 'dst_ip' in df.columns and 'length' in df.columns:
                dst_ip_stats = df.groupby('dst_ip')['length'].agg(['count', 'mean']).reset_index()
                dst_ip_stats.columns = ['dst_ip', 'packets_received', 'avg_received_size']
                
                # Merge back to original DataFrame
                df = pd.merge(df, dst_ip_stats, on='dst_ip', how='left')
            
            # Calculate unique destination ports per source IP
            if 'src_ip' in df.columns and 'dst_port' in df.columns:
                unique_ports = df.groupby('src_ip')['dst_port'].nunique().reset_index()
                unique_ports.columns = ['src_ip', 'unique_ports']
                
                # Merge back to original DataFrame
                df = pd.merge(df, unique_ports, on='src_ip', how='left')
        
        return df


class NetworkSecurityMonitor:
    """
    Main class for network security monitoring
    Integrates the anomaly detector and traffic collector
    """
    def __init__(self, config_path=None, database=None, event_system=None):
        """
        Initialize the network security monitor
        
        Args:
            config_path: Path to configuration file
            database: Database connection for logging and persistence
            event_system: Event system for publishing security events
        """
        self.logger = logging.getLogger('sidas.security.monitor')
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.anomaly_detector = NetworkAnomalyDetector(
            config_path=config_path,
            database=database,
            event_system=event_system
        )
        
        self.traffic_collector = NetworkTrafficCollector(
            interface=self.config.get('network_interface'),
            config=self.config.get('collector', {})
        )
        
        self.database = database
        self.event_system = event_system
        
        # Monitoring state
        self.is_monitoring = False
        self.stop_monitoring = threading.Event()
        self.monitor_thread = None
        
        # Security alerts
        self.alerts = []
        self.max_alerts = self.config.get('max_alerts', 1000)
        
        self.logger.info("Network Security Monitor initialized")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dict with configuration parameters
        """
        default_config = {
            'network_interface': None,  # Auto-detect
            'monitoring': {
                'interval': 60,  # seconds
                'batch_size': 1000
            },
            'collector': {
                'max_buffer_size': 10000,
                'pcap_filter': None
            },
            'detector': {
                'model_path': 'models/anomaly_detector.pkl',
                'thresholds': {
                    'anomaly_score': -0.2,
                    'alert_threshold': -0.5,
                    'critical_threshold': -0.8
                }
            },
            'max_alerts': 1000,
            'auto_train': False,
            'training_period': 3600  # 1 hour
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                
                # Update default config with user config
                self._update_dict(default_config, user_config)
                                self.logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                self.logger.error(f"Error loading config from {config_path}: {str(e)}")
        
        return default_config
    
    def _update_dict(self, d: Dict, u: Dict) -> Dict:
        """
        Recursively update a dictionary
        
        Args:
            d: Dictionary to update
            u: Dictionary with updates
            
        Returns:
            Updated dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_dict(d[k], v)
            else:
                d[k] = v
        return d
    
    def start_monitoring(self) -> Dict[str, Any]:
        """
        Start network security monitoring
        
        Returns:
            Dict with start result
        """
        if self.is_monitoring:
            self.logger.warning("Monitoring already active")
            return {
                'success': True,
                'message': "Monitoring already active"
            }
        
        try:
            # Start traffic collection
            self.traffic_collector.start_collection()
            
            # Check if model is trained
            if not self.anomaly_detector.is_trained:
                if self.config.get('auto_train', False):
                    # Auto-train on initial traffic data
                    self.logger.info("Auto-training anomaly detection model")
                    self._auto_train_model()
                else:
                    self.logger.error("Anomaly detection model not trained")
                    return {
                        'success': False,
                        'message': "Anomaly detection model not trained. Call train_model() first or enable auto_train in config."
                    }
            
            # Start monitoring thread
            self.stop_monitoring.clear()
            self.is_monitoring = True
            
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop
            )
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            self.logger.info("Started network security monitoring")
            
            return {
                'success': True,
                'message': "Network security monitoring started"
            }
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': "Error starting network security monitoring"
            }
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """
        Stop network security monitoring
        
        Returns:
            Dict with stop result
        """
        if not self.is_monitoring:
            self.logger.warning("Monitoring not active")
            return {
                'success': True,
                'message': "Monitoring not active"
            }
        
        try:
            # Signal monitoring thread to stop
            self.stop_monitoring.set()
            
            # Stop traffic collection
            self.traffic_collector.stop_collection()
            
            # Wait for monitoring thread to finish
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            
            self.is_monitoring = False
            
            self.logger.info("Stopped network security monitoring")
            
            return {
                'success': True,
                'message': "Network security monitoring stopped"
            }
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': "Error stopping network security monitoring"
            }
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        monitoring_interval = self.config.get('monitoring', {}).get('interval', 60)
        batch_size = self.config.get('monitoring', {}).get('batch_size', 1000)
        
        while not self.stop_monitoring.is_set():
            try:
                # Get batch of traffic data
                traffic_data = self.traffic_collector.get_traffic_batch(batch_size)
                
                if not traffic_data.empty:
                    # Detect anomalies
                    result = self.anomaly_detector.detect_anomalies(traffic_data)
                    
                    # Process results if anomalies found
                    if result['anomaly_count'] > 0:
                        self.logger.info(
                            f"Detected {result['anomaly_count']} anomalies in {result['total_samples']} samples"
                        )
                        
                        # Process anomalies
                        self._process_anomalies(result['anomalies'])
                
                # Sleep until next interval
                self.stop_monitoring.wait(monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                # Sleep a bit longer after an error
                self.stop_monitoring.wait(monitoring_interval * 2)
    
    def _process_anomalies(self, anomalies: pd.DataFrame) -> None:
        """
        Process detected anomalies
        
        Args:
            anomalies: DataFrame with anomaly data
        """
        # Generate alerts for each anomaly
        for _, anomaly in anomalies.iterrows():
            alert = {
                'timestamp': datetime.datetime.now().isoformat(),
                'anomaly_score': float(anomaly['anomaly_score']),
                'severity': anomaly['severity'],
                'attack_type': anomaly.get('attack_type', 'unknown'),
                'src_ip': anomaly.get('src_ip', 'unknown'),
                'dst_ip': anomaly.get('dst_ip', 'unknown'),
                'protocol': anomaly.get('protocol', 'unknown'),
                'details': anomaly.to_dict()
            }
            
            # Add to alerts list
            self.alerts.append(alert)
            
            # Trim alerts list if it gets too large
            if len(self.alerts) > self.max_alerts:
                self.alerts = self.alerts[-self.max_alerts:]
            
            # Log high severity alerts
            if anomaly['severity'] == 'high':
                self.logger.critical(
                    f"HIGH SEVERITY NETWORK ANOMALY: score={anomaly['anomaly_score']:.4f}, "
                    f"type={anomaly.get('attack_type', 'unknown')}, "
                    f"src={anomaly.get('src_ip', 'unknown')}, "
                    f"dst={anomaly.get('dst_ip', 'unknown')}"
                )
            
            # Publish alert event
            if self.event_system:
                self.event_system.publish(
                    'security_alert',
                    {
                        'type': 'network_anomaly',
                        **alert
                    }
                )
            
            # Record in database
            if self.database:
                self.database.log_security_event(
                    event_type="network_anomaly",
                    data=alert,
                    severity=anomaly['severity']
                )
    
    def _auto_train_model(self) -> None:
        """Auto-train the anomaly detection model on initial traffic data"""
        training_period = self.config.get('training_period', 3600)  # Default 1 hour
        batch_size = self.config.get('monitoring', {}).get('batch_size', 1000)
        
        self.logger.info(f"Collecting training data for {training_period} seconds")
        
        # Start traffic collection if not already started
        if not self.traffic_collector.is_collecting:
            self.traffic_collector.start_collection()
        
        # Wait for training period
        time.sleep(training_period)
        
        # Get training data
        training_data = self.traffic_collector.get_traffic_batch(batch_size)
        
        if training_data.empty:
            self.logger.warning("No training data collected, cannot train model")
            return
        
        # Train model
        self.logger.info(f"Training model with {len(training_data)} samples")
        self.anomaly_detector.train(training_data)
    
    def train_model(self, training_data: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """
        Train the anomaly detection model
        
        Args:
            training_data: DataFrame with training data (optional)
            
        Returns:
            Dict with training result
        """
        try:
            if training_data is None:
                # Use collected traffic data
                batch_size = self.config.get('monitoring', {}).get('batch_size', 1000)
                training_data = self.traffic_collector.get_traffic_batch(batch_size)
                
                if training_data.empty:
                    self.logger.warning("No traffic data available for training")
                    return {
                        'success': False,
                        'message': "No traffic data available for training"
                    }
            
            # Train the model
            result = self.anomaly_detector.train(training_data)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': "Error training anomaly detection model"
            }
    
    def get_alerts(self, limit: Optional[int] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get security alerts
        
        Args:
            limit: Maximum number of alerts to return (optional)
            severity: Filter by severity (optional)
            
        Returns:
            List of alert dictionaries
        """
        if severity:
            filtered_alerts = [a for a in self.alerts if a['severity'] == severity]
        else:
            filtered_alerts = self.alerts
        
        # Sort by timestamp (newest first)
        sorted_alerts = sorted(
            filtered_alerts,
            key=lambda x: x['timestamp'],
            reverse=True
        )
        
        if limit:
            return sorted_alerts[:limit]
        return sorted_alerts
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the network security monitor
        
        Returns:
            Dict with status information
        """
        return {
            'is_monitoring': self.is_monitoring,
            'model_trained': self.anomaly_detector.is_trained,
            'collector_active': self.traffic_collector.is_collecting,
            'alert_count': len(self.alerts),
            'high_severity_alerts': len([a for a in self.alerts if a['severity'] == 'high']),
            'medium_severity_alerts': len([a for a in self.alerts if a['severity'] == 'medium']),
            'low_severity_alerts': len([a for a in self.alerts if a['severity'] == 'low']),
            'performance': self.anomaly_detector.get_performance_metrics(),
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive security report
        
        Returns:
            Dict with report data
        """
        # Get detector report
        detector_report = self.anomaly_detector.generate_report()
        
        # Add monitor-specific information
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'monitor_status': {
                'is_monitoring': self.is_monitoring,
                'collector_active': self.traffic_collector.is_collecting
            },
            'alerts': {
                'total': len(self.alerts),
                'by_severity': {
                    'high': len([a for a in self.alerts if a['severity'] == 'high']),
                    'medium': len([a for a in self.alerts if a['severity'] == 'medium']),
                    'low': len([a for a in self.alerts if a['severity'] == 'low'])
                },
                'recent': self.get_alerts(limit=10)
            },
            'detector': detector_report
        }
        
        return report


# Frontend React component for Network Security Monitoring
```jsx
// NetworkSecurityMonitor.tsx
import React, { useEffect, useState, useCallback } from 'react';
import { Card, Button, Table, Badge, Tabs, Tab, Alert, ProgressBar, Form, Modal } from 'react-bootstrap';
import { Line, Bar, Pie } from 'react-chartjs-2';
import axios from 'axios';
import './NetworkSecurityMonitor.css';

interface Alert {
  timestamp: string;
  anomaly_score: number;
  severity: string;
  attack_type: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
}

interface MonitorStatus {
  is_monitoring: boolean;
  model_trained: boolean;
  collector_active: boolean;
  alert_count: number;
  high_severity_alerts: number;
  medium_severity_alerts: number;
  low_severity_alerts: number;
  performance: {
    avg_detection_time: number;
    detection_rate: number;
  };
  timestamp: string;
}

const NetworkSecurityMonitor: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [isTraining, setIsTraining] = useState(false);
  const [trainingResult, setTrainingResult] = useState<any>(null);
  const [showTrainingModal, setShowTrainingModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [showAlertDetails, setShowAlertDetails] = useState(false);
  const [visualizations, setVisualizations] = useState<any>({});
  const [ipFilter, setIpFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [timeRange, setTimeRange] = useState('24h');
  
  // Fetch alerts and status
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Get authentication token
      const token = localStorage.getItem('token');
      
      // Fetch alerts
      const alertsResponse = await axios.get('/api/security/alerts', {
        params: {
          severity: severityFilter !== 'all' ? severityFilter : undefined,
          ip: ipFilter || undefined,
          timeRange
        },
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      setAlerts(alertsResponse.data);
      
      // Fetch status
      const statusResponse = await axios.get('/api/security/status', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      setStatus(statusResponse.data);
      
      // Fetch visualizations
      const visualizationsResponse = await axios.get('/api/security/visualizations', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      setVisualizations(visualizationsResponse.data);
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'Error fetching data');
      console.error('Error fetching data:', err);
    } finally {
      setLoading(false);
    }
  }, [ipFilter, severityFilter, timeRange]);
  
  useEffect(() => {
    fetchData();
    
    // Set up polling interval
    const interval = setInterval(fetchData, 30000); // 30 seconds
    
    return () => clearInterval(interval);
  }, [fetchData]);
  
  const handleStartMonitoring = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const token = localStorage.getItem('token');
      
      const response = await axios.post('/api/security/start', {}, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      if (response.data.success) {
        fetchData();
      } else {
        setError(response.data.message);
      }
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'Error starting monitoring');
    } finally {
      setLoading(false);
    }
  };
  
  const handleStopMonitoring = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const token = localStorage.getItem('token');
      
      const response = await axios.post('/api/security/stop', {}, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      if (response.data.success) {
        fetchData();
      } else {
        setError(response.data.message);
      }
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'Error stopping monitoring');
    } finally {
      setLoading(false);
    }
  };
  
  const handleTrainModel = async () => {
    try {
      setIsTraining(true);
      setTrainingResult(null);
      setError(null);
      
      const token = localStorage.getItem('token');
      
      const response = await axios.post('/api/security/train', {}, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      
      setTrainingResult(response.data);
      
      if (response.data.success) {
        fetchData();
      } else {
        setError(response.data.message);
      }
      
    } catch (err: any) {
      setError(err.response?.data?.message || 'Error training model');
    } finally {
      setIsTraining(false);
    }
  };
  
  const handleAlertClick = (alert: Alert) => {
    setSelectedAlert(alert);
    setShowAlertDetails(true);
  };
  
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'high':
        return <Badge bg="danger">High</Badge>;
      case 'medium':
        return <Badge bg="warning">Medium</Badge>;
      case 'low':
        return <Badge bg="success">Low</Badge>;
      default:
        return <Badge bg="secondary">{severity}</Badge>;
    }
  };
  
  const renderStatusIndicator = (isActive: boolean, label: string) => (
    <div className="status-indicator">
      <div className={`indicator ${isActive ? 'active' : 'inactive'}`}></div>
      <span>{label}</span>
    </div>
  );
  
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };
  
  const renderAlertTable = () => (
    <div className="alert-table-container">
      <div className="alert-filters">
        <Form.Group className="mb-3">
          <Form.Label>IP Filter</Form.Label>
          <Form.Control
            type="text"
            placeholder="Filter by IP address"
            value={ipFilter}
            onChange={(e) => setIpFilter(e.target.value)}
          />
        </Form.Group>
        
        <Form.Group className="mb-3">
          <Form.Label>Severity</Form.Label>
          <Form.Select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Form.Select>
        </Form.Group>
        
        <Form.Group className="mb-3">
          <Form.Label>Time Range</Form.Label>
          <Form.Select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
          >
            <option value="1h">Last Hour</option>
            <option value="6h">Last 6 Hours</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </Form.Select>
        </Form.Group>
      </div>
      
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Attack Type</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
          {alerts.length > 0 ? (
            alerts.map((alert, index) => (
              <tr key={index} onClick={() => handleAlertClick(alert)} className="alert-row">
                <td>{formatTimestamp(alert.timestamp)}</td>
                <td>{getSeverityBadge(alert.severity)}</td>
                <td>{alert.attack_type || 'Unknown'}</td>
                <td>{alert.src_ip}</td>
                <td>{alert.dst_ip}</td>
                <td>{alert.protocol}</td>
                <td>{alert.anomaly_score.toFixed(4)}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={7} className="text-center">No alerts found</td>
            </tr>
          )}
        </tbody>
      </Table>
    </div>
  );
  
  const renderStatusPanel = () => (
    <div className="status-panel">
      {status && (
        <>
          <div className="status-header">
            <h5>System Status</h5>
            <div className="status-actions">
              <Button
                variant={status.is_monitoring ? "danger" : "success"}
                size="sm"
                onClick={status.is_monitoring ? handleStopMonitoring : handleStartMonitoring}
                disabled={loading}
              >
                {status.is_monitoring ? "Stop Monitoring" : "Start Monitoring"}
              </Button>
              
              <Button
                variant="primary"
                size="sm"
                onClick={() => setShowTrainingModal(true)}
                disabled={loading || isTraining}
              >
                Train Model
              </Button>
            </div>
          </div>
          
          <div className="status-indicators">
            {renderStatusIndicator(status.is_monitoring, "Monitoring")}
            {renderStatusIndicator(status.model_trained, "Model Trained")}
            {renderStatusIndicator(status.collector_active, "Data Collection")}
          </div>
          
          <div className="alert-summary">
            <h6>Alert Summary</h6>
            <div className="alert-counts">
              <div className="alert-count">
                <Badge bg="danger" className="count-badge">{status.high_severity_alerts}</Badge>
                <span>High</span>
              </div>
              <div className="alert-count">
                <Badge bg="warning" className="count-badge">{status.medium_severity_alerts}</Badge>
                <span>Medium</span>
              </div>
              <div className="alert-count">
                <Badge bg="success" className="count-badge">{status.low_severity_alerts}</Badge>
                <span>Low</span>
              </div>
            </div>
          </div>
          
          <div className="performance-metrics">
            <h6>Performance Metrics</h6>
            <div className="metric">
              <span className="metric-label">Detection Time:</span>
              <span className="metric-value">{status.performance.avg_detection_time.toFixed(2)} ms</span>
            </div>
            <div className="metric">
              <span className="metric-label">Detection Rate:</span>
              <span className="metric-value">{(status.performance.detection_rate * 100).toFixed(2)}%</span>
            </div>
          </div>
          
          <div className="status-footer">
            <small className="text-muted">Last updated: {formatTimestamp(status.timestamp)}</small>
          </div>
        </>
      )}
    </div>
  );
  
  const renderVisualizationsPanel = () => (
    <div className="visualizations-panel">
      {visualizations.pca && (
        <div className="visualization-item">
          <h6>Network Traffic PCA</h6>
          <div className="visualization-image">
            <img src={`data:image/png;base64,${visualizations.pca}`} alt="PCA Visualization" />
          </div>
        </div>
      )}
      
      {visualizations.score_distribution && (
        <div className="visualization-item">
          <h6>Anomaly Score Distribution</h6>
          <div className="visualization-image">
            <img src={`data:image/png;base64,${visualizations.score_distribution}`} alt="Score Distribution" />
          </div>
        </div>
      )}
      
      {visualizations.feature_importance && (
        <div className="visualization-item">
          <h6>Feature Importance</h6>
          <div className="visualization-image">
            <img src={`data:image/png;base64,${visualizations.feature_importance}`} alt="Feature Importance" />
          </div>
        </div>
      )}
    </div>
  );
  
  return (
    <div className="network-security-monitor">
      <Card className="main-card">
        <Card.Header>
          <h4>Network Security Monitor</h4>
        </Card.Header>
        <Card.Body>
          {error && <Alert variant="danger">{error}</Alert>}
          
          <div className="monitor-layout">
            <div className="monitor-sidebar">
              {renderStatusPanel()}
            </div>
            
            <div className="monitor-content">
              <Tabs defaultActiveKey="alerts" className="mb-3">
                <Tab eventKey="alerts" title="Security Alerts">
                  {renderAlertTable()}
                </Tab>
                <Tab eventKey="visualizations" title="Visualizations">
                  {renderVisualizationsPanel()}
                </Tab>
                <Tab eventKey="settings" title="Settings">
                  <div className="settings-panel">
                    <h5>Security Monitor Settings</h5>
                    <p>Configuration options for the network security monitoring system.</p>
                    
                    {/* Settings would go here */}
                  </div>
                </Tab>
              </Tabs>
            </div>
          </div>
        </Card.Body>
      </Card>
      
      {/* Training Modal */}
      <Modal show={showTrainingModal} onHide={() => setShowTrainingModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Train Anomaly Detection Model</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {isTraining ? (
            <div className="text-center">
              <p>Training model, please wait...</p>
              <ProgressBar animated now={100} />
            </div>
          ) : (
            <>
              <p>
                Training the anomaly detection model will use current network traffic data to establish a baseline for normal behavior.
                This process may take a few minutes.
              </p>
              
              {trainingResult && (
                <Alert variant={trainingResult.success ? "success" : "danger"}>
                  {trainingResult.message}
                  {trainingResult.success && trainingResult.n_samples && (
                    <div>
                      <small>Trained with {trainingResult.n_samples} samples in {trainingResult.training_time.toFixed(2)} seconds</small>
                    </div>
                  )}
                </Alert>
              )}
            </>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowTrainingModal(false)}>
            Close
          </Button>
          <Button
            variant="primary"
            onClick={handleTrainModel}
            disabled={isTraining}
          >
            {isTraining ? "Training..." : "Start Training"}
          </Button>
        </Modal.Footer>
      </Modal>
      
      {/* Alert Details Modal */}
      <Modal show={showAlertDetails} onHide={() => setShowAlertDetails(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Alert Details</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedAlert && (
            <div className="alert-details">
              <div className="alert-header">
                <h5>{selectedAlert.attack_type || "Unknown Attack Type"}</h5>
                <div>{getSeverityBadge(selectedAlert.severity)}</div>
              </div>
              
              <Table bordered>
                <tbody>
                  <tr>
                    <td>Timestamp</td>
                    <td>{formatTimestamp(selectedAlert.timestamp)}</td>
                  </tr>
                  <tr>
                    <td>Source IP</td>
                    <td>{selectedAlert.src_ip}</td>
                  </tr>
                  <tr>
                    <td>Destination IP</td>
                    <td>{selectedAlert.dst_ip}</td>
                  </tr>
                  <tr>
                    <td>Protocol</td>
                    <td>{selectedAlert.protocol}</td>
                  </tr>
                  <tr>
                    <td>Anomaly Score</td>
                    <td>{selectedAlert.anomaly_score.toFixed(4)}</td>
                  </tr>
                </tbody>
              </Table>
              
              <h6>Detailed Information</h6>
              <pre className="alert-json">
                {JSON.stringify(selectedAlert.details || {}, null, 2)}
              </pre>
              
              <div className="alert-actions">
                <Button variant="secondary" size="sm">Add to Whitelist</Button>
                <Button variant="secondary" size="sm">Add to Blacklist</Button>
                <Button variant="danger" size="sm">Block Source IP</Button>
              </div>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowAlertDetails(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

export default NetworkSecurityMonitor;


