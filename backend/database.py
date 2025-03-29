# backend/database.py
import sqlite3
import psycopg2
import json
import time
import logging
from datetime import datetime
import os

from config import (
    DB_TYPE, DB_HOST, DB_PORT, DB_NAME, 
    DB_USER, DB_PASSWORD
)

logger = logging.getLogger('sidas.database')

class Database:
    def __init__(self):
        self.connection = None
        self.connect()
        self.setup_tables()
        
    def connect(self):
        """Connect to the database"""
        try:
            if DB_TYPE == 'sqlite':
                self.connection = sqlite3.connect(
                    f"{DB_NAME}.db", 
                    check_same_thread=False
                )
                self.connection.row_factory = sqlite3.Row
            elif DB_TYPE == 'postgresql':
                self.connection = psycopg2.connect(
                    host=DB_HOST,
                    port=DB_PORT,
                    dbname=DB_NAME,
                    user=DB_USER,
                    password=DB_PASSWORD
                )
            else:
                raise ValueError(f"Unsupported database type: {DB_TYPE}")
                
            logger.info(f"Connected to {DB_TYPE} database")
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            raise
    
    def setup_tables(self):
        """Set up database tables if they don't exist"""
        cursor = self.connection.cursor()
        
        # Users table
        if DB_TYPE == 'sqlite':
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                last_login INTEGER,
                created_at INTEGER NOT NULL,
                active INTEGER DEFAULT 1
            )
            ''')
            
            # Tracks table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS tracks (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                threat_level TEXT NOT NULL
            )
            ''')
            
            # System events table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                data TEXT NOT NULL,
                severity TEXT NOT NULL
            )
            ''')
            
            # Audit log table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                details TEXT,
                ip_address TEXT
            )
            ''')
            
            # Authentication attempts table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                success INTEGER NOT NULL
            )
            ''')
            
            # Commands table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                target_id TEXT,
                parameters TEXT,
                timestamp INTEGER NOT NULL,
                status TEXT NOT NULL
            )
            ''')
            
        elif DB_TYPE == 'postgresql':
            # Similar CREATE TABLE statements for PostgreSQL
            # Adjusting syntax as needed
            pass
            
        self.connection.commit()
        logger.info("Database tables created if they didn't exist")
    
    def add_user(self, username, password_hash, salt, role='user'):
        """Add a new user to the database"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, salt, role, now)
            )
            self.connection.commit()
            logger.info(f"Added new user: {username}")
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error adding user: {str(e)}")
            return False
    
    def get_user(self, username):
        """Get user data by username"""
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and DB_TYPE == 'sqlite':
            return dict(user)
        return user
    
    def update_last_login(self, username):
        """Update user's last login time"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        try:
            cursor.execute(
                "UPDATE users SET last_login = ? WHERE username = ?",
                (now, username)
            )
            self.connection.commit()
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error updating last login: {str(e)}")
            return False
    
    def log_auth_attempt(self, username, ip_address, success):
        """Log an authentication attempt"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        try:
            cursor.execute(
                "INSERT INTO auth_attempts (username, ip_address, timestamp, success) VALUES (?, ?, ?, ?)",
                (username, ip_address, now, 1 if success else 0)
            )
            self.connection.commit()
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error logging auth attempt: {str(e)}")
            return False
    
    def get_recent_auth_attempts(self, username, ip_address, seconds=300):
        """Get recent authentication attempts for a username or IP"""
        cursor = self.connection.cursor()
        now = int(time.time())
        cutoff = now - seconds
        
        cursor.execute(
            "SELECT * FROM auth_attempts WHERE (username = ? OR ip_address = ?) AND timestamp > ? ORDER BY timestamp DESC",
            (username, ip_address, cutoff)
        )
        
        attempts = cursor.fetchall()
        
        if DB_TYPE == 'sqlite':
            return [dict(attempt) for attempt in attempts]
        return attempts
    
    def update_track(self, track_id, track_data):
        """Update or insert a track"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        # Check if track exists
        cursor.execute("SELECT id FROM tracks WHERE id = ?", (track_id,))
        exists = cursor.fetchone()
        
        try:
            if exists:
                # Update existing track
                cursor.execute(
                    "UPDATE tracks SET data = ?, last_seen = ?, threat_level = ? WHERE id = ?",
                    (json.dumps(track_data), now, track_data['threatLevel'], track_id)
                )
            else:
                # Insert new track
                cursor.execute(
                    "INSERT INTO tracks (id, data, first_seen, last_seen, threat_level) VALUES (?, ?, ?, ?, ?)",
                    (track_id, json.dumps(track_data), now, now, track_data['threatLevel'])
                )
                
            self.connection.commit()
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error updating track: {str(e)}")
            return False
    
    def get_track(self, track_id):
        """Get a track by ID"""
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT * FROM tracks WHERE id = ?", (track_id,))
        track = cursor.fetchone()
        
        if track:
            result = dict(track) if DB_TYPE == 'sqlite' else track
            result['data'] = json.loads(result['data'])
            return result
        return None
    
    def get_all_tracks(self, active_only=True):
        """Get all tracks, optionally only active ones"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        if active_only:
            # Consider tracks active if seen in the last 5 minutes
            cutoff = now - 300
            cursor.execute("SELECT * FROM tracks WHERE last_seen > ?", (cutoff,))
        else:
            cursor.execute("SELECT * FROM tracks")
            
        tracks = cursor.fetchall()
        
        result = []
        for track in tracks:
            track_dict = dict(track) if DB_TYPE == 'sqlite' else track
            track_dict['data'] = json.loads(track_dict['data'])
            result.append(track_dict)
            
        return result
    
    def log_system_event(self, event_type, data, severity='info'):
        """Log a system event"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        try:
            cursor.execute(
                "INSERT INTO system_events (event_type, timestamp, data, severity) VALUES (?, ?, ?, ?)",
                (event_type, now, json.dumps(data), severity)
            )
            self.connection.commit()
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error logging system event: {str(e)}")
            return False
    
    def log_audit(self, action, user_id=None, details=None, ip_address=None):
        """Log an audit entry"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        try:
            cursor.execute(
                "INSERT INTO audit_log (user_id, action, timestamp, details, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, now, json.dumps(details) if details else None, ip_address)
            )
            self.connection.commit()
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error logging audit entry: {str(e)}")
            return False
    
    def log_command(self, user_id, command_type, target_id=None, parameters=None, status='issued'):
        """Log a command"""
        cursor = self.connection.cursor()
        now = int(time.time())
        
        try:
            cursor.execute(
                "INSERT INTO commands (user_id, command_type, target_id, parameters, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user_id, 
                    command_type, 
                    target_id, 
                    json.dumps(parameters) if parameters else None, 
                    now, 
                    status
                )
            )
            self.connection.commit()
            return cursor.lastrowid
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error logging command: {str(e)}")
            return None
    
    def update_command_status(self, command_id, status):
        """Update the status of a command"""
        cursor = self.connection.cursor()
        
        try:
            cursor.execute(
                "UPDATE commands SET status = ? WHERE id = ?",
                (status, command_id)
            )
            self.connection.commit()
            return True
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Error updating command status: {str(e)}")
            return False
    
    def close(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
