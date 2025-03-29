# backend/auth.py
import hashlib
import os
import time
import logging
from datetime import datetime, timedelta
import jwt

from config import (
    SECRET_KEY, JWT_EXPIRATION_HOURS, 
    AUTH_ATTEMPTS_MAX, AUTH_LOCKOUT_SECONDS
)
from database import Database

logger = logging.getLogger('sidas.auth')

class Authentication:
    def __init__(self, database):
        self.db = database
        
    def hash_password(self, password, salt=None):
        """
        Hash a password with salt
        
        Args:
            password: The password to hash
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (password_hash, salt)
        """
        if salt is None:
            salt = os.urandom(32)  # 32 bytes of random salt
        else:
            if isinstance(salt, str):
                salt = bytes.fromhex(salt)
                
        # Hash password with salt using SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # Number of iterations
        )
        
        return password_hash.hex(), salt.hex()
    
    def verify_password(self, password, stored_hash, salt):
        """Verify a password against stored hash and salt"""
        calculated_hash, _ = self.hash_password(password, salt)
        return calculated_hash == stored_hash
    
    def create_user(self, username, password, role='user'):
        """Create a new user"""
        # Check if user already exists
        existing_user = self.db.get_user(username)
        if existing_user:
            logger.warning(f"Attempt to create duplicate user: {username}")
            return False, "Username already exists"
            
        # Hash password
        password_hash, salt = self.hash_password(password)
        
        # Add user to database
        success = self.db.add_user(username, password_hash, salt, role)
        
        if success:
            logger.info(f"Created new user: {username} with role: {role}")
            return True, "User created successfully"
        else:
            logger.error(f"Failed to create user: {username}")
            return False, "Database error creating user"
    
    def authenticate(self, username, password, ip_address):
        """
        Authenticate a user
        
        Args:
            username: Username
            password: Password
            ip_address: Client IP address
            
        Returns:
            Tuple of (success, message, user_data)
        """
        # Check for brute force attempts
        recent_attempts = self.db.get_recent_auth_attempts(
            username, ip_address, AUTH_LOCKOUT_SECONDS
        )
        
        failed_attempts = sum(1 for attempt in recent_attempts if not attempt['success'])
        
        if failed_attempts >= AUTH_ATTEMPTS_MAX:
            logger.warning(f"Account locked due to too many failed attempts: {username} from {ip_address}")
            self.db.log_auth_attempt(username, ip_address, False)
            return False, "Account temporarily locked due to too many failed attempts", None
            
        # Get user from database
        user = self.db.get_user(username)
        
        if not user:
            logger.warning(f"Authentication attempt for non-existent user: {username} from {ip_address}")
            self.db.log_auth_attempt(username, ip_address, False)
            return False, "Invalid username or password", None
            
        # Verify password
        if not self.verify_password(password, user['password_hash'], user['salt']):
            logger.warning(f"Failed authentication for user: {username} from {ip_address}")
            self.db.log_auth_attempt(username, ip_address, False)
            return False, "Invalid username or password", None
            
        # Update last login time
        self.db.update_last_login(username)
        
        # Log successful authentication
        self.db.log_auth_attempt(username, ip_address, True)
        
        # Audit log
        self.db.log_audit(
            action="user_login",
            user_id=username,
            ip_address=ip_address
        )
        
                logger.info(f"Successful authentication for user: {username} from {ip_address}")
        
        # Return user data (excluding sensitive fields)
        user_data = {
            'username': user['username'],
            'role': user['role'],
            'last_login': user['last_login']
        }
        
        return True, "Authentication successful", user_data
    
    def generate_token(self, user_data):
        """
        Generate a JWT token for the authenticated user
        
        Args:
            user_data: User data to include in the token
            
        Returns:
            JWT token string
        """
        expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        
        payload = {
            'sub': user_data['username'],
            'role': user_data['role'],
            'iat': datetime.utcnow(),
            'exp': expiration
        }
        
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        
        return token
    
    def verify_token(self, token):
        """
        Verify a JWT token
        
        Args:
            token: JWT token to verify
            
        Returns:
            Tuple of (valid, user_data or error_message)
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Check if user still exists and is active
            username = payload['sub']
            user = self.db.get_user(username)
            
            if not user or not user['active']:
                logger.warning(f"Token verification failed: User {username} not found or inactive")
                return False, "User not found or inactive"
                
            user_data = {
                'username': username,
                'role': payload['role']
            }
            
            return True, user_data
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token verification failed: Token expired")
            return False, "Token expired"
        except jwt.InvalidTokenError:
            logger.warning("Token verification failed: Invalid token")
            return False, "Invalid token"
    
    def logout(self, username, ip_address):
        """Log user logout"""
        self.db.log_audit(
            action="user_logout",
            user_id=username,
            ip_address=ip_address
        )
        logger.info(f"User logged out: {username} from {ip_address}")
        return True

