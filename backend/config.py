# backend/config.py
import os

# Basic configuration
DEBUG = os.environ.get('SIDAS_DEBUG', 'False').lower() == 'true'
SECRET_KEY = os.environ.get('SIDAS_SECRET_KEY', 'sidas_secret_key_change_in_production')

# Server configuration
HOST = os.environ.get('SIDAS_HOST', '0.0.0.0')
PORT = int(os.environ.get('SIDAS_PORT', 5000))

# Security settings
JWT_EXPIRATION_HOURS = int(os.environ.get('SIDAS_JWT_EXPIRATION_HOURS', 8))
HASH_ALGORITHM = 'sha256'
ENCRYPTION_ALGORITHM = 'aes-256-gcm'

# Authentication settings
AUTH_ATTEMPTS_MAX = int(os.environ.get('SIDAS_AUTH_ATTEMPTS_MAX', 5))
AUTH_LOCKOUT_SECONDS = int(os.environ.get('SIDAS_AUTH_LOCKOUT_SECONDS', 300))

# Logging configuration
LOG_LEVEL = os.environ.get('SIDAS_LOG_LEVEL', 'INFO')
LOG_FILE = os.environ.get('SIDAS_LOG_FILE', 'sidas.log')

# Database configuration
DB_TYPE = os.environ.get('
