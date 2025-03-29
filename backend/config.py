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
DB_TYPE = os.environ.get('SIDAS_DB_TYPE', 'sqlite')
DB_HOST = os.environ.get('SIDAS_DB_HOST', 'localhost')
DB_PORT = int(os.environ.get('SIDAS_DB_PORT', 5432))
DB_NAME = os.environ.get('SIDAS_DB_NAME', 'sidas')
DB_USER = os.environ.get('SIDAS_DB_USER', 'sidas_user')
DB_PASSWORD = os.environ.get('SIDAS_DB_PASSWORD', 'sidas_password')

# API configuration
API_VERSION = os.environ.get('SIDAS_API_VERSION', 'v1')
API_RATE_LIMIT = int(os.environ.get('SIDAS_API_RATE_LIMIT', 100))
API_RATE_LIMIT_PERIOD = int(os.environ.get('SIDAS_API_RATE_LIMIT_PERIOD', 3600))

# Threat detection configuration
THREAT_DETECTION_INTERVAL = int(os.environ.get('SIDAS_THREAT_DETECTION_INTERVAL', 60))
THREAT_LEVELS = ['low', 'medium', 'high', 'critical']
THREAT_RESPONSE_AUTO = os.environ.get('SIDAS_THREAT_RESPONSE_AUTO', 'False').lower() == 'true'

# WebSocket configuration
WS_PING_INTERVAL = int(os.environ.get('SIDAS_WS_PING_INTERVAL', 30))
WS_PING_TIMEOUT = int(os.environ.get('SIDAS_WS_PING_TIMEOUT', 10))

# Encryption key paths
KEY_DIRECTORY = os.environ.get('SIDAS_KEY_DIRECTORY', 'keys')
SIGNING_KEY_PATH = os.path.join(KEY_DIRECTORY, 'signing_key.pem')
ENCRYPTION_KEY_PATH = os.path.join(KEY_DIRECTORY, 'encryption_key.pem')

# Create key directory if it doesn't exist
if not os.path.exists(KEY_DIRECTORY):
    os.makedirs(KEY_DIRECTORY)
