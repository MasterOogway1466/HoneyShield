import os

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Honeypot settings
HONEYPOT_IP = '0.0.0.0'
HONEYPOT_PORT = 22  # Changed to default SSH port

# Real network settings
REAL_NETWORK_PORT = 9090

# Logging settings
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
HONEYPOT_LOG_PATH = os.path.join(LOGS_DIR, 'honeypot.log')
REAL_NETWORK_LOG_PATH = os.path.join(LOGS_DIR, 'real_network.log')

# ML model paths
MODEL_DIR = os.path.join(BASE_DIR, 'models')