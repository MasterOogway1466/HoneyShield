import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
RAW_DATA_DIR = os.path.join(DATA_DIR, 'raw')
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, 'processed')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

# Create directories if they don't exist
for dir_path in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# Model parameters
MODEL_TYPE = 'random_forest'  # Options: 'random_forest', 'svm', 'logistic_regression', 'neural_network'
TEST_SIZE = 0.3  # Percentage of data to use for testing
RANDOM_STATE = 42  # For reproducibility

# Honeypot configuration
HONEYPOT_IP = '127.0.0.1'  # Change to your network setup
HONEYPOT_PORT = 8080
HONEYPOT_LOG_PATH = os.path.join(LOGS_DIR, 'honeypot.log')

# Anomaly detection thresholds
ANOMALY_THRESHOLD = 0.8  # Confidence threshold for anomaly alerts