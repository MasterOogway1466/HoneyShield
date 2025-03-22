import json
import os
import sys
import traceback
from src.detection.anomaly_detector import AnomalyDetector

print("Starting anomaly detection test...")

# Check if sample logs exist
sample_logs_path = 'data/raw/sample_logs.json'
if not os.path.exists(sample_logs_path):
    print(f"ERROR: Sample logs file not found at {sample_logs_path}")
    sys.exit(1)

# Load sample logs
try:
    with open(sample_logs_path, 'r') as f:
        sample_logs = json.load(f)
    print(f"Successfully loaded {len(sample_logs)} sample logs")
except Exception as e:
    print(f"ERROR loading sample logs: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

# Check if model files exist
model_path = os.path.join('models', 'random_forest_model.pkl')
preprocessor_path = os.path.join('models', 'preprocessor.pkl')

if not os.path.exists(model_path):
    print(f"ERROR: Model file not found at {model_path}")
    print("Have you trained the model yet? Try running: python main.py --train data/raw/sample_iot_logs.csv")
    sys.exit(1)

if not os.path.exists(preprocessor_path):
    print(f"ERROR: Preprocessor file not found at {preprocessor_path}")
    print("Have you trained the model yet? Try running: python main.py --train data/raw/sample_iot_logs.csv")
    sys.exit(1)

# Initialize detector
try:
    print("Initializing anomaly detector...")
    detector = AnomalyDetector()
    print("Detector initialized successfully")
except Exception as e:
    print(f"ERROR initializing detector: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

# Test each log
print("\n=== Testing Anomaly Detection ===\n")

try:
    for i, log in enumerate(sample_logs):
        print(f"Log {i+1}:")
        print(f"  - Source IP: {log.get('src_ip', 'N/A')}")
        print(f"  - Destination IP: {log.get('dst_ip', 'N/A')}")
        print(f"  - Protocol: {log.get('protocol', 'N/A')}")
        print(f"  - Actual label: {log.get('label', 'N/A')}")
        
        try:
            is_anomaly, confidence = detector.detect_anomalies(log)
            print(f"  - Detected as anomaly: {is_anomaly}")
            print(f"  - Confidence: {confidence:.4f}")
        except Exception as e:
            print(f"  - ERROR detecting anomaly: {str(e)}")
            traceback.print_exc()
        print()
except Exception as e:
    print(f"ERROR during testing: {str(e)}")
    traceback.print_exc()

print("Test completed")