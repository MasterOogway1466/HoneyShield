# simple_ml_demo.py
import os
import json
import sys
import time
from datetime import datetime

def add_ml_detection_log():
    log_path = 'logs/honeypot.log'
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    # Create detailed ML detection entry
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": "192.168.1.100",
        "port": 12345,
        "type": "ml_blacklisted",
        "details": "ML model detected brute force attack pattern (confidence: 0.87)",
        "device": "camera",
        "label": "threat"
    }
    
    # Write to log file
    with open(log_path, 'a') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')
    
    print(f"ML detection entry written to {log_path}")
    
    # Add a few more entries
    attack_types = ["command_injection", "port_scanning", "ddos_attempt"]
    
    for i, attack in enumerate(attack_types):
        time.sleep(0.5)  # Space out entries
        confidence = 0.65 + i*0.1
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": f"192.168.1.{110+i}",
            "port": 12345 + i,
            "type": "ml_prediction" if i == 0 else "ml_blacklisted",
            "details": f"ML model detected {attack} (confidence: {confidence:.2f})",
            "device": "camera",
            "label": "threat"
        }
        
        with open(log_path, 'a') as log_file:
            log_file.write(json.dumps(log_entry) + '\n')
            
        print(f"Added {attack} entry")
    
    print("\nHere are all ML-related entries:")
    os.system('findstr "ml_" logs\\honeypot.log')

if __name__ == "__main__":
    add_ml_detection_log()