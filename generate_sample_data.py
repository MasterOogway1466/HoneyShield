# filepath: generate_sample_data.py
import pandas as pd
import numpy as np
import random
import ipaddress
import datetime
import os
import sys
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

# Ensure data directory exists
os.makedirs(config.RAW_DATA_DIR, exist_ok=True)

# Define parameters
num_samples = 10000
legitimate_ratio = 0.8  # 80% legitimate traffic, 20% threats
output_file = os.path.join(config.RAW_DATA_DIR, 'sample_iot_logs.csv')

# Define possible values
protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'MQTT', 'CoAP']
ports = [21, 22, 23, 80, 443, 1883, 5683, 8883, 8080] + list(range(49152, 49162))
iot_device_types = ['thermostat', 'camera', 'smartlock', 'lighting', 'speaker', 'hub']

# Generate base network
base_ip = '192.168.1.'
gateway_ip = '192.168.1.1'
subnet_mask = '255.255.255.0'

# Function to generate a random IP
def random_ip(internal=True):
    if internal:
        return f'192.168.1.{random.randint(2, 254)}'
    else:
        return f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}'

# Function to generate timestamp
def random_timestamp():
    start_date = datetime.datetime.now() - datetime.timedelta(days=7)
    end_date = datetime.datetime.now()
    time_between_dates = end_date - start_date
    seconds_between_dates = time_between_dates.total_seconds()
    random_seconds = random.randrange(int(seconds_between_dates))
    return start_date + datetime.timedelta(seconds=random_seconds)

# Generate normal traffic patterns
def generate_normal_log():
    src_ip = random_ip(internal=True)
    dst_ip = random_ip(internal=random.random() < 0.3)  # 30% internal, 70% external
    protocol = random.choice(protocols)
    
    # Normal patterns
    if protocol in ['HTTP', 'MQTT', 'CoAP']:
        port = {'HTTP': 80, 'MQTT': 1883, 'CoAP': 5683}[protocol]
    else:
        port = random.choice(ports)
    
    # Normal traffic characteristics
    packet_size = random.randint(64, 1500)
    duration = random.uniform(0.1, 5.0)
    packets = random.randint(1, 100)
    device_type = random.choice(iot_device_types)
    
    return {
        'timestamp': random_timestamp().isoformat(),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'port': port,
        'packet_size': packet_size,
        'duration': duration,
        'packets': packets,
        'device_type': device_type,
        'label': 'normal'
    }

# Generate threat traffic patterns
def generate_threat_log():
    # 50% chance to simulate internal compromise
    internal_source = random.random() < 0.5
    
    src_ip = random_ip(internal=internal_source)
    dst_ip = random_ip(internal=True)  # Target is always internal
    protocol = random.choice(protocols)
    
    # Threat patterns - often scanning, brute force, or unusual ports
    threat_type = random.choice(['scan', 'bruteforce', 'backdoor', 'dataexfil', 'ddos', 'mitm'])
    
    if threat_type == 'scan':
        # Port scanning
        port = random.randint(1, 65535)
        packet_size = random.randint(40, 100)
        duration = random.uniform(0.01, 0.1)
        packets = random.randint(1, 5)
    elif threat_type == 'bruteforce':
        # Brute force attacks
        port = random.choice([22, 23, 80, 443, 8080])
        packet_size = random.randint(100, 500)
        duration = random.uniform(0.5, 10.0)
        packets = random.randint(100, 1000)
    elif threat_type == 'backdoor':
        # Backdoor communication
        port = random.randint(10000, 65535)
        packet_size = random.randint(200, 1000)
        duration = random.uniform(1.0, 30.0)
        packets = random.randint(10, 50)
    elif threat_type == 'dataexfil':
        # Data exfiltration
        port = random.choice([21, 22, 80, 443, 8080])
        packet_size = random.randint(1000, 9000)
        duration = random.uniform(5.0, 60.0)
        packets = random.randint(100, 500)
    elif threat_type == 'ddos':
        # DDoS traffic
        port = random.choice([80, 443, 53])
        packet_size = random.randint(64, 1500)
        duration = random.uniform(0.1, 1.0)
        packets = random.randint(1000, 10000)
    else:  # mitm
        # Man-in-the-middle
        port = random.choice([80, 443])
        packet_size = random.randint(64, 1500)
        duration = random.uniform(1.0, 30.0)
        packets = random.randint(50, 200)
    
    device_type = random.choice(iot_device_types)
    
    return {
        'timestamp': random_timestamp().isoformat(),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'port': port,
        'packet_size': packet_size,
        'duration': duration,
        'packets': packets,
        'device_type': device_type,
        'threat_type': threat_type,
        'label': 'threat'
    }

# Generate dataset
print(f"Generating {num_samples} sample IoT network logs...")
logs = []

for i in range(num_samples):
    if random.random() < legitimate_ratio:
        logs.append(generate_normal_log())
    else:
        logs.append(generate_threat_log())
    
    if (i+1) % 1000 == 0:
        print(f"Generated {i+1} logs...")

# Convert to DataFrame
df = pd.DataFrame(logs)

# Save to CSV
df.to_csv(output_file, index=False)
print(f"Sample data generated and saved to {output_file}")

# Also save a few samples as JSON for testing anomaly detection
json_samples = []
for _ in range(10):
    if random.random() < 0.5:
        json_samples.append(generate_normal_log())
    else:
        json_samples.append(generate_threat_log())

sample_json_path = os.path.join(config.RAW_DATA_DIR, 'sample_logs.json')
with open(sample_json_path, 'w') as f:
    json.dump(json_samples, f, indent=2)

print(f"Sample JSON logs saved to {sample_json_path}")