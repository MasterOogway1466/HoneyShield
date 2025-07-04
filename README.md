# IoT Security Anomaly Detection System

A comprehensive security solution for detecting anomalies and intrusions in IoT networks using machine learning and honeypot technology.

## Project Overview

This project combines a sophisticated IoT honeypot with machine learning-based intrusion detection to provide enhanced protection for IoT networks. The system is designed to:

1. Detect anomalous network traffic in IoT environments
2. Lure potential attackers with a realistic IoT device honeypot
3. Monitor and analyze attack patterns
4. Use machine learning to identify zero-day threats and sophisticated attacks

## Key Features

- **Enhanced IoT Honeypot**: Simulates various IoT devices (cameras, thermostats, smart locks, etc.) with realistic responses
- **SSH Server Integration**: Provides a realistic SSH interface for attackers to interact with
- **Dynamic Device Simulation**: Offers device-specific commands and responses
- **IP Blacklisting**: Automatically blocks suspicious IP addresses
- **Machine Learning IDS**: Uses CatBoost and other ML models to detect anomalous traffic patterns
- **Real-time Traffic Analysis**: Processes network traffic in real-time to identify threats
- **Command History**: Tracks and provides command history functionality for more realistic interaction
- **Attack Pattern Recognition**: Detects common attack patterns including sandbox escape attempts

## Installation

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/MasterOogway1466/HoneyShield.git
   cd iot-security-anomaly-detection
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Generate or use an existing SSH host key:
   ```bash
   ssh-keygen -t rsa -f ssh_host_rsa_key -N ""
   ```

## Usage

### Running the Honeypot

To start the honeypot server:

```bash
python run_honeypot.py
```

### Running the Machine Learning IDS

To train a new ML model for intrusion detection:

```bash
python main.py --train --dataset path/to/dataset.parquet
```

To simulate real-time traffic analysis:

```bash
python main.py --simulate --dataset path/to/dataset.parquet --interval 0.1 --limit 100
```

### Running the Complete Demo

To run a full demonstration of the system:

```bash
python run_demo.py
```

## Architecture

The system consists of several key components:

### Honeypot

- Located in `src/honeypot/honeypot.py`
- Simulates various IoT devices with realistic behaviors
- Logs all interaction attempts
- Identifies and blocks suspicious behaviors

### Machine Learning IDS

- Located in `src/detection/anomaly_detector.py` and `src/ml_integration/`
- Uses CatBoost and other ML algorithms to detect anomalies
- Processes network traffic in real-time
- Integrates with the honeypot for enhanced protection

### Data Processing Pipeline

- Located in `src/preprocessing/data_processor.py`
- Handles feature extraction and normalization
- Prepares data for machine learning models
- Supports various data formats including CICFlowMeter output

### CICFlowMeter Integration

- Located in `src/ml_integration/cicflowmeter_integration.py`
- Captures and analyzes network traffic in real-time
- Transforms raw network traffic into machine learning-ready features
- Integrates with anomaly detection system for immediate threat identification
- Provides comprehensive flow statistics including timestamps, IPs, ports, protocols, durations, and packet information

## Datasets

The system is designed to work with various datasets including:

1. **CICFlowMeter Generated Data**:
   - The project utilizes the CICFlowMeter tool to generate and process network flow data
   - Flow data includes src/dst IPs, ports, protocols, duration, packet counts, bytes transferred, and flow rates
   - Located in `data/captured_flows/simulated_flows.csv`

2. **Public IoT Security Datasets**:
   - Canadian Institute for Cybersecurity (CIC) IoT datasets
   - Located in `data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`
   - Contains labeled normal and attack traffic patterns

3. **Simulated Attack Data**:
   - Generated through test scripts like `dos_test.py` and `ml_command_injection_test.py`
   - Used for evaluating and validating the detection system

## Testing & Evaluation

The system includes several test scripts:

- `dos_test.py`: Tests detection of DoS attacks
- `ml_dos_test.py`: Tests the ML model's ability to detect DoS attacks
- `ml_command_injection_test.py`: Tests command injection detection
- `test_detection.py`: General detection capabilities testing

## Project Structure

```
├── config.py                     # Configuration settings
├── main.py                       # Main application entry point
├── run_honeypot.py               # Script to run the honeypot
├── run_demo.py                   # Demo script
├── requirements.txt              # Python dependencies
├── data/                         # Data storage
│   ├── captured_flows/           # Captured network flows
│   ├── processed/                # Processed data for ML
│   └── raw/                      # Raw data sources
├── logs/                         # Log files
├── models/                       # Saved ML models
├── src/                          # Source code
│   ├── detection/                # Anomaly detection components
│   ├── honeypot/                 # Honeypot implementation
│   ├── ml_integration/           # ML integration components
│   ├── model/                    # ML model definitions
│   ├── preprocessing/            # Data preprocessing pipelines
│   └── utils/                    # Utility functions
└── evaluation/                   # Evaluation metrics and figures
```

## Machine Learning Models

The system incorporates multiple machine learning models for anomaly detection:

1. **CatBoost Classifier** (Primary model):
   - Gradient boosting on decision trees
   - High performance with mixed data types
   - Handles categorical variables efficiently
   - Located in `models/catboost_model.cbm`

2. **Random Forest Classifier** (Secondary model):
   - Ensemble learning method using multiple decision trees
   - Provides robustness against overfitting
   - Located in `models/random_forest_model.pkl`

3. **Preprocessing Pipeline**:
   - Feature standardization and normalization
   - One-hot encoding for categorical variables
   - Located in `models/preprocessing_pipeline.pkl` and `models/preprocessor.pkl`

## Configuration

The system can be configured by modifying `config.py`. Key settings include:

- `HONEYPOT_IP`: IP address for the honeypot server (default: 0.0.0.0)
- `HONEYPOT_PORT`: Port for the honeypot server (default: 22 - SSH)
- `LOGS_DIR`: Directory for log files
- `MODEL_DIR`: Directory for saved ML models
- `TEST_SIZE`: Ratio for train/test split
- `RANDOM_STATE`: Random seed for reproducibility

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security Notes

1. This system is designed for research and educational purposes.
2. Running the honeypot on port 22 (SSH) may require root/admin privileges.
3. Consider running in a contained environment to prevent potential security issues.
4. Never expose the honeypot directly to the internet without proper security measures.
5. The simulated attacks and detection mechanisms are intended for controlled environments only.

## Future Work

- Integration with MQTT and other IoT protocols
- Improved device simulation capabilities
- Federated learning for distributed anomaly detection
- Integration with security information and event management (SIEM) systems
- Real-time visualization dashboard for threat monitoring
- Extended device profiles for wider IoT ecosystem coverage
- Implementation of threat intelligence feeds
