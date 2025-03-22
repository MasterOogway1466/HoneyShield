import pandas as pd
import numpy as np
import pickle
import logging
import os
import sys
import json
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import config

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'anomaly_detection.log')), 
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, model_path=None, preprocessor_path=None, threshold=None):
        self.threshold = threshold or config.ANOMALY_THRESHOLD
        
        # Set default paths if not provided
        if model_path is None:
            model_path = os.path.join(config.MODELS_DIR, f"{config.MODEL_TYPE}_model.pkl")
        if preprocessor_path is None:
            preprocessor_path = os.path.join(config.MODELS_DIR, "preprocessor.pkl")
            
        # Load model and preprocessor
        self.load_model(model_path)
        self.load_preprocessor(preprocessor_path)
        
    def load_model(self, model_path):
        """Load trained model from file"""
        logger.info(f"Loading model from {model_path}")
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
            
    def load_preprocessor(self, preprocessor_path):
        """Load data preprocessor from file"""
        logger.info(f"Loading preprocessor from {preprocessor_path}")
        try:
            with open(preprocessor_path, 'rb') as f:
                self.preprocessor = pickle.load(f)
            logger.info("Preprocessor loaded successfully")
        except Exception as e:
            logger.error(f"Error loading preprocessor: {str(e)}")
            raise
            
    def preprocess_log(self, log_data):
        """Preprocess a single log entry or batch of logs"""
        if isinstance(log_data, dict):
            # Single log entry
            df = pd.DataFrame([log_data])
        else:
            # Batch of logs
            df = pd.DataFrame(log_data)

        # Add missing columns expected by the preprocessor
        if 'threat_type' not in df.columns:
            df['threat_type'] = 'none'
        else:
            # Fill missing threat_type values
            df['threat_type'] = df['threat_type'].fillna('none')
            
        # Apply the same preprocessing as during training
        try:
            processed_data = self.preprocessor.transform(df)
            return processed_data
        except Exception as e:
            logger.error(f"Error preprocessing log data: {str(e)}")
            raise
            
    def detect_anomalies(self, log_data):
        """Detect anomalies in log data
        
        Args:
            log_data: A single log entry (dict) or batch of logs (list of dicts)
            
        Returns:
            For a single log: (is_anomaly, confidence)
            For batch: List of (is_anomaly, confidence) tuples
        """
        is_single = isinstance(log_data, dict)
        
        try:
            # Preprocess the log data
            processed_data = self.preprocess_log(log_data)
            
            # Get model predictions
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(processed_data)
                # Get probability of threat class (class 1)
                threat_probs = probabilities[:, 1]
            else:
                # For models without probability estimates
                predictions = self.model.predict(processed_data)
                threat_probs = predictions
                
            # Determine anomalies based on threshold
            is_anomaly = threat_probs >= self.threshold
            
            # Format results
            results = list(zip(is_anomaly, threat_probs))
            
            # Log any detected anomalies
            for i, (anomaly, prob) in enumerate(results):
                if anomaly:
                    log_entry = log_data if is_single else log_data[i]
                    logger.warning(f"Anomaly detected! Confidence: {prob:.4f}, Log data: {json.dumps(log_entry)}")
            
            return results[0] if is_single else results
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            raise
            
    def log_anomaly(self, log_data, confidence):
        """Log detected anomaly for further investigation"""
        try:
            anomaly_log_path = os.path.join(config.LOGS_DIR, 'detected_anomalies.log')
            timestamp = datetime.now().isoformat()
            
            with open(anomaly_log_path, 'a') as f:
                f.write(f"{timestamp} | Confidence: {confidence:.4f} | Data: {json.dumps(log_data)}\n")
                
        except Exception as e:
            logger.error(f"Error logging anomaly: {str(e)}")