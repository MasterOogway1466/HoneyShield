import os
import sys
import logging
import argparse
import json
import time
from datetime import datetime
from src.ml_integration.evaluate_model import evaluate_model

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from src.preprocessing.data_processor import DataProcessor
from src.model.model_trainer import ModelTrainer
from src.detection.anomaly_detector import AnomalyDetector
from src.ml_integration.model_adapter import MLIDSModelAdapter
from src.ml_integration.data_simulator import CICIDSDataSimulator
from src.ml_integration.train_model import train_model

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'main.log')), 
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

def analyze_dataset(dataset_path):
    """Analyze the dataset to understand its structure and content"""
    import pandas as pd
    df = pd.read_parquet(dataset_path)
    logger.info(f"Dataset shape: {df.shape}")
    logger.info(f"Dataset columns: {df.columns.tolist()}")
    
    # Check for potential label columns
    for col in ['Label', 'label', 'is_attack', 'Attack', 'attack', 'class', 'Class']:
        if col in df.columns:
            logger.info(f"Found column '{col}' with values: {df[col].value_counts().to_dict()}")
    
    # Sample a few rows to understand structure
    logger.info("First 2 rows of data:")
    for i, row in df.head(2).iterrows():
        logger.info(f"Row {i}: {dict(row)}")

def simulate_real_time_detection(model_path, pipeline_path, col_config_path, dataset_path, interval=0.1, limit=100):
    """
    Run real-time traffic simulation with the ML-IDS model.
    
    Args:
        model_path: Path to the CatBoost model
        pipeline_path: Path to the preprocessing pipeline
        col_config_path: Path to the column configuration
        dataset_path: Path to the CIC-IDS dataset
        interval: Time interval between samples
        limit: Maximum number of samples to process
    """
    logger.info("Initializing ML-IDS model adapter...")
    model_adapter = MLIDSModelAdapter(model_path, pipeline_path, col_config_path)
    
    logger.info("Initializing data simulator...")
    simulator = CICIDSDataSimulator(dataset_path, interval)
    
    # Stats for summary
    stats = {
        'total': 0,
        'benign': 0,
        'malicious': 0
    }
    
    logger.info("Starting real-time traffic simulation...")
    
    def process_sample(sample):
        """Process a single sample from the simulator"""
        prediction = model_adapter.predict(sample)
        probability = model_adapter.predict_proba(sample)
        
        # Update stats
        stats['total'] += 1
        if prediction == 0:
            stats['benign'] += 1
            logger.info(f"[BENIGN] Traffic from {sample.get('src_ip', 'unknown')} to {sample.get('dst_ip', 'unknown')}")
        else:
            stats['malicious'] += 1
            confidence = 0
            if probability is not None and len(probability) > 0:
                confidence = probability[0][1]
            logger.warning(f"[MALICIOUS] Traffic detected from {sample.get('src_ip', 'unknown')} to {sample.get('dst_ip', 'unknown')} (Confidence: {confidence:.4f})")
    
    # Run simulation with callback
    for _ in simulator.simulate_traffic(callback=process_sample, limit=limit):
        pass
    
    # Print summary
    logger.info("\n===== Simulation Summary =====")
    logger.info(f"Total packets processed: {stats['total']}")
    if stats['total'] > 0:
        logger.info(f"Benign packets: {stats['benign']} ({stats['benign']/stats['total']*100:.2f}%)")
        logger.info(f"Malicious packets: {stats['malicious']} ({stats['malicious']/stats['total']*100:.2f}%)")

def main():
    parser = argparse.ArgumentParser(description='IoT Security Anomaly Detection System')
    parser.add_argument('--train', action='store_true', help='Train a new ML-IDS model')
    parser.add_argument('--detect', action='store_true', help='Run anomaly detection')
    parser.add_argument('--simulate', action='store_true', help='Run real-time traffic simulation with ML-IDS model')
    parser.add_argument('--analyze', action='store_true', help='Analyze the dataset structure')
    parser.add_argument('--iterations', type=int, default=100, help='Number of iterations for model training')
    parser.add_argument('--dataset', type=str, default='../../cic-ids/cic-collection.parquet', help='Path to CIC-IDS dataset')
    parser.add_argument('--interval', type=float, default=0.1, help='Interval between packets in simulation')
    parser.add_argument('--limit', type=int, default=100, help='Maximum number of packets to process')
    parser.add_argument('--evaluate', action='store_true', 
                   help='Evaluate model on a labeled dataset')
    parser.add_argument('--test-dataset', type=str, default=None,
                   help='Path to test dataset for evaluation')
    
    args = parser.parse_args()
    
    if args.analyze:
        logger.info(f"Analyzing dataset: {args.dataset}")
        analyze_dataset(args.dataset)
    
    elif args.train:
        logger.info("Training new ML-IDS model")
        result = train_model(args.dataset, iterations=args.iterations)
        logger.info(f"Model trained with accuracy: {result['accuracy']:.4f}")
    
    elif args.simulate:
        # Model file paths
        model_path = "models/catboost_model.cbm"
        pipeline_path = "models/preprocessing_pipeline.pkl"
        col_config_path = "models/column_config.pkl"
        
        # Check if model exists, if not, train it
        if not os.path.exists(model_path):
            logger.info("Model not found, training a new one...")
            result = train_model(args.dataset, iterations=args.iterations)
            model_path = result['model_path']
            pipeline_path = result['pipeline_path']
            col_config_path = result['col_config_path']
        
        # Run simulation
        simulate_real_time_detection(
            model_path, 
            pipeline_path, 
            col_config_path,
            args.dataset,
            interval=args.interval,
            limit=args.limit
        )
    
    elif args.detect:
        # Existing detection code
        pass

    elif args.evaluate:
        if args.test_dataset is None:
            logger.error("No test dataset specified. Use --test-dataset to specify a labeled dataset.")
        else:
            logger.info(f"Evaluating model on {args.test_dataset}")
            model_path = "models/catboost_model.cbm"
            pipeline_path = "models/preprocessing_pipeline.pkl"
            col_config_path = "models/column_config.pkl"
            
            # Evaluate model
            evaluate_model(model_path, pipeline_path, col_config_path, args.test_dataset)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()