import os
import logging
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
import matplotlib.pyplot as plt
from .model_adapter import MLIDSModelAdapter

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def evaluate_model(model_path, pipeline_path, col_config_path, dataset_path, output_dir='evaluation'):
    """
    Evaluate the ML-IDS model on a labeled dataset.
    
    Args:
        model_path: Path to the CatBoost model
        pipeline_path: Path to the preprocessing pipeline
        col_config_path: Path to the column configuration
        dataset_path: Path to a labeled dataset
        output_dir: Directory to save evaluation results
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Load model adapter
    logger.info("Loading model...")
    model_adapter = MLIDSModelAdapter(model_path, pipeline_path, col_config_path)
    
    # Load test dataset
    logger.info(f"Loading dataset from {dataset_path}")
    df = pd.read_parquet(dataset_path)
    
    # Check for normalized label column
    if 'normalized_label' in df.columns:
        y_true = df['normalized_label']
        logger.info("Using 'normalized_label' column for evaluation")
    else:
        # Check for other label columns
        label_column = None
        for col in ['Label', 'label', 'is_attack', 'Attack', 'attack', 'class', 'Class']:
            if col in df.columns:
                label_column = col
                break
        
        if label_column is None:
            logger.error("No label column found in dataset")
            return
        
        # Normalize labels to 0/1
        if df[label_column].dtype == object:
            y_true = df[label_column].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
        else:
            y_true = (df[label_column] != 0).astype(int)
        
        logger.info(f"Using '{label_column}' column for evaluation")
    
    # Remove label columns from features
    X = df.drop([col for col in ['normalized_label', 'Label', 'label', 'is_attack', 'Attack', 'attack', 'class', 'Class'] 
                 if col in df.columns], axis=1, errors='ignore')
    
    # Get predictions
    logger.info("Making predictions...")
    y_pred = model_adapter.predict(X)
    y_prob = model_adapter.predict_proba(X)
    if y_prob is not None:
        y_prob = y_prob[:, 1]  # Get probability of positive class
    
    # Calculate metrics
    logger.info("Calculating metrics...")
    report = classification_report(y_true, y_pred, output_dict=True)
    cm = confusion_matrix(y_true, y_pred)
    
    # Save results
    with open(os.path.join(output_dir, 'evaluation_metrics.txt'), 'w') as f:
        f.write(f"Classification Report:\n{classification_report(y_true, y_pred)}\n\n")
        f.write(f"Confusion Matrix:\n{cm}\n\n")
        f.write(f"Overall Accuracy: {(y_pred == y_true).mean():.4f}\n")
        f.write(f"Benign Accuracy: {(y_pred[y_true == 0] == 0).mean() if sum(y_true == 0) > 0 else 0:.4f}\n")
        f.write(f"Attack Detection Rate: {(y_pred[y_true == 1] == 1).mean() if sum(y_true == 1) > 0 else 0:.4f}\n")
    
    # Log results summary
    logger.info(f"Results:\n{classification_report(y_true, y_pred)}")
    logger.info(f"Confusion Matrix:\n{cm}")
    logger.info(f"Overall Accuracy: {(y_pred == y_true).mean():.4f}")
    
    # Plot precision-recall curve if probabilities are available
    if y_prob is not None:
        precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
        
        # Create figure directory
        os.makedirs(os.path.join(output_dir, 'figures'), exist_ok=True)
        
        # Plot precision-recall curve
        plt.figure(figsize=(10, 6))
        plt.plot(recall, precision, marker='.')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.grid(True)
        plt.savefig(os.path.join(output_dir, 'figures', 'precision_recall_curve.png'))
        
        # Plot precision, recall vs threshold
        plt.figure(figsize=(10, 6))
        plt.plot(thresholds, precision[:-1], 'b-', label='Precision')
        plt.plot(thresholds, recall[:-1], 'g-', label='Recall')
        plt.xlabel('Threshold')
        plt.ylabel('Score')
        plt.title('Precision and Recall vs. Threshold')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(output_dir, 'figures', 'threshold_analysis.png'))
    
    logger.info(f"Evaluation results saved to {output_dir}")
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Evaluate ML-IDS model on a test dataset')
    parser.add_argument('--model', type=str, default='models/catboost_model.cbm',
                        help='Path to CatBoost model file')
    parser.add_argument('--pipeline', type=str, default='models/preprocessing_pipeline.pkl',
                        help='Path to preprocessing pipeline file')
    parser.add_argument('--col-config', type=str, default='models/column_config.pkl',
                        help='Path to column configuration file')
    parser.add_argument('--dataset', type=str, default='test_dataset.parquet',
                        help='Path to test dataset file')
    parser.add_argument('--output', type=str, default='evaluation',
                        help='Directory to save evaluation results')
    
    args = parser.parse_args()
    
    evaluate_model(
        args.model,
        args.pipeline,
        args.col_config,
        args.dataset,
        args.output
    )