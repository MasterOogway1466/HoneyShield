import pandas as pd
import numpy as np
import pickle
import os
import sys
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import config

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'model_training.log')), 
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

class ModelTrainer:
    def __init__(self, model_type=None):
        self.model_type = model_type or config.MODEL_TYPE
        self.model = self._get_model()
        
    def _get_model(self):
        """Initialize model based on configuration"""
        logger.info(f"Initializing model: {self.model_type}")
        
        if self.model_type == 'random_forest':
            return RandomForestClassifier(n_estimators=100, random_state=config.RANDOM_STATE)
        elif self.model_type == 'logistic_regression':
            return LogisticRegression(random_state=config.RANDOM_STATE, max_iter=1000)
        elif self.model_type == 'svm':
            return SVC(probability=True, random_state=config.RANDOM_STATE)
        elif self.model_type == 'neural_network':
            return MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=300, random_state=config.RANDOM_STATE)
        else:
            logger.error(f"Unsupported model type: {self.model_type}")
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def train(self, X_train, y_train):
        """Train the model on preprocessed data"""
        logger.info(f"Training {self.model_type} model")
        self.model.fit(X_train, y_train)
        logger.info("Model training completed")
        return self.model
    
    def evaluate(self, X_test, y_test):
        """Evaluate model performance on test data"""
        logger.info("Evaluating model performance")
        
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, "predict_proba") else None
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
        }
        
        if y_prob is not None:
            roc_auc = roc_auc_score(y_test, y_prob)
            results['roc_auc'] = roc_auc
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        results['confusion_matrix'] = cm
        
        logger.info(f"Model performance: accuracy={accuracy:.4f}, precision={precision:.4f}, recall={recall:.4f}, f1={f1:.4f}")
        
        return results
    
    def save_model(self, file_path=None):
        """Save trained model to file"""
        if file_path is None:
            os.makedirs(config.MODELS_DIR, exist_ok=True)
            file_path = os.path.join(config.MODELS_DIR, f"{self.model_type}_model.pkl")
            
        with open(file_path, 'wb') as f:
            pickle.dump(self.model, f)
            
        logger.info(f"Model saved to {file_path}")
        return file_path
    
    @staticmethod
    def load_model(file_path):
        """Load trained model from file"""
        logger.info(f"Loading model from {file_path}")
        
        with open(file_path, 'rb') as f:
            model = pickle.load(f)
            
        logger.info("Model loaded successfully")
        return model