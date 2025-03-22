import os
import sys
import pickle
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MLIDSModelAdapter:
    """Adapter for the ML-IDS model to integrate with the IoT security project"""
    
    def __init__(self, model_path=None, pipeline_path=None, col_config_path=None):
        """
        Initialize the model adapter.
        
        Args:
            model_path: Path to the CatBoost model file (.cbm)
            pipeline_path: Path to the preprocessing pipeline file (.pkl)
            col_config_path: Path to the column configuration file (.pkl)
        """
        self.model = None
        self.pipeline = None
        self.col_names = None
        self.preserve_cols = None
        
        # Try to import CatBoost
        try:
            from catboost import CatBoostClassifier
            self.CatBoostClassifier = CatBoostClassifier
        except ImportError:
            logger.error("CatBoost is not installed. Install with: pip install catboost")
            raise
            
        # Load model if paths are provided
        if model_path and pipeline_path:
            self.load_model(model_path, pipeline_path, col_config_path)
            
    def load_model(self, model_path, pipeline_path, col_config_path=None):
        """
        Load the model and preprocessing pipeline.
        
        Args:
            model_path: Path to the CatBoost model file (.cbm)
            pipeline_path: Path to the preprocessing pipeline file (.pkl)
            col_config_path: Path to the column configuration file (.pkl)
        """
        try:
            # Load model
            self.model = self.CatBoostClassifier()
            self.model.load_model(model_path)
            logger.info(f"Model loaded from {model_path}")
            
            # Load preprocessing pipeline
            with open(pipeline_path, 'rb') as f:
                self.pipeline = pickle.load(f)
            logger.info(f"Preprocessing pipeline loaded from {pipeline_path}")
            
            # Load column configuration if provided
            if col_config_path:
                with open(col_config_path, 'rb') as f:
                    column_config = pickle.load(f)
                self.col_names = column_config.get('col_names', [])
                self.preserve_cols = column_config.get('preserve_neg_vals', [])
                logger.info(f"Column configuration loaded from {col_config_path}")
                
            return True
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
            
    def preprocess(self, data):
        """
        Preprocess the data using the ML-IDS preprocessing pipeline.
        
        Args:
            data: DataFrame or dict of features
            
        Returns:
            Preprocessed data ready for prediction
        """
        try:
            # Convert dict to DataFrame if needed
            if isinstance(data, dict):
                data = pd.DataFrame([data])
            
            # Filter to required columns if col_names is available
            if self.col_names:
                # Check for missing columns and add them with zeros
                for col in self.col_names:
                    if col not in data.columns:
                        data[col] = 0
                
                # Only keep columns in col_names that are also in data
                existing_cols = [col for col in self.col_names if col in data.columns]
                data = data[existing_cols]
            
            # Basic preprocessing fallback
            data = data.replace([np.inf, -np.inf], np.nan)
            data = data.fillna(0)
            
            # Apply scikit-learn pipeline
            if self.pipeline:
                return self.pipeline.transform(data)
            
            return data
        except Exception as e:
            logger.error(f"Error in preprocessing: {str(e)}")
            raise
            
    def predict(self, data):
        """
        Predict whether data is malicious or benign.
        
        Args:
            data: DataFrame or dict of features
            
        Returns:
            0 for benign, 1 for malicious
        """
        if self.model is None:
            logger.error("Model not loaded")
            return None
            
        try:
            processed_data = self.preprocess(data)
            # Use probability instead of direct prediction
            probs = self.model.predict_proba(processed_data)
            # Lower threshold to catch more potential attacks
            # 0.3 means 30% confidence is enough to mark as malicious
            return (probs[:, 1] > 0.25).astype(int)
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            return None
            
    def predict_proba(self, data):
        """
        Get probability scores for predictions.
        
        Args:
            data: DataFrame or dict of features
            
        Returns:
            Probability scores for each class
        """
        if self.model is None:
            logger.error("Model not loaded")
            return None
            
        try:
            processed_data = self.preprocess(data)
            return self.model.predict_proba(processed_data)
        except Exception as e:
            logger.error(f"Error in prediction probabilities: {str(e)}")
            return None