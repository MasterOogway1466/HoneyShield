import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
import logging
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import config

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'preprocessing.log')), 
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

class DataProcessor:
    def __init__(self):
        self.preprocessor = None
        
    def load_data(self, file_path):
        """Load data from CSV or other formats"""
        logger.info(f"Loading data from {file_path}")
        try:
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
            elif file_path.endswith('.parquet'):
                df = pd.read_parquet(file_path)
            else:
                logger.error(f"Unsupported file format: {file_path}")
                raise ValueError(f"Unsupported file format: {file_path}")
            
            logger.info(f"Loaded data with shape {df.shape}")
            return df
        except Exception as e:
            logger.error(f"Error loading data: {str(e)}")
            raise
    
    def preprocess_data(self, df, categorical_cols=None, numerical_cols=None, target_col='label'):
        """Preprocess data by handling categorical and numerical features"""
        logger.info("Preprocessing data")

        if 'threat_type' not in df.columns:
            df['threat_type'] = 'none'
        else:
            # Fill missing threat_type values for normal logs
            df['threat_type'] = df['threat_type'].fillna('none')
        
        if categorical_cols is None or numerical_cols is None:
            # Auto-detect column types if not specified
            categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()
            numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
            
            # Remove target column from features if present
            if target_col in categorical_cols:
                categorical_cols.remove(target_col)
            if target_col in numerical_cols:
                numerical_cols.remove(target_col)
                
        logger.info(f"Categorical columns: {categorical_cols}")
        logger.info(f"Numerical columns: {numerical_cols}")
        
        # Create preprocessing pipelines
        categorical_transformer = Pipeline(steps=[
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        numerical_transformer = Pipeline(steps=[
            ('scaler', StandardScaler())
        ])
        
        # Combine preprocessing steps
        self.preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, numerical_cols),
                ('cat', categorical_transformer, categorical_cols)
            ])
        
        # Prepare features and target
        X = df.drop(columns=[target_col])
        y = df[target_col].map({'normal': 0, 'threat': 1})  # Binary classification
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE
        )
        
        # Fit preprocessor on training data
        X_train_processed = self.preprocessor.fit_transform(X_train)
        X_test_processed = self.preprocessor.transform(X_test)
        
        logger.info(f"Processed training data shape: {X_train_processed.shape}")
        logger.info(f"Processed test data shape: {X_test_processed.shape}")
        
        return X_train_processed, X_test_processed, y_train, y_test, self.preprocessor
    
    def save_processed_data(self, X_train, X_test, y_train, y_test, output_dir=None):
        """Save processed data to files"""
        if output_dir is None:
            output_dir = config.PROCESSED_DATA_DIR
            
        os.makedirs(output_dir, exist_ok=True)
        
        np.save(os.path.join(output_dir, 'X_train.npy'), X_train)
        np.save(os.path.join(output_dir, 'X_test.npy'), X_test)
        np.save(os.path.join(output_dir, 'y_train.npy'), y_train)
        np.save(os.path.join(output_dir, 'y_test.npy'), y_test)
        
        logger.info(f"Saved processed data to {output_dir}")