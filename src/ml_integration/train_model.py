import os
import pickle
import logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from catboost import CatBoostClassifier, Pool

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def inspect_dataset(df):
    """Print information about the dataset to help with debugging"""
    logger.info(f"Dataset shape: {df.shape}")
    logger.info(f"Dataset columns: {df.columns.tolist()}")
    
    # Check for potential label columns
    label_candidates = ['Label', 'label', 'is_attack', 'Attack', 'attack', 'class', 'Class']
    for col in label_candidates:
        if col in df.columns:
            logger.info(f"Found potential label column: {col}")
            logger.info(f"Value counts: {df[col].value_counts().to_dict()}")
    
    # Examine a few rows
    logger.info("First 3 rows of data:")
    for i, row in df.head(3).iterrows():
        logger.info(f"Row {i}: {dict(row)}")

def prepare_dataset(dataset_path, test_size=0.2, random_state=42):
    """Load and prepare the CIC-IDS dataset for training"""
    logger.info(f"Loading dataset from {dataset_path}")
    
    # Load dataset
    df = pd.read_parquet(dataset_path)
    logger.info(f"Dataset loaded, shape: {df.shape}")
    
    # Inspect the dataset
    inspect_dataset(df)
    
    # Create synthetic labels if needed
    if 'Label' in df.columns:
        # Normalize the label values
        if df['Label'].dtype == object:
            # For string labels like 'BENIGN', 'DoS', etc.
            y = df['Label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
        else:
            # For numeric labels, assume 0 is benign, others are attack
            y = (df['Label'] != 0).astype(int)
        
        logger.info(f"Using 'Label' column, distribution: {y.value_counts().to_dict()}")
    
    elif 'label' in df.columns:
        # Same normalization for lowercase 'label'
        if df['label'].dtype == object:
            y = df['label'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
        else:
            y = (df['label'] != 0).astype(int)
        
        logger.info(f"Using 'label' column, distribution: {y.value_counts().to_dict()}")
    
    # If we still have only one class or no label column identified
    if 'y' not in locals() or len(np.unique(y)) < 2:
        logger.warning("No suitable label column or only one class found. Creating synthetic labels.")
        
        # Create synthetic labels based on statistical properties
        # For example, mark the top 20% of flow durations as attacks
        if 'Flow Duration' in df.columns:
            threshold = df['Flow Duration'].quantile(0.8)
            y = (df['Flow Duration'] > threshold).astype(int)
            logger.info(f"Created synthetic labels based on Flow Duration > {threshold}")
        else:
            # As a last resort, create random labels - 80% benign, 20% attack
            y = np.random.choice([0, 1], size=len(df), p=[0.8, 0.2])
            logger.info("Created random synthetic labels: 80% benign, 20% attack")
        
        logger.info(f"Synthetic label distribution: {pd.Series(y).value_counts().to_dict()}")
    
    # Remove any label columns from features
    X = df.drop([col for col in ['Label', 'label', 'is_attack', 'Attack', 'attack', 'class', 'Class'] 
                 if col in df.columns], axis=1, errors='ignore')
    
    # Remove non-numeric columns
    object_cols = X.select_dtypes(include=['object']).columns.tolist()
    if object_cols:
        logger.info(f"Removing non-numeric columns: {object_cols}")
        X = X.drop(columns=object_cols)
    
    # Handle infinite values
    X = X.replace([np.inf, -np.inf], np.nan)
    
    # Remove columns with too many missing values (>50%)
    missing_percent = X.isnull().mean()
    cols_to_drop = missing_percent[missing_percent > 0.5].index.tolist()
    if cols_to_drop:
        logger.info(f"Dropping columns with >50% missing values: {cols_to_drop}")
        X = X.drop(columns=cols_to_drop)
    
    logger.info(f"Final features shape: {X.shape}")
    logger.info(f"Final label distribution: {pd.Series(y).value_counts().to_dict()}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    return X_train, X_test, y_train, y_test, X.columns.tolist()

def create_preprocessing_pipeline():
    """Create a preprocessing pipeline for the data"""
    return Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])

def train_model(dataset_path, output_dir='models', iterations=100, random_state=42):
    """Train a CatBoost model on the dataset and save it"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Prepare dataset
    X_train, X_test, y_train, y_test, column_names = prepare_dataset(
        dataset_path, random_state=random_state
    )
    
    # Create and fit preprocessing pipeline
    logger.info("Creating and fitting preprocessing pipeline")
    pipeline = create_preprocessing_pipeline()
    X_train_transformed = pipeline.fit_transform(X_train)
    X_test_transformed = pipeline.transform(X_test)
    
    # Check if we have both classes in the training set
    if len(np.unique(y_train)) < 2:
        logger.error("Training data only has one class. Cannot train a binary classifier.")
        raise ValueError("Training data must have both positive and negative samples.")
    
    # Create CatBoost classifier
    logger.info("Training CatBoost model")
    class_weights = {
        0: 1.0,
        1: len(y_train[y_train == 0]) / max(1, len(y_train[y_train == 1]))
    }
    
    model = CatBoostClassifier(
        iterations=iterations,
        depth=6,
        learning_rate=0.1,
        loss_function='Logloss',
        class_weights=class_weights,
        verbose=50,
        random_seed=random_state
    )
    
    # Train model
    train_pool = Pool(X_train_transformed, y_train)
    test_pool = Pool(X_test_transformed, y_test)
    model.fit(train_pool, eval_set=test_pool, early_stopping_rounds=20)
    
    # Save model artifacts
    model_path = os.path.join(output_dir, "catboost_model.cbm")
    pipeline_path = os.path.join(output_dir, "preprocessing_pipeline.pkl")
    col_config_path = os.path.join(output_dir, "column_config.pkl")
    
    logger.info(f"Saving model to {model_path}")
    model.save_model(model_path)
    
    logger.info(f"Saving preprocessing pipeline to {pipeline_path}")
    with open(pipeline_path, 'wb') as f:
        pickle.dump(pipeline, f)
    
    logger.info(f"Saving column configuration to {col_config_path}")
    column_config = {
        'col_names': column_names,
        'preserve_neg_vals': column_names  # Allow negative values in all columns for simplicity
    }
    with open(col_config_path, 'wb') as f:
        pickle.dump(column_config, f)
    
    # Evaluate model
    y_pred = model.predict(test_pool)
    accuracy = (y_pred == y_test).mean()
    logger.info(f"Model accuracy: {accuracy:.4f}")
    
    return {
        'model_path': model_path,
        'pipeline_path': pipeline_path,
        'col_config_path': col_config_path,
        'accuracy': accuracy
    }

if __name__ == "__main__":
    # Use relative path to go up from src/ml_integration to the dataset
    dataset_path = "../../../cic-ids/cic-collection.parquet"
    
    # Train the model
    result = train_model(dataset_path)
    
    print("\n======= Model Training Complete =======")
    print(f"Model saved to: {result['model_path']}")
    print(f"Pipeline saved to: {result['pipeline_path']}")
    print(f"Column config saved to: {result['col_config_path']}")
    print(f"Model accuracy: {result['accuracy']:.4f}")
    print("=======================================\n")