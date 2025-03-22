import os
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_test_dataset(input_file, output_file, sample_size=5000, attack_ratio=0.2, random_seed=42):
    """
    Create a test dataset for model evaluation by sampling from the CIC-IDS dataset.
    
    Args:
        input_file: Input dataset file (parquet format)
        output_file: Output test dataset file
        sample_size: Number of samples to include
        attack_ratio: Target ratio of attack samples (for synthetic labeling)
        random_seed: Random seed for reproducibility
    """
    logger.info(f"Loading dataset from {input_file}")
    
    try:
        # Load the dataset
        df = pd.read_parquet(input_file)
        logger.info(f"Dataset loaded, shape: {df.shape}")
        
        # Check for label column
        label_column = None
        for col in ['Label', 'label', 'is_attack', 'Attack', 'attack', 'class', 'Class']:
            if col in df.columns:
                label_column = col
                break
        
        # If label column exists, use it
        if label_column:
            logger.info(f"Found label column: {label_column}")
            
            # Normalize label values
            if df[label_column].dtype == object:
                df['normalized_label'] = df[label_column].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
            else:
                df['normalized_label'] = (df[label_column] != 0).astype(int)
            
            # Get stats on original labels
            label_counts = df['normalized_label'].value_counts()
            logger.info(f"Original label distribution: {label_counts.to_dict()}")
            
            # Sample from each class to maintain distribution
            benign = df[df['normalized_label'] == 0].sample(
                min(int(sample_size * (1-attack_ratio)), len(df[df['normalized_label'] == 0])),
                random_state=random_seed
            )
            attacks = df[df['normalized_label'] == 1].sample(
                min(int(sample_size * attack_ratio), len(df[df['normalized_label'] == 1])),
                random_state=random_seed
            )
            
            # Combine samples
            sampled_df = pd.concat([benign, attacks])
        else:
            # If no label column, create synthetic one
            logger.info("No label column found. Creating synthetic labels.")
            
            # Sample data
            sampled_df = df.sample(min(sample_size, len(df)), random_state=random_seed)
            
            # Create synthetic label based on statistical properties
            if 'Flow Duration' in sampled_df.columns:
                threshold = sampled_df['Flow Duration'].quantile(1 - attack_ratio)
                sampled_df['normalized_label'] = (sampled_df['Flow Duration'] > threshold).astype(int)
                logger.info(f"Created synthetic labels using Flow Duration threshold: {threshold}")
            else:
                # If no suitable column, assign random labels
                sampled_df['normalized_label'] = np.random.choice(
                    [0, 1], 
                    size=len(sampled_df), 
                    p=[1-attack_ratio, attack_ratio]
                )
                logger.info("Created random synthetic labels")
        
        # Shuffle the dataset
        sampled_df = sampled_df.sample(frac=1, random_state=random_seed).reset_index(drop=True)
        
        # Save to output file
        sampled_df.to_parquet(output_file)
        logger.info(f"Test dataset saved to {output_file} with shape {sampled_df.shape}")
        
        # Report final label distribution
        final_counts = sampled_df['normalized_label'].value_counts()
        logger.info(f"Test dataset label distribution: {final_counts.to_dict()}")
        
        return True
    except Exception as e:
        logger.error(f"Error creating test dataset: {str(e)}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Create test dataset for model evaluation')
    parser.add_argument('--input', type=str, default='../../cic-ids/cic-collection.parquet',
                        help='Input dataset file')
    parser.add_argument('--output', type=str, default='test_dataset.parquet',
                        help='Output test dataset file')
    parser.add_argument('--size', type=int, default=5000,
                        help='Number of samples to include')
    parser.add_argument('--attack-ratio', type=float, default=0.2,
                        help='Target ratio of attack samples')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    create_test_dataset(
        args.input,
        args.output,
        sample_size=args.size,
        attack_ratio=args.attack_ratio,
        random_seed=args.seed
    )