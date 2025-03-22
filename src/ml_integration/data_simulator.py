import pandas as pd
import time
import logging
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

class CICIDSDataSimulator:
    """Simulates real-time network traffic using the CIC-IDS dataset"""
    
    def __init__(self, dataset_path, interval=0.1):
        """
        Initialize the data simulator.
        
        Args:
            dataset_path: Path to the CIC-IDS parquet file
            interval: Time interval between data points in seconds
        """
        self.dataset_path = dataset_path
        self.interval = interval
        self.data = None
        
    def load_dataset(self):
        """Load the CIC-IDS dataset from parquet file"""
        logger.info(f"Loading dataset from {self.dataset_path}")
        try:
            self.data = pd.read_parquet(self.dataset_path)
            logger.info(f"Dataset loaded successfully: {len(self.data)} rows")
            return True
        except Exception as e:
            logger.error(f"Error loading dataset: {str(e)}")
            return False
            
    def get_sample(self, random=False):
        """
        Get a single sample from the dataset.
        
        Args:
            random: If True, return a random sample. If False, iterate through the dataset.
            
        Returns:
            Dictionary representation of a data sample
        """
        if self.data is None:
            if not self.load_dataset():
                return None
        
        if random:
            # Return a random sample
            idx = np.random.randint(0, len(self.data))
            return self.data.iloc[idx].to_dict()
        
        # Return next sample by cycling through the dataset
        if not hasattr(self, 'current_idx'):
            self.current_idx = 0
        
        sample = self.data.iloc[self.current_idx].to_dict()
        self.current_idx = (self.current_idx + 1) % len(self.data)
        return sample
    
    def simulate_traffic(self, callback=None, limit=None):
        """
        Simulate real-time traffic by yielding data points at specified intervals.
        
        Args:
            callback: Function to call with each data point
            limit: Maximum number of data points to yield (None for infinite)
            
        Yields:
            Dictionary representation of a data sample
        """
        if self.data is None:
            if not self.load_dataset():
                return
        
        count = 0
        try:
            for _, row in self.data.iterrows():
                sample = row.to_dict()
                
                # Add timestamp for realism
                sample['timestamp'] = datetime.now().isoformat()
                
                # Call callback if provided
                if callback:
                    callback(sample)
                
                yield sample
                
                # Sleep to simulate real-time
                time.sleep(self.interval)
                
                # Check if we've reached the limit
                count += 1
                if limit and count >= limit:
                    break
                    
        except KeyboardInterrupt:
            logger.info("Simulation stopped by user")
        except Exception as e:
            logger.error(f"Error in traffic simulation: {str(e)}")