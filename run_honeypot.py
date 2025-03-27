import os
import sys
import argparse
import time
import signal
import logging
from src.honeypot.honeypot import EnhancedIoTHoneypot
from src.ml_integration.model_adapter import MLIDSModelAdapter
import config

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

def main():
    """Run the honeypot server with options"""
    parser = argparse.ArgumentParser(description='IoT Security Honeypot')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host IP to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--reset-blacklist', action='store_true', help='Reset blacklist on startup')
    parser.add_argument('--real-network', action='store_true', help='Run as real network (more permissive)')
    
    args = parser.parse_args()
    
    try:
        # Load ML-IDS model
        logger.info("Loading ML-IDS model...")
        
        # Define model paths
        model_path = os.path.join(config.MODEL_DIR, 'catboost_model.cbm')
        pipeline_path = os.path.join(config.MODEL_DIR, 'preprocessing_pipeline.pkl')
        col_config_path = os.path.join(config.MODEL_DIR, 'column_config.pkl')
        
        # Create model adapter with paths
        ml_model = MLIDSModelAdapter(model_path, pipeline_path, col_config_path)
        
        # Initialize and start honeypot
        logger.info(f"Initializing IoT {'real network' if args.real_network else 'honeypot'} on {args.host}:{args.port}")
        honeypot = EnhancedIoTHoneypot(host=args.host, port=args.port, ml_model=ml_model)
        
        # For real network, update credentials
        if args.real_network:
            # Use different credentials for real network
            honeypot.valid_credentials = {"admin": "secure_network_2025", "operator": "op3r4t0r_passw0rd"}
            honeypot.is_real_network = True
        
        if honeypot.start():
            logger.info(f"IoT {'real network' if args.real_network else 'honeypot'} started")
            
            # Listen for Ctrl+C to gracefully shut down
            def signal_handler(sig, frame):
                logger.info("Stopping honeypot...")
                honeypot.stop()
                logger.info("Honeypot stopped")
                sys.exit(0)
                
            signal.signal(signal.SIGINT, signal_handler)
            
            while True:
                time.sleep(1)
                
        else:
            logger.error("Failed to start honeypot")
            return 1
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1
        
    return 0
    
if __name__ == "__main__":
    sys.exit(main())