import os
import sys
import logging
import argparse
import time
from datetime import datetime

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from src.ml_integration.model_adapter import MLIDSModelAdapter
from src.honeypot.honeypot import EnhancedIoTHoneypot

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'honeypot_main.log')), 
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description='IoT Security Honeypot and Anomaly Detection System')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Honeypot listen address')
    parser.add_argument('--port', type=int, default=8080, help='Honeypot listen port')
    parser.add_argument('--no-auth', action='store_true', help='Disable authentication requirement')
    parser.add_argument('--no-ml', action='store_true', help='Disable ML model integration')
    parser.add_argument('--reset-blacklist', action='store_true', help='Reset the IP blacklist')
    
    args = parser.parse_args()
    
    # Initialize ML model
    ml_model = None
    if not args.no_ml:
        logger.info("Loading ML-IDS model...")
        model_path = "models/catboost_model.cbm"
        pipeline_path = "models/preprocessing_pipeline.pkl"
        col_config_path = "models/column_config.pkl"
        
        if os.path.exists(model_path):
            ml_model = MLIDSModelAdapter(model_path, pipeline_path, col_config_path)
            logger.info("ML-IDS model loaded successfully")
        else:
            logger.warning("ML-IDS model not found. Run 'python main.py --train' to train a model first.")
    
    # Initialize honeypot
    logger.info(f"Initializing IoT honeypot on {args.host}:{args.port}")
    honeypot = EnhancedIoTHoneypot(
        host=args.host,
        port=args.port,
        ml_model=ml_model
    )
    
    # Disable authentication if requested
    if args.no_auth:
        honeypot.authentication_required = False
        logger.info("Authentication requirement disabled")
    
    # Start honeypot
    if honeypot.start():
        logger.info("IoT honeypot started")
        
        try:
            # Main loop - just keep the script running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, shutting down...")
        finally:
            honeypot.stop()
            logger.info("IoT honeypot stopped")
    else:
        logger.error("Failed to start honeypot")

    if args.reset_blacklist:
        honeypot.blacklisted_ips.clear()
        logger.info("IP blacklist has been reset")

if __name__ == "__main__":
    main()