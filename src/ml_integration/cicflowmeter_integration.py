# Create file: src/ml_integration/cicflowmeter_integration.py
import subprocess
import os
import threading
import time
import logging
import pandas as pd

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CICFlowMeterIntegration:
    """Integration with CICFlowMeter for real-time traffic analysis"""
    
    def __init__(self, interface='eth0', output_dir='data/captured_flows'):
        """
        Initialize CICFlowMeter integration
        
        Args:
            interface: Network interface to capture traffic from
            output_dir: Directory to save flow data
        """
        self.interface = interface
        self.output_dir = output_dir
        self.process = None
        self.running = False
        self.flow_data = None
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
    def start_capture(self):
        """Start capturing network flows with CICFlowMeter"""
        if self.running:
            logger.warning("CICFlowMeter is already running")
            return False
            
        try:
            logger.info(f"Starting CICFlowMeter capture on interface {self.interface}")
            
            # Note: This assumes CICFlowMeter is installed and in your PATH
            # Adjust the command based on your CICFlowMeter installation
            cmd = [
                "java", "-jar", "CICFlowMeter.jar",
                "--capture", 
                "--interface", self.interface,
                "--output", self.output_dir
            ]
            
            # For demo purposes, we'll simulate this
            # self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Simulate process for demo
            self.running = True
            
            # Start background thread to simulate flow generation
            self.flow_thread = threading.Thread(target=self._simulate_flows)
            self.flow_thread.daemon = True
            self.flow_thread.start()
            
            logger.info("CICFlowMeter capture started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting CICFlowMeter: {str(e)}")
            return False
    
    def stop_capture(self):
        """Stop the CICFlowMeter capture"""
        if not self.running:
            logger.warning("CICFlowMeter is not running")
            return False
            
        try:
            logger.info("Stopping CICFlowMeter capture")
            
            # In a real implementation:
            # self.process.terminate()
            # self.process.wait(timeout=5)
            
            # Simulate stopping for demo
            self.running = False
            time.sleep(0.5)  # Give thread time to clean up
            
            logger.info("CICFlowMeter capture stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping CICFlowMeter: {str(e)}")
            return False
    
    def _simulate_flows(self):
        """Simulate flow generation for demo purposes"""
        flow_file = os.path.join(self.output_dir, "simulated_flows.csv")
        
        # Create headers for our simulated flow data
        headers = [
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", 
            "protocol", "duration", "total_pkts", "total_bytes",
            "flow_rate", "is_attack"
        ]
        
        # Create empty dataframe with headers
        self.flow_data = pd.DataFrame(columns=headers)
        self.flow_data.to_csv(flow_file, index=False)
        
        logger.info(f"Created flow file: {flow_file}")
        
        # Simulate flow generation while running
        while self.running:
            # Generate a random flow (could be from honeypot connections)
            import random
            from datetime import datetime
            
            flow = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": f"192.168.1.{random.randint(2, 254)}",
                "src_port": random.randint(1024, 65535),
                "dst_ip": "192.168.1.1",
                "dst_port": 8080,  # Our honeypot port
                "protocol": random.choice(["TCP", "UDP"]),
                "duration": round(random.uniform(0.1, 5.0), 3),
                "total_pkts": random.randint(1, 50),
                "total_bytes": random.randint(64, 1500),
                "flow_rate": round(random.uniform(100, 10000), 2),
                "is_attack": 1 if random.random() < 0.2 else 0  # 20% are attacks
            }
            
            # Add to dataframe and save
            self.flow_data = pd.concat([self.flow_data, pd.DataFrame([flow])], ignore_index=True)
            self.flow_data.to_csv(flow_file, index=False)
            
            # Log occasional attacks
            if flow["is_attack"] == 1:
                logger.warning(f"Potential attack detected from {flow['src_ip']}:{flow['src_port']}")
            
            # Sleep for random interval
            time.sleep(random.uniform(0.5, 2.0))
    
    def get_latest_flows(self, count=10):
        """Get the latest flow data"""
        if self.flow_data is None or len(self.flow_data) == 0:
            return None
            
        return self.flow_data.tail(count)