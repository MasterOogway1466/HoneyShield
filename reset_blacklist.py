import os
import sys
import argparse

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from src.honeypot.honeypot import EnhancedIoTHoneypot

if __name__ == "__main__":
    # Create an instance with empty blacklist
    honeypot = EnhancedIoTHoneypot(host='0.0.0.0', port=8080)
    
    # Clear the blacklist (it's already empty on new instance)
    honeypot.blacklisted_ips.clear()
    
    print("Blacklist has been cleared.")
    print("Restart the honeypot with: python run_honeypot.py")