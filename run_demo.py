import os
import sys
import argparse
import subprocess
import time
import threading

def run_command(cmd, name):
    """Run a command and prefix its output with the name"""
    process = subprocess.Popen(
        cmd, 
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    for line in process.stdout:
        print(f"[{name}] {line}", end="")
    
    process.wait()
    print(f"[{name}] Process exited with code {process.returncode}")

def main():
    parser = argparse.ArgumentParser(description="IoT Security Honeypot Demo")
    parser.add_argument("--ip", type=str, help="Your IP address for teammates to connect to")
    args = parser.parse_args()
    
    # Get local IP to share with teammates
    if not args.ip:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
    else:
        ip = args.ip
    
    # Clear any existing blacklist
    print("\n=== Resetting Honeypot ===")
    run_command(["python", "reset_blacklist.py"], "Reset")
    
    # Print connection instructions
    print("\n=== CONNECTION INSTRUCTIONS FOR TEAMMATES ===")
    print(f"1. Download the honeypot_client.py file")
    print(f"2. Run: python honeypot_client.py {ip} 8080")
    print(f"3. Use username 'admin' and password 'secure_iot_2025' for authorized access")
    print(f"   Or try wrong passwords to trigger the sandbox")
    print("=" * 50 + "\n")
    
    # Start honeypot in separate thread
    print("Starting IoT Security Honeypot...")
    honeypot_thread = threading.Thread(
        target=run_command,
        args=(["python", "run_honeypot.py", "--host", "0.0.0.0", "--port", "8080", "--reset-blacklist"], "Honeypot")
    )
    honeypot_thread.daemon = True
    honeypot_thread.start()
    
    # Give honeypot time to start
    time.sleep(3)
    
    try:
        print("\nPress Ctrl+C to stop the demo")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down demo...")

if __name__ == "__main__":
    main()