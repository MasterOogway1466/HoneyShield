# dos_test.py
import socket
import threading
import time

def rapid_connection(host, port, count):
    """Make rapid connections to test DoS detection"""
    print(f"Starting rapid connection test: {count} connections")
    
    successful = 0
    failed = 0
    blacklisted = 0
    
    for i in range(count):
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            
            # Connect to the honeypot
            s.connect((host, port))
            
            # Receive welcome message
            data = s.recv(4096)
            response = data.decode('utf-8', errors='ignore')
            
            # Check if blacklisted
            if "blacklisted" in response.lower():
                blacklisted += 1
                print(f"Connection {i+1}: BLACKLISTED")
            else:
                # Try a random command
                s.sendall(b"admin\n")
                time.sleep(0.1)
                s.sendall(b"wrong_password\n")
                time.sleep(0.1)
                
                # Try to receive response
                try:
                    data = s.recv(4096)
                    successful += 1
                    print(f"Connection {i+1}: SUCCESS")
                except:
                    failed += 1
                    print(f"Connection {i+1}: TIMEOUT")
            
            # Close the socket
            s.close()
            
            # Small delay to make the test more realistic
            time.sleep(0.2)
            
        except Exception as e:
            failed += 1
            print(f"Connection {i+1}: FAILED - {e}")
    
    print("\n--- Test Results ---")
    print(f"Total connections: {count}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Blacklisted: {blacklisted}")

if __name__ == "__main__":
    import sys
    
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    
    rapid_connection(host, port, count)