import socket
import sys
import time

def connect_to_honeypot(host='localhost', port=8080):
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to the honeypot
        print(f"Connecting to {host}:{port}...")
        s.connect((host, port))
        
        # Receive welcome message
        data = s.recv(4096)
        print(data.decode('utf-8', errors='ignore'), end='')
        
        # Interactive loop
        while True:
            # Get user input
            user_input = input()
            
            # Send input to server without adding extra newlines
            s.sendall(user_input.encode('utf-8'))
            
            # Receive response with a timeout to prevent hanging
            s.settimeout(1)
            try:
                data = s.recv(4096)
                if not data:
                    print("Connection closed by server")
                    break
                print(data.decode('utf-8', errors='ignore'), end='')
            except socket.timeout:
                # No data received within timeout, but connection still active
                pass
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    print(f"IoT Honeypot Client")
    print(f"-------------------")
    connect_to_honeypot(host, port)