import socket
import sys
import time

def connect_to_honeypot(host='localhost', port=8080):
    """Connect to the honeypot server with improved response handling"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"Connecting to {host}:{port}...")
        s.connect((host, port))
        
        # Receive welcome message with timeout
        s.settimeout(2.0)
        welcome_data = b""
        
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                welcome_data += chunk
                # Short timeout to check for more data
                s.settimeout(0.2)
        except socket.timeout:
            pass  # No more welcome data
            
        if welcome_data:
            print(welcome_data.decode('utf-8', errors='ignore'), end='')
        
        # Main command loop
        while True:
            # Get command from user
            command = input()
            
            # Send command with explicit newline
            s.sendall((command + "\n").encode('utf-8'))
            
            # Wait for server to process
            time.sleep(0.3)
            
            # Get response with timeout
            s.settimeout(1.0)
            response_data = b""
            
            try:
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        print("Connection closed by server")
                        return
                    response_data += chunk
                    # Short timeout for additional data
                    s.settimeout(0.2)
            except socket.timeout:
                pass  # No more response data
            
            # Print response if we got any
            if response_data:
                print(response_data.decode('utf-8', errors='ignore'), end='')
            
    except ConnectionRefusedError:
        print(f"Error: Connection refused to {host}:{port}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    print("IoT Honeypot Client")
    print("-------------------")
    connect_to_honeypot(host, port)