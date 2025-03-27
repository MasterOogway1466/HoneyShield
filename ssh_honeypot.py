import socket
import threading
import logging
import os
import sys
import time
import random

# Add modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'ssh_honeypot.log')),
                             logging.StreamHandler()])

logger = logging.getLogger(__name__)

class SSHHoneypot:
    """SSH port monitoring service that logs connection attempts"""
    
    def __init__(self, ssh_port=22, honeypot_port=8080, host='0.0.0.0', real_network_port=9090):
        self.ssh_port = ssh_port
        self.honeypot_port = honeypot_port
        self.real_network_port = real_network_port
        self.host = host
        self.server_socket = None
        self.running = False
        self.connections = []
        
    def start(self):
        """Start the SSH monitoring service"""
        logger.info(f"Starting SSH monitoring service on {self.host}:{self.ssh_port}")
        
        try:
            print(f"Binding to {self.host}:{self.ssh_port}...")
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.ssh_port))
            self.server_socket.listen(5)
            print(f"Successfully bound to {self.host}:{self.ssh_port}")
            
            self.running = True
            
            # Start listener thread
            listener_thread = threading.Thread(target=self._accept_connections)
            listener_thread.daemon = True
            listener_thread.start()
            
            logger.info(f"SSH monitoring service started on port {self.ssh_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start SSH monitoring service: {str(e)}")
            print(f"Error starting SSH service: {type(e).__name__}: {str(e)}")
            return False
    
    def stop(self):
        """Stop the SSH monitoring service"""
        logger.info("Stopping SSH monitoring service")
        self.running = False
        
        # Close all client connections
        for conn in self.connections:
            try:
                conn.close()
            except:
                pass
                
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
                
        logger.info("SSH monitoring service stopped")
        
    def _accept_connections(self):
        """Accept SSH connections and respond with proper protocol"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.connections.append(client_socket)
                
                # Handle client in a separate thread
                client_thread = threading.Thread(target=self._handle_ssh_client, 
                                              args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting SSH connection: {str(e)}")
                    time.sleep(1)
    
    def _handle_ssh_client(self, client_socket, client_address):
        """Handle SSH client with proper protocol response"""
        ip, port = client_address
        logger.info(f"SSH connection from {ip}:{port}")
        
        try:
            # Send SSH banner (must start with SSH-2.0)
            ssh_banner = b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n"
            client_socket.send(ssh_banner)
            
            # Wait for client's banner
            client_banner = client_socket.recv(1024)
            logger.info(f"Received SSH banner from {ip}:{port}: {client_banner}")
            
            # Generate fake SSH KEX (Key Exchange Init) packet
            # This is a simplified version that will cause the client to disconnect gracefully
            # rather than with a "connection reset" error
            kex_packet = bytes([random.randint(0, 255) for _ in range(32)])
            client_socket.send(kex_packet)
            
            # Log honeypot access attempt
            logger.warning(f"SSH access attempt from {ip}:{port}")
            logger.info(f"Visitor should connect to honeypot on port {self.honeypot_port} or real network on port {self.real_network_port}")
            
            # Wait a moment before closing
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Error handling SSH client {ip}:{port}: {str(e)}")
        finally:
            # Close the connection
            try:
                client_socket.close()
                if client_socket in self.connections:
                    self.connections.remove(client_socket)
            except:
                pass

# Run SSH honeypot if executed directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH Honeypot Service')
    parser.add_argument('--ssh-port', type=int, default=2222, help='SSH port to listen on')
    parser.add_argument('--honeypot-port', type=int, default=8080, help='Honeypot port to redirect to')
    parser.add_argument('--real-port', type=int, default=9090, help='Real IoT network port')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Interface to bind to')
    
    args = parser.parse_args()
    
    ssh_honeypot = SSHHoneypot(
        ssh_port=args.ssh_port,
        honeypot_port=args.honeypot_port,
        host=args.host,
        real_network_port=args.real_port
    )
    
    if ssh_honeypot.start():
        print(f"SSH monitoring service running on port {args.ssh_port}")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping SSH monitoring service...")
            ssh_honeypot.stop()