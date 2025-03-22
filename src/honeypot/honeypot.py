import paramiko
import threading
import socket
import os
import sys
import logging
import json
import time
import re
import random
from datetime import datetime
from collections import defaultdict

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import config
from src.ml_integration.model_adapter import MLIDSModelAdapter

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(os.path.join(config.LOGS_DIR, 'honeypot.log')), 
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

class SSHServer(paramiko.ServerInterface):
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.event = threading.Event()
        self.channel = None

    def check_auth_password(self, username, password):
        if username in self.honeypot.valid_credentials:
            if self.honeypot.valid_credentials[username] == password:
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'
        
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
        
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
        
    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True

    def get_banner(self):
        return b"Welcome to IoT Device Management\n", b"en-US"
        
    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED
        
    def check_channel_env_request(self, channel, name, value):
        return False

class EnhancedIoTHoneypot:
    """Enhanced honeypot that mimics IoT devices and integrates with ML-IDS"""
    
    def __init__(self, host=None, port=None, log_path=None, ml_model=None):
        self.host = host or config.HONEYPOT_IP
        self.port = port or config.HONEYPOT_PORT
        self.log_path = log_path or config.HONEYPOT_LOG_PATH
        self.running = False
        self.server_socket = None
        self.connections = []
        self.ml_model = ml_model

        # Setup SSH logging
        paramiko.util.log_to_file(os.path.join(config.LOGS_DIR, 'ssh.log'))
        
        # Generate or load SSH host key
        key_path = os.path.join(config.BASE_DIR, 'ssh_host_rsa_key')
        try:
            self.host_key = paramiko.RSAKey(filename=key_path)
        except:
            self.host_key = paramiko.RSAKey.generate(2048)
            self.host_key.write_private_key_file(key_path)
        
        # Authentication and security
        self.valid_credentials = {"admin": "secure_iot_2025", "user": "iot_user_pass"}
        self.blacklisted_ips = set()
        self.failed_attempts = defaultdict(int)
        self.max_failed_attempts = 4
        self.authentication_required = True
        
        # Real IoT network details
        self.real_iot_devices = [
            {"ip": "192.168.1.101", "port": 8080, "type": "camera"},
            {"ip": "192.168.1.102", "port": 8080, "type": "thermostat"},
            {"ip": "192.168.1.103", "port": 8080, "type": "smartlock"}
        ]
        
        # IoT device simulation
        self.device_types = ["camera", "thermostat", "smartlock", "smart_bulb", "hub"]
        self.current_device = random.choice(self.device_types)
        
        # Command patterns for IoT devices
        self.device_commands = {
            "camera": ["view", "record", "snapshot", "rotate", "status"],
            "thermostat": ["temperature", "mode", "schedule", "status"],
            "smartlock": ["lock", "unlock", "status", "history"],
            "smart_bulb": ["on", "off", "color", "brightness", "status"],
            "hub": ["devices", "status", "restart", "update"]
        }
        
        # Sandbox environment tracking
        self.sandboxed_sessions = set()
        
        # Active connections tracking
        self.connected_devices = {}  # Maps client_socket to connected device info
        
        # Attack detection patterns
        self.attack_patterns = [
            (r"^\s*(cat|head|tail|more|less)\s+(/etc/passwd|/etc/shadow)", "file_read_attempt"),
            (r"^\s*(wget|curl)\s+http", "download_attempt"),
            (r"^\s*(sh|bash|nc|netcat)\s+-", "shell_attempt"),
            (r"^\s*(ps|netstat|ifconfig|ip addr)", "system_info_attempt"),
            (r"^\s*(nmap|ping)\s+", "network_scan_attempt")
        ]
    
    def start(self):
        """Start the honeypot server"""
        logger.info(f"Starting IoT honeypot on {self.host}:{self.port}")
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            # Start listening thread
            listener_thread = threading.Thread(target=self._accept_connections)
            listener_thread.daemon = True
            listener_thread.start()
            
            logger.info(f"IoT honeypot started successfully (simulating {self.current_device})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start honeypot: {str(e)}")
            return False
    
    def stop(self):
        """Stop the honeypot server"""
        logger.info("Stopping IoT honeypot")
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
                
        logger.info("IoT honeypot stopped")
    
    def _accept_connections(self):
        """Accept and handle incoming connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.connections.append(client_socket)
                
                # Check if IP is blacklisted
                if client_address[0] in self.blacklisted_ips:
                    logger.warning(f"Blacklisted IP attempted connection: {client_address[0]}")
                    self._log_activity(client_address, "blacklisted_connection", "Connection from blacklisted IP")
                    client_socket.send(b"Access denied: Your IP has been blacklisted.\n")
                    client_socket.close()
                    self.connections.remove(client_socket)
                    continue
                
                # Log connection attempt
                self._log_activity(client_address, "connection", f"New connection to {self.current_device}")
                
                # Handle client in a separate thread
                client_thread = threading.Thread(target=self._handle_client, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {str(e)}")
                    time.sleep(1)

    def _handle_client(self, client_socket, client_address):
        """Handle client connection and log activity"""
        ip, port = client_address
        logger.info(f"SSH connection from {ip}:{port}")
        
        try:
            # Set up SSH transport
            transport = paramiko.Transport(client_socket)
            transport.set_gss_host(socket.getfqdn(""))
            transport.add_server_key(self.host_key)
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1"  # Mimic OpenSSH
            
            # Initialize server interface
            server = SSHServer(self)
            
            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                logger.warning(f"SSH negotiation failed from {ip}:{port}: {str(e)}")
                return
                
            # Wait for auth
            server.event.wait(10)
            if not transport.is_active():
                logger.warning(f"Client {ip}:{port} never asked for authentication")
                return
                
            # Wait for channel
            channel = transport.accept(20)
            if channel is None:
                logger.warning(f"No channel from {ip}:{port}")
                return
                
            # Wait for shell request
            server.event.wait(10)
            if not server.event.is_set():
                logger.warning(f"Client {ip}:{port} never asked for a shell")
                return
                
            # Send welcome message
            welcome = f"Welcome to IoT Device Management Console\r\n"
            welcome += f"Type 'help' for available commands\r\n\n"
            channel.send(welcome)
            
            # Interactive shell loop
            while transport.is_active():
                channel.send("$ ")
                command = ""
                
                # Read command character by character
                while True:
                    char = channel.recv(1)
                    if not char:  # EOF
                        break
                    char = char.decode('utf-8', errors='ignore')
                    if char == '\r':  # Enter
                        channel.send('\r\n')
                        break
                    elif char == '\x7f':  # Backspace
                        if command:
                            command = command[:-1]
                            channel.send('\b \b')
                    else:
                        command += char
                        channel.send(char.encode())
                
                if not command:  # Empty command
                    continue
                    
                if command.lower() == 'exit':
                    channel.send('Goodbye!\r\n')
                    break
                
                # Process command and send response
                response = self._process_command(command, client_address)
                channel.send(response + '\r\n')
        
        except Exception as e:
            logger.error(f"Error handling SSH client: {str(e)}")
        finally:
            if 'channel' in locals() and channel is not None:
                channel.close()
            if 'transport' in locals() and transport is not None:
                transport.close()
            if client_socket in self.connections:
                self.connections.remove(client_socket)

    def _process_command(self, command, client_address):
        """Process command and return response"""
        ip, port = client_address
        self._log_activity(client_address, "command", f"Command: {command}")
        
        # Check for malicious commands
        for pattern, attack_type in self.attack_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                self._log_activity(client_address, "attack_detected", f"Attack type: {attack_type}")
                logger.warning(f"Attack detected from {ip}:{port} - {attack_type}")
                return self._get_fake_response_for_attack(attack_type)
        
        # Process legitimate commands
        if command.lower() == 'help':
            return self._get_enhanced_sandbox_help()
        elif command.lower() == 'status':
            return f"Device: {self.current_device}\nStatus: Online\nUptime: {random.randint(1, 24)} hours"
        else:
            return f"Unknown command: {command}. Type 'help' for available commands."
    
    def _get_fake_response_for_attack(self, attack_type):
        """Generate fake responses for attack attempts"""
        if attack_type == "file_read_attempt":
            return "cat: /etc/passwd: No such file or directory\n"
        elif attack_type == "download_attempt":
            return "wget: command not found\n"
        elif attack_type == "shell_attempt":
            return "sh: command not found\n"
        elif attack_type == "system_info_attempt":
            return "bash: ps: command not found\n"
        elif attack_type == "network_scan_attempt":
            return "PING 8.8.8.8: Network unreachable\n"
        else:
            return "Command not recognized\n"
    
    def _log_activity(self, client_address, activity_type, details):
        """Log honeypot activity to file"""
        ip, port = client_address
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "ip": ip,
            "port": port,
            "type": activity_type,
            "details": details,
            "device": self.current_device,
            "label": "threat" if activity_type in ["attack_detected", "blacklisted", "ml_blacklisted", "sandboxed"] else "info"
        }
        
        try:
            # Ensure log directory exists
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            
            # Append to log file
            with open(self.log_path, 'a') as log_file:
                log_file.write(json.dumps(log_entry) + '\n')
                
            if activity_type != "command":  # Don't log every command to console
                logger.info(f"Logged {activity_type} activity from {ip}:{port}")
            
        except Exception as e:
            logger.error(f"Error logging activity: {str(e)}")
            
    def get_blacklisted_ips(self):
        """Return the list of blacklisted IPs"""
        return list(self.blacklisted_ips)
    
    def add_to_blacklist(self, ip):
        """Add an IP to the blacklist"""
        self.blacklisted_ips.add(ip)
        logger.info(f"Added {ip} to blacklist")
        
    def remove_from_blacklist(self, ip):
        """Remove an IP from the blacklist"""
        if ip in self.blacklisted_ips:
            self.blacklisted_ips.remove(ip)
            logger.info(f"Removed {ip} from blacklist")
    
    def _enhance_sandbox_experience(self, client_socket, cmd, client_address):
        """Provide interesting fake responses in sandbox to keep attackers engaged"""
        ip, port = client_address
        cmd_lower = cmd.lower()
        
        # Fake internal network scan results
        if "scan" in cmd_lower or "nmap" in cmd_lower:
            fake_response = "Scanning...\n\n"
            fake_response += "Found 5 devices on network:\n"
            for i in range(5):
                device_ip = f"192.168.1.{random.randint(10, 99)}"
                device_type = random.choice(self.device_types)
                fake_response += f"{device_ip} - {device_type.capitalize()} [{'OPEN' if random.random() > 0.5 else 'FILTERED'}]\n"
            client_socket.send(fake_response.encode())
            self._log_activity(client_address, "sandbox_scan", f"Attacker scanning network in sandbox: {cmd}")
            return True
        
        # Fake file access results
        if "cat" in cmd_lower or "ls" in cmd_lower or "dir" in cmd_lower:
            if "passwd" in cmd_lower or "shadow" in cmd_lower:
                fake_response = "No such file or directory\n"
            else:
                fake_response = "Files found:\n"
                fake_response += "firmware_v1.2.bin\n"
                fake_response += "settings.conf\n"
                fake_response += "network.cfg\n"
                fake_response += "users.db\n"
            client_socket.send(fake_response.encode())
            self._log_activity(client_address, "sandbox_files", f"Attacker exploring files in sandbox: {cmd}")
            return True
        
        # Fake vulnerable responses
        if "wget" in cmd_lower or "curl" in cmd_lower:
            fake_response = "Downloading...\n"
            fake_response += "Download complete: 234KB\n"
            client_socket.send(fake_response.encode())
            self._log_activity(client_address, "sandbox_download", f"Attacker attempting download in sandbox: {cmd}")
            return True
        
        return False  # Command not handled by sandbox enhancer
    
    # Add this new method after _enhance_sandbox_experience
    def _get_enhanced_sandbox_help(self, is_admin=False):
        """Return enhanced help text for the sandbox environment"""
        help_text = "=== IoT Network Management Console ===\n\n"
        help_text += "Available commands:\n"
        help_text += "  help         - Show this help message\n"
        help_text += "  scan         - Scan for devices on the network\n"
        help_text += "  devices      - List available devices\n"
        help_text += "  connect      - Connect to a device (specify number or name)\n"
        help_text += "  status       - Show system status\n"
        
        if is_admin:
            help_text += "  users        - List system users\n"
            help_text += "  adduser      - Add a new user\n"
            help_text += "  reset        - Factory reset a device\n"
            help_text += "  firmware     - Update device firmware\n"
        
        help_text += "  ping         - Test connectivity to a device\n"
        help_text += "  cat          - Display file contents\n"
        help_text += "  ls           - List files in current directory\n"
        help_text += "  exit         - Exit the session\n"
        
        return help_text