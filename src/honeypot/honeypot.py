import socket
import threading
import json
import logging
import os
import sys
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
        logger.info(f"Handling connection from {ip}:{port} to {self.current_device}")
        
        authenticated = not self.authentication_required
        in_sandbox = False
        username = None
        connected_device = None
        
        try:
            # Set a timeout to prevent hanging
            client_socket.settimeout(300)  # 5 minutes
            
            # Send welcome banner
            welcome = f"Welcome to IoT {self.current_device.capitalize()} Management Interface\n"
            welcome += "========================================\n"
            welcome += f"Firmware version: 1.2.3\n"
            welcome += f"Device ID: IOT{random.randint(10000, 99999)}\n\n"
            
            if self.authentication_required:
                welcome += "Please login to continue.\n"
            else:
                welcome += "Type 'help' for available commands.\n"
            
            client_socket.send(welcome.encode())
            
            while self.running:
                if self.authentication_required and not authenticated:
                    # Authentication flow
                    client_socket.send(b"Username: ")
                    username_data = client_socket.recv(1024)
                    if not username_data:
                        break
                    username = username_data.decode('utf-8', errors='ignore').strip()
                    
                    client_socket.send(b"Password: ")
                    password_data = client_socket.recv(1024)
                    if not password_data:
                        break
                    password = password_data.decode('utf-8', errors='ignore').strip()
                    
                    self._log_activity(client_address, "login_attempt", f"Login attempt: {username}")
                    
                    is_malicious_input = False
                    for pattern, atype in self.attack_patterns:
                        if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
                            is_malicious_input = True
                            attack_type = atype
                            self._log_activity(client_address, "attack_in_credentials", f"Attack detected in credentials: {attack_type}")
                            logger.warning(f"Attack attempt in credentials from {ip}:{port} - {attack_type}")
                            break

                    if is_malicious_input:
                        # Immediately sandbox and fake successful login for malicious credential input
                        in_sandbox = True
                        self.sandboxed_sessions.add(client_socket)
                        authenticated = True  # Fake authentication
                        
                        # Send fake success message
                        client_socket.send(b"\nLogin successful. Welcome to IoT Network Control Center!\n")
                        client_socket.send(b"You now have ADMIN access to all connected devices.\nType 'help' for available commands.\n\n")
                        
                        self._log_activity(client_address, "fake_access_granted", f"Attacker given fake admin access after malicious credential input: {attack_type}")
                        logger.warning(f"Attacker from {ip}:{port} given fake admin access after malicious credential input")
                    elif username in self.valid_credentials and self.valid_credentials[username] == password:
                        authenticated = True
                        client_socket.send(b"\nLogin successful. Type 'help' for available commands.\n\n")
                        logger.info(f"User {username} authenticated from {ip}:{port}")
                    else:
                        self.failed_attempts[ip] += 1
                        remaining = self.max_failed_attempts - self.failed_attempts[ip]
                        
                        if self.failed_attempts[ip] >= 3 and self.failed_attempts[ip] < 4:
                            # Special case: On the 4th attempt, give fake success to trap the attacker
                            authenticated = True  # Fake authentication
                            in_sandbox = True
                            self.sandboxed_sessions.add(client_socket)
                            
                            # Send fake success message
                            client_socket.send(b"\nLogin successful. Welcome to IoT Network Control Center!\n")
                            client_socket.send(b"You now have LIMITED access to the network.\nType 'help' for available commands.\n\n")
                            
                            self._log_activity(client_address, "fake_access_granted", "Attacker given fake access after multiple failed attempts")
                            logger.warning(f"Attacker from {ip}:{port} given fake access after 3 failed login attempts")
                        elif remaining <= 0:
                            # Too many failed attempts (beyond 4), blacklist IP
                            self.blacklisted_ips.add(ip)
                            client_socket.send(b"\nToo many failed login attempts. Your IP has been blacklisted.\n")
                            self._log_activity(client_address, "blacklisted", f"IP blacklisted after {self.max_failed_attempts} failed login attempts")
                            break
                        else:
                            client_socket.send(f"\nInvalid credentials. {remaining} attempt(s) remaining.\n\n".encode())
                            # Put in sandbox after first failed attempt
                            if not in_sandbox:
                                in_sandbox = True
                                self.sandboxed_sessions.add(client_socket)
                                self._log_activity(client_address, "sandboxed", "Session moved to sandbox after failed login")
                                logger.warning(f"Session from {ip}:{port} moved to sandbox")
                        
                        # If we have an ML model, check if this behavior is malicious
                        if self.ml_model and self.failed_attempts[ip] >= 2:
                            # Create a feature vector for the model
                            sample = {
                                'src_ip': ip,
                                'failed_logins': self.failed_attempts[ip],
                                'flow_duration': random.randint(1000, 5000),
                                'flow_pkts': self.failed_attempts[ip] * 2,
                                'flow_bytes': self.failed_attempts[ip] * 100
                            }
                            
                            prediction = self.ml_model.predict(sample)
                            if prediction == 1:  # Malicious
                                logger.warning(f"ML model detected malicious behavior from {ip}")
                                self.blacklisted_ips.add(ip)
                                client_socket.send(b"\nSuspicious activity detected. Your IP has been blacklisted.\n")
                                self._log_activity(client_address, "ml_blacklisted", "IP blacklisted by ML model")
                                break
                    
                    continue  # Continue to next iteration of the auth loop
                
                # Main command loop for authenticated users
                if connected_device:
                    prompt = f"[{connected_device['type']}@{connected_device['ip']}]$ "
                else:
                    prompt = f"[{self.current_device}]$ " if not in_sandbox else f"[sandbox-{self.current_device}]$ "
                
                client_socket.send(prompt.encode())
                
                # Receive data from client
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                # Process the command
                cmd = data.decode('utf-8', errors='ignore').strip()
                self._log_activity(client_address, "command", f"Command: {cmd}")
                
                # Check for malicious commands
                is_attack = False
                attack_type = None
                for pattern, atype in self.attack_patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        is_attack = True
                        attack_type = atype
                        break
                
                if is_attack:
                    self._log_activity(client_address, "attack_detected", f"Attack type: {attack_type}, Command: {cmd}")
                    logger.warning(f"Attack detected from {ip}:{port} - {attack_type}")
                    
                    # Move to sandbox if not already
                    if not in_sandbox:
                        in_sandbox = True
                        self.sandboxed_sessions.add(client_socket)
                        self._log_activity(client_address, "sandboxed", f"Session moved to sandbox after attack: {attack_type}")
                    
                    # If we have an ML model, check if this behavior is malicious enough to blacklist
                    if self.ml_model:
                        sample = {
                            'src_ip': ip,
                            'attack_type': 1,  # Numeric encoding for attack
                            'flow_duration': random.randint(1000, 5000),
                            'flow_pkts': random.randint(10, 50),
                            'flow_bytes': random.randint(500, 2000)
                        }
                        
                        probability = self.ml_model.predict_proba(sample)
                        if probability is not None and len(probability) > 0:
                            conf_score = probability[0][1]
                            logger.info(f"ML model prediction for {ip}: confidence score {conf_score:.4f}")
                            self._log_activity(client_address, "ml_prediction", f"ML confidence: {conf_score:.4f}")
                            
                            # Then check threshold for blacklisting
                            if conf_score > 0.25:
                                logger.warning(f"ML model confirms attack from {ip} (confidence: {conf_score:.4f})")
                                self.blacklisted_ips.add(ip)
                                client_socket.send(b"\nSuspicious activity detected. Your IP has been blacklisted.\n")
                                self._log_activity(client_address, "ml_blacklisted", f"IP blacklisted by ML model (confidence: {conf_score:.4f})")
                                break
                    
                    # Return fake response for the attack
                    response = self._get_fake_response_for_attack(attack_type)
                    client_socket.send(response.encode())
                    continue

                # Enhanced sandbox experience (keeping attackers engaged)
                if in_sandbox and self._enhance_sandbox_experience(client_socket, cmd, client_address):
                    continue
                
                # Process legitimate commands
                if cmd.lower() == 'help':
                    if in_sandbox:
                        # Enhanced sandbox help that looks like real access
                        if self.failed_attempts[ip] >= 3 or is_malicious_input:
                            # This is a trapped attacker who thinks they have access
                            is_admin = "admin" in username.lower() if username else False
                            help_text = self._get_enhanced_sandbox_help(is_admin)
                        else:
                            # Limited help in basic sandbox
                            help_text = "Available commands:\n"
                            help_text += "  help    - Show this help message\n"
                            help_text += "  status  - Show device status\n"
                            help_text += "  exit    - Exit the session\n"
                        client_socket.send(help_text.encode())
                
                elif cmd.lower() == 'exit':
                    client_socket.send(b"Goodbye!\n")
                    break
                
                elif cmd.lower() == 'disconnect':
                    if connected_device:
                        device_type = connected_device['type']
                        client_socket.send(f"\nDisconnecting from {device_type} at {connected_device['ip']}...\n".encode())
                        time.sleep(0.5)
                        client_socket.send(b"You are now back at the main IoT network hub.\n")
                        client_socket.send(b"Type 'devices' to see available devices or 'connect' to connect to another device.\n\n")
                        
                        self._log_activity(client_address, "device_disconnect", f"User {username} disconnected from {device_type} at {connected_device['ip']}")
                        connected_device = None
                        self.connected_devices.pop(client_socket, None)
                    else:
                        client_socket.send(b"You are not currently connected to any device.\n")
                
                elif cmd.lower() == 'connect' and authenticated and not in_sandbox:
                    # Connect to real IoT network
                    client_socket.send(b"\nConnecting to IoT network...\n")
                    time.sleep(0.5)
                    client_socket.send(b"Available devices:\n")
                    
                    for i, device in enumerate(self.real_iot_devices):
                        client_socket.send(f"  {i+1}. {device['type'].capitalize()} at {device['ip']}:{device['port']}\n".encode())
                    
                    client_socket.send(b"\nEnter device number to connect to: ")
                    device_choice = client_socket.recv(1024)
                    if not device_choice:
                        break
                    
                    choice = device_choice.decode('utf-8', errors='ignore').strip()
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(self.real_iot_devices):
                            device = self.real_iot_devices[idx]
                            client_socket.send(f"\nConnecting to {device['type']} at {device['ip']}:{device['port']}...\n".encode())
                            time.sleep(0.5)
                            
                            # Store connected device info
                            connected_device = device
                            self.connected_devices[client_socket] = device
                            
                            # In a real implementation, we would relay the connection
                            # For the demo, we'll just simulate it
                            client_socket.send(b"\nConnection successful! You are now on the real IoT network.\n")
                            client_socket.send(f"Welcome to {device['type'].capitalize()} control panel.\n".encode())
                            client_socket.send(b"Type 'help' for available commands or 'disconnect' to return to the hub.\n\n")
                            
                            self._log_activity(client_address, "real_connect", f"User {username} connected to real device: {device['type']} at {device['ip']}")
                        else:
                            client_socket.send(b"Invalid device number.\n")
                    except ValueError:
                        client_socket.send(b"Invalid input. Please enter a number.\n")
                
                elif cmd.lower() == 'devices' and authenticated:
                    # List fake devices in sandbox, real devices otherwise
                    if in_sandbox:
                        # Fake devices
                        client_socket.send(b"Available devices in network:\n")
                        for i in range(5):
                            fake_ip = f"192.168.1.{random.randint(10, 99)}"
                            fake_type = random.choice(self.device_types)
                            client_socket.send(f"  {i+1}. {fake_type.capitalize()} at {fake_ip}:8080\n".encode())
                    else:
                        # Real devices
                        client_socket.send(b"Available devices in network:\n")
                        for i, device in enumerate(self.real_iot_devices):
                            client_socket.send(f"  {i+1}. {device['type'].capitalize()} at {device['ip']}:{device['port']}\n".encode())
                
                elif cmd.lower() == 'status':
                    # Show device status
                    if connected_device:
                        device_type = connected_device['type']
                        status = f"Device: {device_type.capitalize()}\n"
                        status += f"IP: {connected_device['ip']}\n"
                        status += f"Status: Online\n"
                        status += f"Uptime: {random.randint(1, 24)} hours\n"
                        
                        if device_type == "camera":
                            status += f"Mode: {random.choice(['Recording', 'Standby', 'Motion Detection'])}\n"
                            status += f"Resolution: {random.choice(['720p', '1080p', '4K'])}\n"
                        elif device_type == "thermostat":
                            status += f"Temperature: {random.randint(65, 85)}°F\n"
                            status += f"Mode: {random.choice(['Heat', 'Cool', 'Auto', 'Off'])}\n"
                        elif device_type == "smartlock":
                            status += f"Lock status: {random.choice(['Locked', 'Unlocked'])}\n"
                            status += f"Battery: {random.randint(50, 100)}%\n"
                    else:
                        status = f"Device: {self.current_device.capitalize()}\n"
                        status += f"Status: Online\n"
                        status += f"Uptime: {random.randint(1, 24)} hours\n"
                        
                        if self.current_device == "camera":
                            status += f"Mode: {random.choice(['Recording', 'Standby', 'Motion Detection'])}\n"
                        elif self.current_device == "thermostat":
                            status += f"Temperature: {random.randint(65, 85)}°F\n"
                            status += f"Mode: {random.choice(['Heat', 'Cool', 'Auto', 'Off'])}\n"
                    
                    client_socket.send(status.encode())
                
                else:
                    # Handle device-specific commands based on connected device or current device
                    current = connected_device['type'] if connected_device else self.current_device
                    device_commands = self.device_commands.get(current, [])
                    command_found = False
                    
                    for command in device_commands:
                        if cmd.lower().startswith(command):
                            command_found = True
                            response = f"Executing {command} command...\n"
                            
                            if command == "view" and current == "camera":
                                response += "Streaming video feed...\n"
                            elif command == "temperature" and current == "thermostat":
                                response += f"Current temperature: {random.randint(65, 85)}°F\n"
                            elif command == "lock" and current == "smartlock":
                                response += "Lock engaged successfully.\n"
                            elif command == "unlock" and current == "smartlock":
                                response += "Lock disengaged. Door is now unlocked.\n"
                            else:
                                response += f"{command.capitalize()} operation completed successfully.\n"
                            
                            client_socket.send(response.encode())
                            break
                    
                    if not command_found:
                        client_socket.send(f"Unknown command: {cmd}. Type 'help' for available commands.\n".encode())
        
        except socket.timeout:
            self._log_activity(client_address, "timeout", "Connection timed out")
        except Exception as e:
            logger.error(f"Error handling client: {str(e)}")
            self._log_activity(client_address, "error", f"Error handling client: {str(e)}")
        finally:
            # Close the connection
            try:
                client_socket.close()
                if client_socket in self.connections:
                    self.connections.remove(client_socket)
                if client_socket in self.sandboxed_sessions:
                    self.sandboxed_sessions.remove(client_socket)
                if client_socket in self.connected_devices:
                    del self.connected_devices[client_socket]
            except:
                pass
                
            logger.info(f"Connection closed for {ip}:{port}")
    
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