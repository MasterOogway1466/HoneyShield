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
from datetime import datetime, timedelta
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
    def __init__(self, honeypot, client_ip):
        self.honeypot = honeypot
        self.client_ip = client_ip
        self.event = threading.Event()
        self.channel = None
        self.shell_requested = threading.Event()
        self.pty_requested = threading.Event()

    def check_auth_password(self, username, password):
        # Check if IP is already blacklisted
        if self.client_ip in self.honeypot.blacklisted_ips:
            logger.warning(f"Blocked login attempt from blacklisted IP: {self.client_ip}")
            self.honeypot._log_activity((self.client_ip, 0), "blocked_login", f"Blocked login attempt from blacklisted IP")
            return paramiko.AUTH_FAILED

        # Check credentials
        auth_successful = False
        if username in self.honeypot.valid_credentials:
            if self.honeypot.valid_credentials[username] == password:
                # Reset failed attempts on successful login
                if self.client_ip in self.honeypot.failed_attempts:
                    del self.honeypot.failed_attempts[self.client_ip]
                return paramiko.AUTH_SUCCESSFUL
            
        # Track failed login attempt
        self.honeypot.failed_attempts[self.client_ip] += 1
        attempts = self.honeypot.failed_attempts[self.client_ip]
        
        # Convert attempt number to ordinal string
        ordinal = lambda n: f"{n}{'th' if 10<=n%100<=20 else {1:'st',2:'nd',3:'rd'}.get(n%10, 'th')}"
        attempt_str = ordinal(attempts)
        
        logger.warning(f"Failed login attempt ({attempt_str} attempt) from IP: {self.client_ip}")
        
        # Check if IP should be blacklisted
        if attempts >= self.honeypot.max_failed_attempts:
            logger.warning(f"Blacklisting IP {self.client_ip} after {attempts} failed login attempts")
            self.honeypot.add_to_blacklist(self.client_ip)
            self.honeypot._log_activity((self.client_ip, 0), "blacklisted", f"IP blacklisted after {attempts} failed login attempts")
            
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'
        
    def check_channel_request(self, kind, chanid):
        if (kind == "session"):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def check_channel_shell_request(self, channel):
        self.shell_requested.set()
        return True
        
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.pty_requested.set()
        return True
        
    def check_channel_exec_request(self, channel, command):
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
        self.max_failed_attempts = 3  # Reduced from 4 to 3
        self.authentication_required = True
        self.first_command_validated = {}  # Track if user has entered correct first command
        
        # Enhanced attack patterns for sandbox escape detection
        self.attack_patterns = [
            (r"^\s*(exec|eval|subprocess|system|popen|fork|spawn)", "sandbox_escape_attempt"),
            (r"^\s*(cat|tail|head|less|more|grep|awk|sed)", "file_access_attempt"),
            (r"^\s*(nc|netcat|curl|wget|telnet|ftp)", "network_access_attempt"),
            (r"^\s*(factory_reset|flash|root)\s*", "device_tampering_attempt"),
            (r"^\s*(sniff|capture|intercept)\s*", "traffic_sniffing_attempt"),
            (r"^\s*(brute|crack|exploit)\s*", "authentication_bypass_attempt")
        ]
        
        # Sandbox control
        self.sandboxed_sessions = set()  # Store client IDs that are in sandbox
        
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
            (r"^\s*(factory_reset|flash|root)\s*", "device_tampering_attempt"),
            (r"^\s*(sniff|capture|intercept)\s*", "traffic_sniffing_attempt"),
            (r"^\s*(brute|crack|exploit)\s*", "authentication_bypass_attempt")
        ]

        # Enhanced device state tracking
        self.device_states = {
            "camera": {
                "status": "online",
                "recording": False,
                "resolution": "1080p",
                "motion_detection": True,
                "rotation": 0,  # degrees
                "night_vision": False,
                "stream_url": "rtsp://192.168.1.101/live",
                "snapshots_taken": 0
            },
            "thermostat": {
                "status": "online",
                "current_temp": 72,
                "target_temp": 70,
                "mode": "auto",  # auto, heat, cool, off
                "humidity": 45,
                "schedule": {
                    "morning": {"time": "06:00", "temp": 72},
                    "day": {"time": "09:00", "temp": 70},
                    "evening": {"time": "17:00", "temp": 73},
                    "night": {"time": "22:00", "temp": 68}
                },
                "fan": "auto",  # auto, on, circulate
                "energy_mode": "normal"  # normal, eco, away
            }
        }

        # Enhanced device-specific commands and help text
        self.device_commands = {
            "camera": {
                "view": "Start live video stream",
                "record": "Start/stop recording",
                "snapshot": "Take a snapshot",
                "rotate": "Rotate camera (0-360 degrees)",
                "night_vision": "Toggle night vision",
                "motion_detection": "Toggle motion detection",
                "resolution": "Set video resolution",
                "status": "Show camera status"
            },
            "thermostat": {
                "temperature": "Get current temperature",
                "set": "Set target temperature",
                "mode": "Set operation mode (auto/heat/cool/off)",
                "schedule": "View/edit temperature schedule",
                "humidity": "Get current humidity",
                "fan": "Control fan settings",
                "eco": "Toggle energy saving mode",
                "status": "Show thermostat status"
            }
        }
        
        # Command argument specifications
        self.command_args = {
            "camera": {
                "rotate": ["angle"],
                "resolution": ["quality"],
                "record": ["duration"],
            },
            "thermostat": {
                "set": ["temperature"],
                "mode": ["mode"],
                "fan": ["setting"],
                "schedule": ["time", "temp"],
            }
        }

        # Enhanced device list with more details
        self.available_devices = [
            {
                "id": 1,
                "ip": "192.168.1.101",
                "type": "camera",
                "model": "Hikvision DS-2CD2385G1",
                "status": "online",
                "firmware": "v2.3.4",
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "id": 2,
                "ip": "192.168.1.102",
                "type": "thermostat",
                "model": "Nest Learning v3",
                "status": "online",
                "firmware": "v5.6.7",
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "id": 3,
                "ip": "192.168.1.103",
                "type": "smartlock",
                "model": "August Wi-Fi",
                "status": "online",
                "firmware": "v1.2.8",
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "id": 4,
                "ip": "192.168.1.104",
                "type": "camera",
                "model": "Arlo Pro 4",
                "status": "offline",
                "firmware": "v3.2.1",
                "last_seen": (datetime.now() - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            },
            {
                "id": 5,
                "ip": "192.168.1.105",
                "type": "thermostat",
                "model": "Ecobee SmartThermostat",
                "status": "online",
                "firmware": "v4.5.3",
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        ]
        
        # Command history tracking per client
        self.client_command_history = {}  # Maps client address to list of commands
        self.client_history_index = {}    # Maps client address to current history index
    
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
                    client_socket.send(b"Nice try, dumbass!\n")
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
        
        # Initialize command history for this client
        client_id = f"{ip}:{port}"
        self.client_command_history[client_id] = []
        self.client_history_index[client_id] = 0
        
        try:
            # Set up SSH transport
            transport = paramiko.Transport(client_socket)
            transport.set_gss_host(socket.getfqdn(""))
            transport.add_server_key(self.host_key)
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1"
            
            server = SSHServer(self, ip)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                logger.warning(f"SSH negotiation failed from {ip}:{port}: {str(e)}")
                return
                
            # Wait for auth
            channel = transport.accept(20)
            if channel is None:
                logger.warning(f"No channel from {ip}:{port}")
                return
                
            # Wait for shell/pty request
            server.shell_requested.wait(10)
            if not server.shell_requested.is_set():
                logger.warning(f"Client {ip}:{port} never asked for a shell")
                return
                
            # Send welcome message
            welcome = "Welcome to IoT Device Management Console\r\n"
            welcome += "Type 'help' for available commands\r\n\n"
            channel.send(welcome)
            
            # Interactive shell loop with command history
            while transport.is_active():
                channel.send("$ ")
                command = ""
                cursor_pos = 0
                history = self.client_command_history[client_id]
                history_index = len(history)
                self.client_history_index[client_id] = history_index
                
                while True:
                    char = channel.recv(1)
                    if not char:  # EOF
                        break
                        
                    # Handle special characters and escape sequences
                    if char == b'\x1b':  # ESC sequence
                        # Read the next two characters that complete the arrow key sequence
                        next_chars = channel.recv(2)
                        if next_chars == b'[A':  # Up arrow
                            # Clear current line
                            channel.send(b'\r')
                            channel.send(b'$ ')
                            channel.send(b' ' * len(command))
                            channel.send(b'\r')
                            channel.send(b'$ ')
                            
                            # Get previous command from history
                            if history_index > 0:
                                history_index -= 1
                                command = history[history_index] if history else ""
                                cursor_pos = len(command)
                                channel.send(command.encode())
                                
                        elif next_chars == b'[B':  # Down arrow
                            # Clear current line
                            channel.send(b'\r')
                            channel.send(b'$ ')
                            channel.send(b' ' * len(command))
                            channel.send(b'\r')
                            channel.send(b'$ ')
                            
                            # Get next command from history
                            if history_index < len(history):
                                history_index += 1
                                if history_index < len(history):
                                    command = history[history_index]
                                else:
                                    command = ""
                                cursor_pos = len(command)
                                channel.send(command.encode())
                                
                        elif next_chars == b'[C':  # Right arrow
                            if cursor_pos < len(command):
                                cursor_pos += 1
                                channel.send(b'\x1b[C')
                                
                        elif next_chars == b'[D':  # Left arrow
                            if cursor_pos > 0:
                                cursor_pos -= 1
                                channel.send(b'\x1b[D')
                                
                        elif next_chars == b'[3':  # Delete key first part
                            third_char = channel.recv(1)
                            if third_char == b'~':  # Delete key
                                if cursor_pos < len(command):
                                    # Remove character at cursor position
                                    command = command[:cursor_pos] + command[cursor_pos + 1:]
                                    # Redraw the line from cursor position
                                    remainder = command[cursor_pos:]
                                    channel.send(remainder.encode() + b' ' + b'\x1b[D' * len(remainder))
                            
                    elif char == b'\x7f':  # backspace
                        if cursor_pos > 0:
                            # Remove character before cursor
                            command = command[:cursor_pos-1] + command[cursor_pos:]
                            cursor_pos -= 1
                            
                            # Move cursor back
                            channel.send(b'\x1b[D')
                            
                            # Redraw rest of the line
                            if cursor_pos < len(command):
                                remainder = command[cursor_pos:]
                                channel.send(remainder.encode() + b' ' + b'\x1b[D' * len(remainder))
                            else:
                                channel.send(b' ' + b'\x1b[D')
                            
                    elif char == b'\r':  # enter
                        channel.send(b'\r\n')
                        break
                        
                    elif char == b'\x03':  # ctrl-c
                        channel.send(b'^C\r\n')
                        command = ""
                        cursor_pos = 0
                        break
                        
                    elif char == b'\x04':  # ctrl-d
                        if not command:
                            channel.send(b'logout\r\n')
                            return
                            
                    elif char == b'\x17':  # ctrl-w (delete word)
                        if cursor_pos > 0:
                            # Find the start of the current/previous word
                            new_pos = cursor_pos - 1
                            while new_pos > 0 and command[new_pos-1].isspace():
                                new_pos -= 1
                            while new_pos > 0 and not command[new_pos-1].isspace():
                                new_pos -= 1
                                
                            # Delete from new_pos to cursor_pos
                            command = command[:new_pos] + command[cursor_pos:]
                            
                            # Move cursor back and redraw
                            move_back = cursor_pos - new_pos
                            channel.send(b'\x1b[D' * move_back)
                            remainder = command[new_pos:]
                            channel.send(remainder.encode() + b' ' * move_back + b'\x1b[D' * len(remainder))
                            cursor_pos = new_pos
                            
                    elif char == b'\x15':  # ctrl-u (clear line before cursor)
                        if cursor_pos > 0:
                            # Clear from start to cursor
                            command = command[cursor_pos:]
                            # Move cursor to start
                            channel.send(b'\r' + b'$ ')
                            # Redraw remaining text
                            channel.send(command.encode() + b' ' * cursor_pos)
                            # Move cursor to start
                            channel.send(b'\r' + b'$ ')
                            cursor_pos = 0
                            
                    else:
                        # Insert normal character at cursor position
                        try:
                            char_decoded = char.decode('utf-8')
                            if char_decoded.isprintable():
                                # Insert character at cursor position
                                command = command[:cursor_pos] + char_decoded + command[cursor_pos:]
                                cursor_pos += 1
                                
                                # Echo the inserted character
                                channel.send(char)
                                
                                # If cursor is not at end, redraw the rest of the line
                                if cursor_pos < len(command):
                                    remainder = command[cursor_pos:]
                                    channel.send(remainder.encode())
                                    # Move cursor back to insertion point
                                    channel.send(b'\x1b[D' * len(remainder))
                        except UnicodeDecodeError:
                            continue
                
                if not command:  # Empty command
                    continue
                    
                if command.lower() == 'exit':
                    channel.send('Goodbye!\r\n')
                    break
                
                # Add command to history if it's not empty and different from last command
                if command and (not history or command != history[-1]):
                    history.append(command)
                    # Limit history size to prevent memory issues
                    if len(history) > 100:
                        history.pop(0)
                
                # Process command and format response
                response = self._process_command(command, client_address)
                # Split response into lines and send each with proper line ending
                for line in response.splitlines():
                    channel.send(line.rstrip() + '\r\n')
                    
        except Exception as e:
            logger.error(f"Error handling SSH client: {str(e)}")
        finally:
            # Clean up command history when client disconnects
            if client_id in self.client_command_history:
                del self.client_command_history[client_id]
            if client_id in self.client_history_index:
                del self.client_history_index[client_id]
            
            if 'channel' in locals() and channel is not None:
                channel.close()
            if 'transport' in locals() and transport is not None:
                transport.close()
            if client_socket in self.connections:
                self.connections.remove(client_socket)

    def _process_device_command(self, cmd, args, device_type):
        """Process device-specific commands"""
        if device_type == "camera":
            return self._handle_camera_command(cmd, args)
        elif device_type == "thermostat":
            return self._handle_thermostat_command(cmd, args)
        return "Device type not supported"

    def _handle_camera_command(self, cmd, args):
        """Handle camera-specific commands"""
        state = self.device_states["camera"]
        
        if cmd == "view":
            return f"Streaming video feed from {state['stream_url']}\nResolution: {state['resolution']}"
        elif cmd == "record":
            state["recording"] = not state["recording"]
            return f"Recording {'started' if state['recording'] else 'stopped'}"
        elif cmd == "snapshot":
            state["snapshots_taken"] += 1
            return f"Snapshot taken (#{state['snapshots_taken']})"
        elif cmd == "rotate":
            if not args:
                return "Usage: rotate <angle>"
            try:
                angle = int(args[0]) % 360
                state["rotation"] = angle
                return f"Camera rotated to {angle} degrees"
            except ValueError:
                return "Invalid angle. Please enter a number between 0 and 360"
        elif cmd == "night_vision":
            state["night_vision"] = not state["night_vision"]
            return f"Night vision {'enabled' if state['night_vision'] else 'disabled'}"
        elif cmd == "motion_detection":
            state["motion_detection"] = not state["motion_detection"]
            return f"Motion detection {'enabled' if state['motion_detection'] else 'disabled'}"
        elif cmd == "resolution":
            if not args:
                return "Usage: resolution <720p|1080p|4K>"
            if args[0] in ["720p", "1080p", "4K"]:
                state["resolution"] = args[0]
                return f"Resolution set to {args[0]}"
            return "Invalid resolution. Supported values: 720p, 1080p, 4K"
        elif cmd == "status":
            status = [
                f"Camera Status:",
                f"  Status: {state['status']}",
                f"  Recording: {'Yes' if state['recording'] else 'No'}",
                f"  Resolution: {state['resolution']}",
                f"  Motion Detection: {'Enabled' if state['motion_detection'] else 'Disabled'}",
                f"  Rotation: {state['rotation']}°",
                f"  Night Vision: {'Enabled' if state['night_vision'] else 'Disabled'}",
                f"  Stream URL: {state['stream_url']}",
                f"  Snapshots Taken: {state['snapshots_taken']}"
            ]
            return "\n".join(status)
        return f"Unknown camera command: {cmd}"

    def _handle_thermostat_command(self, cmd, args):
        """Handle thermostat-specific commands"""
        state = self.device_states["thermostat"]
        
        if cmd == "temperature":
            return f"Current temperature: {state['current_temp']}°F\nTarget temperature: {state['target_temp']}°F"
        elif cmd == "set":
            if not args:
                return "Usage: set <temperature>"
            try:
                temp = int(args[0])
                if 60 <= temp <= 85:
                    state["target_temp"] = temp
                    return f"Target temperature set to {temp}°F"
                return "Temperature must be between 60°F and 85°F"
            except ValueError:
                return "Invalid temperature. Please enter a number"
        elif cmd == "mode":
            if not args:
                return "Usage: mode <auto|heat|cool|off>"
            mode = args[0].lower()
            if mode in ["auto", "heat", "cool", "off"]:
                state["mode"] = mode
                return f"Mode set to {mode}"
            return "Invalid mode. Supported modes: auto, heat, cool, off"
        elif cmd == "schedule":
            if not args:
                schedule = [
                    "Current Schedule:",
                    *[f"  {period}: {details['time']} - {details['temp']}°F"
                      for period, details in state['schedule'].items()]
                ]
                return "\n".join(schedule)
            if len(args) >= 3:
                period = args[0].lower()
                if period in state["schedule"]:
                    try:
                        time = args[1]
                        temp = int(args[2])
                        if 60 <= temp <= 85:
                            state["schedule"][period] = {"time": time, "temp": temp}
                            return f"Updated {period} schedule: {time} - {temp}°F"
                        return "Temperature must be between 60°F and 85°F"
                    except ValueError:
                        return "Invalid temperature. Please enter a number"
                return "Invalid period. Use: morning, day, evening, or night"
            return "Usage: schedule [period] [time] [temperature]"
        elif cmd == "humidity":
            return f"Current humidity: {state['humidity']}%"
        elif cmd == "fan":
            if not args:
                return f"Current fan setting: {state['fan']}"
            setting = args[0].lower()
            if setting in ["auto", "on", "circulate"]:
                state["fan"] = setting
                return f"Fan set to {setting}"
            return "Invalid fan setting. Use: auto, on, or circulate"
        elif cmd == "eco":
            if state["energy_mode"] == "normal":
                state["energy_mode"] = "eco"
                state["target_temp"] = 78 if state["mode"] == "cool" else 68
                return "Eco mode enabled. Temperature adjusted for energy savings"
            else:
                state["energy_mode"] = "normal"
                return "Eco mode disabled. Returning to normal settings"
        elif cmd == "status":
            status = [
                f"Thermostat Status:",
                f"  Status: {state['status']}",
                f"  Current Temperature: {state['current_temp']}°F",
                f"  Target Temperature: {state['target_temp']}°F",
                f"  Mode: {state['mode'].capitalize()}",
                f"  Humidity: {state['humidity']}%",
                f"  Fan: {state['fan'].capitalize()}",
                f"  Energy Mode: {state['energy_mode'].capitalize()}"
            ]
            return "\n".join(status)
        return f"Unknown thermostat command: {cmd}"

    def _process_command(self, command, client_address):
        """Process command and return response"""
        ip, port = client_address
        client_id = f"{ip}:{port}"
        self._log_activity(client_address, "command", f"Command: {command}")
        
        # Split command and arguments
        cmd_parts = command.strip().lower().split()
        if not cmd_parts:
            return ""
            
        cmd = cmd_parts[0]
        args = cmd_parts[1:] if len(cmd_parts) > 1 else []

        # Check if this is the first command for this client
        if client_id not in self.first_command_validated:
            if cmd != "fbi_open_up":
                self.sandboxed_sessions.add(client_id)
                logger.warning(f"Client {ip}:{port} failed first command check, entering sandbox mode")
                self._log_activity(client_address, "sandboxed", "")
                self.first_command_validated[client_id] = False
            else:
                self.first_command_validated[client_id] = True
                return "Access granted. Welcome to the IoT management console."

        # Check for sandbox escape attempts and instantly blacklist if detected
        if client_id in self.sandboxed_sessions:
            for pattern, attack_type in self.attack_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    logger.warning(f"Sandbox escape attempt from {ip}:{port} - {attack_type}")
                    self._log_activity(client_address, "sandbox_escape", f"Escape attempt: {attack_type}")
                    self.add_to_blacklist(ip)
                    return "Access violation detected. Your IP has been blacklisted."
            return "Error: Command not found." # Pretend the command is not recognized in sandbox mode

        # Regular command processing for validated sessions
        # Check for malicious commands
        for pattern, attack_type in self.attack_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                self._log_activity(client_address, "attack_detected", f"Attack type: {attack_type}")
                logger.warning(f"Attack detected from {ip}:{port} - {attack_type}")
                return self._get_fake_response_for_attack(attack_type)
        
        # Handle basic commands first
        if cmd == 'help':
            return self._get_enhanced_sandbox_help()
        elif cmd == 'devices':
            return self._list_devices()
        elif cmd == 'connect':
            if not args:
                return "Usage: connect <device_id>"
            try:
                device_id = int(args[0])
                return self._connect_to_device(device_id)
            except ValueError:
                return "Invalid device ID. Please enter a number."
        elif cmd == 'scan':
            scan_results = [
                "Scanning network for devices...",
                "\nActive devices found:",
                "----------------------------------------"
            ]
            
            # Add some realistic device entries
            devices = [
                ("192.168.1.101", "Camera", "Online", "Hikvision DS-2CD2385G1"),
                ("192.168.1.102", "Thermostat", "Online", "Nest Learning v3"),
                ("192.168.1.103", "Smart Lock", "Online", "August Wi-Fi"),
                ("192.168.1.104", "Camera", "Offline", "Arlo Pro 4"),
                ("192.168.1.105", "Thermostat", "Online", "Ecobee SmartThermostat")
            ]
            
            for ip, type_, status, model in devices:
                scan_results.append(f"IP: {ip:<15} | Type: {type_:<10} | Status: {status:<8} | Model: {model}")
            
            scan_results.extend([
                "----------------------------------------",
                f"\nTotal devices found: {len(devices)}",
                "Scan complete."
            ])
            
            return "\n".join(scan_results)
        elif cmd == 'status':
            if self.current_device in ["camera", "thermostat"]:
                return self._process_device_command("status", args, self.current_device)
            return "Device type not supported for detailed status"
        
        # Handle device-specific commands
        if self.current_device in ["camera", "thermostat"]:
            if cmd in self.device_commands[self.current_device]:
                return self._process_device_command(cmd, args, self.current_device)
        
        return f"Unknown command: {command}\nType 'help' for available commands."

    def _list_devices(self):
        """List available IoT devices with their details"""
        device_list = [
            "Available IoT Devices:",
            "----------------------------------------"
        ]
        
        for device in self.available_devices:
            status_icon = "🟢" if device["status"] == "online" else "🔴"
            device_list.append(
                f"[{device['id']}] {status_icon} {device['type'].capitalize()} - {device['model']}\n"
                f"    IP: {device['ip']} | Status: {device['status'].capitalize()}\n"
                f"    Firmware: {device['firmware']} | Last seen: {device['last_seen']}"
            )
        
        device_list.extend([
            "----------------------------------------",
            f"Total devices: {len(self.available_devices)}",
            "\nUse 'connect <id>' to connect to a device"
        ])
        
        return "\n".join(device_list)

    def _connect_to_device(self, device_id):
        """Connect to a specific IoT device"""
        for device in self.available_devices:
            if device["id"] == device_id:
                if device["status"] == "offline":
                    return f"Error: Device {device_id} ({device['type']} - {device['model']}) is currently offline"
                
                self.current_device = device["type"]
                return (f"Connected to {device['type'].capitalize()} - {device['model']}\n"
                       f"IP: {device['ip']} | Firmware: {device['firmware']}\n"
                       f"Type 'help' to see available commands for this device")
        
        return f"Error: Device with ID {device_id} not found"

    def _get_fake_response_for_attack(self, attack_type):
        """Generate fake responses for attack attempts"""
        return "Error: Command not recognized. Type 'help' for available commands.\n"

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
        return False  # Disabled system command sandboxing

    def _get_enhanced_sandbox_help(self, is_admin=False):
        """Return enhanced help text for the sandbox environment"""
        help_text = [
            "=== IoT Network Management Console ===\n",
            "Available commands:",
            "  help         - Show this help message",
            "  scan         - Scan for devices on the network",
            "  devices      - List available devices",
            "  connect <n>  - Connect to device number <n>",
            "  status       - Show current device status",
            "  exit         - Exit the session"
        ]
        
        # Add device-specific commands if connected to a device
        if self.current_device in self.device_commands:
            help_text.extend([
                f"\nDevice-specific commands for {self.current_device}:"
            ])
            for cmd, desc in self.device_commands[self.current_device].items():
                help_text.append(f"  {cmd:<12} - {desc}")
        
        if is_admin:
            help_text.extend([
                "\nAdmin commands:",
                "  users        - List system users",
                "  adduser      - Add a new user",
                "  reset        - Factory reset a device",
                "  firmware     - Update device firmware"
            ])
        
        return "\n".join(help_text)