# ml_dos_test.py
import socket
import threading
import time
import argparse
import json
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

def format_success(message):
    return f"{Fore.GREEN}{message}{Style.RESET_ALL}"

def format_error(message):
    return f"{Fore.RED}{message}{Style.RESET_ALL}"

def format_warning(message):
    return f"{Fore.YELLOW}{message}{Style.RESET_ALL}"

def format_info(message):
    return f"{Fore.CYAN}{message}{Style.RESET_ALL}"

def format_ml(message):
    return f"{Fore.BLUE}[ML-FIRST] {message}{Style.RESET_ALL}"

def analyze_response(response):
    """Analyze response to determine if it was blocked by ML or other reasons"""
    if "blacklisted" in response.lower():
        return "BLACKLISTED"
    elif "suspicious activity" in response.lower() or "too many connections" in response.lower():
        return "ML_REJECTED"
    elif "access denied" in response.lower():
        return "ACCESS_DENIED"
    return "SUCCESS"

def rapid_connection(host, port, count, thread_id=None, interval=0.2, save_results=False):
    """Make rapid connections to test ML-first proxy DoS detection"""
    thread_label = f"Thread-{thread_id}: " if thread_id is not None else ""
    print(f"{format_info(thread_label + 'Starting ML-First DoS test:')} {count} connections to {host}:{port}")
    
    successful = 0
    failed = 0
    blacklisted = 0
    rejected_by_ml = 0
    access_denied = 0
    
    detailed_results = []
    
    for i in range(count):
        connection_result = {
            "connection_id": i+1,
            "thread_id": thread_id,
            "timestamp": time.time(),
            "status": "UNKNOWN",
            "response": "",
            "ml_detected": False,
            "error": None
        }
        
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            
            # Connect to the ML-first proxy
            s.connect((host, port))
            
            # Receive welcome message
            data = s.recv(4096)
            response = data.decode('utf-8', errors='ignore').strip()
            connection_result["response"] = response
            
            # Analyze the response
            result = analyze_response(response)
            connection_result["status"] = result
            
            if result == "BLACKLISTED":
                blacklisted += 1
                print(f"{thread_label}Connection {i+1}: {format_warning('BLACKLISTED')}")
                connection_result["ml_detected"] = True
            elif result == "ML_REJECTED":
                rejected_by_ml += 1
                print(f"{thread_label}Connection {i+1}: {format_ml('REJECTED BY ML')}")
                connection_result["ml_detected"] = True
            elif result == "ACCESS_DENIED":
                access_denied += 1
                print(f"{thread_label}Connection {i+1}: {format_error('ACCESS DENIED')}")
            else:
                # Try a random command
                s.sendall(b"admin\n")
                time.sleep(interval/2)  # Smaller delay between commands
                s.sendall(b"wrong_password\n")
                time.sleep(interval/2)  # Smaller delay between commands
                
                # Try to receive response
                try:
                    data = s.recv(4096)
                    additional_response = data.decode('utf-8', errors='ignore').strip()
                    connection_result["response"] += "\n" + additional_response
                    
                    # Check if the additional response indicates ML detection
                    additional_result = analyze_response(additional_response)
                    if additional_result != "SUCCESS":
                        connection_result["status"] = additional_result
                        if additional_result == "ML_REJECTED":
                            rejected_by_ml += 1
                            print(f"{thread_label}Connection {i+1}: {format_ml('COMMAND REJECTED BY ML')}")
                            connection_result["ml_detected"] = True
                        elif additional_result == "BLACKLISTED":
                            blacklisted += 1
                            print(f"{thread_label}Connection {i+1}: {format_warning('COMMAND TRIGGERED BLACKLIST')}")
                            connection_result["ml_detected"] = True
                        else:
                            access_denied += 1
                            print(f"{thread_label}Connection {i+1}: {format_error('COMMAND DENIED')}")
                    else:
                        successful += 1
                        print(f"{thread_label}Connection {i+1}: {format_success('SUCCESS')}")
                except:
                    failed += 1
                    print(f"{thread_label}Connection {i+1}: {format_error('TIMEOUT')}")
                    connection_result["status"] = "TIMEOUT"
            
            # Close the socket
            s.close()
            
        except Exception as e:
            failed += 1
            error_msg = str(e)
            print(f"{thread_label}Connection {i+1}: {format_error(f'FAILED - {error_msg}')}")
            connection_result["status"] = "ERROR"
            connection_result["error"] = error_msg
        
        # Add to detailed results
        detailed_results.append(connection_result)
        
        # Small delay to make the test more realistic
        time.sleep(interval)
    
    # Calculate ML detection rate
    total_connections = count
    ml_detected = rejected_by_ml + blacklisted
    ml_detection_rate = (ml_detected / total_connections * 100) if total_connections > 0 else 0
    
    print(f"\n{thread_label}{format_info('--- ML-First DoS Test Results ---')}")
    print(f"{thread_label}Total connections: {count}")
    print(f"{thread_label}Successful: {successful}")
    print(f"{thread_label}Failed: {failed}")
    
    print(f"\n{thread_label}{format_info('ML-First Layer Performance:')}")
    print(f"{thread_label}Connections rejected by ML: {rejected_by_ml}")
    print(f"{thread_label}Connections blacklisted: {blacklisted}")
    print(f"{thread_label}Total ML detections: {ml_detected}")
    print(f"{thread_label}ML detection rate: {ml_detection_rate:.2f}%")
    
    # Save detailed results if requested
    if save_results and thread_id is None:  # Only save for single-threaded tests
        try:
            filename = f"ml_dos_results_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump({
                    "summary": {
                        "total": count,
                        "successful": successful,
                        "failed": failed,
                        "rejected_by_ml": rejected_by_ml,
                        "blacklisted": blacklisted,
                        "access_denied": access_denied,
                        "ml_detection_rate": ml_detection_rate
                    },
                    "test_parameters": {
                        "host": host,
                        "port": port,
                        "connection_count": count,
                        "interval": interval
                    },
                    "detailed_results": detailed_results
                }, f, indent=2)
            print(f"\nDetailed results saved to {filename}")
        except Exception as e:
            print(f"\nError saving results: {e}")
    
    return {
        "total": count,
        "successful": successful,
        "failed": failed,
        "rejected_by_ml": rejected_by_ml,
        "blacklisted": blacklisted,
        "access_denied": access_denied,
        "ml_detection_rate": ml_detection_rate
    }

def main():
    parser = argparse.ArgumentParser(description="ML-First Architecture DoS Test")
    parser.add_argument("host", nargs="?", default="localhost", help="Target host")
    parser.add_argument("port", nargs="?", type=int, default=8080, help="Target port (ML proxy)")
    parser.add_argument("-c", "--count", type=int, default=30, help="Number of connections per thread")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of parallel threads")
    parser.add_argument("-i", "--interval", type=float, default=0.2, help="Delay between connections (seconds)")
    parser.add_argument("-f", "--fast", action="store_true", help="Use faster connection rate (0.05s interval)")
    parser.add_argument("--save", action="store_true", help="Save detailed results to JSON file")
    
    args = parser.parse_args()
    
    # Override interval if fast mode
    if args.fast:
        args.interval = 0.05
    
    print(f"\n{format_info('='*60)}")
    print(f"{format_info('ML-FIRST ARCHITECTURE DoS TEST')}")
    print(f"{format_info('='*60)}")
    print(f"Target: {args.host}:{args.port}")
    print(f"Connections: {args.count} per thread")
    print(f"Threads: {args.threads}")
    print(f"Interval: {args.interval} seconds")
    print(f"Save detailed results: {'Yes' if args.save else 'No'}")
    print(f"{format_info('='*60)}\n")
    
    print(format_ml("This test evaluates how the ML-First architecture responds to DoS attacks"))
    print(format_ml("The ML layer should detect and block high-rate connection attempts"))
    print(format_ml("As the attack progresses, connections should be rejected earlier in the process"))
    print()
    
    # If single thread, run directly
    if args.threads == 1:
        results = rapid_connection(args.host, args.port, args.count, interval=args.interval, save_results=args.save)
    else:
        # Create and start threads
        threads = []
        for i in range(args.threads):
            thread = threading.Thread(
                target=rapid_connection,
                args=(args.host, args.port, args.count, i+1, args.interval, False)
            )
            threads.append(thread)
            thread.start()
            # Short delay between thread starts to prevent exact synchronization
            time.sleep(0.05)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Aggregate results would be more complex, but at least provide a summary
        total_connections = args.count * args.threads
        print(f"\n{format_info('=== ML-First DoS Test Complete ===')}")
        print(f"Total connection attempts: {total_connections}")
        print(format_ml("Check individual thread results for ML detection details"))

if __name__ == "__main__":
    main() 